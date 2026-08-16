---
name: 'htb-methodology'
description: 'HTB 打靶强制检查表：阶段0题型识别→侦察25项→初始立足→横向移动→提权→Docker 专项 + 核心教训。数据库即攻击面、JNLP 侦察、内网服务 fuzz。'
whenToUse: '打靶机全流程的强制检查表：拿到 shell 后立即执行阶段0题型识别，各阶段按协议分类逐项确认。'
metadata: { domain: meta, tier: T1 }
---

# HTB 标准化打靶流程（强制检查表）

> 🔴 **本 checklist 是快速索引。拿到 shell 后 → 立即加载 linux-privesc 技能（Linux）或 ad-checklist 技能（Windows/AD）**
> 🆕 **内网服务 → 加载 unknown-service-probe 技能**

## 🔴 阶段零：题型识别（拿 shell 后第一秒）⚠️ Checkpoint 最大教训

```
[ ] 这是什么 OS 版本？
    ├─ Windows Server 2025 → 🎯 考虑: dMSA/BadSuccessor, VBS, Credential Guard
    ├─ Windows Server 2016+ → 考虑: Shadow Credentials, ADCS, RBCD
    ├─ Windows Server 2008-2012 → 传统 AD, Potato, 内核 CVE
    └─ Linux → linux-privesc 技能

[ ] 🔴 有什么新特性/异常属性？（LDAP/bloodyAD 查）
    ├─ KDS Root Key 存在 (CN=Group Key Distribution Service)
    │   └─ ⚠️ BadSuccessor/BetterSuccessor 题型！→ bloodyAD/badS4U2self
    ├─ msDS-KeyCredentialLink 属性存在 → Shadow Credentials 可用
    ├─ ADCS 存在 → certipy find → ESC1-13
    └─ 无特殊 → 传统路径

[ ] 🔴 已控用户有什么权限？
    ├─ CreateChild on OU + GenericWrite on 目标
    │   └─ 🎯 BetterSuccessor 完美条件 → 直接出目标 hash，不需要爆破！
    ├─ GenericWrite on 目标 → Shadow Credentials / Targeted Kerberoast
    ├─ WriteDacl / WriteOwner → RBCD / 直接改权限
    └─ 仅 READ → 信息收集

[ ] 🔴 判定题型 → 选择攻击路径
    ├─ BadSuccessor 题型 → bloodyAD + badS4U2self，别碰爆破和 Kerberoast
    ├─ Shadow Credentials → certipy shadow auto / bloodyAD shadowCredentials
    ├─ Kerberoast 题型 → 传统 hashcat 爆破
    └─ 综合 → 先试最短路径

[ ] 🔴 有 .vmem/.vmdk/.vhd 文件？
    └─ 🎯 VMkatz 直接提取 → 别手写 volatility

[ ] 🆕 有数据库访问权限？
    ├─ MySQL/PostgreSQL → 查所有表结构（SHOW TABLES / \dt）
    ├─ 🔴 重点查: CHANNEL / CONFIGURATION / *_CHANNELS 表
    │   └─ Java 应用（Mirth/ServiceMix 等）的 CHANNEL 表 = 攻击链地图！
    │   └─ 暴露: HTTP endpoint、method、content-type、字段映射、内部服务地址
    ├─ PERSON / PERSON_PASSWORD → 用户 + 密码 hash
    └─ CONFIGURATION → digest.algorithm、SMTP 配置、加密密钥
```

## 阶段一：侦察（25 项 — 按协议分类，每类必须确认）

### 网络层
```
[ ] nmap -sV -sC -p- --min-rate 1000 -T4 <IP>             # TCP 全端口
[ ] nmap -sU -sV --top-ports 100 <IP>                      # 🔴 UDP top 100
```

### Web 层
```
[ ] 访问 HTTP/HTTPS + 源码找版本号
[ ] whatweb <url>; wappalyzer 识别技术栈                   # 🔴 技术栈指纹
[ ] wafw00f <url>                                          # 🔴 WAF 检测
[ ] gobuster/ffuf vhost + 目录扫描                         # ← ❗不可跳过！
[ ] ffuf -u http://<IP> -H "Host: FUZZ.htb" -w subdomain.txt
[ ] gobuster dir -u <url> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[ ] 🔴 搜 JS chunk 版本 → 立即查 CVE（不过滤条件！）
[ ] 🔴 每个子域/应用独立版本识别（HTML footer、HTTP header、错误页面）
[ ] 🔴 每个子域/应用独立搜 CVE
[ ] 🔴 robots.txt, sitemap.xml, /.git/, /.svn/, /.DS_Store
[ ] 🔴 源码泄露 → tar.gz / .zip / .bak → ls -la 列出所有文件 → 每个都读！
[ ] 🔴 API 端点: /api, /swagger, /graphql, /v1, /v2, /docs, /.env
[ ] 🔴 邮件地址收割 → 用户名喷洒
[ ] 🔴 默认凭证库: cirt.net, default-password.info
[ ] 🔴 WordPress: wpscan --url <url> --enumerate p,t,u
[ ] 🆕 JNLP 文件（Java Web Start）: webstart.jnlp → 包含完整 JAR 列表 + 版本号！
```

### SMB / RPC
```
[ ] 🔴 SMB 枚举: smbclient -L //<IP>; smbmap -H <IP>
[ ] 🔴 SMB 递归列出: smbmap -r <share>; smbclient recurse → 找 .vhd .bak .xml .config .kdbx
[ ] 🔴 rpcclient -N -U "" <IP> → enumdomusers, lsaenumsid, querydispinfo
```

### LDAP / AD
```
[ ] 🔴 LDAP 匿名绑定: ldapsearch -x -H ldap://<IP> -b "dc=domain,dc=com"
[ ] 🔴 所有 description / info / notes 字段 → 密码宝库！（Baby 教训）
```

### 其他协议
```
[ ] 🔴 SNMP: snmpwalk -v2c -c public <IP>
[ ] 🔴 DNS 区域传送: dig axfr @<IP> <domain>
[ ] 🔴 NFS: showmount -e <IP>
[ ] 🔴 SMTP: VRFY / EXPN / RCPT TO 用户枚举
[ ] 🔴 FTP: anonymous 匿名登录
[ ] 🔴 WinRM: 端口 5985/5986 → evil-winrm 可用性
```

## 阶段二：初始立足

```
[ ] 找到应用版本 → searchsploit + GitHub Advisories + NVD（完整列出，不过滤）
[ ] 版本确认后第一秒搜 PoC，不许自己写！
[ ] 🔴 Web: SQLi / SSTI / XXE / LFI / File Upload / Command Injection → 每个参数试
[ ] 有漏洞直接利用；无漏洞则爆破/默认凭证
[ ] 🔴 凭据喷洒字典 = 系统用户名 + 邮箱本地部分 + 软件名本身 + 域名前缀
[ ] 🔴 密码来源：env 变量、配置文件、config 注释、默认密码、常见弱密码
[ ] 🔴 SMB 发现 .vhd / .vhdx → 挂载 → SAM/SYSTEM 提取 → secretsdump
[ ] 一旦拿到 shell → 立即执行阶段零 + 阶段三检查表 + 读对应 OS 详细 checklist
```

## 阶段三：横向移动（拿到 shell 立即执行）

### 全线（Linux + Windows 通用）
```
[ ] 🔴 env && cat /proc/1/environ | tr '\0' '\n'          # 环境变量是第一站！
[ ] 🔴 所有 env PASSWORD/SECRET/KEY/TOKEN → 立即试 SSH
[ ] 找 config：.env, web.config, app.ini, database.*, *.conf
[ ] ps aux / tasklist → root/SYSTEM 进程、异常服务
[ ] ss -ntlp / netstat -ano → 内网服务（127.0.0.1 / localhost）
[ ] mount / cat /proc/1/mountinfo → 挂载点、Docker 检测
[ ] 🔴 bash_history / PowerShell ConsoleHost_history.txt
[ ] 🔴 .ssh/id_rsa, authorized_keys, *.pem, *.ppk
[ ] 🔴 凭据收集完 → 去交互化（SSH key 去密码、写 authorized_keys）
[ ] 🆕 🔴 数据库连接 → SHOW TABLES → 重点查 CHANNEL/CONFIGURATION/PERSON_PASSWORD
[ ] 🆕 🔴 内网服务 → Python socket 直连 fuzz → 加载 unknown-service-probe 技能
```

### Linux 专项
```
[ ] id; uname -a; cat /etc/os-release; cat /etc/passwd
[ ] getcap -r / 2>/dev/null; find / -perm -4000 -type f 2>/dev/null
[ ] sudo -l; crontab -l; cat /etc/crontab; systemctl list-timers --all
[ ] find / -writable -type f 2>/dev/null | grep -v proc
[ ] 容器内？→ 立即 docker/LXC 相关检查 → container-escape 技能
[ ] 引用: linux-privesc 技能（完整版）
```

### Windows 专项
```
[ ] whoami /all; whoami /priv; net user; net localgroup
[ ] systeminfo | findstr /B /C:"OS" /C:"Hotfix"  # 内核版本 + 补丁
[ ] 🔴 PowerShell history: type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
[ ] 🔴 reg save HKLM\SAM / HKLM\SYSTEM（如果权限够）
[ ] 杀软/EDR: wmic /namespace:\\root\securitycenter2 path antivirusproduct
[ ] 引用: ad-checklist 技能（完整版）+ windows-privesc 技能
```

## 阶段四：提权

### Linux
```
[ ] sudo -l → sudoedit? → CVE-2023-22809
[ ] getcap → cap_sys_admin/cap_sys_ptrace → 利用
[ ] SUID → GTFOBins; 内核 → searchsploit
[ ] 🔴 Wildcard 注入 / 共享库劫持 / 可写 passwd&sudoers / TMUX
[ ] 🔴 已安装软件包 → dpkg -l / rpm -qa → 逐版本 searchsploit
[ ] 引用: linux-privesc 技能（完整版）
```

### Windows 软件枚举（🔴 第一优先级！）
```
[ ] 🔴 64-bit: reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall /s
[ ] 🔴 32-bit: reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall /s
[ ] 🔴 dir "C:\Program Files"; dir "C:\Program Files (x86)" → 每个文件夹名 = 攻击面
[ ] 🔴 每个软件 → 精确版本号 → searchsploit + GitHub CVE
[ ] 🔴 凭据管理软件专项:
     mRemoteNG → %APPDATA%\mRemoteNG\confCons.xml → mremoteng_decrypt.py
     PuTTY    → reg query HKCU\Software\SimonTatham\PuTTY\Sessions
     FileZilla → %APPDATA%\FileZilla\sitemanager.xml
     WinSCP   → reg query HKCU\Software\Martin Prikryl\WinSCP 2\Sessions
     KeePass  → *.kdbx → john/keepass2john
[ ] 🔴 浏览器密码: LaZagne.exe browsers
[ ] 🔴 全局 AppData: dir /s /b %APPDATA%\*confCons* *.rdp *.rdg *.sdtid
[ ] 🔴 加密密码 → 搜 GitHub decryptor（别手写！）
```

### Windows 快速提权
```
[ ] whoami /priv → SeImpersonate → Potato; SeBackup → SAM dump; SeDebug → 进程注入
[ ] AlwaysInstallElevated: reg query HKCU + HKLM \Policies\Microsoft\Windows\Installer
[ ] Unquoted service path: wmic service get name,pathname | findstr /v C:\Windows
[ ] systeminfo → 补丁 N/A? → searchsploit kernel
[ ] 引用: windows-privesc 技能（完整版）
```

## Docker 容器专项

```
[ ] env + /proc/1/environ + /proc/1/mountinfo
[ ] uname -r → kernel CVE; Docker Desktop 版本 → CVE（如 CVE-2025-9074）
[ ] 检查 192.168.65.7:2375（Docker Desktop API）
[ ] docker/lxc/lxd 组 → 容器逃逸 → container-escape 技能
[ ] 挂载点 .. 遍历
```

## 反弹 Shell 纪律（DSH 本机 bash）

```
[ ] 🔴 推荐 socat 给 PTY（有提示符，配合 sleep 等待输出）:
    socat file:$(tty),raw,echo=0 tcp-listen:4444
[ ] nc 备选（无 PTY 无提示符）: nc -lvp 4444
[ ] 快命令等 300-500ms 再读，慢命令（find/ps/nmap）等 1-3 秒
[ ] 长任务用 bash 工具 run_in_background + job_output 收结果
```

**🔴 核心原则：**
1. **socat 给 PTY** — 有提示符，不要 nc
2. **拿到 shell 第一件事跑完整检查表** — 先题型识别 → 再 env → SSH → configs → 引用 OS 专项技能
3. **不过滤 CVE** — 先列出全部，再筛选
4. **🔴 爆破是最后选项，不是第一反应** — 先试 BetterSuccessor / Shadow Credentials / 已知 CVE
5. 🆕 **数据库是攻击面地图** — CHANNEL/CONFIG 表直接暴露数据流、端点、内部服务
6. 🆕 **内网服务用 Python socket 直连** — 不通过 nc/curl 中转，完整读 body
7. 🆕 **搜索摘要 ≠ 完整信息** — 版本变更/算法参数类搜索必须点原文读全文

## 核心教训

### Checkpoint 🔴: 题型识别缺失 → 2小时浪费在爆破上 / Server 2025 = dMSA / KDS + CreateChild + GenericWrite = BetterSuccessor / VMkatz 处理 vmem
### Interpreter 🆕: 搜索摘要漏关键参数（600000 iters）→ hash 破解失败 / 黑盒 fuzz 绕过源码审计直接定位 eval() / DB CHANNEL 表 = 攻击链地图 / JNLP 文件暴露完整技术栈
### MonitorsFour: vhost 不可跳过 / Docker Desktop CVE / 有 PoC 不手写
### Silentium: env 是密码宝库 / CVE 不过滤 / captcha 可找人帮
### Kobold: 子域独立搜 CVE / 软件名做用户名 / 版本号来源多样化
### Conversor: 源码全读 / XSLT 命名空间逐个试 / 凭据 > 反弹 shell
### Bastion 🔴: 32-bit 注册表 / mRemoteNG 立即搜凭据 / VHD 可能来自别的机器 / 凭据管理软件 > 内核提权
### Baby 🔴: LDAP description 字段是密码 / Backup Operators = Domain Admin / diskshadow VSS
