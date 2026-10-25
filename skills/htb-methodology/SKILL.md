---
name: 'htb-methodology'
description: 'HTB 打靶强制检查表：阶段0题型识别→侦察25项→初始立足→横向移动→提权→Docker 专项 + 阶段五收尾复核 + 核心教训。数据库即攻击面、JNLP 侦察、内网服务 fuzz。🆕 含内网判活铁律（RST 源 MAC / 三态 / 换源）、探针 liveness 断言（"无结果"前先证工具活着）与全否型结论的 retester 复核。（检索词：htb/methodology/checklist/enumeration/privesc/lateral/docker/jnlp/fuzz/判活/liveness/探针/先证探针/RST 源 MAC/源地址 ACL/三态探测/换源/pivot 源/阶段五/收尾/retester/复测/独立复核/假否证/false negative/baseline/对照/证据角色/全否/停摆/查询原语/primitive/阳性对照)'
whenToUse: '打靶机全流程的强制检查表：拿到 shell 后立即执行阶段0题型识别，各阶段按协议分类逐项确认；收尾时执行阶段五（全否型结论必须过独立 retester 复核）。'
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
    ├─ ADCS 存在 → certipy find → ESC1-16+（certipy 工具覆盖；本库分节止于 ESC14）
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

#### 🔴🆕 判活铁律（代价换来的，内网/被路由网段尤其必须走）

```
[ ] 🔴 RST ≠ 主机存在：中间盒会对【整个被路由网段】代答 RST —— 含【广播地址 .255】与非整数地址。
    ⇒ 判活必须看 RST 的【源 MAC】：tcpdump -e 抓，源 MAC = 网关 ⇒ 是代答，不是主机。
    实测: 某网段 10.100.1.0/24「.1/.2/.5/…/.255 全部 RST」，tcpdump -e 显示【源 MAC 全是网关】；
          同段 .5/.12/.101 的 RST 带自己 MAC（cf:e4:2e / …）⇒ 前者全是代答。
    ✅ 对照法（不用抓包也能判）：「必然不存在的地址」+「广播地址」一起探测，
       若它们与"可疑活主机"行为【完全一致】⇒ 全是代答，该段无主机。
[ ] 🔴 只看 "Connected" 的扫描器会把【主机活但端口关】误判成【无主机】。
    必须区分三态：LISTEN（开）/ ECONNREFUSED（主机活、端口关）/ ETIMEDOUT（被丢弃，什么都证明不了）。
    ⇒ Python socket 扫描记录 errno（connect_ex 返回值），不要只记布尔。
[ ] 🔴 换源 = 换结论：被路由网段/源地址 ACL 下，"X 到不了 Y" 只说明【这个源】到不了。
    ⇒ 存疑时补第二个源；枢纽机原生发包 ≠ 经 SOCKS/proxychains 转发
      （代理会让源 IP 被替换 ⇒ 你其实没换源，只是换了个说法）。
[ ] 🔴 完成【完整三次握手】的 OPEN 才是硬证据（多个端口同时 OPEN + tracert 仅一跳 ⇒ 真实主机）。
[ ] 🔴 只扫"常见端口"不足以判服务面（实测有主机 1-65535 只有 22 开）⇒ 判"没有服务"前必须全端口扫过。
[ ] 🔴 六点独立证据法（判"这个段不存在"）：MAC 层 tcpdump / UDP 探测 / DNS 转发器与 zone / 段侧配置
    （任务、服务路径、netstat）/ IPv6 复扫 / 对照组。缺一类就还只是"没找到"。
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
[ ] 🔴 有 SeBackupPrivilege / Backup Operators → 转储 hive 用 impacket-reg 的 backup 子命令
    （★ 别用 reg.exe save：WinRM/SMB 是网络登录，令牌里没这个特权 → rpc_s_access_denied）
    impacket-reg -k -no-pass dom/user@dc backup -o 'C:\Windows\SYSVOL\sysvol'
    ★ 落点选 SYSVOL：SYSTEM 能本地写，且 \\DC\SYSVOL 任意域用户可读 → 不必有 DC 的 WinRM/C$
    ★ 别写 UNC（\\其他主机\共享）→ rpc_s_access_denied；0xb7 = 上一次其实成功了
      → 错误码对照 + 取回 + 清理 见 ad-checklist §8.12
[ ] 杀软/EDR: wmic /namespace:\\root\securitycenter2 path antivirusproduct
[ ] 引用: ad-checklist 技能（完整版）+ windows-privesc 技能
```

## 阶段四：提权

### Linux
```
[ ] sudo -l → sudoedit? → CVE-2023-22809
[ ] getcap -r / → 文件 xattr capability（🔴 与容器进程的 CapEff 是两回事，勿混）
[ ] 🔴 在容器内 → 提权顺序是"先横向到特权容器"，不是找 D-Bus/SUID → container-escape 技能
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
[ ] 🔴 grep CapEff /proc/self/status            → 全 cap(0000003fffffffff) = privileged
[ ] 🔴 cat /sys/fs/cgroup/devices/devices.list  → "a *:* rwm" = privileged
[ ] 🔴 有 privileged 容器 → mknod + debugfs 直读宿主 fs（🔴 禁止 rw/loop 二次挂载）
[ ] uname -r → kernel CVE; Docker Desktop 版本 → CVE（如 CVE-2025-9074）
[ ] 检查 192.168.65.7:2375（Docker Desktop API）
[ ] docker/lxc/lxd 组 → 容器逃逸 → container-escape 技能
[ ] 挂载点 .. 遍历
[ ] 🔴 多容器(compose)题型 → 逐个枚举每个容器的 CapEff/devices.list 建表对比，
      逃逸口往往不在第一个拿到的容器上
```
🔴 CVE 路径需要版本+触发条件，命中率低；**privileged 是看一眼 CapEff 就能确定的 100% 路径，优先试它。**

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
8. 🔴 **否证必须带对照** — 判"不存在 / 无响应 / 被拦"前先给出 `baseline` 对照；**没有对照的"全否"不是结论**（见「阶段五」）

## 阶段五：收尾与复核（🔴 全否型结论必须过 retester）

> **本阶段唯一目的**：防止**假否证**把一条正确的路从搜索空间里永久划掉。
> 依据：`Store`（LFI 判死 25 min）与 2026-10 那次最贵误判（oracle 拿内存镜像自身字节当密文，
> 产出一个**看起来极严谨**的假否证，差点让正确路被永久排除；换对 oracle 后 25 分钟解出）。
> 🔴 **否证的可信度取决于 oracle 的正确性，不取决于扫描量。**

```
[ ] 🔴 停摆自检：目标未达成 且 无在跑 owner ⇒ 必须产生下一步
    （新任务 / 换 oracle 重派 / 显式宣布放弃并写理由）。**禁既不派单也不宣布终止。**
[ ] 🔴 "无结果"前先证探针活着：ps 进程在否 · ss 端口在听否 · 日志字节数涨否
    （把"日志没有 Received connection"读成"没连上"，真相是中继进程早已静默退出 —— 20 min 白走）
[ ] 🔴 否证先过工具闸：htb_coverage record(conclusion="negative", role="baseline", …)
    —— 缺 baseline 对照证据 id 会被工具直接拒绝。四元组（probe / primitive / 字段类型或协议语义 /
    control）+ retest_cost 的判据见 `frontier-and-evidence-anchors` §2.5
[ ] 🔴 结论落表必填 role：判活 / 判"不存在" / 判"被拦" ⇒ `baseline` 对照**强制**
    （判"段不存在"用「必然不存在的地址 + 广播地址」对照；判"无响应"要拿**确实存在**的文件对照）
[ ] 🔴 假否证复核：把所有 结论 ∈ {全否, 已证否, 已排除, 无响应, 不存在} 的条目
    交**独立子代理**复核（不要复用产出该否证的 agent —— 它复现不了自己的盲区）
    ├─ 🔴 卡住信号一出现就派（失败 ≥3 次 / 换 ≥2 方向不通 / 队列空 / idle > 20 min），不等收尾
    ├─ 任务书写法：believed <结论>，probed with <原语> — please re-test with a **different primitive**
    ├─ 显式邀请"一步到位的变体"（实测：两步方案被换成一发 ESC1）
    ├─ 判据：复核到"**喂了什么输入**"那一行；只有结论、没有输入来源 ⇒ 直接判【不可信】
    ├─ 三态回报：仍成立 / 已推翻 / 无法确认
    └─ 处置：判「已推翻」或「不可信」⇒ 移回待办链并**换正确 oracle** 重派一轮
[ ] 🔴 双旗搜全盘非默认位置（既有纪律）；改过的必须还原**并给复核输出**
[ ] 结论落回 `loot/`（别只留在对话里）；frontier「已收敛」表随收尾归档
```

> 完整模板（frontier / 资产覆盖矩阵 / 结论台账 / retester 任务书 / 跨 agent 过程检索配方）
> 见 `frontier-and-evidence-anchors`；多子代理场子的派单纪律见 `htb-workflow` §子代理分发协议。

## 核心教训

### Checkpoint 🔴: 题型识别缺失 → 2小时浪费在爆破上 / Server 2025 = dMSA / KDS + CreateChild + GenericWrite = BetterSuccessor / VMkatz 处理 vmem
### Interpreter 🆕: 搜索摘要漏关键参数（600000 iters）→ hash 破解失败 / 黑盒 fuzz 绕过源码审计直接定位 eval() / DB CHANNEL 表 = 攻击链地图 / JNLP 文件暴露完整技术栈
### MonitorsFour: vhost 不可跳过 / Docker Desktop CVE / 有 PoC 不手写
### Silentium: env 是密码宝库 / CVE 不过滤 / captcha 可找人帮
### Kobold: 子域独立搜 CVE / 软件名做用户名 / 版本号来源多样化
### Conversor: 源码全读 / XSLT 命名空间逐个试 / 凭据 > 反弹 shell
### Bastion 🔴: 32-bit 注册表 / mRemoteNG 立即搜凭据 / VHD 可能来自别的机器 / 凭据管理软件 > 内核提权
### Baby 🔴: LDAP description 字段是密码 / Backup Operators = Domain Admin / diskshadow VSS
### Dante（Pro Lab 27/27）🆕: **墙几乎都是「源×目的」二维 ACL，不是"不存在"** —— "X 到不了 Y" ≠ "Y 不存在"，只有换过 ≥2 个源才够说"无主机" / 判活看 **RST 源 MAC** + "必然不存在的地址 + 广播地址"对照 / **跨段凭据回收**（钥匙常在别的机器上，不在旗边上）/ **负结论与正结论同价**，标 `已证否 · 别重复` / 越界红线：VPN 推来的其它 lab 网段一律不碰，脚本写显式白名单
### Store 🆕: **"无响应" ≠ "被拦"** —— LFI 判死前必须让 payload 指向真实存在的文件 + 扫完参数空间（本例 `../` 深度 3 挂、**6 才到 `/etc/passwd`**；我因此把已到手的 LFI 判成死路 25 min） / **跨实例可见 ⇒ 先假设共享后端**（Store 是"三节点 + 一个 SFTP 后端 + 各自本地缓存"，我却先猜了组件更多的"peer 同步"） / **受限账号按通道查能力**（`ForceCommand internal-sftp` 不拦 `ssh -N -L`） / **提权面常只监听 127.0.0.1**（`ss -tlnp` + `ps auxww` 必须成对看用户列）
### Ifrit（Pro Lab 7/7）🆕: 🔴 **一条假否证 = 2.5 小时可达窗口** —— 承重否证"SIEM 里查过 `net user`，无果"的真相是**查询原语用错**：`process.command_line` 是 Elastic **wildcard** 类型，`match_phrase` 对它**恒返回 0**；换 `query_string` 一条命中 9 台机器管理员明文口令（后半场胜负手）。**教训是三重叠加的**：① 原语错 ② 没设阳性对照 ③ 已有硬闸（`htb_coverage` 的 baseline 规则）却一条否证都没记进去 ⇒ **闸存在 ≠ 闸生效** / **"没有输出" ≠ "没有发生"**（中继进程早已静默退出，我读的是"证据的缺席"却没先证采集工具还活着） / **构造期/部署期日志是最高价值凭据源**（`process.command_line` 里有全部管理员明文口令，且 `"net  user"` 在脚本里是**两个空格**）/ **卡住时二分**：结构性突破（网络 ACL / 端口占用）与"已有数据源扫干净了吗"必须交替推进，本次 65 min 全压在前者
