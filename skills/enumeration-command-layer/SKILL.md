---
name: 'enumeration-command-layer'
description: '两阶段枚举框架：外部枚举 (nmap后四轮) + 内部枚举 (拿shell后五维摸底: 定位/网络/进程/文件/用户)。'
whenToUse: '外部枚举（nmap 后四轮）或拿 shell 后内部五维摸底时；每个内网端口都是新攻击面，注意 Unix socket 感知 + localhost 陷阱。'
metadata: { domain: meta, tier: T1 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

# 枚举指挥层 — 完整的枚举行动框架

> 🔴 **两阶段枚举：外部（nmap后）→ 内部（拿shell后）。两个阶段同等重要。**
> 来源：80+ 台 HTB 机器的统计规律 — 按概率排序，不是按端口号。

---

## 铁律

```text
① 每一轮只做一件事 — 全部端口先扫第一阶段，再全部扫第二阶段
② 每个端口最多 2 分钟 — 不通就跳过，记下，下一轮试变异
③ 优先不认证的 — anonymous / null session / 无密码 > 需密码 > 需爆破
④ 拿到 shell 立即停 — 不继续枚举外部端口，开始第二阶段的内部枚举
⑤ 内部枚举扫完 → 没有攻击面 → 才回到外部继续
🆕 ⑥ 外部端口 > 3 次探测无响应 → 拿 shell 后立即 ss -tlnp 确认是否 127.0.0.1 绑定（Paperwork 教训: 9100 外部不可达浪费 20 分钟）
```text

---

# 阶段 1：外部枚举 (nmap 后 ~15 分钟)

## 第一轮：秒杀（≤ 4 分钟）

```text
[ ] SSL 证书 (所有 SSL 端口): nmap -sC 输出的 ssl-cert
    → Subject CN / SAN → 新子域? → 加 /etc/hosts
    时间限制: 30 秒

[ ] SMB (445): 匿名列出 → 有可写共享? → SCF 放 Responder
    smbclient -N -L //IP && smbmap -H IP
    时间限制: 1 分钟

[ ] Redis (6379): 无密码连接 → 写 SSH key / crontab / webshell
    redis-cli -h IP INFO
    时间限制: 30 秒

[ ] NFS (2049): showmount → no_root_squash? → SUID bash
    时间限制: 2 分钟

[ ] FTP (21): anonymous 登录 → 下载所有文件
    时间限制: 1 分钟

[ ] Docker API (2375): 未认证检查
    curl IP:2375/containers/json
    时间限制: 30 秒

[ ] SNMP (161): public community → snmpwalk 全量
    时间限制: 1 分钟
```text

## 第二轮：无认证数据收集（≤ 5 分钟）

```text
[ ] DNS (53): dig axfr → 子域全泄露?
[ ] LDAP (389): 匿名 bind → ldapsearch 全量 → 查 description
[ ] rpcclient (111): 空会话 → enumdomusers
[ ] MongoDB (27017): 无认证 → show dbs → dump
[ ] Elasticsearch (9200): curl /_cat/indices?v → dump
[ ] CouchDB (5984): curl /_all_dbs → CVE-2017-12635
[ ] Memcached (11211): stats → cachedump
[ ] rsync (873): 匿名列表 → 下载所有
[ ] IPMI (623): dumphashes (UDP)
```text

## 第三轮：Web 攻击面（≤ 10 分钟）

```text
[ ] 目录爆破 (每个端口 3 分钟)
[ ] Vhost 爆破 (5 分钟)
[ ] JS chunks → grep version → CVE
[ ] HTML 源码 → 框架/版本/API 端点
[ ] robots.txt / sitemap.xml / .git/config / .env
[ ] 后台登录 → 默认凭据 (最多 5 组)
[ ] 识别出版本号 → 立即 searchsploit
```text

## 第四轮：凭据喷洒（有凭据后）

```text
SMB / WinRM / SSH / MySQL / MSSQL / RDP / Jenkins / Grafana → 全试
```text

## 不知名端口 → unknown-service-probe 三步探测

---

# 阶段 2：内部枚举 (拿到 shell 后 — 🔴 这是新环境，你是个陌生人)

> 🔴 **拿到 shell = 你到了一个新环境。你的第一任务不是提权，是把整个环境摸透。**
> 🔴 **跳过这一步直接提权 = 你可能错过内网的全部攻击面。**

## 铁律

```text
① 先看清楚你在哪 → 才决定往哪走
② 内网服务 = 外部看不到的攻击面 → 优先于提权
③ 每发现一个新用户 / 新服务 / 新连接 → 回到第一行重新摸底
④ 完整的内部枚举 ≤ 10 分钟 → 之后才进入提权
🆕 ⑤ 外部端口探测 > 3 次无响应 ≠ 服务不存在 → 拿 shell 后 ss -tlnp 验证!
```text

## I. 定位 — 我在哪？（1 分钟）

```text
[ ] whoami; id; groups
[ ] uname -a; cat /etc/os-release; hostname
[ ] pwd; ls -la /; df -h
[ ] env | tr ' ' '\n'  | grep -iE "HOME|PATH|USER|SHELL|PWD|LOGNAME|DB|PASS|KEY|TOKEN|SECRET|CONFIG"

🔴 容器/沙箱检测 (优先级最高！):
[ ] cat /proc/1/cgroup | grep -E 'docker|lxc|kubepods|libpod'
[ ] snap list 2>/dev/null; flatpak list 2>/dev/null; firejail --list 2>/dev/null
[ ] grep NoNewPrivs /proc/self/status
[ ] mount | grep -E "/snap/|/var/lib/flatpak|/run/host"
→ 命中 → container-escape / noncontainer-sandbox-escape
```text

## II. 网络 — 哪些通路是对外不可见的？（2 分钟）

```text
[ ] ip a; ifconfig; hostname -I                # 我的 IP / 网卡
[ ] ip route; route -n                          # 路由表 → 其他网段?
[ ] cat /etc/hosts                               # 内部域名 → 新靶标
[ ] iptables -L -n 2>/dev/null                   # 防火墙规则
[ ] arp -a; cat /proc/net/arp                    # 邻居 → 内网存活主机

[ ] 🔴 ss -tlnp | grep LISTEN                   # TCP 监听端口 — 最重要!
    → 127.0.0.1:25151  → Cobbler (Cobblestone)
    → 0.0.0.0:4566      → LocalStack (Nimbus)
    → 127.0.0.1:9100    → JetDirect (Paperwork)
    → 127.0.0.1:3306    → MySQL (常规)
    → 127.0.0.1:8080    → 内部 Web
    → 每个 localhost 端口 → nc 直连 或 端口转发 → 重新进入阶段1外部枚举!

[ ] 🆕 ss -tlnp | grep 'srw'                    # Unix domain sockets — 极易忽略!
    → srw-rw---- root:archivist /run/xxx/mgmt.sock
    → 🔴 检查: 当前用户是否在 socket 的 GID 中?
    → 在组内 → python3 -c "import socket;s=socket.socket(socket.AF_UNIX);s.connect('/path')"
    → 不在组内 → 提权到该组 = 明确攻击路径

[ ] ss -tup | grep ESTAB                        # 当前连接 → 连到哪?
    → 连到 10.x.x.x:1433 → MSSQL 内网横向
    → 连到 DC:389 → 域成员 → AD 攻击面
```text

## III. 进程 — 谁在跑？谁跑的命令有参数？（2 分钟）

```text
[ ] ps aux | head -50                           # 不看全量，先看 root 和当前用户
[ ] ps aux | grep -vE "\[" | grep -v "ps aux"   # 去掉内核线程
[ ] cat /proc/1/cmdline | tr '\0' ' '           # init 进程 → systemd? docker-init?
[ ] pspy64 -pf -i 1000 & sleep 3; kill %1       # 无 root 也能看进程事件

🔴 重点看:
   ps aux 输出中的命令行参数 → -p 密码? -u 用户? --token? 第三个参数是 ROOT_DIR?
   定时执行的进程 → *.py / *.sh / 路径含 cron/timer
   root 进程 → 哪个是你的？哪个是别人的？
```text

## IV. 文件 — 哪些不是系统自带的？（3 分钟）

```text
[ ] ls -la /opt/ /srv/ /var/www/ /var/backups/ /tmp/ /dev/shm/
[ ] 🆕 ls -la /tmp/*.py /tmp/*.sh /opt/*/exploit* 2>/dev/null  # 🔴 先查已有 exploit!
    → 前一轮会话可能留了 exploit 脚本在 /tmp
    → Paperwork 教训: exploit_lpd.py 就在 /tmp 但被忽略
[ ] find / -maxdepth 4 -type f -name "*.conf" -o -name "*.env" -o -name "*.ini" 2>/dev/null | head -20
[ ] find / -maxdepth 4 -type f -name ".git" -o -name ".svn" 2>/dev/null
[ ] cat ~/.bash_history 2>/dev/null; cat ~/.mysql_history 2>/dev/null
[ ] ls -la /home/*/ /root/ 2>/dev/null           # 其他用户的家目录
[ ] find / -writable -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -30
[ ] grep -r "password\|passwd\|secret\|key\|token\|jdbc\|connection" /etc/ /opt/ /var/ 2>/dev/null | head -20

🔴 可写文件 = 攻击向量:
   可写 .service → systemctl daemon-reload → 以 root 启动恶意服务
   可写 cron 脚本 → 等定时执行
   可写 /etc/passwd → 直接加 root 用户
   可写 web root → webshell
   可写 .so 文件 → ld_preload / library hijacking
```text

## V. 用户 & 权限 — 我能变成谁？（2 分钟）

```text
[ ] who; w; last -a | head -10                   # 谁在线？谁刚登过？
[ ] cat /etc/passwd | grep -v nologin | grep -v false  # 真实用户
[ ] cat /etc/shadow 2>/dev/null                   # 🔴 可读 = 直接破解
[ ] ls -la /etc/passwd /etc/shadow                # 可写?
[ ] sudo -l 2>/dev/null                           # 我能 sudo 什么?
[ ] find / -perm -4000 -type f 2>/dev/null        # SUID
[ ] find / -perm -2000 -type f 2>/dev/null        # SGID
[ ] getcap -r / 2>/dev/null                       # capabilities
[ ] crontab -l; cat /etc/crontab; ls -la /etc/cron.*
[ ] systemctl list-timers --all 2>/dev/null
[ ] cat /etc/exports                               # NFS 共享
```text

---

## 两个阶段的关系

```text
阶段1 (外部枚举): nmap 后 → 发现 80, 445, 3000
                  ↓
                 SMB 匿名失败, Grafana LFI 拿到 Postgres 凭据
                  ↓
                 Postgres RCE → 🚩 SHELL as www-data
                  ↓
                 停！不继续扫 445 了。进入阶段2。

阶段2 (内部枚举): www-data → ss -tlnp → 127.0.0.1:9100 + srw-rw---- mgmt.sock
                  ↓
                 "JetDirect 在 localhost → nc 直连" → FSUPLOAD 路径穿越
                  ↓
                 archivist SSH → SCM_RIGHTS → admin 密码 → ROOT FLAG
```text

**内部枚举发现的每一个新端口/新 socket，都是新攻击面 — 把它当一台新机器重新走一遍外部枚举。**

---

**Why:** 80+ 台机器中，至少 15 台的关键攻击面在 internal 端口/socket，外部 nmap 根本看不到。
**How to apply:** 拿 shell → 停 → 内部枚举 10 分钟 → 有内网服务 → 转发/直连 → 回到阶段1。不跳步。
