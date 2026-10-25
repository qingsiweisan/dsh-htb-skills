---
name: 'tls-cert-san-enumeration'
description: 'TLS 证书 SAN/CN 子域枚举：nmap ssl-cert、openssl s_client(含 -starttls)、sslyze、curl 从任意 TLS 服务的证书里读出内部主机名,补上 DNS/vhost 爆破扫不到的虚拟主机。（检索词：TLS certificate/SAN/subjectAltName/CN/证书枚举/证书 SAN/子域枚举/vhost/虚拟主机/openssl s_client/starttls/sslyze/nmap ssl-cert/证书/域名/TLS-certificate/nmap ssl cert/enumeration）'
whenToUse: 'nmap 扫出 443/993/995/21(STARTTLS) 等任意 TLS 服务,但 DNS/vhost 爆破无结果;或页面只返回默认 vhost、资源指向一个解析不了的主机名时加载。'
metadata: { domain: network, tier: T3 }
---

# TLS 证书 SAN 子域枚举

> 来自 Insane 官方 WP 逐台回核,**5 台命中**:Brainfuck / Ariekei / CrossFit / Sorcery / Response(另有 Ghost 的 8443 证书 CN 旁证)。

**为什么要单独做一遍**:证书由管理员签发、由服务端在握手里主动交出来,**不经过 DNS 解析**。所以 `gobuster vhost`、`wfuzz`、`dig axfr` 扫不到的名字经常就写在证书里,而且零成本。

## 触发信号

- `nmap` 扫出**任意 TLS 端点** —— 443、5000/5001(registry)、993(IMAPS)、995(POP3S)、21(STARTTLS FTP),但 DNS 爆破 / vhost 爆破**全空**
- **页面返回默认 vhost**:首页正常但没有任何功能,或只是一张"联系 xxx@域.htb"的报错图(PlayerTwo)
- 页面资源(JS/CSS/表单 action/重定向 Location)指向一个**当前解析不了的主机名**(Toby 的 `wordpress.toby.htb`、Cobblestone 的 `deploy.cobblestone.htb`)
- 响应带 `Access-Control-Allow-Origin`,说明存在信任当前源的其他子域(CrossFit 用 `Origin` 头当字典)
- 只有一个 IP 可达,`/etc/hosts` 里没有对应名字 —— **这是"扫不出来"的常见原因,不是"没有"**

## 前置验证

```bash
nmap -p- --min-rate=1000 -T4 10.10.10.208   # 先确认哪些端口真的在讲 TLS
# 域名骨架:机器名 + .htb 是最常见的基础域
# Brainfuck/Ariekei/CrossFit/Sorcery 都直接从证书给出 <name>.htb 或 *.name.htb
echo '10.10.10.223 webhosting.htb www.webhosting.htb' | sudo tee -a /etc/hosts   # 拿到即写入
```

## 模式 1: nmap 服务扫描顺手取(`ssl-cert`)

条件:只要端口是 TLS,`-sC`/`--script` 就会在握手时把证书字段打出来 —— "零额外成本"的那一遍。

```bash
nmap -p22,80 cobblestone.htb -sC -sV        # 服务/脚本扫描,证书内容直接在输出里

# 显式点名(靶机上 root cron 的扫描脚本就是这么写的)
nmap -p 443 --script scripts/ssl-enum-ciphers,scripts/ssl-cert,scripts/ssl-heartbleed <IP>
```

**`ssl-cert` 是取 CN/SAN 的那一个**,`ssl-enum-ciphers` 只给密码套件。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Brainfuck | `nmap` 扫描时从 SSL 证书中枚举出 `brainfuck.htb` 与 `sup3rs3cr3t.brainfuck.htb`,写入 `/etc/hosts` 后才能访问这两个站点 |
| Sorcery | `nmap` 只有 22 与 443(`nginx/1.27.1`),证书 CN 为 `sorcery.htb`;据此访问登录页 `/auth/login` 与落地页给出的 Gitea 仓库 `git.sorcery.htb` |
| Response | 靶机上 root cron 的扫描脚本**改过** `ssl-cert.nse` —— 把证书字段当文件名用 → 目录穿越。定位法 `diff ./ssl-cert.nse /usr/share/nmap/scripts/ssl-cert.nse`;触发命令 `nmap -p 443 --script scripts/ssl-enum-ciphers,scripts/ssl-cert,scripts/ssl-heartbleed <IP>` |
| Ghost | `nmap` 的 ssl-cert 在 8443 读出 `CN=core.ghost.htb`;WP 明写"从 Nmap 扫描得到 DC01.ghost.htb、core.ghost.htb、ghost.htb",其中 `core` 是 DNS 爆破扫不出的 vhost |

## 模式 2: `openssl s_client`(含 `-starttls` 变体)

条件:只想看一张证书,或服务不是纯 TLS 而是**明文协议上做 STARTTLS** —— 这时必须加 `-starttls <proto>`。

```bash
openssl s_client -connect 10.10.10.65:443                 # 纯 TLS

openssl s_client -connect 10.10.10.208:21 -starttls ftp   # STARTTLS:FTP/SMTP/IMAP/POP3/XMPP

openssl s_client -showcerts -connect webhosting.htb:5000 < /dev/null   # 导出整链证书
```

🔴 **不要漏 `-starttls`** —— 21/25/143/110 默认不是 TLS,直接 `s_client` 只会挂住或立刻断开。

### HTB 案例
| 机器 | 细节 |
|------|------|
| CrossFit | `openssl s_client -connect 10.10.10.208:21 -starttls ftp` 从证书 CN `*.crossfit.htb` **以及其中的邮箱**推出 `gym-club.crossfit.htb`,写入 `/etc/hosts` |
| RegistryTwo | `openssl s_client -showcerts -connect webhosting.htb:5000 < /dev/null` 导出 `ca.crt`,装进 `/usr/local/share/ca-certificates/` 后 `update-ca-certificates`,才能 `docker pull webhosting.htb:5000/hosting-app` |

## 模式 3: `sslyze`(一把拿全 TLS 面)

条件:想知道"这个 IP 上到底签了哪些名字",或 nmap 输出太长/太糊 —— `--regular` 把证书链、SAN、协议支持一次列全,比 `nmap ssl-cert` 更适合**多主机名**场景。

```bash
sslyze --regular 10.10.10.65
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Ariekei | `sslyze --regular 10.10.10.65` 从证书里枚举出 `calvin.ariekei.htb` 与 `beehive.ariekei.htb`;对 `calvin` 目录爆破发现 `/upload` 与 `/cgi-bin/stats`(Bash 4.2.37,Shellshock)。这两个名字 `Dirbuster` 扫不出来 |

## 模式 4: `curl` 看 CN(已经在手边的最后一条)

条件:已经能连上某个 TLS 服务,只想确认"它认为自己是哪个名字" —— 顺带能拿 302 的 `Location` 与 `Server` 头。

```bash
curl -vk https://10.10.10.208/                # -v 把证书 subject/issuer/SAN 打到 stderr

curl -k -i https://magicgardens.htb:5000/v2/_catalog -u AlexMiles:diamonds   # 跳过校验+保留响应头
```

🔴 **IPv6 字面量在 URL 里必须加方括号**,否则解析失败:

```bash
http://[dead:beef::250:56ff:fe8f:6451]
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| MagicGardens | `curl -k -i https://magicgardens.htb:5000/v2/_catalog -u AlexMiles:diamonds` 认证成功后拿到仓库名,再用 `drg.py --dump` 拉层 |
| Mischief | SNMP 的 OID `1.3.6.1.2.1.4.34.1.3` 返回**十进制点分 IPv6**,先转十六进制,再按 `http://[dead:beef::250:56ff:fe8f:6451]` 加方括号访问隐藏面板 |

## 与相邻卡的分工

- `unknown-service-probe` —— 管 **favicon / banner / 协议指纹 / magic bytes**;证书 SAN 不在它的三步法里
- `enumeration-command-layer` —— 管 **nmap 四轮**(外部)+ 拿 shell 后五维摸底(内部);它不解析证书字段
- **本卡补的就是这一格**:任何 TLS 端点的 **证书 CN/SAN** 是一条独立的主机名枚举通道

## 快速检查清单

```bash
[ ] nmap 结果里有没有 443 / 993 / 995 / 5000 / 5001 / 21-STARTTLS?
[ ] 证书 CN 与 SAN 分别是什么?SAN 常比 CN 多出好几个名字
[ ] SAN 里是通配符(*.x.htb)吗?→ 把常见前缀(gym-club/ftp/wordpress/deploy/git)逐个试
[ ] 证书里的邮箱、O、OU 字段有没有泄漏用户名或子域?
[ ] 21/25/143/110 是不是要加 -starttls?
[ ] 枚举出的每个名字都写进 /etc/hosts 了吗?(漏这步 = 攻击面消失)
[ ] 页面资源(JS/CSS/action/Location)有没有指向另一个主机名?
[ ] 有没有 CORS 响应头?→ 可用 Origin 头当字典
[ ] IPv6 访问是否加了方括号?十进制点分是否已转十六进制?
[ ] TLS 上的脚本/工具是否被改过?(diff 官方 .nse)
```

## 教训

1. 🔴 **枚举出的 vhost 必须写进 `/etc/hosts`** —— 不写就等于不存在:请求会被路由到默认 vhost 或直接失败,**整个攻击面消失**。Brainfuck、CrossFit、Ariekei、PlayerTwo、Toby、Dyplesher 全靠这一步才打开。先把所有名字一次性写进去,再开始爆破。
2. 🔴 **IPv6 字面量在 URL 里要加方括号** —— `http://[dead:beef::250:56ff:fe8f:6451]`;从 SNMP 拿到的还是**十进制点分**格式,必须先逐段转十六进制才能用。
3. **`ssl-cert` 这类脚本可能被改过** —— 靶机上出现 `scripts/ssl-cert` 时先 `diff ./ssl-cert.nse /usr/share/nmap/scripts/ssl-cert.nse`;被改的版本会把证书字段当文件名去读(目录穿越),那本身就是漏洞。
4. **证书里的信息不止主机名** —— CN/SAN 给 vhost,**邮箱/O/OU 给用户名与组织线索**(CrossFit 从证书邮箱推出子域);一次握手要全字段读。
5. **STARTTLS 端口不能用纯 TLS 客户端,证书也只是入口** —— 21/25/143/110 必须 `-starttls <proto>`;拿到名字后仍要逐个做目录爆破、CORS 探测、资源引用比对,名字写对了才会看到真实应用(如 `calvin.ariekei.htb` 的 `/upload`)。

## 相关卡

- `unknown-service-probe` —— 证书之外的服务指纹(favicon/banner/magic bytes),本卡只补 SAN 这一格
- `enumeration-command-layer` —— nmap 四轮与内部五维摸底的主框架
- `service-attacks` —— 拿到端口后按端口号查具体利用
- `tunneling-port-forwarding` —— 子域只在内网可达时的隧道打法(Ariekei 用 `ssh -L` 绕 WAF 打通 Shellshock)
- `snmp-enumeration` —— Mischief 的十进制 IPv6 来源
