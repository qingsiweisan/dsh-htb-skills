---
name: 'unknown-service-probe'
description: '未知服务探测 SOP：端口不在 service-attacks 查表中 → 三步探测法 (Banner→协议指纹→CVE)。含二进制协议指纹 magic bytes 和 5 分钟规则。'
whenToUse: '端口开放但不在 service-attacks 查表中时'
metadata: { domain: network, tier: T1 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

# 未知服务探测 SOP

> 🔴 **nmap 告诉你端口开放但不知道是什么 → 别猜，逐步骤执行。**
> 来源：HTB 实战积累 — 至少 10 台机器的入口是"查表没有的端口"。

## 为什么需要这个 — service-attacks 有上限

```text
service-attacks 覆盖: 50+ 端口（以 service-attacks 实际表为准） ✅
HTB 可能出现的端口: 无限
你第一次见 :4840 → "OPC UA...这是什么？"
第一次见 :50051 → "gRPC...怎么连？"
```text

## 三步探测法（5 分钟完成）

### 步骤 1：Banner 抓取（30 秒）

```bash
# ① TCP raw — 连接看 server 自己说什么
nc -w 3 <IP> <PORT>              # TCP connect + 读 banner
echo "" | nc -w 3 <IP> <PORT>    # 有些服务需要先收数据
printf "OPTIONS / HTTP/1.0\r\n\r\n" | nc -w 3 <IP> <PORT>  # 试 HTTP

# ② SSL/TLS — 如果是加密的
openssl s_client -connect <IP>:<PORT> -servername <IP> 2>/dev/null
nmap --script ssl-enum-ciphers -p <PORT> <IP>

# ③ 读 banner 里的关键词
# "ActiveMQ" "OpenWire" → ActiveMQ
# "gRPC" → gRPC
# "SSH-2.0" → SSH 在非标端口
# "220" → SMTP 在非标端口
# "+OK" → POP3
# "* OK" → IMAP
```text

### 步骤 2：协议指纹（2 分钟）

```bash
# ④ nmap 深度探测
nmap -sV --version-all -p <PORT> <IP>    # 最高强度版本探测
nmap -p <PORT> --script "banner" <IP>     # 纯 banner

# ⑤ 用 curl 试 Web 协议
curl http://<IP>:<PORT> -v                    # HTTP
curl https://<IP>:<PORT> -k -v                # HTTPS
curl http://<IP>:<PORT> -H "Upgrade: websocket" -v  # WebSocket?

# ⑥ 用 nc 发典型协议 hello
# 试 SMB
printf '\x00\x00\x00\x90\xffSMBr\x00\x00\x00\x00...' | nc -w 2 <IP> <PORT> | xxd
# 试 gRPC/HTTP2
printf "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" | nc -w 2 <IP> <PORT>
# 试 MySQL
nc -w 2 <IP> <PORT> | xxd                    # 裸连先收到服务端 greeting，直接读 banner 即可；4 字节魔数非握手包
# 试 Redis
printf "PING\r\n" | nc -w 2 <IP> <PORT>                    # 返回 +PONG
# 试 memcached
printf "stats\r\n" | nc -w 2 <IP> <PORT>
```text

### 步骤 3：搜版本 → CVE（2 分钟）

```bash
# 重点: nmap 版本信息 → 精确到版本号 → 搜 CVE
# 如: "node.js 14.17.0" → GitHub Advisory: "node.js 14.17.0 exploit"
#      "gunicorn 19.9.0" → searchsploit gunicorn

searchsploit <software> <version>
# GitHub Advisory: https://github.com/advisories → 搜 <software> <version>
# NVD: https://nvd.nist.gov/vuln/search → 搜软件名
# Google: "<software> <version> exploit github"
```text

## 内网特有：端口转发后重新探测

```text
🔴 内网服务通常只在 localhost 监听 → 先建端口转发再跑上述三步
chisel 转发: chisel client <ATTACKER>:8000 R:8081:<INTERNAL_IP>:<PORT>
然后 nc / curl / nmap 都指向 localhost:8081
```text

## 常见"nmap 不识别的端口"实际身份

| nmap 显示 | 可能是 | 怎么确认 |
|-----------|--------|---------|
| `unknown` / `tcpwrapped` | 定制应用 / 被 DROP 的 ACK | nc 发数据 → 无响应 → 可能是防火墙拦截 |
| `http?` / `ssl/http?` | 非标 Web | curl + 目录爆破 |
| `generic` / `line` | TCP echo 或聊天协议 | nc 交互 → 输入 test → 看响应 |
| `??` | 二进制协议 | xxd 看返回 → 搜 magic bytes |
| `ssl/unknown` | 加密的任意协议 | openssl s_client → 手打协议命令 |
| `java-rmi?` / `rmiregistry?` | Java RMI | `nmap --script rmi-dumpregistry` |
| 高端口 30000+ | Docker/K8s 随机端口 / .NET Remoting / 游戏协议 | 搜容器漏洞 |

## 卡了 5 分钟还没进展 → 判定

```text
[ ] Banner 读出来了 → 搜到了软件名 → 回到 CVE 管道 ✅
[ ] Banner 是乱码 → 是二进制协议 → 搜 `"<PORT> 端口 协议"` → 匹配? ✅
[ ] 完全无响应 → 可能不是服务，是被防火墙拦截的端口 ❌ (跳过)
[ ] 有响应但完全不懂 → 记下端口号 + banner hexdump → 跳过，先搞已知攻击面
    → 回来时搜 HackTricks + Google 该端口号
```text

## 🔴 最大教训

```text
不能因为"不认识这个端口"就跳过它。
但也不能因为"不认识"就在同一个端口上死磕。

5 分钟规则:
  → 5 分钟内不能确定是什么协议 → 记下，跳过
  → 打完已确认的攻击面后 → 回来搜 HackTricks 这个端口号
  → 搜不到 → 可能是非预期端口 (SSH 在 2222, HTTP 在 8081)
```text

**Why:** service-attacks 表覆盖 50+ 端口（以实际表为准），但你下一个 HTB 机器大概率会开表外端口。这套 SOP 是让你把"不认识"变成"5 分钟找到答案"，而不是跳过或死磕。
**How to apply:** 任何 nmap 结果中标记为 unknown/tcpwrapped/generic 的端口 → 即时用这三步，不走查表路径。
