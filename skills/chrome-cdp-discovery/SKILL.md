---
name: 'chrome-cdp-discovery'
description: 'Chrome DevTools Protocol 随机端口发现 + 利用：ss 找端口 → /json 探测 → HTTP API 操作标签页。来源 Makesense。'
disable-model-invocation: true
metadata: { domain: web, tier: T3 }
---


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
```text

### CDP 端点速查

| 端点 | 方法 | 用途 |
|------|------|------|
| `/json` | GET | 列出所有可调试页面（含 WebSocket URL） |
| `/json/version` | GET | 浏览器版本信息 |
| `/json/new?url=<URL>` | PUT | 打开新标签页 |
| `/json/close/<id>` | GET | 关闭标签页 |
| `/json/activate/<id>` | GET | 激活标签页 |

### WebSocket 连接限制

Chrome 111+ 需要 `--remote-allow-origins=*` 才能通过 WebSocket 连接。无此参数时返回 **403 Forbidden**。

### 绕过尝试

- **HTTP CDP 端点**（`/json/*`）无需 WebSocket，可直接调用
- `/json/new?url=` 可打开新标签页，但 `data:` 和 `javascript:` URL 会被拒绝（`about:blank`）
- 可尝试打开同源 URL 利用已有 cookies
- 如能写文件到 web root，可构造恶意 HTML 页面让 bot 访问

### 进程信息

- Chrome 二进制: `/opt/google/chrome/chrome`
- ChromeDriver: `/home/<user>/.wdm/drivers/chromedriver/linux64/<version>/chromedriver-linux64/chromedriver`
- 用户数据目录: `/tmp/org.chromium.Chromium.scoped_dir.XXXXXX`
