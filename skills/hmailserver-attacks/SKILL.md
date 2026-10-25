---
name: 'hmailserver-attacks'
description: '25 端口 banner 是 `220 <HOST> ESMTP`、EHLO 只给 SIZE/AUTH LOGIN/HELP 没有 STARTTLS、`RCPT TO` 对不存在用户回 `550 Unknown user` 时加载：hmailserver 只在 Windows 上跑的开源邮件服务器攻击面 —— 未认证邮箱枚举、autoban 默认值（按 IP 不按账户、RCPT 失败不计入）、版本判定信号、以及拿到低权 shell 后 `ProgramData\hMailServer` 对普通用户可读 ⇒ 全部邮件 + hMailServer.ini 里的口令。(检索词：hmailserver/hMailServer/hmail/SMTP/ESMTP/25/587/110/143/邮件服务器/mail server/RCPT TO/VRFY/EXPN/Unknown user/用户枚举/mailbox enumeration/autoban/auto-ban/自动封禁/550 Unknown user/250-SIZE/hMailServer.ini/AdministratorPassword/Blowfish/THIS_KEY_IS_NOT_SECRET/PHPWebAdmin/hMailServer.sdf/SQLCE/邮箱/收件人枚举/邮件)'
whenToUse: '25 端口跑着 hMailServer（Windows 靶机上的邮件服务），需要枚举用户、判断能不能免认证打、或已经从别的口拿到低权 shell 想找凭据时'
metadata: { domain: network, tier: T3 }
---

# hMailServer 攻击面（Windows 上的自建邮件服务器）

> ⚠️ **一手实测卡**（HTB JobTwo, hMailServer 5.x 默认配置, 2026-09-30）+ 上游源码/官方文档核对，**非 WP 语料回灌**。
> 结论分两类：**实测**（JobTwo 真机验证）与**文档**（读 hmailserver 源码/官方 doc 得出，标 🔷 的是推论）。

## 触发信号

```text
220 <HOST> ESMTP                       ← banner 就是"主机名 + ESMTP"，不含版本号
250-<HOST>
250-SIZE 20480000                      ← 20480 KB = hMailServer 默认 maxmessagesize
250-AUTH LOGIN                         ← 没有 STARTTLS / AUTH PLAIN 时多半是默认配置
250 HELP
```
```text
VRFY x            → 502 VRFY disallowed.        ← hMailServer 硬禁用 VRFY，零信息量
EXPN  x           → 503 Bad sequence of commands ← 根本没实现
HELP              → 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
                     ↑ "SAML" 是源码里的拼写错误（应是 STARTTLS）—— 很好的版本指纹
RCPT TO:<hr@dom>  → 250 OK
RCPT TO:<x@dom>   → 550 Unknown user            ← 唯一的用户枚举预言机
```

## 前置验证

```bash
# 1) 邮箱枚举（🔴 hMailServer 默认不限速、不断连——一条连接发无限多个 RCPT 就行）
python3 - <<'PY'
import socket, time
s = socket.create_connection(('TARGET', 25), 10); s.settimeout(8); s.recv(4096)
s.sendall(b'EHLO a.local\r\n'); time.sleep(.3); s.recv(4096)
s.sendall(b'MAIL FROM:<a@a.local>\r\n'); time.sleep(.3); s.recv(4096)
for u in ['hr','admin','postmaster','it','info','jobs']:
    s.sendall(f'RCPT TO:<{u}@DOMAIN>\r\n'.encode()); time.sleep(.25)
    print(u, s.recv(4096).decode(errors='replace').strip())
PY

# 2) 是不是 catch-all？（catch-all 会让枚举完全失效）
#    ✓ 只要有一个名字回 550 Unknown user ⇒ 该域没有 catch-all，枚举可信

# 3) 是否开放中继 / 能否无认证投递外部发件人的邮件
swaks --to hr@DOMAIN --from anyone@external.tld --server TARGET
```

## 模式 1: 用户枚举与 550 文案的信息量

`RCPT TO` 的 550 文案**不止回答"存在与否"**，不同文案还会泄露账户状态：

| 响应 | 含义 |
|---|---|
| `550 Unknown user` | 该域**没有**这个账户（且该域没有 catch-all） |
| `550 Account is not active.` | 账户存在但被停用 |
| `550 Domain has been disabled.` | 域存在但被停用 |
| `550 Alias is not active.` / `550 Distribution list is not active.` | 别名/通讯组存在 |
| `550 Recipient not in route list.` | Route 表里有该域但收件人不在名单 |
| `250 OK` | 可用收件人 |

🔷 **ETA 型侧信道**：`AUTH LOGIN` 的错误文案对所有情况都相同（`535 Authentication failed.`），
但**校验耗时不同** —— 账户不存在/停用时会**立刻返回**，而存在的活跃账户会真的跑一次 KDF 校验（Argon2id/PBKDF2 或历史 MD5/SHA256/Blowfish）。
⇒ 拿不准时可以比时间，但更稳的还是 RCPT。

### HTB 案例
| 机器 | 细节 |
|------|------|
| JobTwo | 只有 `hr@job2.vl` 有效（试了 70+ 常见名）；站点正文点名要投给 hr |

## 模式 2: 🔴 autoban 默认值 —— 别拿攻击 IP 去喷密码

| 参数 | 默认值 |
|---|---|
| `AutoBanOnLogonFailureEnabled` | 1（开） |
| `MaxInvalidLogonAttempts` | **3** |
| `LogonAttemptsWithinMinutes` | 30 |
| `AutoBanMinutes` | **60** |

- 🔴 **作用域是"整个源 IP"，不是单个账户**：失败记录存在 `hm_logon_failures(ipaddress1, ipaddress2, failuretime)`，按 IP 计数与清除。
- 触发后它创建一个名为 `Auto-ban: <username>` 的安全范围，**对所有协议生效** ⇒ SMTP + POP3 + IMAP 一起被封 60 分钟。
- 🔴 **RCPT 的失败不计入 autoban**（只喂另一个"单连接无效命令计数"，默认 100，且 `DisconnectInvalidClients` 默认 **0 = 关**）
  ⇒ **可以放心用 RCPT 枚举，但绝不能拿同一个 IP 试口令。**
- 规避：同一源 IP 每 30 分钟最多 2 次认证失败；或换源 IP（很贵，慎用）。

## 模式 3: 版本判定

| 信号 | 说明 |
|---|---|
| banner | **不含版本**：`welcomesmtp` 默认 0 ⇒ banner = `计算机名 + " ESMTP"`，别把主机名当版本 |
| `250-SIZE 20480000` | = 默认 `maxmessagesize`(20480 KB)，是"默认安装"的旁证 |
| `211 HELP` 列表里的 `SAML` 拼写错误 | 5.x 源码特征 |
| 未知用户 550 文案 | `Unknown user` 是源码里的字面量 |
| 本机（需立足点） | `{app}\Bin\hMailServer.exe` 文件版本、DB 行 `hm_dbversion`、`hMailServer.ini` |

## 模式 4: 🔴🔴 免认证 RCE —— **5.x 没有，别抱期待**

- 5.x 线（JobTwo 观察到的全部特征都指向 5.x 默认安装）**没有任何公开的免认证 RCE / 认证绕过 / 任意文件读**。
- 唯一已知的免认证 RCE 是 **CVE-2026-100741**（CVSS 9.8，影响 **6.0.0 – 6.3.3**，修于 6.3.4）：
  JScript 事件脚本分发器里的 eval 注入（口令含 `\` + `'`，任意 logon 通道命中已存在且活跃的账户即执行）。
  🔴 **但它需要非默认配置**：事件脚本开启（默认关）+ 脚本语言是 **JScript**（默认是 VBScript）+ 定义了 `OnClientValidatePassword`。
  ⇒ **先确认这三样再投入时间**；无公开 PoC。
- 老洞只有 DoS：CVE-2008-3676（IMAP 资源耗尽）、CVE-2013-5571（≤5.3.4 内存破坏）。

## 模式 5: 拿到低权 shell 后的凭据面（本卡最高价值）

🔴 **hMailServer 把"邮件 + 配置"放在一个对 `Users` 可读的目录里** —— 厂商文档自己写明这是已知风险，
给出的修法是 `icacls "C:\ProgramData\hMailServer" /remove:g *S-1-5-32-545`（默认没做）。
⇒ **任何本地普通用户 = 能读全部邮件 + DB 口令 + 管理员口令**。

```cmd
:: 数据/配置位置（新版在 ProgramData；老版在安装目录或 %WinDir%）
dir "C:\ProgramData\hMailServer"                :: hMailServer.ini / Data / Database / Logs / Events
dir "C:\Program Files (x86)\hMailServer"        :: 老式布局：Bin / Data / Database / Events / Logs

:: 🔴 最值钱的文件：口令都在这儿
type "C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini"
```

```ini
[Security]
AdministratorPassword=<REDACTED>   ← 装的时候写的是 MD5，可离线破
[Database]
Type=MSSQLCE
Password=<REDACTED>                ← Blowfish 加密
PasswordEncryption=1
Internal=1
```

- **DB 口令**：12 字符 GUID 派生串，用**硬编码 key `THIS_KEY_IS_NOT_SECRET`** 做 Blowfish 加密；
  hMailServer 自己就带 `Addons/Utilities/DecryptBlowfish.vbs` 可解（🔷 未在 JobTwo 上验证，因为不需要）。
- **管理员口令**：安装器写 **MD5**（`[Security] AdministratorPassword`），后期改动才换强方案 ⇒ 可直接破。
  HTB 案例里这个 MD5 不在 rockyou/常见规则空间（GPU 67.7 GH/s 秒级扫完未命中）。
- **全部邮件**：`Data\<domain>\<mailbox>\<2位>\{GUID}.eml` —— 目录本身对普通用户可读，
  可直接 `findstr /s /i "password credential" *.eml` 扫凭据。
  🔴 但要预期**多数邮件就是你自己的钓鱼投递**，别把"我能读邮件"当成已拿到凭据。
- **`.sdf` 数据库**（`Type=MSSQLCE` 时的 `Database\hMailServer.sdf`）：
  🔴 **实测它对普通用户可读、可复制，但内容是整体加密的**（`strings -a` 无结构、`strings -a -el` **0 条**）。
  这是 SQLCE 自身的库加密，**不是** ini 里那个 Blowfish 方案 ⇒ **不要指望用手上的 key 离线解密**。
- **PHPWebAdmin**：可选组件，IIS/PHP 前端经 DCOM 走 COM API（`com.allow_dcom = true`，还要给服务账户授 COM 权限）；
  版本登录后可见（🔷 未认证时的泄露未验证）。

### HTB 案例
| 机器 | 细节 |
|------|------|
| JobTwo | `hMailServer.ini` 对 `JOB2\Julian` 可读 → 拿到 admin MD5 + DB 口令；`Data\job2.vl\hr\` 8 个 .eml 全部可读（但都是自己投的） |

## 模式 6: 让 hMailServer 主动出站（OOB 通道）

🔷 文档口径。可用于确认"靶机能不能连回你"：

- **NDR/bounce（最强）**：消息被收下后投递失败时，`SubmitErrorLog_` 会用**原始 `MAIL FROM`**（完全可控）
  造一封退信并排队 ⇒ hMailServer 主动向你的域/Route 发 SMTP。
- 账户 **自动回复/vacation**（对发件人回一次）与规则动作 **Reply** 同理，目标都是攻击者的 `MAIL FROM`。
- 规则动作 `Forward email` / `Send using route` / `Run function`（脚本）由管理员配置，但**触发条件**（From/To/Subject/Body/头/大小）是攻击者可控的。
- **Route** 的 "Target SMTP host" 可以直接填 IP（`ServerTargetResolver` 对 `IsValidIPAddress` 有专门分支），
  ⇒ 管理员配了 Route 就能指定 IP:port，不走 MX。地址字面量（`user@[1.2.3.4]`）🔷 没有"直连该 IP"的行为，别指望。

## 快速检查清单

```bash
[ ] RCPT TO 枚举有效收件人（一条连接无限发；确认有没有 catch-all）
[ ] 目标是否开放中继（无认证投递外部发件人）
[ ] 判断是 5.x 还是 6.x —— 5.x 不要找免认证 RCE
[ ] 🔴 拿到任何低权 shell 后立刻读 hMailServer.ini（admin MD5 + DB 口令）
[ ] 读 Data\ 下全部 .eml，扫 password/credential（预期大量是自己的钓鱼邮件）
[ ] 不要拿攻击 IP 喷 AUTH —— autoban 3 次封 60 分钟，且封所有协议
[ ] .sdf 可读也没用：整体加密，别做离线解密的幻想
```

## 教训

1. 🔴 **"服务是什么版本"在没有本地立足点时基本判不出来**：banner 不含版本、EHLO 不含版本。
   能用的只有"默认值旁证"（SIZE 20480000）和拼写错误这类源码指纹 ⇒ **别在这上面耗时间，先找立足点。**
2. 🔴 **RCPT 枚举免费、AUTH 试错致命**：这两件事在同一个端口上，但一个不计入 autoban、一个 3 次就封 IP 且封所有协议。
   把"枚举"和"猜口令"当成完全不同风险等级的操作来对待。
3. 🔴 **"能读邮件" ≠ "拿到凭据"**：先把 Data 目录扫一遍再决定值不值得投入；靶场里多数邮件就是你自己投进去的。
4. 🔴 **同一产品里"加密"可能有好几套互不相通的方案**：ini 里的 Blowfish key 解不了 SQLCE 的库加密。手上有 key ≠ 能解所有密文。

## 相关卡

- `office-document-phishing-payloads` —— 收件人 hr@ 明确要求投 Office 文档时的 payload 选型与投放
- `credential-hunting-locations` —— 拿到 shell 后按"凭据载体"系统性找下一组口令
- `service-attacks` —— 25 端口不是 hMailServer（Postfix/Exim/Exchange）时的通用面
- `exchange-owa-attacks` —— 目标是 Exchange/OWA 时的用户枚举与喷洒
- `password-attacks` —— 拿到 ini 里的 MD5 / DB 口令哈希之后的破解策略
- `linux-privesc` / `windows-privesc` —— 读 hMailServer.ini 只是提权路上的一步，不是终点

## 来源

hMailServer 上游源码（`RecipientParser.cpp` / `SMTPConnection.cpp` / `AccountLogon.cpp` / `PersistentLogonFailure.cpp` /
`BlowFish.cpp` / `IniFileSettings.cpp` / `CreateTablesMSSQL.sql` / 安装脚本 `hMailServerInnoExtension.iss`）、
官方文档 `book_other/security.md`、NVD CVE-2026-100741 / CVE-2025-52372 / CVE-2025-52373 / CVE-2025-52374。
JobTwo 实测项已在文中标注。
