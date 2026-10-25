---
name: 'group-type-abuse'
description: 'AD groupType 写权限滥用：通讯组的 SID 不进令牌 ⇒ 以它为主体的 ACE 静默失效；改 groupType 可激活权限或解除 GPO 隔离（Scaffold Hard 来源）。（检索词：group type abuse）'
whenToUse: 'ACL 链看起来完整却打不通、bloodyAD 的 writable 里出现 groupType、或某组 ACE 主体明明匹配却无效果时使用。'
metadata: { domain: ad-win, tier: T3 }
---

# AD groupType 写权限滥用（通讯组 = 权限静默失效）

> 来源：Scaffold HTB (Hard)。作者用「IT 组是通讯组」让 `IT:AddSelf` 这条 ACE 变成死链路，
> 再用另一个账户持 `groupType` 写权去修复——这是全机最容易误判的一步。

## 漏洞形状

ACE 的授权检查比对的是**访问者令牌里的 SID 集合**。而 **distribution（通讯）组的 SID 永远不会进入任何令牌**。
于是产生一个反直觉结论：

```
某个组 G 是通讯组  ⇒  任何 "G: <right> → 对象 O" 的 ACE 对 G 的所有成员都不生效
                      （ACL 上看得见、BloodHound 也报得出来，但运行时永远匹配不上）
```

因此"ACL 链完整却打不通"的根因，经常不在 ACE 本身，而在**主体组的 groupType**。

## 🔴 识别信号

- `dacledit` / BloodHound 报了某组对某对象的 AddSelf / GenericWrite / WriteProperty，但用该组成员实测 `ERROR_DS_INSUFF_ACCESS_RIGHTS` 或 ACE 完全不触发
- `bloodyAD ... get writable --detail` 的输出里，某对象只有一条 `groupType: WRITE`
- 某组成员被 GPO 的 `SeDenyNetworkLogonRight` 挡住（隔离），而该组是**安全组**

## groupType 位语义（★ 我曾搞反，务必先算十六进制）

| 十进制 | 十六进制 | 含义 |
|---|---|---|
| `2` | `0x00000002` | Global **通讯组** |
| `4` | `0x00000004` | DomainLocal **通讯组** |
| `8` | `0x00000008` | Universal **通讯组** |
| `-2147483646` | `0x80000002` | Global **安全组** |
| `-2147483644` | `0x80000004` | DomainLocal **安全组** |
| `-2147483640` | `0x80000008` | Universal **安全组** |

- **高位 `0x80000000` = SECURITY_ENABLED 置位 ⇒ 是安全组**。负值不代表"特殊"，只代表最高位被置上。
- **Global 组不能直接改成 DomainLocal**，必须经 Universal（`-2147483640`）中转。

## ✅ 两个利用方向

```bash
# 方向 A：把「静默失效的权限」激活（通讯组 → 安全组）
bloodyAD --host DC -d dom -u U -p P set object 'CN=IT,OU=IT,OU=dc,DC=dom' groupType -v -2147483646
# 之后 IT 的成员令牌才真正包含 IT 的 SID ⇒ "IT:AddSelf → 目标组" 才开始生效

# 方向 B：解除 GPO 的 deny-network-logon 隔离（安全组 → 通讯组）
bloodyAD --host DC -d dom -u U -p P set object 'CN=Quarantined_Accounts,OU=dc,DC=dom' groupType -v 8
# 成员令牌不再含该 SID ⇒ GPO 里 SeDenyNetworkLogonRight 指向的 SID 匹配不上 ⇒ 恢复网络登录
```

**写入前先做无副作用验证**：把 `groupType` 写成**当前值**，能成功就说明写权真实有效（来源凭据组是安全组时才会生效，见上表）。

## 与隔离机制配合的判定顺序

1. 目标账户 `STATUS_ACCOUNT_DISABLED` ⇒ 先要 GenericWrite 清 `ACCOUNTDISABLE`（能清位的账户通常来自另一条 ACL 链）。
2. 账户可用后仍登录失败（LDAP/SMB 报 `ERROR_LOGON_TYPE_NOT_GRANTED` / `0x569`）⇒ 查 `SeDenyNetworkLogonRight` 与它指向的组**是不是安全组**。
3. 若授权方把隔离组设成通讯组，隔离本身是**装饰性**的；反之要解隔离就得把它改回通讯组。
4. **Kerberos 取 TGT 不受登录权限约束**（AS-REQ/TGS-REQ 不产生 LSA 登录），但**用票据访问服务受约束**——被隔离账户的 TGT 照样换不来 SMB/LDAP 会话。

## 验证标准（可复算的谓词）

- 改完 `groupType` 后，用 `ldapsearch` 复核该属性**等于**写入值（十六进制可复算）。
- 用主体组成员**真实执行**一次依赖该 ACE 的操作（例如 AddSelf 加组），以 `[+] ... added to ...` 作为通过证据；只有 ACL 变化不算通过。
- 需要登录的场景：用该账户实测一次认证（如 SMB）并由 `[+]` 状态码判定。

## ⚠️ 坑

1. **先算十六进制再看高位**——把 `-2147483646` 读成"通讯组"会让整条链的判断反复推翻。
2. **Global→DomainLocal 直跳会 `ERROR_NOT_SUPPORTED`**，必须经 Universal 中转两步走。
3. 通讯组**不影响 memberOf 的 LDAP 读取**（属性照旧），只影响**令牌/授权**；因此"memberOf 里有它"不能作为权限生效的证据。
4. 应用侧若用 `IsInRole`（令牌）判定角色，通讯组一样拿不到角色；若用 LDAP `memberOf` 判定则相反——判断应用用哪种，别想当然。
5. 改 groupType **不是**提权本身，它只是把已有 ACE 接通；链路两端（授予方与目标）都要齐备。

**Why:** 这一条把"ACL 明明有权限却用不了"从玄学变成可算的位运算，是 Hard 级 AD 靶机里最常见的静默陷阱。
**How to apply:** 拿到任何 ACE 链后，先把主体组的 groupType 算成十六进制确认是安全组；不是就找 groupType 写权（`ad-checklist` 的可写性扫描会暴露它）。
