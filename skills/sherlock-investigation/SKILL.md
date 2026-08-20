---
name: 'sherlock-investigation'
description: 'HTB Sherlocks 取证调查：题型识别→样本静态分析/CTI画像/内存取证/日志分析四流程，含全部关键坑'
whenToUse: '做 HTB Sherlocks 取证题时：题型识别→样本静态分析/CTI画像/内存取证/日志分析四流程。'
metadata: { domain: forensics, tier: T1 }
---
# HTB Sherlocks 取证调查 playbook

> 用法: 用 skill 工具按名加载 sherlock-investigation
> 收到新 Sherlocks 题目时调用。传入完整场景描述，按题型路由到对应流程。

## 0. 环境准备（每次必做）

> 🤖 **下载/取题/交答案走自动化脚本 `scripts/sherlock.mjs`**（Node 18+，零依赖，Windows/Kali 都能跑）。别再手动抓 Playwright 或猜 API。

```bash
# 1. 一次性拿 token 落盘（3 天有效；过期重登后重跑这一步）：
#    页面上下文 fetch: localStorage.getItem('htb-token') → data: URL 下载成 htb-token.txt → 移到 ~/.dsh/htb-token.txt
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
| NTUSER.DAT / UsrClass.dat 注册表 hive，"文件夹何时被访问/访问过什么" | Shellbag 取证 | §7 |

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

## 8. 通用规则

- **答案以原始材料为准**（报告原文/反汇编字节/kmsg），掩码长度是提示不是装饰
- 做题过程随时把发现写入 ANALYSIS.md，逐题对照，避免答串
- 提交后错题 → 回到对应证据重新核对，不要猜
- 详细记忆：恶意样本静态分析见 malware-static-analysis 卡；Sherlocks 答案速查卡待建（教练侧）
- 收尾: 新题型复盘 → 更新本 SKILL.md 并重生成索引卡
