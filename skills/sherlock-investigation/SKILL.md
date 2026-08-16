---
name: 'sherlock-investigation'
description: 'HTB Sherlocks 取证调查：题型识别→样本静态分析/CTI画像/内存取证/日志分析四流程，含全部关键坑'
whenToUse: '做 HTB Sherlocks 取证题时：题型识别→样本静态分析/CTI画像/内存取证/日志分析四流程。'
metadata: { domain: forensics, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# HTB Sherlocks 取证调查 playbook

> 用法: `加载技能 sherlock-investigation`
> 收到新 Sherlocks 题目时调用。传入完整场景描述，按题型路由到对应流程。

## 0. 环境准备（每次必做）

1. **附件获取**: zip 密码通常在题目描述/场景里（如 hacktheblue），**先试密码再爆破**
2. **大文件（>100MB）直接在 Kali 下载**（Kali 有外网，curl 签名链接即可），别先下 Windows 再传输
3. 小文件（<50MB）可本地下载后 `scp kali:/tmp/`（SSH 别名 kali = root@192.168.111.128:2222 免密）
4. Kali 上 Volatility3: `/usr/local/bin/vol`（PATH 里可能没有，用完整路径）
5. 解压后 `file` 确认类型 → 路由到对应题型

## 1. 题型识别（读场景描述第一句就判断）

| 场景关键词 | 题型 | 流程 |
|---|---|---|
| "static analysis" / "suspicious binary" / 给 .zip 含 ELF/PE 样本 | 恶意样本静态分析 | §2 |
| "build a comprehensive profile of the threat actor" / 给多篇报告 URL | CTI 威胁画像 | §3 |
| "memory dump" / "rootkit" / "memory forensics" / 给 .mem/.raw + profile | 内存取证 | §4 |
| 日志文件（IIS/EDR/Sysmon/PCAP） | 日志分析 | §5 |
| 磁盘镜像（E01/raw） | 磁盘取证 | §6 |

## 2. 恶意样本静态分析（四板斧）

```
file + sha256sum → strings -n 4 → readelf -d（NEEDED 库）→ nm（未剥离直接看函数名）
→ objdump -d 反汇编关键函数 → objdump -s -j .rodata 确认字符串精确字节
```

🔴 坑：
- **函数名/输出字符串 ≠ 实际比较的命令字符串**：命令分发真相在反汇编 strncmp/strcmp 引用的 .rodata 地址字节（Phantom Ring: cmd_selfdestruct 函数但命令是 `sdestruct`）
- **命令字符串数 ≠ 命令种类数**：别名（ss/netstat → 同一分支）按种类算
- 端口 = `htons()` 里的常量反转；重连延时 = `sleep()` 参数
- 答案以字节为准，不以直觉/文案为准；题目掩码长度是精确提示（`**********-**` = 10字符+连字符+2字符）

## 3. CTI 威胁画像（四步）

```
1. 抓全报告: tavily_extract(advanced) 逐篇抓；截断 → Kali curl + python 去 HTML 标签
   （re.sub(r"<[^>]+>", " ", raw) + html.unescape；TOC 干扰用 rfind 找正文起点）
2. 提取事实表: 身份/别名/时间线/目标/动机/武器库(版本演进/C2变化/CVE)/基础设施/IOC/受害者
3. 交叉关联: 同一组织不同厂商命名（Kaspersky "X" = Knownsec 404 "Y"）；武器溯源
4. 映射 ATT&CK + 逐题对掩码
```

🔴 坑：
- **答案带版本号时掩码会提示**（Asyncshell-v2 教训：全小写+版本号，以报告原文为准）
- 厂商拼写不一致（Asyncshell vs AsyncShell）→ 原文优先
- 防混淆：同工具多文件/多版本别搞混（ts.dat vs $cache.dat）
- ATT&CK ID 是纯记忆题: T1547.001(启动项) / T1059.001(PowerShell) / T1041(Exfil Over C2)

## 4. Linux 内存取证（10 步 rootkit 检测链）

```
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
```

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

## 6. 通用规则

- **答案以原始材料为准**（报告原文/反汇编字节/kmsg），掩码长度是提示不是装饰
- 做题过程随时把发现写入 ANALYSIS.md，逐题对照，避免答串
- 提交后错题 → 回到对应证据重新核对，不要猜
- 详细记忆（含答案速查）: phantom-ring-sherlock / cti-threat-profiling-sherlock / linux-memory-forensics-rootkit
- 收尾: 新题型复盘 → remember 更新本 skill 对应章节
