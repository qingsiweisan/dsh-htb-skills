---
name: 'parallel-recon'
description: 'HTB 侦察并行化：subagent 工具（后台并行）逐端口并行探测 + 所有搜索/研究丢 subagent，保护主上下文'
whenToUse: '侦察阶段：并行端口探测 + 所有搜索/研究丢给子代理，保护主上下文。'
metadata: { domain: meta, tier: T1 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

# parallel-recon：并行侦察 & 搜索 subagent 化

> **核心目标：保护主上下文。** DeepSeek 上下文是稀缺资源 — 所有大输出、多轮搜索、逐端口探测全部丢给 subagent，主线程只收结论。

## 触发时机

```text
[1] 拿到全端口列表 + 版本识别结果后 → 立即用 subagent 工具（后台并行）并行探测（不等串行）
[2] 任何需要搜索 CVE/PoC/技术资料 → 一律 subagent 任务，禁止在主线程多轮搜
[3] 任何预计 >300 行输出的工具 → subagent 跑完只回摘要
```text

## 模式 A：端口并行探测（阶段1 侦察）

### 流程
```text
1. nmap -p- 完成 → 提取端口列表 → nmap -sV -sC 版本识别（主线程，30s）
2. 按端口分组 → subagent 工具（后台并行）并行任务（每个任务 1-2 个端口，read-only）
3. 收集各任务摘要 → 主线程拼"信息汇总表" → 才进入决策
```text

### subagent 工具（后台并行）任务提示词模板
```text
你是 HTB 侦察子代理，目标 {IP}，端口 {PORT}（{SERVICE} {VERSION}）。
跑以下只读探测并返回发现摘要：
- HTTP: curl -sI 头部 + 首页 title + /.git/.env/robots.txt 探测 + gobuster 小词表（dirb common, -t 20）
- SMB: nxc smb -u '' -p '' --shares 2>&1
- 其他服务: 按 service-attacks skill 的对应探测
标记: [SIGNAL]=可利用信号 / [INFO]=背景 / [NOISE]=无关
返回格式（≤300字）: 服务确认版本 + 发现列表 + 最可疑的 1-2 个方向 + 建议下一步利用命令。
禁止贴原始输出全文。
```text

### 规则
```text
🔴 每个任务 self-contained：提示词里给全 IP/端口/服务/版本，subagent 无主上下文
🔴 多端口归组：同服务类型（如多个 HTTP）合成 1 个任务，避免重复跑 gobuster
🔴 汇总表由主线程拼（信息汇总表）
🔴 子代理隔离三件套（强制，独立性靠机制不靠提醒）:
   1. 用 subagent 工具（独立上下文）——禁止 subagent_fork（fork 继承主对话上下文，传播盲区）
   2. 所有并行任务在同一条消息里一次性发出（单消息并发；逐个发会退化成串行）
   3. 每个任务只喂该任务的 IP/端口/服务/版本——不夹带其它任务的发现（互不见推理）
```text

## 模式 B：搜索/研究 subagent 化（贯穿全阶段）

### 何时必用
```text
- 搜 CVE PoC（"<服务> <版本> exploit github"）
- 读漏洞公告/发行版 security 页面（长文）
- 版本适配判断（上游 vs 发行版补丁后缀）
- 逆向/反混淆类任务（如 javascript-obfuscator 反混淆）
```text

### subagent 任务提示词模板
```text
搜索 {软件} {版本} 的已知漏洞与可用 PoC：
1. searchsploit + Tavily/Bing: "{软件} {版本} CVE"（不加年份限制）
2. GitHub 搜 PoC → 读 README/源码确认真可用（防假 PoC: 只有触发逻辑无提权逻辑=假）
3. 版本适配: 对照发行版补丁后缀（-ubuntuX.Y）与 security 公告修复版本
返回（≤200字）: CVE 编号 + 可用性结论（可用/需适配/假PoC/无） + payload 要点 + 来源 URL。
禁止贴源码全文。
```text

### 规则
```text
🔴 搜索摘要 ≠ 完整信息 → subagent 必须点进原文读全文（tavily_extract/web_fetch）
🔴 训练库可能没有 2026 新 CVE → 搜索是必经路径，不是最后手段
🔴 拿到结论后主线程仍要二次验证（对照目标实际版本再执行）
```text

## 反模式

```text
❌ 主线程跑 gobuster 大词表 / sqlmap 全量 → 输出撑爆上下文
❌ 主线程多轮搜索（搜→点→再搜）→ 交给 subagent 一轮完成
❌ subagent 返回原始输出 → 提示词里明确"只回摘要"
❌ 串行逐端口探测 → 端口多时浪费大量轮次
```text

**Why:** HTB 侦察+搜索是上下文消耗大户；subagent 工具（后台并行）提供隔离执行，只回结论。
**How to apply:** 版本扫描完成 → 立即模式 A；任何搜索需求 → 立即模式 B。与 blocking-points-detail 卡 配合（端口探测表在 service-attacks skill）。
