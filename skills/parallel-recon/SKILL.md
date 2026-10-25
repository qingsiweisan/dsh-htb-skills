---
name: 'parallel-recon'
description: 'HTB 侦察并行化：并行子代理 逐端口并行探测 + 所有搜索/研究丢 subagent，保护主上下文；并显式划出并行边界（有依赖的必须串行 + 同名目标唯一 owner）（检索词：parallel/recon/subagent/concurrency/任务书/brief/自包含/owner/互斥/串行/serial/依赖/dependency）'
whenToUse: '侦察阶段：并行端口探测 + 所有搜索/研究丢给子代理，保护主上下文。'
metadata: { domain: meta, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# parallel-recon：并行侦察 & 搜索 subagent 化

> **核心目标：保护主上下文。** DeepSeek 上下文是稀缺资源 — 所有大输出、多轮搜索、逐端口探测全部丢给 subagent，主线程只收结论。

## 触发时机

```
[1] 拿到全端口列表 + 版本识别结果后 → 立即 并行子代理 并行探测（不等串行）
[2] 任何需要搜索 CVE/PoC/技术资料 → 一律 subagent（research/task），禁止在主线程多轮搜
[3] 任何预计 >300 行输出的工具 → subagent 跑完只回摘要
```

## 模式 A：端口并行探测（阶段1 侦察）

### 流程
```
1. nmap -p- 完成 → 提取端口列表 → nmap -sV -sC 版本识别（主线程，30s）
2. 按端口分组 → 并行子代理 并行任务（每个任务 1-2 个端口，read-only）
3. 收集各任务摘要 → 主线程拼"信息汇总表" → 才进入决策
```

### 并行子代理 任务提示词模板
```
你是 HTB 侦察子代理，目标 {IP}，端口 {PORT}（{SERVICE} {VERSION}）。
跑以下只读探测并返回发现摘要：
- HTTP: curl -sI 头部 + 首页 title + /.git/.env/robots.txt 探测 + gobuster 小词表（dirb common, -t 20）
- SMB: nxc smb -u '' -p '' --shares 2>&1
- 其他服务: 按 service-attacks skill 的对应探测
标记: [SIGNAL]=可利用信号 / [INFO]=背景 / [NOISE]=无关
返回格式（≤300字）: 服务确认版本 + 发现列表 + 最可疑的 1-2 个方向 + 建议下一步利用命令。
禁止贴原始输出全文。
```

### 规则
```
🔴 每个任务 self-contained：提示词里给全 IP/端口/服务/版本，subagent 无主上下文
🔴 并行子代理 任务用 read_only=true（探测只读，不写文件）
🔴 多端口归组：同服务类型（如多个 HTTP）合成 1 个任务，避免重复跑 gobuster
🔴 汇总表由主线程拼（AGENTS.md 网状枚举铁律的"信息汇总表"）
```

## 模式 B：搜索/研究 subagent 化（贯穿全阶段）

### 何时必用
```
- 搜 CVE PoC（"<服务> <版本> exploit github"）
- 读漏洞公告/发行版 security 页面（长文）
- 版本适配判断（上游 vs 发行版补丁后缀）
- 逆向/反混淆类任务（如 javascript-obfuscator 反混淆）
```

### research/task 提示词模板
```
搜索 {软件} {版本} 的已知漏洞与可用 PoC：
1. searchsploit + Tavily/Bing: "{软件} {版本} CVE"（不加年份限制）
2. GitHub 搜 PoC → 读 README/源码确认真可用（防假 PoC: 只有触发逻辑无提权逻辑=假）
3. 版本适配: 对照发行版补丁后缀（-ubuntuX.Y）与 security 公告修复版本
返回（≤200字）: CVE 编号 + 可用性结论（可用/需适配/假PoC/无） + payload 要点 + 来源 URL。
禁止贴源码全文。
```

### 规则
```
🔴 搜索摘要 ≠ 完整信息 → subagent 必须点进原文读全文（tavily_extract/web_fetch）
🔴 训练库可能没有 2026 新 CVE → 搜索是必经路径，不是最后手段
🔴 拿到结论后主线程仍要二次验证（对照目标实际版本再执行）
```

## 边界：什么不能并行（本卡只管「独立的」并行）

```
🔴 可并行：端口 / 主机 / 协议**互不相关**的探测；彼此独立的研究题
🔴 必须串行：有依赖的（A 的结果决定 B 怎么做）—— 并行 = 两边都在猜，结论还会互相污染
🔴 唯一 owner：同一个目标（主机 / 端口 / 账号）同时只允许一个子代理打；派单前查主台账的
   「在跑任务表」，派单时逐条写"不要碰 X（别的 agent 在做）"——实测撞车两次：
   同一份凭据扫描被派了两遍（白做一遍），同段两个 agent 并行且互把对方流量当 lab 配置
🔴 任务书自包含 + 邀请它反驳你的前提 + 先回报后利用 + 收尾还原 —— 完整调度纪律见
   `htb-workflow` §子代理分发协议（本卡只负责"并行侦察"这一段，不写全流程）
```

## 反模式

```
❌ 主线程跑 gobuster 大词表 / sqlmap 全量 → 输出撑爆上下文
❌ 主线程多轮搜索（搜→点→再搜）→ 交给 subagent 一轮完成
❌ subagent 返回原始输出 → 提示词里明确"只回摘要"
❌ 串行逐端口探测 → 端口多时浪费大量轮次
❌ 把**有依赖**的两步并行派出去 → 两个子代理各自猜前提（实测真发生过）
❌ 不做 owner 互斥就派单 → 同一目标被两个子代理同时打（重复劳动 + 互把对方流量当 lab 配置）
```

**Why:** HTB 侦察+搜索是上下文消耗大户；并行子代理/task/research 提供隔离执行，只回结论。
**How to apply:** 版本扫描完成 → 立即模式 A；任何搜索需求 → 立即模式 B。与 AGENTS.md 阻断点2 配合（端口探测表在 service-attacks skill）。派单粒度 / owner 互斥 / 「有依赖必须串行」的全流程调度纪律见 `htb-workflow` §子代理分发协议。
