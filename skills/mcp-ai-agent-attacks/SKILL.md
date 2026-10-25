---
name: 'mcp-ai-agent-attacks'
description: 'MCP / Agentic AI 攻击面：prompt injection→工具滥用→RCE、MCP 客户端差异、agent 供应链、已披露 CVE 表。2026 新增领域（检索词：mcp/ai/agent/llm/prompt-injection/agentic/prompt injection/attacks）'
whenToUse: '目标环境跑 AI agent / MCP server / LLM 应用（Langflow、Semantic Kernel、Copilot、Cursor、Claude Code、自建 MCP）时加载；或红队需要问"这环境有哪些 AI agent、它们能访问什么、我能影响哪些输入"。'
metadata: { domain: ai, tier: T2 }
---

# MCP / Agentic AI 攻击面（2026）

> 定位：AI 安全 ≈ 十年前的攻防 Web —— 人人知道重要，几乎没人会测。
> 核心问题三连：**这环境跑哪些 AI agent？它们能访问什么？我能影响哪些输入？**
> 不问这三句，就漏掉了一整个攻击维度。

## 0. 识别信号（侦察阶段先问）

```
[ ] 目标是否暴露 Langflow / Flowise / n8n / Dify / OpenWebUI / Marimo / LiteLLM？
    → 这些是"AI 基础设施"，常带广域网络访问 + 云凭据 + LLM API key
[ ] 是否有 MCP server（HTTP/SSE 端点、/sse、/messages、stdio 包装的 HTTP 网关）？
[ ] 是否存在 .claude/ / .vscode/ / .cursor/ 配置目录（agent 持久化的首选落点）？
[ ] CI/CD 里是否有 AI 分诊/审查 agent（GitHub issue 自动处理、PR review bot）？
[ ] 是否有 agent 持有 SaaS 权限（Salesforce / M365 / Workday / Jira）？
[ ] 开发者机器上是否装了 MCP 客户端（Claude Desktop/Code、Cursor、Cline、Continue、Gemini CLI）？
```

## 1. Lethal Trifecta（判断"能否打穿"的核心框架）

三个条件同时成立 ⇒ 可完整失陷：

1. **访问私有数据**
2. **接触不可信内容**（网页、issue、邮件、文档、日志、工单）
3. **能对外通信**（发 HTTP / 写外部系统）

> 注：agent 的爆炸半径 = 它持有的**全部**权限的并集。一个同时接了 Salesforce + M365 + Workday 的 agent，不是暴露一个用户的数据，而是暴露它在所有系统里的**有效权限**。

## 2. 为什么 agent 时代 prompt injection "更糟了"

| | 传统 LLM 集成 | Agentic 系统 |
|---|---|---|
| 注入影响 | 单次推理，输出被误用 | **重定向目标、规划与多步行为** |
| 爆炸半径 | 受单次调用限制 | 贯穿整个工作流 |

- **OWASP Agentic Applications Top 10 2026** 为此新开 **ASI01 = Agent Goal Hijack**。
- **CIS（2026-03）**：prompt injection 是"AI 版的 Living-off-the-Land" —— 滥用合法能力，而非利用代码级漏洞。建议把 AI 安全评估并入渗透测试计划。
- 关键分界线：**一旦模型接了工具，prompt injection 就从"内容安全问题"变成"代码执行原语"**。

## 3. MCP 攻击面

**协议本身不强制**认证、授权、访问控制 —— 全靠实现方补。

| 攻击类型 | 说明 |
|---------|------|
| **Tool poisoning** | 恶意指令藏在**工具描述/元数据**里，模型隐式信任 |
| **Rug pull** | 工具在获批后**改变行为** |
| **Cross-tool contamination** | 被控 server 通过共享上下文影响合法工具 |
| **Confused deputy / token passthrough / session hijacking / SSRF** | 已被 MCP 规范自身的安全指引列为一等风险 |
| **MCP sampling 攻击**（Unit 42） | ① 资源盗用 ② 会话劫持（持久污染整个会话）③ **隐蔽工具调用** —— server 改写用户 prompt，让 LLM 在用户不知情下额外调工具 |

🔴 **采样攻击的关键放大器**：某些客户端对工具输出做**二次摘要**再展示，导致隐藏内容在聊天界面里**完全不可见**。只有展开 server 原始 console 输出才看得到 —— 而正常用户没有理由这么做。

### 已披露 CVE
| CVE | 目标 | 要点 |
|-----|------|------|
| CVE-2025-49596 | **MCP Inspector < 0.14.1** | Inspector client↔proxy 无认证 → 配合 **DNS rebinding** 实现浏览器端 RCE |
| *编号未核实*（原引用 CVE-2025-53967） | **Framelink Figma MCP**（1万+ star） | 严重 RCE。🔴 该编号在 2025-12-30 nuclei 模板快照里 **0 命中**（同年 `http/cves/2025` 有 267 个模板）⇒ **编号存疑，勿当权威引用**；技术面（Figma MCP server 未认证 RCE）本身有效 |
| **CVE-2026-23744** | **MCPJam Inspector** | 缺失认证，**19 个公开 exploit**，多种 VulnCheck Canary 已检出 |
| CVE-2026-25253 | Clawdbot / OpenClaw | — |
| CVE-2026-22812 | OpenCode | — |
| CVE-2026-34070 | LangChain | — |

### 客户端差异（arXiv 2603.21642，首个跨客户端实证）
评测对象：**Claude Desktop、Claude Code、Cursor、Cline、Continue、Gemini CLI、Langflow**。
评估维度：静态校验 / 参数可见性 / 注入检测 / 用户告警 / 执行沙箱 / 审计日志。
→ 不同客户端的 tool-poisoning 抵抗力差异显著；**同一 payload 在不同客户端结果不同**，测试时必须逐个试。

## 4. Agent 框架 RCE（注入 → 代码执行）

| 目标 | CVE | 要点 |
|------|-----|------|
| **Semantic Kernel**（微软，27k+ star） | **CVE-2026-25592** / **CVE-2026-26030** | 注入可越过内容安全 → 代码执行原语。26030 需把 **Python AST 遍历载荷**走私过 `eval()` sink。微软发布了**配套 CTF**（沙箱内弹 calc.exe） |
| **Langflow** | **CVE-2026-33017** | CVSS 9.3 未认证 RCE，< 1.9.0。**公开披露后约 20 小时**被利用，**且无公开 PoC** —— 攻击者仅凭公告 + patch diff 写出 exploit |
| **Langflow** | **CVE-2026-33309** | CVSS 9.9，认证攻击者用**路径穿越文件名** POST `/api/v2/files/` 写任意文件 → RCE。是 2025 年某个 Langflow 路径穿越补丁的**不完整修复绕过**（原引用编号 `CVE-2025-68478` 在 2025-12-30 模板快照里 **0 命中** ⇒ **该编号未能在本地快照中核实**，此处只保留"前序补丁被绕过"这一技术事实，不给编号） |
| **AutoJack** | — | AI agent RCE（Microsoft Research 2026-06，PoC 确认） |
| **Marimo**（Python notebook） | **CVE-2026-39987** | RCE，**已进 CISA KEV** |
| **BerriAI LiteLLM** | **CVE-2026-42208** / **CVE-2026-42271** | SQL 注入 / 命令注入，**已进 CISA KEV** |

> 🔴 **2026 首次**：AI 开发工具作为一类**活跃被利用目标**登上 CISA KEV。
> 原因：AI 基础设施常被部署在同样环境里，却**没有接受过传统 Web 应用那样的安全审视**，同时持有广域网络访问、云服务与 LLM provider 的 API 凭据、以及大量企业数据。

## 5. Agent 供应链

- 恶意 **MCP server** 或 **skill 文件**被 agent 当作**正常工作流**执行 —— 以 agent 被授予的权限、在**机器速度**下运行，**人类监控层被完全移除**。
- 持久化落点：**`.claude/`** 与 **`.vscode/`**（当前终端工具**默认经常排除**这两个目录）。
- **Clinejection**（教科书案例）：一条文本框里的句子跨 **6 层边界** —— GitHub issue → AI 分诊 agent → shell 执行 → CI/CD 缓存 → npm token → registry。传统安全工具全程无感。
- **JetBrains Marketplace 恶意插件**窃取开发者 **AI API key**（2026-06-20 确认）。
- Google Red Team（2026-08）：AI 让 **xz-utils 式供应链攻击"变便宜"**，也让**为 agent 制作恶意 skill 文件**变便宜；低级行为体也能获得武器化零日与高级 TTP。
- 事件响应：现有 playbook 假设"响应环路里有人"。**agent 版要提前写** —— 被污染工具/skill 的爆炸半径 = 那些 agent 被授权访问的一切。

## 6. 测试 SOP

```
1. 资产盘点：列出所有 agent、它们注册的工具、持有的凭据/权限范围
2. 输入面枚举：agent 会读哪些不可信内容？（网页/issue/邮件/文档/日志/工单/文件名）
3. Trifecta 判定：三条件是否齐备？缺哪个就补哪个（例如让它去读一个攻击者可控的页面）
4. 注入点投递：
   - 直接注入：聊天输入、表单、API 参数
   - 间接注入（更真实）：把指令埋进 agent 必然会读取的内容里
     └─ 隐藏手法：HTML 注释、白色文字、alt 文本、元数据、工具描述字段
5. 提权链：注入 → 工具调用 → 文件写/命令执行/凭据外带
6. 记录：客户端版本 + 具体 payload + 可复现步骤（不同客户端结果不同，必须标注）
```

## 7. 检测 / 防御要点

- 大多数方案只盯着**用户输入**。**必须同时检查工具返回内容** —— 埋在日志条目或工单描述里的指令，会被 agent 读成命令而不是数据。
- 纵深：输入校验 + 输出过滤 + **最小权限** + 运行时行为监控 + 对 agent 身份的 IAM（与人类同等严格，含 token 管理与动态授权）。
- 合规：NIST AI RMF、ISO 42001 已要求 prompt injection 的具体控制措施。
- MCP 侧加固：OWASP GenAI《A Practical Guide for Secure MCP Server Development》（2026-02）。
- 把文件完整性监控扩展到 `.claude` / `.vscode`。

## 8. 常见坑

- ❌ 只测直接注入 → 真实场景是**间接注入**（数据驱动），agent 从"可信数据源"里读到用户可控内容。
- ❌ 认为"官方 MCP server 就安全" → CVE-2025-53967 就是高星官方项目。
- ❌ 用一套 payload 测所有客户端 → 各客户端防御差异大。
- ❌ 忽略多 agent 场景 → 级联/多跳注入：单跳能过对齐检查的良性指令，可能在 orchestrator 层触发失控推理或下游失陷。
- ⚠️ 对"AI 能自动挖洞"的叙事保持怀疑：VulnCheck 指出 Anthropic 披露账本宣称 23,019 个发现，实际**从未超过初始 1,611 条**，126 条产出 CVE，**仅 1 条**（CVE-2026-26980）确认在野利用。

## 9. 参考

- OWASP Top 10 for Agentic Applications 2026（ASI01 Agent Goal Hijack）
- OWASP LLM Top 10（LLM01 Prompt Injection）
- Unit 42《New Prompt Injection Attack Vectors Through MCP Sampling》
- Unit 42《Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild》(2026-03)
- 微软《When prompts become shells: RCE vulnerabilities in AI agent frameworks》(2026-05)
- arXiv 2603.21642（跨 7 客户端 tool-poisoning 实证）
- Simon Willison "Lethal Trifecta"
