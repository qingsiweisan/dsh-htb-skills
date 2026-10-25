/**
 * HTB 并行侦察工作流模板（给 `workflow` 工具用）
 *
 * 目的：把"单端口探测 / 目录爆破 / vhost 枚举"这类**输出量大、彼此独立**的侦察
 * 一次性扇出到多个 subagent，主上下文只收结构化结论 —— 中间输出不进父对话。
 *
 * 用法：把本文件内容作为 `workflow` 工具的 `script` 参数（**去掉最外层注释块后**），
 * `args` 传 `{ targets: ["10.10.11.5"], machine: "BoxName" }`。
 *
 * ⚠️ 三条经源码核对过的约束（2026-10-21）：
 *   1. `agent(prompt, opts)` 的普通失败**返回 null，不抛错**；基础设施失败才会抛
 *      WorkflowError。所以必须判 null，且不要用 try/catch 吞掉真正的错误。
 *   2. 工作流**没有整体经过时间截止**（请求 timeoutMs: null）。卡住的子 agent 不会
 *      被工作流超时救回来 —— 要么让子任务自己带超时，要么用 run_in_background +
 *      job_kill 从外部掐。因此下面的 prompt 里显式要求"先跑一条带超时的命令"。
 *   3. `parallel(thunks)` 里每个 thunk 抛错会被转成 null，fatal 错误才向上传播。
 *      并发上限由引擎的 maxConcurrentAgents 决定（0 = 按 CPU 并行度），
 *      所以本脚本不自己分批，但**不要把 targets × 任务数堆到几十个**。
 */

phase('侦察扇出')

const targets = Array.isArray(args.targets) ? args.targets : []
const machine = typeof args.machine === 'string' ? args.machine : 'unknown'

if (targets.length === 0) {
  return { error: 'args.targets 为空：至少给一个目标 IP' }
}

// 每个目标三类任务。命令里统一加超时，避免单个子 agent 无限挂着（约束 2）。
const jobs = targets.flatMap((t) => [
  {
    kind: 'port',
    target: t,
    prompt: `对 ${t} 做全端口 TCP 扫描。要求：
- 用 \`nmap -p- --min-rate 2000 -T4 --max-retries 1 --host-timeout 20m\`（或等价工具）
- 只回报：开放端口列表 + 服务/版本（含 banner 关键行）
- 不要贴原始输出，不要贴进度行
- 如果 20 分钟内跑不完，回报"超时，已完成到 X 端口"`
  },
  {
    kind: 'http',
    target: t,
    prompt: `对 ${t} 的 Web 面做一次快速摸底。要求：
- 先探测 80/443/8080 等常见端口是否开放；不开放就直接回报"无 Web"
- 开放则：抓首页标题与响应头、试 robots.txt / sitemap.xml
- 用 \`ffuf\` 或 \`feroxbuster\` 跑一次**中等字典**目录枚举，超时 10 分钟
- 只回报：状态码非 404 的路径（最多 30 条）+ 值得注意的响应头
- 不要贴完整响应体`
  },
  {
    kind: 'vhost',
    target: t,
    prompt: `对 ${t} 做 vhost / 子域枚举。要求：
- 前提：已知 Web 端口；未知则先回报"跳过：无 Web"
- 用 Host 头 fuzz（ffuf -H "Host: FUZZ.<domain>"），超时 8 分钟
- 只回报命中项（响应长度或状态码与基线不同者）
- 若没有可用域名，回报"跳过：无域名基线"`
  },
])

log(`派发 ${jobs.length} 个子任务（${targets.length} 个目标 × 3 类）`)

const results = await parallel(
  jobs.map((j) => () =>
    agent(j.prompt, { label: `${j.kind}@${j.target}` })
  )
)

phase('汇总')

// 约束 1：agent() 普通失败 → null。这里把 null 显式记为 failed，
// 而不是静默丢掉 —— 否则"某个方向没扫"会变成看不见的空白。
const rows = results.map((out, i) => {
  const job = jobs[i]
  if (out === null) return { kind: job.kind, target: job.target, status: 'failed', summary: null }
  const text = typeof out === 'string' ? out : JSON.stringify(out)
  return {
    kind: job.kind,
    target: job.target,
    status: text.trim() === '' ? 'empty' : 'ok',
    summary: text.length > 4000 ? `${text.slice(0, 4000)}…(截断)` : text,
  }
})

const failed = rows.filter((r) => r.status !== 'ok')

return {
  machine,
  total: rows.length,
  ok: rows.length - failed.length,
  failed: failed.length,
  // 失败明细单独列出：这是主 agent 唯一能看到的"哪里没扫到"
  failures: failed.map((r) => `${r.kind}@${r.target} (${r.status})`),
  findings: rows.filter((r) => r.status === 'ok'),
  next: failed.length > 0
    ? '对 failures 里的项逐个用普通 subagent 重试，或确认目标不可达后记 htb_frontier op=dead（需 baseline 证据）'
    : '全部成功：把结论写进 htb_fact，再据 coverage 缺口生成新的 frontier',
}
