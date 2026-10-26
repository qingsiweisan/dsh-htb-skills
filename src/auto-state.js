/**
 * auto-state.js — 从工具调用里**自动**推断"战线"，并在切换时给一次复核提醒
 *
 * 为什么需要它（DutyBound 会话实测，2026-10-25）：
 *   那一场 `htb_frontier` **0 次调用**。而框架里三个最值钱的机制——
 *   预算到期、连续判死换层、死因聚合——**全部以 frontier 记录为前提**：
 *
 *     frontier 未使用 → budget 不存在 → 不会到期
 *                     → dead 不存在   → 换层检查不触发
 *                     → reasonCode 不存在 → 死因无法聚合
 *
 *   也就是说状态层是**单点故障**：模型不申报，整套机制变成死代码。
 *   这不是模型偷懒 —— 攻坚时注意力全在目标上，记账必然被推到后面
 *   （实测：4 条 fact、2 条 evidence 全在拿到 flag 之后才补）。
 *
 *   所以这里换个方向：**不要求模型申报，而是从命令本身推断**。
 *   代码里已有先例 —— `scope-observe.js` 自动记录出站目标，从来没失效过。
 *
 * 它做三件事：
 *   1. 从命令推断当前"战线"（侦察 / Web / 数据库 / 图形会话 / 凭据 / 主机）
 *   2. 战线切换时给一条摘要（上一战线花了多少次调用、产出几条事实、停留多久）
 *      —— 直接对应那场"30 分钟在一个假设上打转却没人提醒"的失败
 *   3. 把 `type:"auto-probe"` 写进 `<machine>-state.jsonl`，让状态层不空
 *
 * 边界：
 *   - **只记 front / calls / facts，不记命令原文** —— 命令里可能有 payload 与凭据，
 *     落进账本等于把答案写进会被后续会话读到的地方。
 *   - 推断会错（`curl` 可能属于侦察也可能属于利用），所以它是**标签**不是**闸门**：
 *     不阻断、不改变任何工具结果，只影响一条提醒的措辞。
 *   - 账本解析失败（多个 `*-state.jsonl` 且没配 machine）时静默跳过，不新建文件。
 *   - 任何异常都不影响原结果。
 */

import { appendFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'

/** Stable Cordis plugin name. */
export const name = 'htb-auto-state'

/** 依赖工具注册表。 */
export const inject = ['tools']

/** 默认观测的执行类工具。 */
export const EXEC_TOOLS = ['bash', 'pwsh', 'ssh_exec', 'ssh_cluster']

/** 默认日志位置。 */
export const DEFAULT_LOG_PATH = join(homedir(), '.dsh', 'htb-auto-state.jsonl')

/** 上一战线至少要有这么多次调用，才值得给切换摘要（避免一次性命令触发提醒）。 */
export const DEFAULT_MIN_CALLS_FOR_SUMMARY = 8

/**
 * 滞后：连续这么多次调用都指向新战线，才真正切换。
 * 真实命令是交替的（curl → nmap → curl），逐条切换会让战线变成噪声。
 */
export const DEFAULT_SWITCH_AFTER_CALLS = 3

/**
 * 战线内预算：一条战线累计这么多次调用仍**零事实**，就当场提醒一次。
 *
 * 🔴 2026-10-25 新增。Watcher 实测：`凭据` 战线跑了 **63 次调用 / 0 条事实 /
 *    155 分钟**（hashcat 死磕 bcrypt），而当时的摘要是**退出时**才结算 ——
 *    等它提示，2.5 小时已经花完了。
 *    改成"进战线后按调用数结算"，同样一条信息能提前约 2 小时出现。
 */
export const DEFAULT_FRONT_BUDGET_CALLS = 40

/**
 * 长空档阈值：连续这么多次执行调用没有任何新事实/证据，就建议换视角。
 *
 * 🔴 2026-10-26 新增。依据三场的实测空档分布（距上次 htb_fact / evidence_add）：
 *
 *   场次        最长无进展        实际情况
 *   DutyBound   225 次 / 85 min   **正常**（SQLi 提取 → hashcat → 提权，动作族一直在变）
 *   Atlas       147 次 / 56 min   异常（8 次换字典，0 次读自己的 crack.c）
 *   Watcher     214 次 / 269 min  异常（hashcat 换规则）
 *
 * 关键：**DutyBound 的 85 分钟和 Atlas 的 56 分钟在"时长/调用数"上分不开**，
 * 所以调阈值一定会误报正常攻坚。因此这条提示刻意设计成**建议而非闸**：
 * 误报的代价是"多一条提示 + 可能多派一个 12 分钟的子 agent"，
 * 而漏报的代价是 Atlas 那 44 分钟 / Watcher 那 4.5 小时。
 *
 * 为什么建议"换视角"而不是"停止"：Watcher 实测 stop 触发后，agent 在推理里
 * **复述了规则**（"don't keep burning this session"）然后继续跑 2 小时 ——
 * 通知可以被一句话覆盖。而 Atlas 那场 subagent 用 12 分钟解决了主 agent
 * 44 分钟没解决的问题，因为它没有"我已经试过很多次"的包袱。
 */
export const DEFAULT_STALE_CALLS_FOR_REVIEW = 60

/**
 * 长空档的**时长**下限（分钟）。与调用数**同时**满足才建议。
 *
 * 为什么要两个条件：只用调用数时，早期密集侦察（一分钟几十次 curl）会瞬间攒够 60 次，
 * 而那时会话才跑了几分钟、完全正常。实测三场回放：
 *
 *   Atlas 26 分钟（空档 17 分钟）→ 误报（正在打 RCE）
 *   Atlas 49 分钟（空档 17 分钟）→ 误报
 *   Atlas 73 分钟（空档 23 分钟）→ **真报**（正在换字典）
 *
 * 加上 20 分钟下限后，前两次被过滤，只留真报那次。
 */
export const DEFAULT_STALE_MINUTES_FOR_REVIEW = 20

/**
 * 构造"换视角"建议。
 *
 * 措辞要点：不是"你卡住了"（那会被当成噪音），而是给一个**具体的、低成本的**动作，
 * 并明确子 agent 的职责边界 —— 否则它会去重跑主 agent 的步骤（Atlas 那场
 * subagent 前 8 分钟就在重新枚举，直到读了 crack.c 才转向）。
 * @param calls - 已经连续多少次调用没有新事实/证据。
 * @returns 提示文本。
 */
export function buildReviewNotice(calls) {
  return [
    `🧭 已连续 ${calls} 次调用没有新的 fact / evidence。`,
    '   如果这条路是"每次都有一点输出、但没有结论"，考虑派一个**审查者**子 agent（subagent）：',
    '   · 职责是**审查你的工具与假设**，不是重跑你的步骤',
    '   · 让它优先读你写的脚本 / 配置 / 爆破器，而不是继续用它们',
    '   · 回报"哪里错了 / 哪条路还没试过"，不要求它拿到 flag',
    '   依据：自写的校验器 / 解码器 / 爆破器出错时，输出会**全是否定**——',
    '   这时换输入（字典、参数、工具）永远不中，只有换视角才会去看代码本身。',
  ].join('\n')
}

/** 账本路径解析的缓存周期（按调用次数），避免每次 readdir。 */
const LEDGER_RESOLVE_EVERY = 40

/**
 * 战线表。顺序即优先级：先匹配更专一的（侦察工具）再匹配通用的（curl）。
 *
 * 刻意只放"从命令行就能看出来"的类别。`python3 - <<PY` 这种通用解释器
 * 不参与推断 —— 它可能是任何事，猜错比不猜更糟。
 */
export const FRONTS = [
  {
    id: 'recon',
    label: '侦察',
    test: /\b(nmap|masscan|rustscan|ffuf|gobuster|feroxbuster|dirb|wfuzz|nikto|whatweb|dnsrecon|enum4linux|nbtscan)\b/i,
  },
  {
    id: 'web',
    label: 'Web',
    test: /\b(curl|wget|httpie|sqlmap|flask-unsign|urllib|requests\.|httpx|jwt_tool)\b/i,
  },
  {
    id: 'db',
    label: '数据库',
    test: /\b(psql|mysql|mssqlclient|sqlcmd|redis-cli|mongo|mongosh|pg_dump)\b/i,
  },
  {
    id: 'graphical',
    label: '图形会话',
    test: /\b(xdpyinfo|xwininfo|xdotool|xev|xrandr|openbox|Xorg|Xvfb|xterm)\b/i,
  },
  {
    id: 'creds',
    label: '凭据',
    test: /\b(hashcat|john|hydra|kerbrute|secretsdump|impacket-\w+|netexec|nxc)\b/i,
  },
  {
    id: 'host',
    label: '主机',
    test: /\b(sudo|systemctl|crontab|linpeas|winpeas|getcap|ps -eo|ps aux|find \/)\b/i,
  },
]

/**
 * 从一条命令推断战线。
 * @param command - 命令行原文。
 * @returns 战线 id，或 null（推断不出就不猜）。
 */
export function inferFront(command) {
  if (typeof command !== 'string' || command.trim() === '') return null
  for (const front of FRONTS) {
    try {
      if (front.test.test(command)) return front.id
    } catch {
      /* 单个正则坏掉不影响其它 */
    }
  }
  return null
}

/** 取战线的中文标签；未知 id 原样返回。 */
export function labelOf(frontId) {
  const hit = FRONTS.find((f) => f.id === frontId)
  return hit === undefined ? String(frontId) : hit.label
}

/** 把毫秒差渲染成"12 分钟" / "40 秒"。 */
function humanMinutes(ms) {
  const sec = Math.max(0, Math.round(ms / 1000))
  if (sec < 90) return `${sec} 秒`
  return `${Math.round(sec / 60)} 分钟`
}

/**
 * 构造战线切换摘要。
 *
 * 措辞刻意问一句"是被新线索带走的吗" —— DutyBound 那场的 30 分钟空转，
 * 就是因为上一条战线被新线索打断后既没记 dead 也没回头。
 * @param prev - 上一战线 id。
 * @param stats - 上一战线的统计 { calls, facts, enteredAt }。
 * @param next - 新战线 id。
 * @param now - 当前时间戳（毫秒）。
 * @returns 提示文本。
 */
export function buildSwitchNotice(prev, stats, next, now) {
  const stayed = humanMinutes(now - stats.enteredAt)
  return [
    `🧭 战线切换：${labelOf(prev)}（${stats.calls} 次调用 / ${stats.facts} 条事实 / 停留 ${stayed}）→ ${labelOf(next)}`,
    '   上一条战线如果是被新线索带走的（不是确认无路），先记一条 dead（带 reasonCode）再走 ——',
    '   否则下次会重走一遍。',
  ].join('\n')
}

/**
 * 构造战线内预算告警。
 *
 * 措辞刻意给一个**必须回答的问题**，而不是"你超时了" —— 后者只会换来"再跑一会儿"。
 * Watcher 那场唯一的转机，就是它自己在"再投 2.4 小时"面前停下来问了一次
 * "有没有更快的原语"。这条提示是把那个动作提前。
 * @param front - 战线 id。
 * @param stats - 该战线统计 { calls, facts }。
 * @param budget - 预算调用数。
 * @returns 提示文本。
 */
export function buildBudgetNotice(front, stats, budget) {
  return [
    `🧭 战线「${labelOf(front)}」已 ${stats.calls} 次调用 / ${stats.facts} 条事实（预算 ${budget}）。`,
    '   继续之前先回答一句：这条路上有没有**更快的原语**，还是只是我这条路慢？',
    '   如果是后者：写一条 frontier dead（带 reasonCode）说明理由，再换战线。',
  ].join('\n')
}

/** 解析账本路径。返回 null 表示"当前无法确定，跳过"。 */
function resolveLedger(stateRoot, machine, cache) {
  if (cache.path !== undefined && cache.misses < LEDGER_RESOLVE_EVERY) {
    cache.misses += 1
    return cache.path
  }
  cache.misses = 0
  let path = null
  try {
    if (typeof machine === 'string' && machine.trim() !== '') {
      const name = machine.trim().endsWith('-state.jsonl') ? machine.trim() : `${machine.trim()}-state.jsonl`
      path = join(stateRoot, name)
    } else if (existsSync(stateRoot)) {
      const names = readdirSync(stateRoot).filter((n) => n.endsWith('-state.jsonl'))
      // 多个账本且没配 machine：不猜，跳过（与 state-tools 的 findLedger 同口径）。
      if (names.length === 1) path = join(stateRoot, names[0])
    }
  } catch {
    path = null
  }
  cache.path = path
  return path
}

/**
 * 挂载自动采集器。
 *
 * 配置：
 *   - `enabled`（默认 true）：设 false 完全不挂。
 *   - `stateRoot`：账本目录（默认 `<cwd>/loot`，与 state-tools 同口径）。
 *   - `machine`：机器名；给了就写 `<stateRoot>/<machine>-state.jsonl`。
 *   - `minCallsForSummary`（默认 8）：上一战线至少这么多次调用才给切换摘要。
 *   - `switchAfterCalls`（默认 3）：连续多少次调用指向新战线才真正切换（滞后）。
 *   - `frontBudgetCalls`（默认 40）：一条战线累计多少次调用仍零事实时当场提醒（每条战线最多 2 次）。
 *   - `staleCallsForReview`（默认 60）：连续多少次执行调用没有新 fact/evidence 时，
 *     建议派一个"审查者"子 agent（每段空档只提一次，有新进展后重置）。
 *   - `staleMinutesForReview`（默认 20）：同时要求空档持续这么久 —— 只用调用数时，
 *     早期密集侦察会瞬间攒够次数，全是误报。
 *     两条依据见 {@link DEFAULT_STALE_CALLS_FOR_REVIEW} / {@link DEFAULT_STALE_MINUTES_FOR_REVIEW}。
 *   - `logPath`：观测日志（默认 `~/.dsh/htb-auto-state.jsonl`）。
 *   - `tools`：覆盖观测的工具名列表。
 * @param ctx - host 插件上下文。
 * @param config - 见上。
 */
export function apply(ctx, config) {
  const cfg = config ?? {}
  if (cfg.enabled === false) return

  const stateRootRaw = typeof cfg.stateRoot === 'string' && cfg.stateRoot.trim() !== ''
    ? cfg.stateRoot
    : join(process.cwd(), 'loot')
  const stateRoot = isAbsolute(stateRootRaw) ? stateRootRaw : resolve(process.cwd(), stateRootRaw)
  const machine = typeof cfg.machine === 'string' && cfg.machine.trim() !== '' ? cfg.machine.trim() : undefined
  const minCalls = Number.isFinite(Number(cfg.minCallsForSummary)) && Number(cfg.minCallsForSummary) >= 0
    ? Number(cfg.minCallsForSummary)
    : DEFAULT_MIN_CALLS_FOR_SUMMARY
  const switchAfter = Number.isFinite(Number(cfg.switchAfterCalls)) && Number(cfg.switchAfterCalls) >= 1
    ? Number(cfg.switchAfterCalls)
    : DEFAULT_SWITCH_AFTER_CALLS
  const frontBudget = Number.isFinite(Number(cfg.frontBudgetCalls)) && Number(cfg.frontBudgetCalls) > 0
    ? Number(cfg.frontBudgetCalls)
    : DEFAULT_FRONT_BUDGET_CALLS
  const staleCalls = Number.isFinite(Number(cfg.staleCallsForReview)) && Number(cfg.staleCallsForReview) > 0
    ? Number(cfg.staleCallsForReview)
    : DEFAULT_STALE_CALLS_FOR_REVIEW
  const staleMinutes = Number.isFinite(Number(cfg.staleMinutesForReview)) && Number(cfg.staleMinutesForReview) > 0
    ? Number(cfg.staleMinutesForReview)
    : DEFAULT_STALE_MINUTES_FOR_REVIEW
  const logPath = typeof cfg.logPath === 'string' && cfg.logPath.trim() !== ''
    ? (isAbsolute(cfg.logPath) ? cfg.logPath : resolve(process.cwd(), cfg.logPath))
    : DEFAULT_LOG_PATH
  const tools = new Set(Array.isArray(cfg.tools) && cfg.tools.length > 0 ? cfg.tools : EXEC_TOOLS)

  // 每 agent 的状态：当前战线 + 每条战线的统计 + 账本路径缓存。
  const trackers = new Map()
  const trackerOf = (agentId) => {
    let t = trackers.get(agentId)
    if (t === undefined) {
      t = {
        front: null,
        stats: new Map(),
        pendingFront: null,
        pendingCount: 0,
        ledger: { path: undefined, misses: 0 },
        // 长空档：距上次 fact/evidence 的执行调用数与时间（跨战线累计，换战线不清零）。
        callsSinceProgress: 0,
        progressAt: Date.now(),
        reviewSuggested: false,
      }
      trackers.set(agentId, t)
    }
    return t
  }

  const appendLedger = (t, record) => {
    try {
      const path = resolveLedger(stateRoot, machine, t.ledger)
      if (path === null) return
      if (!existsSync(dirname(path))) mkdirSync(dirname(path), { recursive: true })
      appendFileSync(path, `${JSON.stringify(record)}\n`)
    } catch { /* 账本写失败不影响工具结果 */ }
  }

  const appendLog = (record) => {
    try {
      if (!existsSync(dirname(logPath))) mkdirSync(dirname(logPath), { recursive: true })
      appendFileSync(logPath, `${JSON.stringify(record)}\n`)
    } catch { /* 日志写失败不影响工具结果 */ }
  }

  ctx.on('tools/post-execute', async (exec, result, next) => {
    const decision = await next()
    try {
      const agentId = typeof exec?.agent?.id === 'string' ? exec.agent.id : 'unknown'
      const t = trackerOf(agentId)

      // ① 进展信号：fact / evidence 都算"学到了新东西"。
      //    2026-10-26：`evidence_add` 也归零 —— 它和 fact 一样是"外部可验证的产出"，
      //    只看 fact 会把"登记了证据但没写 fact"的推进误判成空档。
      if (exec?.name === 'htb_fact' || exec?.name === 'evidence_add') {
        const args = exec.arguments ?? {}
        const op = typeof args === 'object' && args !== null ? args.op : undefined
        // htb_fact 只有 op=add 算进展（list/query/run-start 不算）。
        // evidence_add 没有 op 参数，调用即登记。
        const isProgress = exec.name === 'evidence_add' || op === 'add'
        if (isProgress) {
          t.callsSinceProgress = 0
          t.progressAt = Date.now()
          t.reviewSuggested = false
          if (exec.name === 'htb_fact' && op === 'add' && t.front !== null) {
            const st = t.stats.get(t.front)
            if (st !== undefined) st.facts += 1
          }
        }
        return decision
      }

      if (typeof exec?.name !== 'string' || !tools.has(exec.name)) return decision

      // ② 长空档计数：**在战线推断之前**加 —— 推断不出战线的命令（python3 之类）
      //    同样是"在干活"，漏计会让空档永远到不了阈值。
      t.callsSinceProgress = (t.callsSinceProgress ?? 0) + 1

      // ③ 长空档 → 建议换视角（每段空档只提一次；有新 fact 后重置）。
      let reviewNotice = null
      const staleMs = Date.now() - (t.progressAt ?? Date.now())
      if (t.callsSinceProgress >= staleCalls && staleMs >= staleMinutes * 60000 && t.reviewSuggested !== true) {
        t.reviewSuggested = true
        reviewNotice = { type: 'text', text: buildReviewNotice(t.callsSinceProgress) }
        appendLog({
          ts: new Date().toISOString(),
          agent: agentId,
          event: 'review-suggest',
          callsSinceProgress: t.callsSinceProgress,
          minutesSinceProgress: Math.round(staleMs / 60000),
          front: t.front,
        })
      }

      // ④ 战线推断：推断不出就保持当前战线（不猜）。
      const args = exec.arguments ?? {}
      const command = typeof args === 'object' && args !== null && typeof args.command === 'string'
        ? args.command
        : ''
      const nextFront = inferFront(command)
      if (nextFront === null) {
        if (reviewNotice === null) return decision
        const baseNull = Array.isArray(decision?.content) ? decision.content : (result.content ?? [])
        return { kind: 'accept', content: [...baseNull, reviewNotice] }
      }

      const now = Date.now()
      let notice = null

      // ②b 滞后（2026-10-25 由重放发现）：真实的渗透命令是交替的 ——
      //   `curl` 看一眼、`nmap` 扫一下、再 `curl`。逐条切换会让"战线"变成
      //   每次调用都翻面的噪声（DutyBound 重放：245 次调用切了 39 次，且每条
      //   摘要都写"停留 0 秒"）。所以要求**连续 switchAfterCalls 次**都指向
      //   新战线才真正切换；中间只要回到当前战线，计数就清零。
      if (nextFront === t.front) {
        t.pendingFront = null
        t.pendingCount = 0
      } else if (t.front !== null) {
        if (t.pendingFront === nextFront) t.pendingCount += 1
        else { t.pendingFront = nextFront; t.pendingCount = 1 }

        if (t.pendingCount < switchAfter) {
          // 还没攒够：这条命令仍算在当前战线下（不切、不提示、不写账本）。
          const cur = t.stats.get(t.front)
          if (cur !== undefined) cur.calls += 1
          return decision
        }
      }

      if (nextFront !== t.front) {
        const prev = t.front
        const prevStats = prev === null ? undefined : t.stats.get(prev)

        // ③ 切换摘要：只在上一条战线"够长"时给，避免一次性命令触发提醒。
        if (prev !== null && prevStats !== undefined && prevStats.calls >= minCalls) {
          notice = { type: 'text', text: buildSwitchNotice(prev, prevStats, nextFront, now) }
        }

        t.front = nextFront
        t.pendingFront = null
        t.pendingCount = 0
        t.stats.set(nextFront, { calls: 0, facts: 0, enteredAt: now, warned: 0 })

        // ④ 写账本：只写战线元信息，不写命令原文。
        appendLedger(t, {
          ts: new Date().toISOString(),
          type: 'auto-probe',
          front: nextFront,
          prev: prev ?? undefined,
          prevCalls: prevStats === undefined ? undefined : prevStats.calls,
          prevFacts: prevStats === undefined ? undefined : prevStats.facts,
          ...(machine !== undefined ? { machine } : {}),
        })
        appendLog({
          ts: new Date().toISOString(),
          agent: agentId,
          event: 'switch',
          from: prev,
          to: nextFront,
          prevCalls: prevStats === undefined ? 0 : prevStats.calls,
          prevFacts: prevStats === undefined ? 0 : prevStats.facts,
        })
      }

      const st = t.stats.get(nextFront)
      if (st !== undefined) {
        st.calls += 1

        // ③b 战线内预算告警（2026-10-25）：不等退出，在战线内按调用数结算。
        // 只在"零事实"时提醒 —— 有产出说明这条路在推进，不该打断。
        // 每条战线最多 2 次（budget、2×budget），避免变成每 40 步一次的噪音。
        if (notice === null && st.facts === 0 && st.calls % frontBudget === 0 && st.warned < 2) {
          st.warned += 1
          notice = { type: 'text', text: buildBudgetNotice(nextFront, st, frontBudget) }
          appendLog({
            ts: new Date().toISOString(),
            agent: agentId,
            event: 'budget',
            front: nextFront,
            calls: st.calls,
            facts: st.facts,
          })
        }
      }

      // 两条提示可能同时命中（长空档 + 战线切换/预算），都保留 —— 它们说的是不同的事。
      const notices = [reviewNotice, notice].filter((n) => n !== null)
      if (notices.length === 0) return decision

      // base 取上一条 hook 的产出，避免覆盖别的模块刚追加的内容。
      const base = Array.isArray(decision?.content) ? decision.content : (result.content ?? [])
      return { kind: 'accept', content: [...base, ...notices] }
    } catch (error) {
      // 采集器坏掉绝不能影响工具结果 —— 但也不能静默：
      // 2026-10-25 实测，一个变量名写错（switchAfterCalls vs switchAfter）被
      // 这个 catch 吞掉，表现为"该提示的时候不提示"，从外部完全看不出来。
      // 所以这里留一条诊断日志（只写文件，不进会话）。
      appendLog({ ts: new Date().toISOString(), agent: 'unknown', event: 'error', message: String(error?.message ?? error) })
      return decision
    }
  })
}
