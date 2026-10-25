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
  const logPath = typeof cfg.logPath === 'string' && cfg.logPath.trim() !== ''
    ? (isAbsolute(cfg.logPath) ? cfg.logPath : resolve(process.cwd(), cfg.logPath))
    : DEFAULT_LOG_PATH
  const tools = new Set(Array.isArray(cfg.tools) && cfg.tools.length > 0 ? cfg.tools : EXEC_TOOLS)

  // 每 agent 的状态：当前战线 + 每条战线的统计 + 账本路径缓存。
  const trackers = new Map()
  const trackerOf = (agentId) => {
    let t = trackers.get(agentId)
    if (t === undefined) {
      t = { front: null, stats: new Map(), pendingFront: null, pendingCount: 0, ledger: { path: undefined, misses: 0 } }
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

      // ① 事实计数：htb_fact op=add 记到"当前战线"名下。
      //    这是"这条战线有没有产出"的唯一客观依据。
      if (exec?.name === 'htb_fact') {
        const args = exec.arguments ?? {}
        const op = typeof args === 'object' && args !== null ? args.op : undefined
        if (op === 'add' && t.front !== null) {
          const st = t.stats.get(t.front)
          if (st !== undefined) st.facts += 1
        }
        return decision
      }

      if (typeof exec?.name !== 'string' || !tools.has(exec.name)) return decision

      // ② 战线推断：推断不出就保持当前战线（不猜）。
      const args = exec.arguments ?? {}
      const command = typeof args === 'object' && args !== null && typeof args.command === 'string'
        ? args.command
        : ''
      const nextFront = inferFront(command)
      if (nextFront === null) return decision

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

      if (notice === null) return decision

      // base 取上一条 hook 的产出，避免覆盖别的模块刚追加的内容。
      const base = Array.isArray(decision?.content) ? decision.content : (result.content ?? [])
      return { kind: 'accept', content: [...base, notice] }
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
