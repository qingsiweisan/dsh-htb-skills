/**
 * context-hygiene.js — 执行类工具的输出量检测与分流教育（不阻断）
 *
 * 为什么是"事后检测"而不是"禁止主 agent 执行"（2026-10-21 结论）：
 *   1. 单次大输出已经被 `dsh-spill-policy`（maxInlineTokens: 12500）兜住了 ——
 *      超限会自动截断成「首尾 + 完整结果文件路径」。所以"一次 nmap 撑爆上下文"
 *      这个担心其实已经解决。
 *   2. 真正的瓶颈是**次数累积**：356 次 × 每次几百 token。spill 不管累积。
 *   3. 但"主 agent 不执行"是用**决策质量**换上下文干净 —— 渗透的关键判断依赖
 *      "再看一眼"（404 长度异常、banner 怪），只看子 agent 摘要会失去这个。
 *
 *   所以这里做的是：**不改变谁能执行，只让"这次吃了多少上下文"变得可见**，
 *   并在超标时给出具体的分流建议。跑几台之后，要么模型学会分流，要么日志
 *   证明它学不会 —— 那时才值得上更硬的手段。
 *
 * 边界：
 *   - 只观测执行类工具（bash/pwsh/ssh_*），不碰 read/grep
 *   - 失败结果不提示（失败输出通常短，且提示会干扰排错）
 *   - 提示按**滑动窗口**限流（默认每 60 次执行调用最多 2 次），另有会话绝对上限
 *   - 任何异常都不影响原结果
 *
 * 🔴 2026-10-25 改口径：原来"每会话最多 3 次"，实测在 DutyBound 会话里
 *   **3 次预算在头 40 秒（step 1–2）就用完了**（seq 31 的 1451 行、seq 40 的 435 行），
 *   之后 90 分钟包括一个 575 行的结果一次提示都没有。
 *   上下文压力是**随时间累积**的，不是一次性的 —— 所以限流必须按"过了多少次调用"
 *   来算，而不是按会话总数。绝对上限保留，只防刷屏。
 */

import { appendFileSync, existsSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'

/** Stable Cordis plugin name. */
export const name = 'htb-context-hygiene'

/** 依赖工具注册表。 */
export const inject = ['tools']

/** 默认观测的执行类工具。 */
export const EXEC_TOOLS = ['bash', 'pwsh', 'ssh_exec', 'ssh_cluster']

/** 默认日志位置。 */
export const DEFAULT_LOG_PATH = join(homedir(), '.dsh', 'htb-context-hygiene.jsonl')

/** 默认阈值：超过这么多行就认为"这次该分流"。 */
export const DEFAULT_THRESHOLD_LINES = 200

/**
 * 默认滑动窗口长度（按**观测到的执行调用次数**计，不是按行数）。
 * 60 次调用 ≈ DutyBound 那种节奏下 20–25 分钟 —— 刚好是"一次攻坚段落"的长度。
 */
export const DEFAULT_NOTICE_WINDOW_CALLS = 60

/** 默认每个窗口内最多提示几次。 */
export const DEFAULT_MAX_NOTICES_PER_WINDOW = 2

/** 默认会话绝对上限（只防刷屏，正常会话远达不到）。 */
export const DEFAULT_MAX_NOTICES = 8

/**
 * 累积检测的窗口（按执行调用次数）。
 *
 * 🔴 2026-10-25 新增。Watcher 实测：286 次 `ssh_exec` 触发 **5 次 compaction**，
 *    但单次超过 200 行的结果只有 2 个 —— 上下文是被"每次几百字符 × 上百次"
 *    撑爆的，单次阈值完全看不见这种形态。
 *    窗口长度按"一次攻坚段落"取 20 次调用。
 */
export const DEFAULT_ACCUM_WINDOW_CALLS = 20

/**
 * 累积阈值（窗口内字符数总和）。用 Watcher 的真实分布标定：
 * 20 次窗口的 中位 12K / P75 23K / P90 35K / 最大 63K —— 取 40K，
 * 命中约 6% 的窗口，属于"明显偏高"而不是常态。
 */
export const DEFAULT_ACCUM_CHARS = 40000

/** 累积提示之间的最小间隔（按调用次数）—— 比单次提示的窗口更长，避免刷屏。 */
export const DEFAULT_ACCUM_COOLDOWN_CALLS = 40

/** 累积提示的会话上限。 */
export const DEFAULT_MAX_ACCUM_NOTICES = 4

/**
 * 统计一次工具结果的行数与字符数。
 *
 * 只数文本块；图片块（type 不是 text）不计。若检测到 spill 已经截断过
 * （content 里出现"完整结果"之类的路径提示），返回 `truncated: true`，
 * 调用方应跳过 —— 此时行数不代表真实输出量。
 * @param result - 工具执行结果。
 * @returns 行数、字符数与是否已被截断。
 */
export function measure(result) {
  const content = Array.isArray(result?.content) ? result.content : []
  let text = ''
  let chars = 0
  for (const part of content) {
    if (part && part.type === 'text' && typeof part.text === 'string') {
      // 块之间用一个换行分隔；chars 只累加真实文本，不含分隔符。
      text += (text === '' ? '' : '\n') + part.text
      chars += part.text.length
    }
  }
  const lines = text === '' ? 0 : text.split('\n').length
  return {
    lines,
    chars,
    truncated: /完整结果|full result|saved to|结果文件|Omitted \d+ bytes|dsh-spill/i.test(text),
  }
}

/**
 * 按工具类型给出具体的分流建议。
 * 刻意写成"下次该怎么做"，而不是"你错了"——后者模型会当噪音。
 * @param tool - 工具名。
 * @param lines - 本次输出行数。
 * @param threshold - 阈值。
 * @param truncated - 结果是否已被 spill 截断（2026-10-25 新增：截断也提示，但要说明）。
 * @returns 提示文本。
 */
export function buildNotice(tool, lines, threshold, truncated = false) {
  const ratio = Math.round((lines / threshold) * 10) / 10
  const kind = tool === 'ssh_exec' || tool === 'ssh_cluster' ? '远端命令' : '本地命令'
  const out = [
    `⚠️ 上下文卫生：这次 ${kind} 输出 ${lines} 行（阈值的 ${ratio} 倍），已计入你的上下文。`,
  ]
  if (truncated) {
    out.push('   （这次结果已被 spill 截断过；上面是**实际进入上下文**的行数，完整内容在落盘文件里，需要时按行读，别整份读。）')
  }
  out.push(
    '   这类输出通常只值一个结论，不值全文。下次同类任务改用：',
    '   · 全端口扫描 / 大字典爆破 / 多目标探测 → `workflow` 一次扇出，只收汇总',
    '   · 单点深挖（一个服务、一个方向）→ `subagent`，任务书里写明"只回报结论"',
    '   · 命令内自己收敛输出：`| head` / `--stats` / `-oN` 落盘后再 `grep`',
    '   快速验证（curl -I / nc -zv / 单次小字典）继续自己做 —— 那类结果需要立刻判断。',
  )
  return out.join('\n')
}

/**
 * 构造"累积"提示。
 *
 * 与单次超标的提示刻意分开：单次说的是"这一次太大"，累积说的是
 * "每一次都不大，但加起来很大" —— 后者才是长会话上下文爆掉的主因。
 * @param calls - 窗口内的调用次数。
 * @param chars - 窗口内字符总数。
 * @returns 提示文本。
 */
export function buildAccumNotice(calls, chars) {
  const k = Math.round(chars / 1000)
  const tokens = Math.round(chars / 4 / 1000)
  return [
    `⚠️ 上下文累积：最近 ${calls} 次调用共约 ${k}K 字符（≈${tokens}K token）进了上下文，单次都不大。`,
    '   检查一下：这些中间结果是不是都只值一个结论？需要全文的落盘后再按行读，别整份贴。',
  ].join('\n')
}

/**
 * 挂载检测器。
 *
 * 配置：
 *   - `enabled`（默认 true）：设 false 完全不挂。
 *   - `thresholdLines`（默认 200）：超过多少行触发。
 *   - `noticeWindowCalls`（默认 60）：滑动窗口长度，按观测到的执行调用次数计。
 *     设 0 退回旧的"纯会话上限"模式（只受 `maxNotices` 约束）。
 *   - `maxNoticesPerWindow`（默认 2）：一个窗口内最多提示几次。
 *   - `maxNotices`（默认 8）：会话绝对上限，防刷屏。
 *   - `accumWindowCalls`（默认 20）/ `accumChars`（默认 40000）：累积检测窗口与阈值。
 *     单次都不大但加起来撑爆上下文的场景靠这两个参数兜住。
 *   - `accumCooldownCalls`（默认 40）/ `maxAccumNotices`（默认 4）：累积提示的间隔与会话上限。
 *   - `logPath`：观测日志（默认 `~/.dsh/htb-context-hygiene.jsonl`）。
 *   - `tools`：覆盖观测的工具名列表。
 * @param ctx - host 插件上下文。
 * @param config - 见上。
 */
export function apply(ctx, config) {
  const cfg = config ?? {}
  if (cfg.enabled === false) return

  const threshold = Number.isFinite(Number(cfg.thresholdLines)) && Number(cfg.thresholdLines) > 0
    ? Number(cfg.thresholdLines)
    : DEFAULT_THRESHOLD_LINES
  const maxNotices = Number.isFinite(Number(cfg.maxNotices)) && Number(cfg.maxNotices) >= 0
    ? Number(cfg.maxNotices)
    : DEFAULT_MAX_NOTICES
  const windowCalls = Number.isFinite(Number(cfg.noticeWindowCalls)) && Number(cfg.noticeWindowCalls) >= 0
    ? Number(cfg.noticeWindowCalls)
    : DEFAULT_NOTICE_WINDOW_CALLS
  const maxPerWindow = Number.isFinite(Number(cfg.maxNoticesPerWindow)) && Number(cfg.maxNoticesPerWindow) > 0
    ? Number(cfg.maxNoticesPerWindow)
    : DEFAULT_MAX_NOTICES_PER_WINDOW
  const logPath = typeof cfg.logPath === 'string' && cfg.logPath.trim() !== ''
    ? (isAbsolute(cfg.logPath) ? cfg.logPath : resolve(process.cwd(), cfg.logPath))
    : DEFAULT_LOG_PATH
  const tools = new Set(Array.isArray(cfg.tools) && cfg.tools.length > 0 ? cfg.tools : EXEC_TOOLS)
  const accumWindow = Number.isFinite(Number(cfg.accumWindowCalls)) && Number(cfg.accumWindowCalls) > 0
    ? Number(cfg.accumWindowCalls)
    : DEFAULT_ACCUM_WINDOW_CALLS
  const accumChars = Number.isFinite(Number(cfg.accumChars)) && Number(cfg.accumChars) > 0
    ? Number(cfg.accumChars)
    : DEFAULT_ACCUM_CHARS
  const accumCooldown = Number.isFinite(Number(cfg.accumCooldownCalls)) && Number(cfg.accumCooldownCalls) >= 0
    ? Number(cfg.accumCooldownCalls)
    : DEFAULT_ACCUM_COOLDOWN_CALLS
  const maxAccum = Number.isFinite(Number(cfg.maxAccumNotices)) && Number(cfg.maxAccumNotices) >= 0
    ? Number(cfg.maxAccumNotices)
    : DEFAULT_MAX_ACCUM_NOTICES

  // 每 agent 的限流状态。用 id 字符串做键（与 struggle-watch 同口径）。
  //   calls   —— 观测到的执行调用总数（窗口按它滑动）
  //   notices —— 每次提示发生时的 calls 值，用于算窗口内已提示几次
  //   total   —— 本会话累计提示次数（绝对上限）
  //   recent  —— 最近 accumWindow 次调用的字符数（累积检测用）
  const trackers = new Map()
  const trackerOf = (agentId) => {
    let t = trackers.get(agentId)
    if (t === undefined) {
      t = { calls: 0, notices: [], total: 0, recent: [], accumNotices: 0, lastAccumAt: -Infinity }
      trackers.set(agentId, t)
    }
    return t
  }

  ctx.on('tools/post-execute', async (exec, result, next) => {
    const decision = await next()
    try {
      if (typeof exec?.name !== 'string' || !tools.has(exec.name)) return decision
      if (result?.isError === true) return decision

      const agentId = typeof exec.agent?.id === 'string' ? exec.agent.id : 'unknown'
      const t = trackerOf(agentId)
      t.calls += 1

      const m = measure(result)

      // 累积窗口：**无论单次大小**都计入 —— 这正是"单次阈值看不见"的那部分。
      t.recent.push(m.chars)
      if (t.recent.length > accumWindow) t.recent.shift()
      const recentChars = t.recent.reduce((a, b) => a + b, 0)

      if (m.lines < threshold) {
        // 单次不超标，仍可能"累积超标"（Watcher 的 5 次 compaction 就是这么来的）。
        if (t.recent.length < accumWindow) return decision
        if (recentChars < accumChars) return decision
        if (t.accumNotices >= maxAccum) return decision
        if (t.calls - t.lastAccumAt < accumCooldown) return decision

        t.accumNotices += 1
        t.lastAccumAt = t.calls
        try {
          if (!existsSync(dirname(logPath))) mkdirSync(dirname(logPath), { recursive: true })
          appendFileSync(logPath, `${JSON.stringify({
            ts: new Date().toISOString(),
            agent: agentId,
            tool: exec.name,
            kind: 'accum',
            windowCalls: t.recent.length,
            windowChars: recentChars,
            accumChars,
          })}\n`)
        } catch { /* 日志写失败不影响提示 */ }

        const base0 = Array.isArray(decision?.content) ? decision.content : (result.content ?? [])
        return { kind: 'accept', content: [...base0, { type: 'text', text: buildAccumNotice(t.recent.length, recentChars) }] }
      }

      // 窗口内已提示次数：只数"最近 windowCalls 次调用里"发生的提示。
      // windowCalls === 0 时退回旧口径（只受 maxNotices 约束）。
      const recent = windowCalls > 0 ? t.notices.filter((at) => t.calls - at < windowCalls) : []
      if (windowCalls > 0) t.notices = recent

      const withinTotal = t.total < maxNotices
      const withinWindow = windowCalls === 0 || recent.length < maxPerWindow
      // 🔴 2026-10-25：spill 截断**不再跳过**。原来跳过是为了避免"行数不代表真实量"，
      // 但实测反了：DutyBound seq 31 是全场最大的上下文消耗（1451 行 / 49KB），
      // 正因为被 spill 截断过而被静默 —— 最该提醒的一次没提醒。
      // 现在改成"照常提示 + 说明已截断"，让数字指代"实际进入上下文的量"。
      const shouldNotice = withinTotal && withinWindow

      if (shouldNotice) {
        t.notices.push(t.calls)
        t.total += 1
      }

      // 记录：无论是否提示都写，这样能统计"主 agent 自己吃了多少上下文"。
      try {
        if (!existsSync(dirname(logPath))) mkdirSync(dirname(logPath), { recursive: true })
        appendFileSync(logPath, `${JSON.stringify({
          ts: new Date().toISOString(),
          agent: agentId,
          tool: exec.name,
          lines: m.lines,
          chars: m.chars,
          threshold,
          truncated: m.truncated,
          noticed: shouldNotice,
          calls: t.calls,
          windowNotices: recent.length,
        })}\n`)
      } catch { /* 日志写失败不影响提示 */ }

      if (!shouldNotice) return decision

      // 追加到 content 末尾。base 取**上一条 hook 的产出**（decision.content），
      // 而不是原始 result.content —— 否则本模块会把别的模块（如 error-classify）
      // 刚追加的提示覆盖掉。只有一个模块追加时两者等价。
      const base = Array.isArray(decision?.content) ? decision.content : (result.content ?? [])
      const notice = { type: 'text', text: buildNotice(exec.name, m.lines, threshold, m.truncated) }
      return { kind: 'accept', content: [...base, notice] }
    } catch {
      // 检测器坏掉绝不能影响工具结果。
      return decision
    }
  })
}
