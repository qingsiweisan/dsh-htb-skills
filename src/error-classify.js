/**
 * error-classify.js — 工具失败的类型归因与"同类合并"（只提示，永不阻断）
 *
 * 为什么需要它（DutyBound 会话实测，2026-10-25）：
 *   那一场 260 条工具结果里有 74 条（28.5%）带错误信号，但**没有任何地方给错误分类**。
 *   后果是同一个坑被当成新问题反复重新推理：
 *
 *     `COPY ... FROM PROGRAM` 在子命令退出码非 0 时会让整条 COPY 报错
 *     → 连续 6 次空结果 → 两次误判成"SQLi 停止工作"
 *     → 直到第 6 次才定位到"ls 目标不存在 → exit 1 → COPY error"
 *
 *   如果第 2 次就归到 `channel` 类并提示"这是通道语义，不是你的命令错了"，
 *   后面 4 次往返和 2 次误判都不会发生。
 *
 * 设计取舍：
 *   - **只提示，不阻断。** 分类靠正则推断，一定有误判；阻断会让误判直接杀掉正确路径。
 *     （对照：`guard` 的 `pkill -f` 拦截是确定性规则，那种才配阻断。）
 *   - **同类第 2 次才提示**，第 1 次静默 —— 单次失败是正常的，不需要教育。
 *   - 提示带"上一次的形态"，因为模型需要先判断"是不是同一个原因"，而不是无脑换方法。
 *   - 分类口径按**应对方式**分，不按错误来源分：同一句 "Permission denied"
 *     在文件读写和数据库里解法一样（换路径/提权），所以归同一类。
 *
 * 边界：
 *   - 只观测执行类工具（与 context-hygiene 同口径），不碰 read/grep
 *   - 结果里已经有本模块的提示时不重复追加
 *   - 任何异常都不影响原结果
 */

import { appendFileSync, existsSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'

/** Stable Cordis plugin name. */
export const name = 'htb-error-classify'

/** 依赖工具注册表。 */
export const inject = ['tools']

/** 默认观测的执行类工具（与 context-hygiene 保持一致）。 */
export const EXEC_TOOLS = ['bash', 'pwsh', 'ssh_exec', 'ssh_cluster']

/** 默认日志位置。 */
export const DEFAULT_LOG_PATH = join(homedir(), '.dsh', 'htb-errors.jsonl')

/** 默认第几次出现时提示。 */
export const DEFAULT_HINT_AT = 2

/** 默认第几次出现时升级为"停止同类变体"。 */
export const DEFAULT_ESCALATE_AT = 3

/** 默认每会话最多提示几次（防刷屏；按类各自计数后，正常远达不到）。 */
export const DEFAULT_MAX_HINTS = 12

/** 提示标记：用于避免重复追加（也被测试用来断言）。 */
export const MARKER = '同类失败'

/**
 * 错误分类表。
 *
 * 顺序即优先级：先判"通道"（因为它最容易被误当成命令错误），
 * 再判权限/认证（两者都可能出现 "access denied"，权限在前），
 * 最后是语法/语义。
 *
 * 每个类的 `advice` 写的是**下一步动作**，不是"你错了"——后者模型会当噪音。
 */
export const ERROR_CLASSES = [
  {
    id: 'channel',
    label: '通道',
    // 通道类：命令跑了，但执行通道把"非 0 退出"当整体失败，于是拿不到 stdout。
    // 特征：结果里只有 `[exit code: N]`（N≠0），stdout 几乎为空。
    // 这是 DutyBound 里 `COPY ... FROM PROGRAM` 的形态。
    test(text) {
      const m = /\[exit code:\s*(\d+)\]/i.exec(text)
      if (m === null || m[1] === '0') return false
      const after = text.split(/stdout:/i)[1]
      const out = after === undefined ? '' : after.split(/stderr:/i)[0]
      return out.trim().length < 20
    },
    advice: '通道类：命令本身可能没错，是执行通道把"非 0 退出"当整体失败。先让命令以 0 退出（尾部加 `; true`）再判断输出。',
  },
  {
    id: 'permission',
    label: '权限',
    test: (t) => /permission denied|operation not permitted|must be superuser|read-only file system|not authorized to|insufficient privilege/i.test(t),
    advice: '权限类：换路径或提权，别在同一路径上换参数。',
  },
  {
    id: 'auth',
    label: '认证',
    test: (t) => /authentication failed|login failed|invalid password|access denied|unauthorized|\b401\b|\b403\b|bad credentials/i.test(t),
    advice: '认证类：换凭据（复用/爆破/窃取），别重试同一组。',
  },
  {
    id: 'timeout',
    label: '超时',
    // 与 network 分开：`grep -r /root` 超时和"目标连不上"解法完全不同。
    // DutyBound 实测：第 1.9 分钟就把"本地命令超时"判成网络类，提示
    // "先证明环境活着"——环境没问题，是命令太宽。
    test: (t) => /timed out|timeout|deadline exceeded/i.test(t),
    advice: '超时类：命令太宽或目标太慢 —— 收窄范围（`--max-depth` / 指定目录）、加超时、或转后台。',
  },
  {
    id: 'network',
    label: '网络',
    test: (t) => /connection refused|connection reset|no route to host|network is unreachable|could not resolve|name or service not known|broken pipe/i.test(t),
    advice: '网络类：先证明环境活着（端口/隧道/路由），再怀疑方法。',
  },
  {
    id: 'syntax',
    label: '语法',
    test: (t) => /syntax error|unexpected token|invalid option|unknown option|command not found|no such option|invalid syntax|unrecognized argument|usage:/i.test(t),
    advice: '语法类：查工具用法（`--help` / 版本差异），别靠记忆改 flag。',
  },
  {
    id: 'semantic',
    label: '语义',
    test: (t) => /no such table|no such column|does not exist|0 rows|empty result|not found/i.test(t),
    advice: '语义类：返回成功但没有你要的东西 —— 假设可能错了，换层比换 payload 有效。',
  },
]

/** 把工具结果的文本块拼起来（与 context-hygiene 的 measure 同口径，但不数行）。 */
export function textOf(result) {
  const content = Array.isArray(result?.content) ? result.content : []
  let text = ''
  for (const part of content) {
    if (part && part.type === 'text' && typeof part.text === 'string') {
      text += (text === '' ? '' : '\n') + part.text
    }
  }
  return text
}

/**
 * 归类一次工具结果。
 *
 * 返回 `{ id, label, advice }`，或 `null`（不是失败 / 归不进任何类）。
 * 刻意不返回"置信度"：调用方只会用它决定要不要提示，不需要更细的分级。
 * @param text - 工具结果文本。
 * @returns 分类结果或 null。
 */
export function classify(text) {
  if (typeof text !== 'string' || text.trim() === '') return null
  for (const cls of ERROR_CLASSES) {
    let hit = false
    try {
      hit = cls.test(text) === true
    } catch {
      hit = false
    }
    if (hit) return { id: cls.id, label: cls.label, advice: cls.advice }
  }
  return null
}

/**
 * 取一段"上一次的形态"，用于让模型判断是不是同一个原因。
 *
 * 2026-10-25 改：优先取**报错那一行**，而不是第一行。DutyBound 重放里第一条提示
 * 的 snippet 是 `=== token files ===`（命令自己的分区标题），对判断毫无帮助 ——
 * 真正要看的 `timed out after 60000 ms` 在后面。
 */
export function snippetOf(text, limit = 90) {
  const lines = text.split('\n').map((l) => l.trim()).filter((l) => l !== '')
  const hit = lines.find((l) => /error|denied|refused|timed out|timeout|not found|does not exist|unable|cannot|failed|invalid|no such|unmatched|unexpected|traceback|exception/i.test(l))
    ?? lines[0]
    ?? ''
  return hit.length > limit ? `${hit.slice(0, limit)}…` : hit
}

/**
 * 构造提示文本。
 * @param cls - classify 的返回值。
 * @param count - 这是第几次出现同类错误。
 * @param snippet - 上一次的形态。
 * @param escalateAt - 第几次开始升级为"停止同类变体"。
 * @returns 提示文本。
 */
export function buildHint(cls, count, snippet, escalateAt = DEFAULT_ESCALATE_AT) {
  if (count >= escalateAt) {
    return [
      `🛑 ${MARKER}（${cls.label}）第 ${count} 次。停止在这个方向试同类变体 ——`,
      '   换层（服务→应用→凭据→主机→网络），或换通道。',
      `   本类应对：${cls.advice}`,
    ].join('\n')
  }
  return [
    `⚠️ ${MARKER}（${cls.label}）第 ${count} 次。上一次的形态：${snippet}`,
    '   先判断是不是同一个原因：是 → 换方法；不是 → 忽略这条。',
    `   本类应对：${cls.advice}`,
  ].join('\n')
}

/**
 * 挂载分类器。
 *
 * 配置：
 *   - `enabled`（默认 true）：设 false 完全不挂。
 *   - `hintAt`（默认 2）：同类第几次出现时开始提示。
 *   - `escalateAt`（默认 3）：同类第几次出现时升级为"停止同类变体"。
 *   - `maxHints`（默认 6）：每会话最多提示几次。
 *   - `logPath`：观测日志（默认 `~/.dsh/htb-errors.jsonl`）。
 *   - `tools`：覆盖观测的工具名列表。
 * @param ctx - host 插件上下文。
 * @param config - 见上。
 */
export function apply(ctx, config) {
  const cfg = config ?? {}
  if (cfg.enabled === false) return

  const hintAt = Number.isFinite(Number(cfg.hintAt)) && Number(cfg.hintAt) > 1
    ? Number(cfg.hintAt)
    : DEFAULT_HINT_AT
  const escalateAt = Number.isFinite(Number(cfg.escalateAt)) && Number(cfg.escalateAt) >= hintAt
    ? Number(cfg.escalateAt)
    : Math.max(DEFAULT_ESCALATE_AT, hintAt)
  const maxHints = Number.isFinite(Number(cfg.maxHints)) && Number(cfg.maxHints) >= 0
    ? Number(cfg.maxHints)
    : DEFAULT_MAX_HINTS
  const logPath = typeof cfg.logPath === 'string' && cfg.logPath.trim() !== ''
    ? (isAbsolute(cfg.logPath) ? cfg.logPath : resolve(process.cwd(), cfg.logPath))
    : DEFAULT_LOG_PATH
  const tools = new Set(Array.isArray(cfg.tools) && cfg.tools.length > 0 ? cfg.tools : EXEC_TOOLS)

  // 每 agent 的状态：
  //   counts  —— 每个类出现过几次
  //   last    —— 每个类上一次的形态（给"是不是同一个原因"用）
  //   hinted  —— 每个类已提示几次（**按类限流**，见下）
  //   hints   —— 本会话已提示总数（只作兜底上限）
  const trackers = new Map()
  const trackerOf = (agentId) => {
    let t = trackers.get(agentId)
    if (t === undefined) {
      t = { counts: new Map(), last: new Map(), hinted: new Map(), hints: 0 }
      trackers.set(agentId, t)
    }
    return t
  }

  const log = (record) => {
    try {
      if (!existsSync(dirname(logPath))) mkdirSync(dirname(logPath), { recursive: true })
      appendFileSync(logPath, `${JSON.stringify(record)}\n`)
    } catch { /* 日志写失败不影响提示 */ }
  }

  ctx.on('tools/post-execute', async (exec, result, next) => {
    const decision = await next()
    try {
      if (typeof exec?.name !== 'string' || !tools.has(exec.name)) return decision

      const text = textOf(result)
      if (text === '') return decision
      // 已经有本模块的提示：不重复追加（多 hook 串联时的自我保护）。
      if (text.includes(MARKER)) return decision

      const cls = classify(text)
      if (cls === null) return decision

      const agentId = typeof exec.agent?.id === 'string' ? exec.agent.id : 'unknown'
      const t = trackerOf(agentId)
      const count = (t.counts.get(cls.id) ?? 0) + 1
      const prevSnippet = t.last.get(cls.id) ?? ''
      t.counts.set(cls.id, count)
      t.last.set(cls.id, snippetOf(text))

      // 只在 hintAt 与 escalateAt 两个点提示：第 4 次以后不再提示，
      // 因为那时模型要么已经换方法，要么提示也救不了（交给 struggle/budget 收网）。
      //
      // 🔴 按类限流，不是全局先到先得。DutyBound 重放实测：旧的全局 maxHints=6
      // 在第 61 分钟就被 timeout/semantic 这类低价值提示吃光，导致第 70 分钟
      // 真正值钱的 channel 提示（COPY 空结果）**一次都没发出来**。
      // 现在每类最多 2 条（count=hintAt 与 escalateAt 各一次），全局只留兜底上限。
      const perClass = t.hinted.get(cls.id) ?? 0
      const shouldHint = (count === hintAt || count === escalateAt)
        && perClass < 2
        && t.hints < maxHints
      if (shouldHint) {
        t.hinted.set(cls.id, perClass + 1)
        t.hints += 1
      }

      try {
        log({
          ts: new Date().toISOString(),
          agent: agentId,
          tool: exec.name,
          class: cls.id,
          count,
          hinted: shouldHint,
          snippet: snippetOf(text, 60),
        })
      } catch { /* 日志写失败不影响提示 */ }

      if (!shouldHint) return decision

      // base 取上一条 hook 的产出，避免覆盖别的模块刚追加的内容。
      const base = Array.isArray(decision?.content) ? decision.content : (result.content ?? [])
      const notice = { type: 'text', text: buildHint(cls, count, prevSnippet, escalateAt) }
      return { kind: 'accept', content: [...base, notice] }
    } catch (error) {
      // 分类器坏掉绝不能影响工具结果 —— 但也不能静默（同 auto-state 的理由）。
      log({ ts: new Date().toISOString(), agent: 'unknown', tool: '?', event: 'error', message: String(error?.message ?? error) })
      return decision
    }
  })
}
