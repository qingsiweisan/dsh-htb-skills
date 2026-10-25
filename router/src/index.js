/**
 * dsh-htb-router — deterministic skill routing for HTB sessions.
 *
 * Host half only. It subscribes to session `tool/call` events (logged by the
 * harness BEFORE tool execution), pattern-matches the tool name + arguments
 * against a configurable rule table, and injects the matched HTB skill card
 * BODIES directly into the agent context through `agent.inject()`.
 *
 * Why: three validation runs on the same Hard box showed that model-side
 * routing ("the model chooses which card to load") is reliable only at
 * flow-start nodes. Mid-flow stages (cloud credentials obtained, container
 * reached, CodeBuild reached) are systematically skipped because the model
 * judges the cards redundant with its pretraining knowledge. Injecting the
 * card content itself removes selection from the model entirely — the
 * knowledge is simply present at the next decision point.
 *
 * The rules are technique-based (protocols, services, keywords) — no
 * per-box data, so the router generalizes to black-box targets.
 */

import { appendFileSync } from 'node:fs'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createUserMessage } from '@deepseek-ai/dsh-llm'

/** Stable Cordis plugin name. */
export const name = 'htb-router'

/** Sessions (event stream) and skills (card bodies) are host-plane services. */
export const inject = ['sessions', 'skills']

const DEFAULT_RULES = []

/** 参数是"文档内容"而非"攻击动作"的工具名。
 *
 *  实测（2026-10-17，本机）：一次 `evidence_add` 登记含技术术语的证据正文，其 arguments 全文
 *  被当成 9 个攻击阶段命中 ⇒ 单次注入 10 张卡（约 150KB）灌进上下文。任何"写文档"的动作
 *  （证据正文 / 报告 / 复盘 / 子代理任务书）都会重现这个雪崩。
 *
 *  本路由器的设计意图是判定"**当前攻击阶段**"——写文档、登记证据、派子代理在语义上不是攻击动作，
 *  故这些工具的 arguments 不参与规则匹配（只保留 tool name；它通常不含技术关键词 ⇒ 不命中）。 */
const CONTENT_TOOLS = new Set([
  // 证据 / 报告层：参数就是文档正文
  'evidence_add', 'research_report', 'ledger_query', 'htb_traces', 'htb_coverage',
  // 文件写入层：参数是要落盘的代码或文档
  'write', 'edit',
  // 编排层：任务是给另一个 agent 读的自然语言
  'subagent', 'subagent_fork', 'workflow',
  // 交互 / 看板层：问题描述与卡片文本
  'ask_user_question', 'schedule_create', 'schedule_update',
  'task_board_create', 'task_board_update',
])

/** 独立于 logger 的调试日志,写系统临时目录下的 htb-router.log(每行短小,便于现场定位)。
 *  原实现硬编码 '/tmp/htb-router.log' —— Windows 上解析成 C:\tmp\... 通常不存在,
 *  appendFileSync 抛 ENOENT 被 catch 吞掉 ⇒ 诊断日志静默丢失(功能不受影响,但排障瞎眼)。 */
function trace(line) {
  try {
    appendFileSync(join(tmpdir(), 'htb-router.log'), new Date().toISOString() + ' ' + line + '\n')
  } catch {
    /* ignore */
  }
}

/**
 * 读 state 账本（L1c 的 fact / intent），带 mtime 缓存。
 *
 * 与关键词规则的分工：关键词是"**猜**当前阶段"，这里是"**知道**当前阶段" ——
 * 依据是 agent 自己登记过的事实与意图（ARTEMIS 的任务状态驱动 / Intentest 的黑板）。
 * 多账本时取**最近修改**的那本（正在用的那台机），而不是拒绝服务 ——
 * 注意这与本插件"编排器写账本"那条路径的取舍不同：那条只在唯一账本时写（宁可不写也不写错机器），
 * 这条是只读的，取最近一本没有污染风险。
 */
function makeLedgerReader(stateRoot, machine) {
  // 可选精确绑定：配置 machine 时只读该机器账本，不再靠 mtime 猜。
  // 不配置时保持原有"选最新"行为 —— 但会把选中的文件名与歧义状态带出来，
  // 让"读到了别的靶机的账本"从静默变成可见（2026-10-21 复审的缺陷点）。
  const pinned = typeof machine === 'string' && machine.trim() !== ''
    ? (machine.trim().endsWith('-state.jsonl') ? machine.trim() : `${machine.trim()}-state.jsonl`)
    : undefined
  let cache = { path: undefined, mtimeMs: 0, facts: [], intents: [], file: undefined, ambiguous: false }
  return function read() {
    try {
      const names = readdirSync(stateRoot).filter((n) => n.endsWith('-state.jsonl'))
      if (names.length === 0) return cache
      let best
      let bestT = -1
      if (pinned !== undefined) {
        if (!names.includes(pinned)) {
          return { ...cache, path: undefined, facts: [], intents: [], file: undefined, missing: pinned, ambiguous: names.length > 1 }
        }
        best = pinned
        try { bestT = statSync(join(stateRoot, pinned)).mtimeMs } catch { bestT = 0 }
      } else {
        best = names[0]
        for (const n of names) {
          try {
            const t = statSync(join(stateRoot, n)).mtimeMs
            if (t > bestT) { bestT = t; best = n }
          } catch { /* 单个文件读不到就跳过 */ }
        }
      }
      const path = join(stateRoot, best)
      if (path === cache.path && bestT === cache.mtimeMs) return cache
      const facts = []
      const intents = new Map()
      for (const line of readFileSync(path, 'utf-8').split('\n')) {
        const t = line.trim()
        if (t === '') continue
        let r
        try { r = JSON.parse(t) } catch { continue }
        if (r.type === 'fact') facts.push(r)
        else if (r.type === 'intent') intents.set(r.id, { ...r, status: r.status ?? 'todo' })
        else if (r.type === 'intent-update' && intents.has(r.id)) {
          intents.set(r.id, { ...intents.get(r.id), status: r.status ?? intents.get(r.id).status })
        }
      }
      cache = { path, mtimeMs: bestT, facts, intents: [...intents.values()], file: best, ambiguous: names.length > 1, missing: undefined }
      return cache
    } catch {
      return cache
    }
  }
}

/** 状态规则：`when` 里所有条件都满足时返回该规则（条件之间是 AND）。 */
function evalStateRules(stateRules, ledger) {
  const out = []
  for (const rule of stateRules) {
    const w = rule.when ?? {}
    if (typeof w.hasFactKind === 'string' && !ledger.facts.some((f) => f.kind === w.hasFactKind)) continue
    if (Number.isFinite(w.minFacts) && ledger.facts.length < w.minFacts) continue
    if (typeof w.noIntentMatching === 'string') {
      let re
      try { re = new RegExp(w.noIntentMatching, 'i') } catch { continue }
      if (ledger.intents.some((i) => re.test(String(i.action ?? '')))) continue
    }
    if (typeof w.intentStatus === 'string' && !ledger.intents.some((i) => i.status === w.intentStatus)) continue
    out.push(rule)
  }
  return out
}

export function apply(ctx, config) {
  config = config ?? {}
  trace('apply: rules=' + (Array.isArray(config.rules) ? config.rules.length : 'NONE'))
  const skillsRoot = typeof config.skillsRoot === 'string' ? config.skillsRoot : undefined
  const maxInjections = Number.isFinite(config.maxInjections) ? config.maxInjections : 8
  const maxCardBytes = Number.isFinite(config.maxCardBytes) ? config.maxCardBytes : 20000
  // 单次 tool/call 最多注入几张卡。maxInjections 限的是注入**次数**，管不住单次的**卡数** ——
  // 一次命中 N 条规则就会灌 N 张卡，额度到顶时最坏 maxInjections × N。两道闸必须一起关。
  const maxCardsPerCall = Number.isFinite(config.maxCardsPerCall) ? config.maxCardsPerCall : 3
  // arguments 超此长度即视为"文档"，只匹配 tool name
  // （兜底：将来新增的内容型工具没进 CONTENT_TOOLS 时仍受保护）。
  const maxArgumentBytes = Number.isFinite(config.maxArgumentBytes) ? config.maxArgumentBytes : 8000

  const rules = []
  for (const raw of Array.isArray(config.rules) ? config.rules : DEFAULT_RULES) {
    if (!raw || typeof raw.pattern !== 'string' || !Array.isArray(raw.cards)) continue
    try {
      // notPattern（2026-10-25）：负向条件。关键词对上了但场景不对时不注入。
      // 动机：DutyBound 那场 6 次注入里 3 次误报（password-attacks / container-escape /
      // python-sandbox-escape），模型两次明确写下 "false route"。误报的代价不是
      // token，是**信任** —— 连续判"无关"之后，真命中的卡也会被扫一眼就过。
      // 负向条件写坏了就忽略它（fail-open）：宁可多注入一张卡，也不要整条规则失效。
      let notRegex
      if (typeof raw.notPattern === 'string' && raw.notPattern.trim() !== '') {
        try {
          notRegex = new RegExp(raw.notPattern, 'i')
        } catch (error) {
          ctx.logger.warn('htb-router: bad notPattern %j: %s', raw.notPattern, error.message)
        }
      }
      rules.push({
        regex: new RegExp(raw.pattern, 'i'),
        notRegex,
        cards: raw.cards,
        label: raw.label ?? raw.id ?? 'scene',
        note: typeof raw.note === 'string' && raw.note.trim() !== '' ? raw.note.trim() : undefined,
        state: (raw.state && typeof raw.state === 'object' && typeof raw.state.type === 'string') ? raw.state : undefined,
      })
    } catch (error) {
      ctx.logger.warn('htb-router: bad rule pattern %j: %s', raw.pattern, error.message)
    }
  }
  if (rules.length === 0) ctx.logger.warn('htb-router: no valid rules configured; router is inert')

  // ── 编排器写账本(移植 Anthropic:found_bugs.jsonl 由 pipeline 写,不靠 agent 自觉)──
  const stateRoot = typeof config.stateRoot === 'string' ? config.stateRoot : '/root/htb'
  const stateMaxPerType = Number.isFinite(config.stateMaxPerType) ? config.stateMaxPerType : 3

  // ── L1c 状态驱动规则（与关键词规则互补）────────────────────────────────
  // 关键词规则问"这条命令**像**什么阶段"；状态规则问"台账里**已知**什么、还缺什么"。
  // 例：已有 cred 事实、但没有登记任何横向意图 ⇒ 注入横向/喷洒卡。每条每会话只触发一次。
  const stateRules = Array.isArray(config.stateRules)
    ? config.stateRules.filter((r) => r !== null && typeof r === 'object'
        && typeof r.id === 'string' && r.when !== undefined)
    : []
  const ledgerMachine = typeof config.machine === 'string' ? config.machine : undefined
  const readLedger = makeLedgerReader(stateRoot, ledgerMachine)
  if (stateRules.length > 0) trace('apply: stateRules=' + stateRules.length)

  /** 找到工作区里唯一的 <box>-state.jsonl(agent 开局建的);没有则不写。 */
  function stateLedgerPath() {
    try {
      const names = readdirSync(stateRoot).filter(n => n.endsWith('-state.jsonl'))
      if (ledgerMachine !== undefined && ledgerMachine.trim() !== '') {
        const want = ledgerMachine.trim().endsWith('-state.jsonl')
          ? ledgerMachine.trim()
          : `${ledgerMachine.trim()}-state.jsonl`
        return names.includes(want) ? join(stateRoot, want) : undefined
      }
      if (names.length === 1) return join(stateRoot, names[0])
    } catch {
      /* ignore */
    }
    return undefined
  }

  /** 编排器直接 append 一条事件(模型零参与)。返回是否已写。 */
  function appendStateEvent(type, what, evidence, sessionId, perSession) {
    const path = stateLedgerPath()
    if (path === undefined) return false
    const key = type + '|' + evidence.slice(0, 120)
    if (perSession.stateWritten.has(key)) return false
    const count = [...perSession.stateWritten].filter(k => k.startsWith(type + '|')).length
    if (count >= stateMaxPerType) return false
    perSession.stateWritten.add(key)
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      type,
      who: '',
      what,
      evidence,
    })
    try {
      appendFileSync(path, line + '\n')
      trace('state-append ' + line.slice(0, 140))
      return true
    } catch (error) {
      ctx.logger.warn('htb-router: state append failed: %s', error.message)
      return false
    }
  }

  // sessionId -> { injected: Set<card>, count: number, stateWritten: Set<string> }
  const perSession = new Map()

  async function loadCardBody(card) {
    try {
      const loaded = await ctx.skills.get(card)
      if (loaded && typeof loaded.content === 'string' && loaded.content.trim() !== '') {
        return loaded.content
      }
    } catch {
      /* registry miss — fall through to filesystem */
    }
    if (skillsRoot) {
      const p = join(skillsRoot, card, 'SKILL.md')
      if (existsSync(p)) return readFileSync(p, 'utf-8')
    }
    return undefined
  }

  function inject(agent, text) {
    try {
      agent.inject(createUserMessage({
        content: [{ type: 'text', text }],
        // Session format v4 (dsh >= 0.2.x) refuses the retired v3 plugin wrapper
        // shape { kind: 'plugin', plugin: <name> } at native read/write admission
        // ("format v4 message requires a producer-owned source kind", see
        // session-format-v3-to-v4/src/message-sources.ts). A producer that is not
        // one of the first-party same-name kinds must identify itself as
        // `plugin:<name>` — the same kind the V3-to-V4 migration assigns to an
        // unknown plugin name.
        source: { kind: 'plugin:htb-router' },
      }))
    } catch (error) {
      ctx.logger.warn('htb-router: inject failed: %s', error.message)
    }
  }

  ctx.on('session/event', (session, event) => {
    if (!event || event.type !== 'tool/call') return
    const data = event.data ?? {}
    const toolName = String(data.name ?? '')
    if (toolName === 'skill') return // 模型自己已经在加载卡——别打断
    const rawArgs = String(data.arguments ?? '')
    // 内容型工具 / 超长参数 ⇒ arguments 是文档而非攻击动作，不参与匹配（见 CONTENT_TOOLS 注释）。
    // 🔴 2026-10-17 加**前缀通配**：engram_* 的参数是记忆文本、htb_* 是台账/证据/任务书，
    //    都不是"正在执行的攻击动作"。实证事故：一条 engram 记忆里**引用了** `PtH`/`getst`/`etw`
    //    这几个词（我当时正在描述"短词假阳性"这个问题本身），结果 router 注入了 3 张 AD 攻击卡
    //    共 12KB，与当时任务完全无关。
    //    注意 `maxArgumentBytes` 那个兜底**不够**：那条记忆只有约 3KB，远低于 8000 的兜底线。
    //    用前缀而非逐个列举 —— engram 系列将来新增的工具会自动覆盖。
    const argsAsContent = CONTENT_TOOLS.has(toolName)
      || toolName.startsWith('engram_')
      || toolName.startsWith('htb_')
      || rawArgs.length > maxArgumentBytes
    const haystack = argsAsContent ? toolName : toolName + ' ' + rawArgs
    trace('tool/call ' + toolName + (argsAsContent ? ' [args-as-content ' + rawArgs.length + 'B]' : ''))

    let state = perSession.get(session.id)
    if (!state) {
      state = { injected: new Set(), count: 0, stateWritten: new Set(), notes: new Set() }
      perSession.set(session.id, state)
    }
    if (state.count >= maxInjections) return

    const hits = []
    const notes = []
    const picked = new Set() // 本次调用已收录的卡（跨规则去重）
    let withheld = 0
    for (const rule of rules) {
      if (!rule.regex.test(haystack)) continue
      // 负向条件：关键词对上了但场景不对 → 跳过（见规则构建处的说明）。
      if (rule.notRegex !== undefined && rule.notRegex.test(haystack)) {
        trace('rule suppressed by notPattern: ' + rule.label)
        continue
      }
      trace('rule hit: ' + rule.label)
      for (const card of rule.cards) {
        // 同一张卡可能被多条规则引用（如 aws-attack-surface 同属 SSRF 与 AWS 两条）：
        // 去重必须在**收集阶段**做，否则日志与注入列表都会重复出现同一张卡。
        if (state.injected.has(card) || picked.has(card)) continue
        picked.add(card)
        // 超出单次卡数上限的卡【不】标记为已注入 ⇒ 下次命中仍有机会被注入。
        if (hits.length >= maxCardsPerCall) { withheld += 1; continue }
        hits.push({ card, label: rule.label })
      }
      // note 与卡一样按会话去重：否则同一个阻断点提醒每次命中都重灌一遍，既占上下文，
      // 又会把 maxInjections 额度吃光 —— note-only 注入同样会执行 state.count += 1
      //（实测 2026-10-17：FLAG_CAPTURE 提醒在一次会话里被重复注入 3 次）。
      if (rule.note !== undefined && !notes.includes(rule.note) && !state.notes.has(rule.note)) notes.push(rule.note)
      // 编排器写账本:规则命中即由插件 append 事件(兜底层,不依赖模型自觉)
      if (rule.state !== undefined) {
        appendStateEvent(rule.state.type, rule.state.what ?? 'router-detected',
          String(data.arguments ?? '').slice(0, 200), session.id, state)
      }
    }
    // ── 状态驱动：读台账，条件满足即注入（每条 stateRule 每会话一次）──────────
    // 放在关键词规则之后：两者命中都进同一个 hits/notes，共用 cap 与去重。
    if (stateRules.length > 0 && state.count < maxInjections) {
      const ledger = readLedger()
      // 账本歧义可见化（2026-10-21）：stateRoot 下有多个账本时，读的是 mtime 最新那个。
      // 不配置 machine 就可能读到别的靶机 —— 这里每个会话只提示一次，让误绑定不再静默。
      if (ledger.ambiguous && ledger.file !== undefined && !state.injected.has('__ledger_ambiguity__')) {
        state.injected.add('__ledger_ambiguity__')
        const warn = `⚠️ 状态规则读的账本是 \`${ledger.file}\`（stateRoot 下有多个账本，按 mtime 选最新）。`
          + `若这不是当前靶机，请在 htb-router 配置里加 \`machine: "<靶机名>"\` 精确绑定。`
        if (!notes.includes(warn)) notes.push(warn)
      }
      if (ledger.facts.length > 0) {
        for (const sr of evalStateRules(stateRules, ledger)) {
          const key = 'state:' + sr.id
          if (state.injected.has(key)) continue
          state.injected.add(key)
          trace('state rule hit: ' + (sr.label ?? sr.id) + ' (facts=' + ledger.facts.length + ')')
          for (const card of Array.isArray(sr.cards) ? sr.cards : []) {
            if (state.injected.has(card) || picked.has(card)) continue
            if (hits.length >= maxCardsPerCall) { withheld += 1; continue }
            picked.add(card)
            hits.push({ card, label: sr.label ?? sr.id })
          }
          if (typeof sr.note === 'string' && sr.note.trim() !== '' && !notes.includes(sr.note.trim())) {
            notes.push(sr.note.trim())
          }
        }
      }
    }

    if (withheld > 0) {
      trace('card cap: ' + withheld + ' more card(s) withheld (maxCardsPerCall=' + maxCardsPerCall + ')')
    }
    if (hits.length === 0 && notes.length === 0) return

    // 异步加载卡正文,完成后注入(不阻塞事件循环)。
    void (async () => {
      const parts = []
      for (const hit of hits) {
        if (state.injected.has(hit.card)) continue
        state.injected.add(hit.card)
        const body = await loadCardBody(hit.card)
        if (body === undefined) {
          ctx.logger.warn('htb-router: card %s not loadable', hit.card)
          continue
        }
        const trimmed = body.length > maxCardBytes
          ? body.slice(0, maxCardBytes)
            + '\n\n…（以上是**卡头部** ' + maxCardBytes + '/' + body.length + ' 字节：含触发信号、'
            + '判据与快速索引。需要完整命令细节时用 skill 工具加载 ' + hit.card + ' 取全文）'
          : body
        parts.push('【' + hit.card + '】' + (hit.label ? '（' + hit.label + ' 场景命中）' : '') + '\n' + trimmed)
      }
      for (const note of notes) { state.notes.add(note); parts.push(note) }
      if (parts.length === 0) return
      state.count += 1
      const agents = ctx.get('agents')
      const agent = agents?.get(session.id)
      if (agent === undefined) {
        trace('NO AGENT for session ' + session.id)
        return
      }
      trace('injecting ' + (hits.map(h => h.card).join(',') || '(note-only)'))
      const head = hits.length > 0
        ? '⚡ htb-router 自动路由:当前攻击阶段命中技能卡,正文已直接注入上下文,直接使用其中内容(无需再加载):\n\n'
        : '⚡ htb-router 阻断点提醒:\n\n'
      inject(agent, head + parts.join('\n\n' + '─'.repeat(40) + '\n\n'))
    })().catch((error) => ctx.logger.warn('htb-router: route failed: %s', error.message))
  })
}
