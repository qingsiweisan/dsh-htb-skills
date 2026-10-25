/**
 * state-tools.js — 作战状态账本：fact 节点 / intent 边（append-only JSONL）
 *
 * 为什么需要它（外部实证）：
 *   Intentest (arXiv 2609.07344) 用 fact-intent DAG + 全局控制黑板把长时程渗透的成功率
 *   从「纯文本共享记忆」的 44.1% 提到 88.2%（hard 任务 25% → 75%），并指出纯文本记忆的
 *   失败模式（状态漂移、重复劳动、无目的探索）全部是"状态不可靠"的症状。
 *   我们的 loot/<machine>.md + traces/*.md 正是"纯文本共享记忆"。
 *
 * 与既有机制的接缝（刻意复用，不另起炉灶）：
 *   - 文件：`<stateRoot>/<machine>-state.jsonl` —— **与 router/ 的 state 事件同一个文件**。
 *     router 命中规则时写 `type:"access"`，本工具写 `type:"fact" | "intent" | "intent-update"`。
 *     两边合起来就是 Intentest 那个"全局黑板"的雏形。
 *   - 证据：fact 的 `evidenceId` 直接指向 dsh-htb-evidence 的账本 id（ev-<12hex>）。
 *     于是这张 DAG 是**可验证的**：每个事实都能回到已存证据字节。
 *
 * 工具层强制的一条硬规则（与 htb_coverage 的 baseline 闸同源）：
 *   `htb_frontier op=dead` 必须带 `baselineEvidenceId` ——
 *   "没有对照的全否不是结论"。判死是永久排除一条路，代价最高，所以最需要对照。
 *   第二条硬规则：`htb_fact` 写 cred/vuln/flag 且 confidence=verified 时必须带 evidenceId，
 *   否则必须显式写 confidence:"inferred"（推测不许伪装成事实 —— 见 engagement-inventory-and-triage）。
 */

import { appendFileSync, existsSync, readFileSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/** fact 节点类型。 */
const KINDS = ['host', 'service', 'cred', 'vuln', 'flag', 'note']
/** 需要"证据或显式推测"的高价值类型。 */
const STRICT_KINDS = ['cred', 'vuln', 'flag']
/** intent 边状态。 */
const STATUSES = ['todo', 'doing', 'done', 'dead']
/**
 * 判死原因枚举（2026-10-21）。
 *
 * 为什么要枚举而不是自由文本：自由文本无法聚合。而"我总死在哪一类原因上"
 * 这个分布，直接决定下一步该补什么：
 *   not-vulnerable → 补漏洞识别（版本/CVE 检索）
 *   auth-failed    → 补凭据（爆破/复用/窃取）
 *   blocked        → 补权限（提权/绕过）
 *   timeout        → 补性能/网络（并发、隧道、超时参数）
 *   no-path        → 补入口发现（目录/vhost/API）
 *   other          → 留给未归类的，但应当尽量少用
 */
const DEAD_REASONS = ['not-vulnerable', 'auth-failed', 'blocked', 'timeout', 'no-path', 'other']
/** evidence id 形态：ev-<12 hex>（dsh-htb-evidence 的编号形态）。 */
const EVIDENCE_RE = /^ev-[0-9a-f]{12}$/

function renderText(value) {
  return [{ type: 'text', text: value }]
}
function strOutput() {
  return { schema: { type: 'string' }, render(_args, value) { return renderText(String(value)) } }
}
function paramsSpec(props, required) {
  return { type: 'object', properties: props, required }
}

function stateRootOf(config) {
  const raw = typeof config?.stateRoot === 'string' && config.stateRoot.trim() !== ''
    ? config.stateRoot
    : join(process.cwd(), 'loot')
  return isAbsolute(raw) ? raw : resolve(process.cwd(), raw)
}

/**
 * 证据账本目录。默认取 `<stateRoot>/.evidence-ledger` —— 与 dsh-htb-evidence 的
 * `ledgerRoot` 默认布局一致（该插件把账本放在 loot 下一层）。
 * 显式 config.ledgerRoot 优先，便于两者被配到不同位置时仍能对齐。
 */
function ledgerRootOf(config) {
  const raw = typeof config?.ledgerRoot === 'string' && config.ledgerRoot.trim() !== ''
    ? config.ledgerRoot
    : join(stateRootOf(config), '.evidence-ledger')
  return isAbsolute(raw) ? raw : resolve(process.cwd(), raw)
}

/**
 * 证据 id 是否真的存在于账本索引里。
 *
 * 动机（2026-10-21 可行性复审）：原实现只校验 `ev-<12hex>` 的**形态**，
 * 于是随手编一个符合格式的 id 就能把 fact 标成 verified —— 硬规则形同虚设。
 * 这里补上**存在性**校验，但仍**不做语义支持性判断**（"证据里是否真的出现了
 * 该事实"需要读证据正文做匹配，属 P4 critic 的职责，不在本函数内混淆）。
 *
 * 三态返回，刻意区分"不存在"与"无法判断"：
 *   - true  ：索引里有这个 id
 *   - false ：索引可读，但没有这个 id → 调用方应拒绝
 *   - undefined：账本目录/索引不可读（未启用 evidence）→ 调用方应放行并警告，
 *                不能因为没装证据插件就把整个台账锁死
 * @param config - 插件配置（含 stateRoot / ledgerRoot）。
 * @param id - 待校验的证据 id。
 */
function evidenceExists(config, id) {
  const indexPath = join(ledgerRootOf(config), 'index.jsonl')
  let text
  try {
    text = readFileSync(indexPath, 'utf-8')
  } catch {
    return undefined
  }
  for (const line of text.split('\n')) {
    const t = line.trim()
    if (t === '') continue
    try {
      if (JSON.parse(t).id === id) return true
    } catch { /* 坏行跳过：索引与账本同为 append-only */ }
  }
  return false
}

/**
 * 账本里"当前轮次"的 run 标识。
 *
 * 背景（2026-10-21 复审）：同一台靶机重打 / reset 后，新一轮的 fact 与 intent
 * 会追加进同一个 `<machine>-state.jsonl`，与上一轮的 dead intent、旧凭据混在
 * 一起 —— frontier 查询会读到已经作废的结论。
 *
 * 兼容策略：**没有 run-start 记录时返回 undefined**，此时所有过滤退化为"不过滤"，
 * 行为与引入 run 之前完全一致。只有显式调用 `op=run-start` 之后才启用隔离，
 * 所以这次改动不会改变任何既有账本的读取结果。
 * @param rows - 账本全部行。
 * @returns 当前 run 标识；账本从未开过轮次时 undefined。
 */
function latestRun(rows) {
  for (let i = rows.length - 1; i >= 0; i -= 1) {
    const r = rows[i]
    if (r.type === 'run-start' && typeof r.run === 'string' && r.run !== '') return r.run
  }
  return undefined
}

/**
 * 按 run 过滤账本行。
 * @param rows - 账本全部行。
 * @param selector - `'all'` 取全部；具体 run 名取该轮；缺省取 {@link latestRun}。
 * @returns 过滤后的行；`selector` 无法解析时返回全部（宁可多读，不可静默丢）。
 */
function selectRun(rows, selector) {
  if (selector === 'all') return rows
  const latest = latestRun(rows)
  // 账本从未开过轮次：全部可见 —— 与引入 run 之前的行为完全一致。
  if (latest === undefined) return rows
  const want = typeof selector === 'string' && selector.trim() !== '' ? selector.trim() : latest
  // 🔴 一旦存在 run-start，legacy 记录（无 run 字段）就**不再默认显示**。
  //    原实现把 legacy 一并保留（`r.run === undefined || r.run === want`），后果是
  //    **第一次启用轮次隔离时隔离完全无效**：历史记录全是 legacy，reset 后上一轮的
  //    dead intent 与旧凭据仍然可见 —— 正好是这个功能要解决的问题（2026-10-21 复审）。
  //    需要历史时用 run:"all"；只想看未归属记录用 run:"legacy"。
  if (want === 'legacy') return rows.filter((r) => r.run === undefined)
  return rows.filter((r) => r.run === want)
}


/**
 * 定位账本文件。与 router 的 stateLedgerPath() 同规则：
 * 优先用 stateRoot 下**唯一**的 `*-state.jsonl`；否则要求调用方给 machine。
 */
function findLedger(root, machine) {
  let names = []
  try {
    names = readdirSync(root).filter((n) => n.endsWith('-state.jsonl'))
  } catch {
    return { error: `stateRoot 不存在或不可读: ${root}（首次使用请传 machine，工具会创建文件）` }
  }
  if (typeof machine === 'string' && machine.trim() !== '') {
    const want = machine.endsWith('-state.jsonl') ? machine : `${machine}-state.jsonl`
    return { path: join(root, want), existing: names.includes(want) }
  }
  if (names.length === 1) return { path: join(root, names[0]), existing: true }
  if (names.length === 0) {
    return { error: `stateRoot (${root}) 下没有 *-state.jsonl —— 首次使用请传 machine 参数（如 machine: "Dump"），工具会建账本` }
  }
  return { error: `stateRoot (${root}) 下有 ${names.length} 个 *-state.jsonl（${names.join(', ')}）—— 请显式传 machine 参数` }
}

function readLedger(path) {
  if (!existsSync(path)) return []
  const rows = []
  for (const line of readFileSync(path, 'utf-8').split('\n')) {
    const t = line.trim()
    if (t === '') continue
    try { rows.push(JSON.parse(t)) } catch { /* 坏行跳过：账本是 append-only，宁可少读不可中断 */ }
  }
  return rows
}

function nextId(rows, prefix) {
  let max = 0
  for (const r of rows) {
    if (typeof r.id === 'string' && r.id.startsWith(prefix)) {
      const n = Number.parseInt(r.id.slice(prefix.length), 10)
      if (Number.isFinite(n) && n > max) max = n
    }
  }
  return `${prefix}${max + 1}`
}

function append(path, event) {
  appendFileSync(path, `${JSON.stringify(event)}\n`)
}

/** 事件溯源折叠：intent 的当前状态 = 该 id 上最后一条 intent / intent-update。 */
function foldIntents(rows) {
  const map = new Map()
  for (const r of rows) {
    if (r.type === 'intent') {
      map.set(r.id, { ...r, status: r.status ?? 'todo' })
    } else if (r.type === 'intent-update' && map.has(r.id)) {
      const cur = map.get(r.id)
      const next = { ...cur, status: r.status ?? cur.status }
      for (const k of ['baseline', 'reason', 'owner', 'result', 'claimedAt', 'reasonCode']) {
        if (r[k] !== undefined) next[k] = r[k]
      }
      map.set(r.id, next)
    }
  }
  return [...map.values()]
}

// ── 复用 router 规则表（86 条"场景 → 卡"映射）────────────────────────────────
// ARTEMIS (ICLR 2026) 的 dynamic prompt creation 要求：子 agent 的 system prompt 由
// supervisor **之外**的模块生成，用途之一是"提示该用哪些工具"。
// 我们那 86 条 `场景 → 卡` 映射正好就是这个提示库 —— 直接复用，不另建一份。
// 零依赖：规则表结构规整，用正则解析，不引入 yaml 库（本包没有该依赖）。

/** 解析 router 的 cordis.patch.yml，抽出 {id,label,pattern,cards,hasNote}。 */
export function parseRouterRules(text) {
  const rules = []
  let cur = null
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    const mId = /^- id:\s*(\S+)/.exec(line)
    if (mId !== null) {
      if (cur !== null && cur.pattern !== undefined) rules.push(cur)
      cur = { id: mId[1] }
      continue
    }
    if (cur === null) continue
    const mLabel = /^label:\s*'([^']*)'/.exec(line)
    if (mLabel !== null) { cur.label = mLabel[1]; continue }
    const mPat = /^pattern:\s*'([^']*)'/.exec(line)
    if (mPat !== null) { cur.pattern = mPat[1]; continue }
    const mCards = /^cards:\s*\[([^\]]*)\]/.exec(line)
    if (mCards !== null) {
      cur.cards = [...mCards[1].matchAll(/'([^']+)'/g)].map((m) => m[1])
      continue
    }
    if (/^note:\s*\|/.test(line)) cur.hasNote = true
  }
  if (cur !== null && cur.pattern !== undefined) rules.push(cur)
  return rules
}

/**
 * router 规则表的候选路径。
 *
 * 🔴 2026-10-25：router 从"独立仓库 `~/dsh-htb-router`"并入本包的 `router/` 子目录，
 *    所以默认路径必须**先找包内**，再退回旧的独立安装位置 —— 否则从本仓库新装的人
 *    永远读不到规则表（`loadRouterRules` 会静默返回空规则，brief 降级但不报错）。
 * @param config - 插件配置（`routerPatchPath` 显式指定时优先）。
 * @returns 候选路径列表（按优先级）。
 */
function routerPatchCandidates(config) {
  const explicit = typeof config?.routerPatchPath === 'string' ? config.routerPatchPath.trim() : ''
  if (explicit !== '') return [explicit]
  const pkgRoot = fileURLToPath(new URL('..', import.meta.url))
  return [
    join(pkgRoot, 'router', 'cordis.patch.yml'),
    join(homedir(), 'dsh-htb-router', 'cordis.patch.yml'),
  ]
}

/** 读 router 规则表；失败不抛（brief 要能在规则表缺失时降级可用）。 */
function loadRouterRules(config) {
  const candidates = routerPatchCandidates(config)
  let lastPath = candidates[candidates.length - 1]
  for (const raw of candidates) {
    const path = isAbsolute(raw) ? raw : resolve(process.cwd(), raw)
    try {
      return { path, rules: parseRouterRules(readFileSync(path, 'utf-8')) }
    } catch {
      lastPath = path // 继续试下一个候选
    }
  }
  return {
    path: lastPath,
    rules: [],
    error: 'router 规则表不存在（已尝试包内 router/ 与 ~/dsh-htb-router）',
  }
}

// ── htb_fact ────────────────────────────────────────────────────────────────

function runFact(config, args) {
  const root = stateRootOf(config)
  const found = findLedger(root, args.machine)
  if (found.error !== undefined) return `⚠️ ${found.error}`
  const rows = readLedger(found.path)
  const facts = rows.filter((r) => r.type === 'fact')
  const op = typeof args.op === 'string' && args.op !== '' ? args.op : 'list'

  if (op === 'run-start') {
    const label = typeof args.run === 'string' && args.run.trim() !== ''
      ? args.run.trim()
      : `r${rows.filter((r) => r.type === 'run-start').length + 1}`
    const prev = latestRun(rows)
    // 本轮之前的未归属记录数：开轮次后它们将不再默认显示，必须让调用方看见这个后果。
    const legacyCount = rows.filter(
      (r) => (r.type === 'fact' || r.type === 'intent') && r.run === undefined,
    ).length
    append(found.path, {
      ts: new Date().toISOString(),
      type: 'run-start',
      run: label,
      ...(args.note !== undefined ? { note: String(args.note) } : {}),
    })
    return `✅ 已开启新一轮 run=${label}（上一轮: ${prev ?? '(无)'}）\n`
      + `   之后 add 的 fact/intent 会带 run=${label}；默认读取只看本 run。\n`
      + (legacyCount > 0
        ? `   ⚠️ 此前有 ${legacyCount} 条未归属轮次的记录（legacy）将**不再默认显示** —— 这是刻意的：\n`
          + '      它们可能属于 reset 前的旧状态。要看全部：run:"all"；只看 legacy：run:"legacy"。\n'
        : '')
      + `   → ${found.path}`
  }

  if (op === 'add') {
    if (typeof args.key !== 'string' || args.key.trim() === '') return '⚠️ add 需要 key（这条事实是什么，如 "svc_web:password"）'
    const kind = typeof args.kind === 'string' && args.kind !== '' ? args.kind : 'note'
    if (!KINDS.includes(kind)) return `⚠️ kind 必须是 ${KINDS.join(' / ')} 之一，收到 "${kind}"`
    const confidence = typeof args.confidence === 'string' && args.confidence !== '' ? args.confidence : 'verified'
    if (!['verified', 'inferred'].includes(confidence)) return '⚠️ confidence 只能是 verified（有证据）或 inferred（推测）'

    if (STRICT_KINDS.includes(kind) && confidence === 'verified' && args.evidenceId === undefined) {
      return `⚠️ 工具层拒绝：kind=${kind} 且 confidence=verified 时必须带 evidenceId。\n`
        + '   两条合法路径：① 先用 evidence_add 登记证据（原始命令 + 完整输出），把 ev-… 传进来；\n'
        + '   ② 若确实还没证据，显式写 confidence: "inferred" —— 推测可以进台账，但必须**看起来像推测**。'
    }
    if (args.evidenceId !== undefined && !EVIDENCE_RE.test(String(args.evidenceId))) {
      return `⚠️ evidenceId 形态不对：期望 ev-<12位hex>（如 ev-02b8cdb79116），收到 "${args.evidenceId}"`
    }

    // 存在性校验（2026-10-21 新增）：形态对但账本里没有这个 id = 编造。
    // 三态：false 拒绝；undefined（账本未启用）放行并附警告；true 正常。
    let evidenceWarning = ''
    if (args.evidenceId !== undefined && STRICT_KINDS.includes(kind) && confidence === 'verified') {
      const exists = evidenceExists(config, String(args.evidenceId))
      if (exists === false) {
        return `⚠️ 工具层拒绝：evidenceId ${args.evidenceId} 在证据账本索引里不存在。\n`
          + `   索引: ${join(ledgerRootOf(config), 'index.jsonl')}\n`
          + '   三条合法路径：① 用 evidence_add 真实登记证据，拿返回的 ev-…；\n'
          + '   ② 若证据在别处，先把原始输出登记进账本；\n'
          + '   ③ 若确实还没证据，显式写 confidence: "inferred" —— 编一个格式正确的 id 不是证据。'
      }
      if (exists === undefined) {
        evidenceWarning = `\n   ⚠️ 未找到证据账本索引（${join(ledgerRootOf(config), 'index.jsonl')}），本次只校验了 id 形态 —— 存在性未核实。`
      }
    }

    const id = nextId(facts, 'f')
    const run = latestRun(rows)
    append(found.path, {
      ts: new Date().toISOString(),
      type: 'fact',
      id,
      kind,
      key: args.key,
      ...(args.value !== undefined ? { value: String(args.value) } : {}),
      ...(args.evidenceId !== undefined ? { evidence: String(args.evidenceId) } : {}),
      confidence,
      ...(args.source !== undefined ? { source: String(args.source) } : {}),
      ...(run !== undefined ? { run } : {}),
    })
    return `✅ ${id} [${kind}/${confidence}] ${args.key}`
      + `${args.value !== undefined ? ` = ${args.value}` : ''}\n   → ${found.path}`
      + `${run !== undefined ? `\n   run=${run}` : ''}${evidenceWarning}`
  }

  if (op !== 'list' && op !== 'query') return `⚠️ op 只能是 add / run-start / list / query，收到 "${op}"`

  const q = typeof args.q === 'string' ? args.q.toLowerCase() : undefined
  const scoped = selectRun(rows, args.run)
  const scopedFacts = scoped.filter((r) => r.type === 'fact')
  const sel = scopedFacts.filter((f) => {
    if (args.kind !== undefined && f.kind !== args.kind) return false
    if (q !== undefined && !JSON.stringify(f).toLowerCase().includes(q)) return false
    return true
  })
  const runNote = args.run === 'all' || latestRun(rows) === undefined
    ? ''
    : `  [run=${typeof args.run === 'string' && args.run.trim() !== '' ? args.run.trim() : latestRun(rows)}]`
  if (sel.length === 0) {
    return scopedFacts.length === 0
      ? `(台账里还没有 fact${runNote})`
      : `(没有匹配的 fact${runNote})`
  }
  return `# facts (${sel.length}/${scopedFacts.length})${runNote}\n` + sel.map((f) => {
    const ev = f.evidence !== undefined ? `  ←${f.evidence}` : ''
    const val = f.value !== undefined ? ` = ${f.value}` : ''
    const warn = STRICT_KINDS.includes(f.kind) && f.confidence === 'inferred' ? '  ⚠️推测' : ''
    return `  ${f.id} [${f.kind}/${f.confidence}] ${f.key}${val}${ev}${warn}`
  }).join('\n')
}

// ── htb_frontier ────────────────────────────────────────────────────────────

function runFrontier(config, args) {
  const root = stateRootOf(config)
  const found = findLedger(root, args.machine)
  if (found.error !== undefined) return `⚠️ ${found.error}`
  const rows = readLedger(found.path)
  const scopedRows = selectRun(rows, args.run)
  const factIds = new Set(scopedRows.filter((r) => r.type === 'fact').map((r) => r.id))
  const intents = foldIntents(scopedRows)
  // 🔴 id 必须在**全部**历史上取最大，不能用 scoped —— 否则开新 run 后
  //    nextId 会从 i1 重新开始，把上一轮的 i1 覆盖掉（2026-10-21 实测踩到）。
  const allIntents = foldIntents(rows)
  const op = typeof args.op === 'string' && args.op !== '' ? args.op : 'list'

  if (op === 'add') {
    if (typeof args.action !== 'string' || args.action.trim() === '') return '⚠️ add 需要 action（要做什么，一句话）'
    const fromList = typeof args.from === 'string'
      ? args.from.split(',').map((s) => s.trim()).filter((s) => s !== '')
      : []
    const missing = fromList.filter((f) => !factIds.has(f))
    if (missing.length > 0) {
      return `⚠️ from 指向不存在的 fact: ${missing.join(', ')}\n`
        + `   现有 fact: ${[...factIds].join(', ') || '(空)'} —— 先 htb_fact op=add 把前置事实登记了`
    }
    const id = nextId(allIntents, 'i')
    const run = latestRun(rows)
    const budget = Number.isFinite(Number(args.budget)) && Number(args.budget) > 0
      ? Number(args.budget)
      : undefined
    append(found.path, {
      ts: new Date().toISOString(),
      type: 'intent',
      id,
      action: args.action,
      from: fromList,
      ...(args.target !== undefined ? { target: String(args.target) } : {}),
      status: 'todo',
      ...(args.retestCost !== undefined ? { retestCost: String(args.retestCost) } : {}),
      ...(args.owner !== undefined ? { owner: String(args.owner) } : {}),
      // 假设三件套（2026-10-21）：把老手的「我心里有个赌注」变成可查的文本。
      // 假设留在脑子里永远不会被推翻；写成字段才可能被后续证据打脸。
      ...(args.assume !== undefined && String(args.assume).trim() !== '' ? { assume: String(args.assume).trim() } : {}),
      ...(args.ifWrong !== undefined && String(args.ifWrong).trim() !== '' ? { ifWrong: String(args.ifWrong).trim() } : {}),
      ...(budget !== undefined ? { budget } : {}),
      ...(run !== undefined ? { run } : {}),
    })
    const hints = []
    if (args.assume === undefined) hints.push('   提示：没写 assume（当前假设）—— 没有假设的 intent 无法被证伪，退化成待办清单。')
    if (budget === undefined) hints.push('   提示：没写 budget（预计分钟）—— 没有预算的方向不会自己到期。')
    return `✅ ${id} [todo] ${args.action}${run !== undefined ? `\n   run=${run}` : ''}`
      + (hints.length > 0 ? `\n${hints.join('\n')}` : '')
  }

  if (op === 'claim' || op === 'done' || op === 'dead') {
    if (typeof args.id !== 'string' || args.id.trim() === '') return `⚠️ ${op} 需要 id（如 i1）`
    const cur = intents.find((r) => r.id === args.id)
    if (cur === undefined) return `⚠️ 没有 intent ${args.id}。现有: ${intents.map((r) => r.id).join(', ') || '(空)'}`

    if (op === 'dead') {
      // 🔴 与 htb_coverage 同源的硬规则：判死必须带对照组证据。
      if (args.baselineEvidenceId === undefined) {
        return '⚠️ 工具层拒绝：判 dead（"这条路不通"）必须带 baselineEvidenceId。\n'
          + '   理由与 htb_coverage 同一条硬规则 —— **没有对照的全否不是结论**。\n'
          + '   判死会永久排除一条路，代价最高，所以最需要对照。先做三步：\n'
          + '   ① 跑一个"证明工具/通道本身是活的"的对照探测（例如读一个确定存在的文件）；\n'
          + '   ② evidence_add 把该探测的命令 + 输出登记为证据；\n'
          + '   ③ 把 ev-… 作为 baselineEvidenceId 传进来，并写 reason 说明"哪一步失败 + 为什么是对照过的失败"。'
      }
      if (!EVIDENCE_RE.test(String(args.baselineEvidenceId))) {
        return `⚠️ baselineEvidenceId 形态不对：期望 ev-<12位hex>，收到 "${args.baselineEvidenceId}"`
      }
      // 与 htb_fact 同一条存在性校验：格式对但账本里没有 = 编造的对照。
      const baseExists = evidenceExists(config, String(args.baselineEvidenceId))
      if (baseExists === false) {
        return `⚠️ 工具层拒绝：baselineEvidenceId ${args.baselineEvidenceId} 在证据账本索引里不存在。\n`
          + `   索引: ${join(ledgerRootOf(config), 'index.jsonl')}\n`
          + '   判死的对照必须是**真实登记过的探测**，不是填一个格式正确的 id。'
      }
    }

    const status = op === 'claim' ? 'doing' : op === 'done' ? 'done' : 'dead'
    const nowIso = new Date().toISOString()
    // reasonCode（2026-10-21）：把"为什么死"从自由文本变成可聚合的枚举。
    // 自由文本的 reason 无法统计；枚举才能回答"agent 最常死在哪一类原因上"——
    // 而这个分布直接决定该补知识、补凭据、还是换路径。
    const reasonCode = op === 'dead' && typeof args.reasonCode === 'string'
      && DEAD_REASONS.includes(args.reasonCode)
      ? args.reasonCode
      : undefined
    append(found.path, {
      ts: nowIso,
      type: 'intent-update',
      id: args.id,
      status,
      ...(op === 'claim' ? { claimedAt: nowIso } : {}),
      ...(op === 'claim' && args.owner !== undefined ? { owner: String(args.owner) } : {}),
      ...(op === 'dead' ? { baseline: String(args.baselineEvidenceId), ...(args.reason !== undefined ? { reason: String(args.reason) } : {}) } : {}),
      ...(op === 'dead' && reasonCode !== undefined ? { reasonCode } : {}),
      ...(op === 'done' && args.result !== undefined ? { result: String(args.result) } : {}),
    })

    let out = `✅ ${args.id} → ${status}`
      + `${args.reason !== undefined && op === 'dead' ? `（${args.reason}）` : ''}`
    if (op === 'dead' && reasonCode === undefined) {
      out += `\n   提示：没写 reasonCode（${DEAD_REASONS.join(' / ')}）—— 自由文本无法聚合，`
        + '写枚举才能在复盘时回答"我总死在哪一类原因上"。'
    }
    // 换层提示（软，不阻断）：同一 target 连续判死 ≥3 条时，
    // 提示"可能不是方法不对，而是层不对"。老手的"退一步"能力靠这个触发。
    if (op === 'dead') {
      const tgt = cur.target
      const deadSameTarget = intents.filter(
        (r) => r.status === 'dead' && (tgt === undefined ? r.target === undefined : r.target === tgt),
      ).length + 1
      if (deadSameTarget >= 3) {
        out += `\n\n⚠️ **换层检查**：${tgt ?? '该目标'} 上已连续判死 ${deadSameTarget} 条。`
          + '\n   连续判死通常不是"方法还不够多"，而是**层选错了**。按序自问：'
          + '\n   ① 服务层：端口/版本判对了吗（换扫描方式验证一次）'
          + '\n   ② 应用层：入口找全了吗（目录/vhost/参数/API）'
          + '\n   ③ 凭据层：有没有拿到但没用的凭据'
          + '\n   ④ 主机层：本机提权面查过吗'
          + '\n   ⑤ 网络层：是否有第二个网段/跳板'
          + '\n   走完把结论写进 loot，再决定是继续同层还是换层。'
      }
    }
    return out
  }

  if (op !== 'list') return `⚠️ op 只能是 add / list / claim / done / dead，收到 "${op}"`

  const groups = STATUSES.map((s) => [s, intents.filter((r) => r.status === s)])
  const curRun = typeof args.run === 'string' && args.run.trim() !== '' ? args.run.trim() : latestRun(rows)
  const runTag = args.run === 'all' || curRun === undefined ? '' : ` [run=${curRun}]`
  const lines = [`# frontier (${intents.length} 条)${runTag}`]
  for (const [status, list] of groups) {
    if (list.length === 0) continue
    lines.push(`\n## ${status} (${list.length})`)
    for (const r of list) {
      const from = Array.isArray(r.from) && r.from.length > 0 ? ` ←${r.from.join(',')}` : ''
      const tgt = r.target !== undefined ? ` @${r.target}` : ''
      const own = r.owner !== undefined ? ` (${r.owner})` : ''
      const base = r.status === 'dead' && r.baseline !== undefined ? ` [对照 ${r.baseline}]` : ''
      const rc = r.status === 'dead' && r.reasonCode !== undefined ? ` [${r.reasonCode}]` : ''
      // 预算与已投入：doing 状态才有时效意义。超预算不阻断，但必须让调用方看见 ——
      // 老手的"这个方向不值了"是模糊判断，这里把它变成可核对的事实。
      let clock = ''
      if (r.status === 'doing' && typeof r.claimedAt === 'string') {
        const mins = Math.max(0, Math.round((Date.now() - Date.parse(r.claimedAt)) / 60000))
        if (Number.isFinite(mins)) {
          clock = r.budget !== undefined
            ? ` ⏱${mins}/${r.budget}min${mins > r.budget ? ' ⚠️超预算' : ''}`
            : ` ⏱${mins}min`
        }
      }
      lines.push(`  ${r.id} ${r.action}${tgt}${from}${own}${base}${rc}${clock}`)
      if (r.assume !== undefined) lines.push(`      假设: ${r.assume}`)
      if (r.ifWrong !== undefined) lines.push(`      若错则看: ${r.ifWrong}`)
      if (r.status === 'dead' && r.reason !== undefined) lines.push(`      理由: ${r.reason}`)
    }
  }
  if (intents.length === 0) lines.push('(还没有 intent —— 用 op=add 把"下一步打算做什么"写进来)')
  return lines.join('\n')
}

/**
 * htb_brief：从 frontier 的一条 intent 生成**子 agent 任务书**。
 *
 * 三重动机：
 *   ① ARTEMIS：任务书由 supervisor 之外的模块生成 ⇒ 不占主 agent 上下文；
 *      且能给子 agent 塞"该用哪些工具"的提示（这里复用 router 的规则表）。
 *   ② 框架 L8 的交接契约：子 agent **没有 loot 写权限**（工具层 deny），
 *      所以任务书必须写明"结论以文本回报、落盘由主 agent 做" —— 否则子 agent 会白写。
 *   ③ L1c 的 frontier：任务书的内容来自结构化状态（intent + 其 from facts），
 *      而不是主 agent 临时回忆 —— 与 Intentest 的"黑板"同源。
 */
function composeBrief(config, args) {
  const root = stateRootOf(config)
  const found = findLedger(root, args.machine)
  if (found.error !== undefined) return `⚠️ ${found.error}`
  const rows = readLedger(found.path)
  const scopedRows = selectRun(rows, args.run)
  const facts = scopedRows.filter((r) => r.type === 'fact')
  const intents = foldIntents(scopedRows)

  const rawIntent = typeof args.intent === 'string' ? args.intent.trim() : ''
  if (rawIntent === '') {
    return '⚠️ htb_brief 需要 intent：frontier 的 intent id（如 i1）或一句自然语言任务。\n'
      + `   现有 intent: ${intents.map((r) => `${r.id}(${r.status})`).join(', ') || '(空 —— 先用 htb_frontier op=add 登记一条)'}`
  }
  const hit = intents.find((r) => r.id === rawIntent)
  const action = hit !== undefined ? hit.action : rawIntent
  const targetHost = hit?.target

  const explicit = typeof args.facts === 'string'
    ? args.facts.split(',').map((s) => s.trim()).filter((s) => s !== '')
    : []
  const fromIds = explicit.length > 0 ? explicit : (Array.isArray(hit?.from) ? hit.from : [])
  const ctxFacts = fromIds.map((id) => facts.find((f) => f.id === id)).filter((f) => f !== undefined)

  const { path: rulesPath, rules, error } = loadRouterRules(config)
  const haystack = [action, targetHost ?? '', ...ctxFacts.map((f) => `${f.kind} ${f.key} ${f.value ?? ''}`)].join(' ')
  const cards = []
  for (const rule of rules) {
    if (typeof rule.pattern !== 'string') continue
    let re
    try { re = new RegExp(rule.pattern, 'i') } catch { continue }
    if (!re.test(haystack)) continue
    for (const card of rule.cards ?? []) if (!cards.includes(card)) cards.push(card)
  }
  const capped = cards.slice(0, 8)

  const out = []
  out.push(`# 子 agent 任务书${hit !== undefined ? `（来自 frontier ${hit.id}，状态 ${hit.status}）` : '（临时任务，未登记 frontier）'}`)
  out.push('')
  // 规则表读不到时，brief 最值钱的那一节（卡建议）会静默消失 —— 提到顶部，
  // 否则主 agent 会以为"这次确实没匹配到卡"，而实际是文件读不了（2026-10-21 复审）。
  if (error !== undefined) {
    out.push(`> ⚠️ **规则表读取失败**（${rulesPath}）：${error}`)
    out.push('> 本次任务书缺少"建议加载的技能卡"，其余内容不受影响。')
    out.push('')
  }
  out.push('## 任务')
  out.push(action + (targetHost !== undefined ? `　｜　目标: ${targetHost}` : ''))
  if (hit?.retestCost !== undefined) out.push(`重测成本估计: ${hit.retestCost}`)
  // 把主 agent 的赌注传给子 agent：子 agent 不只是"执行一个动作"，
  // 它是在**验证一条假设**。知道假设是什么，才能回报"假设成立/不成立"，
  // 而不是只回报"命令跑完了"。
  if (hit?.assume !== undefined) {
    out.push(`主 agent 的假设: ${hit.assume}`)
    out.push(`若这条不成立，主 agent 会转看: ${hit.ifWrong ?? '（未指定退路）'}`)
  }
  out.push('')
  if (ctxFacts.length > 0) {
    out.push('## 已知事实（来自主 agent 台账，**可直接使用，不必重新验证**）')
    for (const f of ctxFacts) {
      out.push(`- [${f.kind}/${f.confidence}] ${f.key}${f.value !== undefined ? ` = ${f.value}` : ''}`
        + `${f.evidence !== undefined ? `　（证据 ${f.evidence}）` : ''}`)
    }
    out.push('')
  }
  out.push('## 建议加载的技能卡（按任务场景命中规则表，用 skill 工具按名加载）')
  if (capped.length > 0) for (const c of capped) out.push(`- ${c}`)
  else out.push(`（未命中规则表${error !== undefined ? `；规则表读取失败: ${error}` : `；规则表: ${rulesPath}`}）`)
  out.push('')
  out.push('## 回报格式（🔴 你**没有 loot 写权限**，结论一律以文本回报，落盘由主 agent 做）')
  out.push('1. 做了什么 —— 确切命令原文')
  out.push('2. 观察到什么 —— 原始输出片段（不要只给结论）')
  out.push('3. 结论 + 它由哪条命令的哪段输出支撑')
  out.push('4. 失败的尝试 —— 哪一步失败、失败判据是什么（供主 agent 记 dead 边）')
  out.push('')
  out.push('## 边界')
  out.push('- 不写 `loot/`、不改台账（工具层会直接拒绝）')
  out.push('- 判"这条路不通"之前先做**对照探测**（没有对照的全否不是结论）')
  out.push('- 每条事实都要能指回"哪条命令的哪段输出"；推测必须显式标为推测')
  return out.join('\n')
}

/** 在 apply() 里调用：注册 htb_fact / htb_frontier / htb_brief。返回注册函数数组。 */
export function registerStateTools(ctx, config) {
  const machineProp = { type: 'string', description: '机器名（对应 <machine>-state.jsonl）。省略则用 stateRoot 下唯一的账本' }
  const defs = [
    {
      name: 'htb_fact',
      description:
        '作战状态账本：登记/查询**事实节点**（host/service/cred/vuln/flag/note）。'
        + '与 loot/<machine>.md 的自由文本不同，这里是结构化的、可被后续查询与推理的事实集；'
        + '每条可挂 evidenceId 指回 dsh-htb-evidence 的证据（于是攻击图是可验证的）。'
        + '🔴 硬规则：cred/vuln/flag 若标 confidence=verified 则必须带 evidenceId；没证据就得显式写 inferred（推测不许伪装成事实）。'
        + '🔴 存在性校验（2026-10-21 新增）：evidenceId 必须在证据账本索引里真实存在，编一个格式正确的 id 会被拒绝。'
        + '🔴 轮次隔离（2026-10-21 新增）：同一台机器重打 / reset 后，先调 op=run-start 开新一轮；'
        + '之后 add 的记录带 run 标记，list/query 默认只看当前 run（历史 legacy 记录仍可见），传 run:"all" 看全部。'
        + '不调 run-start 时行为与之前完全一致。'
        + '与 htb_frontier（意图边）共用 loot/<machine>-state.jsonl。'
        + '🔴 边界（2026-10-17）：这里只记**这台靶机上的技术事实**。'
        + '用户偏好 / 项目约定 / 决策 / 跨会话经验属于另一个库 —— 用 engram_save 存'
        + '（engram 也有个叫 fact 的房间，但它的语义是"用户说过的事实"，'
        + '与这里的"靶机上的技术事实"不是一回事，混用会让两边都失真）。',
      parameters: paramsSpec({
        op: { type: 'string', description: 'add / run-start / list / query（默认 list）' },
        kind: { type: 'string', description: `事实类型: ${KINDS.join(' / ')}` },
        key: { type: 'string', description: 'add 必填：这条事实是什么（如 "svc_web:password"、"10.10.10.5:445"）' },
        value: { type: 'string', description: '值（如口令、hash、版本号）' },
        evidenceId: { type: 'string', description: '证据 id（ev-<12hex>，来自 evidence_add）—— 会被校验是否真实存在' },
        confidence: { type: 'string', description: 'verified（有证据，默认）/ inferred（推测）' },
        source: { type: 'string', description: '来源（如 "nmap"、"ldapsearch"、"mimikatz"）' },
        q: { type: 'string', description: 'query：关键词（在整条记录里做不区分大小写子串匹配）' },
        run: { type: 'string', description: 'run-start：轮次名（省略自动 r1/r2…）；list/query：轮次过滤，传 "all" 看全部' },
        note: { type: 'string', description: 'run-start：这一轮的说明（如 "reset 后重打"）' },
        machine: machineProp,
      }, ['op']),
      output: strOutput(),
      async execute(args) { return runFact(config, args ?? {}) },
    },
    {
      name: 'htb_frontier',
      description:
        '作战状态账本：登记/推进**意图边**（下一步打算做什么），构成 fact→intent 的攻击路径图。'
        + 'todo / doing / done / dead 四态；claim 认领、done 收尾、dead 判死。'
        + '🔴 硬规则：op=dead（判"这条路不通"）**必须带 baselineEvidenceId** —— 没有对照的全否不是结论'
        + '（与 htb_coverage 同源）；判死会永久排除一条路，所以最需要对照。该证据 id 会被校验是否真实存在。'
        + 'list 会按四态分组渲染当前 frontier（会话中断后可据此接手）；'
        + '默认只看当前 run（由 htb_fact op=run-start 开启），传 run:"all" 看全部。',
      parameters: paramsSpec({
        op: { type: 'string', description: 'add / list / claim / done / dead（默认 list）' },
        id: { type: 'string', description: 'claim/done/dead 必填：intent id（如 i1）' },
        action: { type: 'string', description: 'add 必填：要做什么（一句话）' },
        from: { type: 'string', description: 'add：前置 fact id，逗号分隔（如 "f1,f2"）—— 会校验存在性' },
        target: { type: 'string', description: '目标（host/IP/服务）' },
        retestCost: { type: 'string', description: '重测成本估计（low/medium/high）—— 用于决定先做哪条' },
        owner: { type: 'string', description: '认领者（主 agent / 子代理标识），避免重复劳动' },
        assume: { type: 'string', description: 'add：这条路径押的**假设**是什么（如"upload 目录可写"）。没有假设的 intent 无法被证伪' },
        ifWrong: { type: 'string', description: 'add：如果这个假设错了，应该去看什么（强制预留退路）' },
        budget: { type: 'number', description: 'add：预计投入多少分钟。claim 后超时会在 list 里标 ⚠️超预算' },
        reasonCode: { type: 'string', description: `dead：死因枚举（${DEAD_REASONS.join('/')}）—— 自由文本无法聚合，枚举才能统计"最常死在哪类原因"` },
        baselineEvidenceId: { type: 'string', description: 'dead 必填：对照组探测的证据 id（会校验是否真实存在）' },
        reason: { type: 'string', description: 'dead：哪一步失败、为什么这是"对照过的失败"' },
        result: { type: 'string', description: 'done：产出了什么（如 fact id）' },
        run: { type: 'string', description: 'list：轮次过滤，传 "all" 看全部（默认当前 run）' },
        machine: machineProp,
      }, ['op']),
      output: strOutput(),
      async execute(args) { return runFrontier(config, args ?? {}) },
    },
    {
      name: 'htb_brief',
      description:
        '从 frontier 的一条 intent 生成**子 agent 任务书**：任务 + 已知事实（含证据回指）'
        + '+ 建议加载的技能卡（复用 router 的 86 条"场景→卡"映射作工具提示）+ 回报格式 + 边界。'
        + '为什么要它：①ARTEMIS 证明任务书应由主 agent 之外的模块生成，既不占上下文又能给子 agent 工具提示；'
        + '②子 agent 没有 loot 写权限（工具层 deny），任务书必须写明"结论文本回报、落盘由主 agent 做"；'
        + '③内容取自结构化状态而非临时回忆。intent 可传 frontier 的 id（如 i1）或一句自然语言任务。',
      parameters: paramsSpec({
        intent: { type: 'string', description: 'frontier 的 intent id（如 i1）或一句自然语言任务（必填）' },
        facts: { type: 'string', description: '要带上的 fact id，逗号分隔；省略则用该 intent 的 from' },
        run: { type: 'string', description: '轮次过滤（默认当前 run；复盘旧轮时传 run 名，或 "all"）' },
        machine: machineProp,
      }, ['intent']),
      output: strOutput(),
      async execute(args) { return composeBrief(config, args ?? {}) },
    },
  ]
  return defs.map((def) => ctx.tools.register(def))
}

/** 供离线测试直接调用（不经 ctx.tools）。 */
export const _internal = { runFact, runFrontier, composeBrief, foldIntents, findLedger, stateRootOf }
