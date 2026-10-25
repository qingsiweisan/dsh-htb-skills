/**
 * 内容级双闸（落地 J4 · loot/_audit/J4-contentgate.md §2/§3/§4）
 *
 *   闸 B 卡内自相矛盾
 *     B1  frontmatter `description` 的族上界 > 正文 limit，且 fm 内没有承认该 limit
 *     B3  正文内存在「更大上界 vs 更小 limit」且该上界没有被归属/和解
 *     BC  第三方锚点：卡内 ESC 最大编号 <= audit_routing.py 的显式常量 ESC_MAX
 *         （读法：精确读 ESC_ALIASES 编号集合 + ESC_MAX 声明，并校验二者一致；
 *          **不再**对 audit_routing.py 做全文正则 —— 旧写法与那份 DANGLING-REF
 *          豁免名单隐式耦合，清理白名单会把 BC 弄红）
 *
 *   闸 A 跨卡边界一致性
 *     A1（主判据，会失败） subject = (族, domain, 模态)，组内 >=2 张卡且 >=2 个不同上界 → WARN
 *     A2（低优先第二路，仅 INFO） subject = (族) 全局 —— 按 D2 保留输出、不触发失败
 *
 * 口径要点（照 J4 收紧，勿放宽）：
 *   · PLUS 号必须**紧邻**数字 —— 否则 `htb-workflow:337`「ESC3 + adminCount」误报
 *   · external-doc 模态排除 —— `hacktricks-url-index:33`「ADCS 全系（ESC1-8）」是外链文档范围
 *   · 不建端口/版本/年份族（J4 §2.6 已实测判否）；族白名单 + 自动晋级（>=2 条 range 且跨 >=2 卡）
 *   · 闸 A 只比**覆盖上界**（range/plus）；limit 是范围自限、不是覆盖声称（J4 口径下 limit 会让
 *     同一句「certipy 覆盖 ESC1-16+ / 本卡分节止于 ESC14」自己撞自己）
 *
 * 只读 ~/.dsh/skills。有 WARN → exit 1（framework-check.mjs:51-55 契约）。
 * 收编方式：framework-check.mjs:29 自动收集 scripts/ 下 /test.*\.mjs$/ —— 本文件即第 17 道闸，零改动接入。
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs'
import path from 'node:path'

const SKILLS_DIR = 'C:/Users/Administrator/.dsh/skills'
const AUDIT_PY = 'C:/Users/Administrator/dsh-htb-skills/scripts/audit_routing.py'

const FAMILIES = ['ESC', 'MS', 'CVE', 'CWE', 'KB']

const RANGE = /\b([A-Z]{2,5})\s?(\d{1,3})\s*(?:[-–—~]|至|到|to)\s*(?:\1\s?)?(\d{1,3})\b/gi
const PLUS = /\b([A-Z]{2,5})\s?(\d{1,3})\+(?!\s*[A-Za-z\u4e00-\u9fff])/g // `+` 必须紧邻数字（J4 §2.5）
const LIMIT = /(止于|止步|仅到|只到|上限|不超过|覆盖到|截至|不含|不涉及|本卡不|未覆盖|up to|through)\s*[^。\n]{0,24}?\b([A-Z]{2,5})\s?(\d{1,3})/g
const LIMIT2 = /\b([A-Z]{2,5})\s?(\d{1,3})\s*[^。\n]{0,12}?(为止|以上|封顶)/g

const MOD = [
  [/hacktricks|https?:\/\/|\.html|\/wiki\/|官方文档|官网|参考文档|upstream|外链/i, 'external-doc'],
  [/certipy|已覆盖|工具|支持到|版本/, 'tool'],
  [/本卡|本节|本表|分节|§|止于|止步|仅|只到|上限|不涉及/, 'self-scope'],
  [/→|阶段|流程/i, 'pointer'],
]
const modality = (line) => MOD.find(([rx]) => rx.test(line))?.[1] ?? 'unknown'
const isCoverage = (kind) => kind === 'range' || kind === 'plus'
// B3 和解标记：同一行同时给出「工具归属」与「本库/本卡范围」才算把两个数说清
const TOOL_ATTR = /certipy|已覆盖|工具|支持到/
const SCOPE_ACK = /本卡|本节|本表|分节|本库|范围|止于|上限/

function parseCard(name, text) {
  const lines = text.split('\n')
  let bodyStart = 0
  if (lines[0]?.trim() === '---') {
    for (let i = 1; i < lines.length; i++) if (lines[i].trim() === '---') { bodyStart = i + 1; break }
  }
  const head = text.slice(0, 4000)
  return {
    name,
    lines,
    bodyStart,
    domain: /domain:\s*([A-Za-z0-9_-]+)/.exec(head)?.[1] ?? '?',
  }
}

function claimsOf(card) {
  const out = []
  const push = (line, i, family, value, kind) => {
    if (!FAMILIES.includes(family)) return
    out.push({
      card: card.name, domain: card.domain, line: i,
      src: i <= card.bodyStart ? 'fm' : 'body',
      family, value, kind, modality: modality(line), text: line,
    })
  }
  card.lines.forEach((line, idx) => {
    const i = idx + 1
    for (const m of line.matchAll(RANGE)) push(line, i, m[1].toUpperCase(), Math.max(+m[2], +m[3]), 'range')
    for (const m of line.matchAll(PLUS)) push(line, i, m[1].toUpperCase(), +m[2], 'plus')
    for (const m of line.matchAll(LIMIT)) push(line, i, m[2].toUpperCase(), +m[3], 'limit')
    for (const m of line.matchAll(LIMIT2)) push(line, i, m[1].toUpperCase(), +m[2], 'limit2')
  })
  return out
}

// 族自动晋级：一个族要到「>=2 条覆盖声称 且 跨 >=2 张卡」才参与比对（J4 §2.1）
function activeFamilies(claims) {
  const per = new Map()
  for (const c of claims.filter((c) => isCoverage(c.kind))) {
    if (!per.has(c.family)) per.set(c.family, new Set())
    per.get(c.family).add(c.card)
  }
  return [...per.entries()].filter(([, cards]) => cards.size >= 2).map(([f]) => f)
}

// 闸 A1：subject = (族, domain, 模态)，比每张卡的覆盖上界
function gateA(claims, fams) {
  const groups = new Map()
  for (const c of claims) {
    if (!isCoverage(c.kind) || !fams.includes(c.family) || c.modality === 'external-doc') continue
    const key = `${c.family}|${c.domain}|${c.modality}`
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(c)
  }
  const hits = []
  for (const [key, list] of groups) {
    const perCard = new Map()
    for (const c of list) perCard.set(c.card, Math.max(perCard.get(c.card) ?? 0, c.value))
    if (perCard.size < 2) continue
    const bounds = [...new Set(perCard.values())].sort((a, b) => a - b)
    if (bounds.length < 2) continue
    hits.push({ key, bounds, cards: [...perCard.keys()].sort(), list })
  }
  return hits.sort((a, b) => a.key.localeCompare(b.key))
}

// 闸 A2（低优先第二路）：subject = (族) 全局，只报不判
function gateA2(claims, fams) {
  const per = new Map()
  for (const c of claims) {
    if (!isCoverage(c.kind) || !fams.includes(c.family) || c.modality === 'external-doc') continue
    if (!per.has(c.family)) per.set(c.family, [])
    per.get(c.family).push(c)
  }
  const out = []
  for (const [family, list] of per) {
    // 第二路刻意用「逐条声称」的取值（J4 §2.4 V0 口径）：它要看的是卡内/卡间的全部取值分布，
    // 主判据 A1 才用「每张卡 max」（J4 §2.3）。
    const bounds = [...new Set(list.map((c) => c.value))].sort((a, b) => a - b)
    out.push({ family, bounds, cards: [...new Set(list.map((c) => c.card))].sort(), diverges: bounds.length >= 2 })
  }
  return out.sort((a, b) => a.family.localeCompare(b.family))
}

// 闸 B1 + B3
function gateB(cards, claims, fams) {
  const b1 = []
  const b3 = []
  for (const card of cards) {
    const mine = claims.filter((c) => c.card === card.name)
    for (const family of fams) {
      const descCov = mine.filter((c) => c.src === 'fm' && c.family === family && isCoverage(c.kind) && c.modality !== 'external-doc')
      const bodyLim = mine.filter((c) => c.src === 'body' && c.family === family && !isCoverage(c.kind))
      const fmLim = mine.filter((c) => c.src === 'fm' && c.family === family && !isCoverage(c.kind))
      // B1：desc 的上界必须被 fm 自己承认（否则「自称 vs 自限」矛盾）
      if (descCov.length && bodyLim.length) {
        const descMax = Math.max(...descCov.map((c) => c.value))
        const bodyMax = Math.max(...bodyLim.map((c) => c.value))
        const acknowledged = fmLim.some((c) => c.value === bodyMax)
        if (descMax > bodyMax && !acknowledged)
          b1.push({ card: card.name, family, descMax, bodyMax, at: bodyLim[0].line })
      }
      // B3：正文内部「更大上界 vs 更小 limit」
      if (!bodyLim.length) continue
      const L = Math.max(...bodyLim.map((c) => c.value))
      for (const c of mine.filter((x) => x.src === 'body' && x.family === family && isCoverage(x.kind))) {
        if (c.value <= L) continue
        if (c.modality === 'external-doc' || c.modality === 'pointer') continue
        const sameLineAck = mine.some((x) => x.line === c.line && !isCoverage(x.kind) && x.value === L)
        const reconciled = sameLineAck || (TOOL_ATTR.test(c.text) && SCOPE_ACK.test(c.text))
        // 同一行可能同时命中 range 与 plus（ESC1-16 与 ESC16+）→ 按 (卡, 行, 值) 去重
        const key = `${card.name}|${c.line}|${family}${c.value}`
        if (!reconciled && !b3.some((h) => h.key === key))
          b3.push({ key, card: card.name, family, value: c.value, limit: L, at: c.line, limitAt: bodyLim[0].line, text: c.text.trim().slice(0, 70) })
      }
    }
  }
  return { b1, b3 }
}

// 闸 BC：卡内最大 ESC 编号 <= audit_routing.py **声明的 ESC 上界**（J4 §3.4）
//
// 🔴 锚点必须是显式常量，不是全文正则。
//    旧实现 `[...py.matchAll(/\besc(\d+)\b/gi)]` 从整份 audit_routing.py 抓 esc 编号：
//    于是 BC 实际读的是"这份文件里出现过的最大 esc 数字"，与 WHITELIST_WHY
//    （DANGLING-REF 的豁免名单）**隐式耦合** —— 清理白名单会顺手把 BC 弄红（实测发生过）。
//    现在只读两行显式常量：ESC_ALIASES（编号集合）+ ESC_MAX（声明的上界），并校验
//    `ESC_MAX === max(ESC_ALIASES)`。文件不存在 / 常量缺失 / 格式变了 ⇒ 报 FAIL 并说清
//    原因（**绝不静默取 0**，否则闸会退化成"永远绿"）。
const ESC_BLOCK = /^ESC_ALIASES\s*=\s*frozenset\(\(\n([\s\S]*?)^\)\)/m
const ESC_DECL = /^ESC_MAX\s*=\s*(\d+)\b.*$/m

function parseEscAnchor(src) {
  const blk = ESC_BLOCK.exec(src)
  if (!blk) return { err: '找不到 ESC_ALIASES = frozenset(( … )) 常量块（解析契约见该常量上方注释）' }
  // 与 Python 语义一致：`#` 之后是注释，不构成集合成员 —— 不剥掉就会重蹈"注释变条目"。
  const body = blk[1].replace(/#[^\n]*/g, '')
  const nums = [...body.matchAll(/'esc(\d+)'/g)].map((m) => +m[1])
  if (!nums.length) return { err: "ESC_ALIASES 块内没有任何 'esc<N>' 字面量（集合被清空？）" }
  const aliasMax = Math.max(...nums)
  const decl = ESC_DECL.exec(src)
  if (!decl) return { err: '找不到整数常量 ESC_MAX = <int>（BC 的上界声明，别删）', aliasMax }
  const escMax = +decl[1]
  if (escMax !== aliasMax)
    return { err: `ESC_MAX=${escMax} 与 ESC_ALIASES 的最大编号 ${aliasMax} 不一致（单一真源被破坏）`, aliasMax, escMax }
  return { aliasMax, escMax, count: nums.length }
}

function gateAnchor(claims) {
  const esc = claims.filter((c) => c.family === 'ESC').map((c) => c.value)
  if (!esc.length) return null
  const cardMax = Math.max(...esc)
  if (!existsSync(AUDIT_PY)) return { cardMax, aliasMax: null, bad: true, err: `锚点文件不存在：${AUDIT_PY}` }
  const a = parseEscAnchor(readFileSync(AUDIT_PY, 'utf8'))
  if (a.err) return { cardMax, aliasMax: a.aliasMax ?? null, escMax: a.escMax ?? null, bad: true, err: a.err }
  return { cardMax, aliasMax: a.aliasMax, bad: cardMax > a.aliasMax }
}

// —— 反例自检（防止本闸退化成「永远绿」）——
function selfTest() {
  const fm = (desc, body) => `---\nname: 'fx'\ndescription: '${desc}'\nmetadata: { domain: ad-win, tier: T2 }\n---\n${body}\n`
  const cl = (text, name = 'fx') => claimsOf(parseCard(name, text))
  const bf = (text, fams = ['ESC']) => gateB([parseCard('fx', text)], cl(text), fams)
  const PY_SANE = "ESC_ALIASES = frozenset((\n    'esc1', 'esc2',\n    'esc16',\n))\nESC_MAX = 16\n"
  const cases = [
    ['B1 抓 desc 上界 vs 正文 limit', () => bf(fm('ADCS：certipy find→ESC1-16+', '本卡分节止于 ESC14')).b1.length === 1],
    ['D1(a) 句式（desc 承认 14）不报', () => {
      const r = bf(fm('certipy 覆盖 ESC1-16+；本库分节止于 ESC14', 'certipy 覆盖 ESC1-16+；本库分节止于 ESC14'))
      return r.b1.length === 0 && r.b3.length === 0
    }],
    ['B3 抓正文内 16+ vs limit 14', () => bf(fm('x', 'Certipy 已覆盖 ESC1–ESC16+\n本卡分节止于 ESC14')).b3.length === 1],
    ['PLUS 不误吃 ESC3 + adminCount', () => !cl(fm('x', '特权账户 — ESC3 + adminCount 解保护')).some((c) => c.kind === 'plus')],
    ['external-doc 模态被排除', () => gateA(cl(fm('x', '| ADCS 全系（ESC1-8） | hacktricks ad-cs |')), ['ESC']).length === 0],
    ['闸 A 抓同域同模态跨卡分歧', () => gateA([
      ...cl(fm('x', 'certipy find -vulnerable → ESC1-13'), 'fxa'),
      ...cl(fm('x', 'certipy 覆盖 ESC1-16+'), 'fxb'),
    ], ['ESC']).length === 1],
    ['更小自限不报（8 <= 14）', () => bf(fm('x', '本卡 §8 ADCS ESC1-8\n本卡分节止于 ESC14')).b3.length === 0],
    // —— BC 锚点读取器（防它退化成"找不到就取 0/永远绿"）——
    ['BC 锚点精确读出 16', () => parseEscAnchor(PY_SANE).aliasMax === 16],
    ['BC 锚点：ESC_MAX 与集合不一致 → 报错', () => !!parseEscAnchor(PY_SANE.replace('ESC_MAX = 16', 'ESC_MAX = 13')).err],
    ['BC 锚点：常量缺失 → 报错（不静默取 0）', () => !!parseEscAnchor('WHITELIST = {}\n').err],
    ['BC 锚点：块内注释里的编号不算成员', () => parseEscAnchor(
      "ESC_ALIASES = frozenset((\n    'esc1',\n    # 曾讨论过 esc99\n))\nESC_MAX = 1\n").aliasMax === 1],
  ]
  const failed = cases.filter(([, fn]) => { try { return !fn() } catch { return true } }).map(([n]) => n)
  return { total: cases.length, failed }
}

// —— 主流程 ——
const cards = []
for (const d of readdirSync(SKILLS_DIR).sort()) {
  const p = path.join(SKILLS_DIR, d, 'SKILL.md')
  if (!existsSync(p)) continue
  cards.push(parseCard(d, readFileSync(p, 'utf8')))
}
const claims = cards.flatMap((c) => claimsOf(c))
const fams = activeFamilies(claims)
const A = gateA(claims, fams)
const A2 = gateA2(claims, fams)
const B = gateB(cards, claims, fams)
const BC = gateAnchor(claims)
const st = selfTest()

const warn = []
if (st.failed.length) warn.push(`self-test 反例未触发：${st.failed.join(' / ')}`)
for (const h of A) warn.push(`BOUNDARY-A ${h.key} bounds=[${h.bounds}] ← ${h.cards.join(', ')}`)
for (const h of B.b1) warn.push(`BOUNDARY-B1 ${h.card} desc=${h.family}${h.descMax} > body-limit ${h.family}${h.bodyMax} (:${h.at})`)
for (const h of B.b3) warn.push(`BOUNDARY-B3 ${h.card}:${h.at} ${h.family}${h.value} > limit ${h.family}${h.limit}(:${h.limitAt}) :: ${h.text}`)
if (BC?.bad) warn.push(BC.err
  ? `BOUNDARY-BC 锚点不可用：${BC.err}（卡内最大 ESC${BC.cardMax}`
    + `${BC.escMax != null ? ` vs 声明上界 ESC_MAX=${BC.escMax} — 已越界` : ''} ⇒ 无法判定/越界，按 FAIL 处理，不静默放行）`
  : `BOUNDARY-BC 卡内最大 ESC${BC.cardMax} > audit_routing.py 声明的上界 ESC_MAX=${BC.aliasMax} → 需补审计锚点`)

console.log(`CONTENT-GATE 内容级双闸（只读 ${SKILLS_DIR}）`)
console.log(`  库：${cards.length} 卡 · 边界声称 ${claims.length} 条 · 晋级族 [${fams.join(', ')}] · self-test ${st.total - st.failed.length}/${st.total}`)
for (const line of A2) console.log(`  INFO (低优先第二路 family-global) ${line.family} bounds=[${line.bounds}] ← ${line.cards.length} 卡：${line.cards.join(', ')}（不判失败，供人眼复核）`)
for (const w of warn) console.log(`  ⚠ ${w}`)
console.log(`BOUNDARY-A: ${A.length} groups · BOUNDARY-B: B1=${B.b1.length} B3=${B.b3.length} · BOUNDARY-BC: ${BC?.err ? 'ERR(anchor)' : BC?.bad ? 'STALE' : `ok(${BC?.aliasMax})`}`)
console.log(warn.length ? `CONTENT-GATE: ${warn.length} warnings → FAIL` : 'CONTENT-GATE: 0 warnings → PASS')
process.exit(warn.length ? 1 : 0)
