#!/usr/bin/env node
/**
 * router-rules-test.mjs — dsh-htb-router 规则表的回归闸
 *
 * 为什么需要它：规则表是后加入的组件，此前**没有任何闸覆盖**，而 2026-10-17 实测
 * 暴露的两类缺陷都只能靠人工发现，必须变成闸：
 *   ① **悬空卡引用** —— 规则指向不存在的卡 ⇒ loadCardBody 返回 undefined ⇒ 整条规则
 *      什么都不注入（静默死掉，连提示都没有）。
 *   ② **顶层短词无词边界** —— `etw` 命中 `network`、`PtH` 命中 `depth`、
 *      `getst` 命中 `getstatus`：任意普通英文文本都被判成某个攻击阶段。
 *
 * 契约（与 framework-check.mjs 的其余闸一致）：exit 0 = 通过；任何 FAIL 一律 exit 1。
 * 环境变量覆盖：HTB_ROUTER_PATCH / HTB_SKILLS_ROOT。
 */
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { parseRouterRules } from '../src/state-tools.js'

const ROUTER_PATCH = process.env.HTB_ROUTER_PATCH ?? join(homedir(), 'dsh-htb-router', 'cordis.patch.yml')
const SKILLS_ROOT = process.env.HTB_SKILLS_ROOT ?? join(homedir(), '.dsh', 'skills')

const fails = []
const ok = []

if (!existsSync(ROUTER_PATCH)) {
  console.log(`SKIP  规则表不存在: ${ROUTER_PATCH}`)
  process.exit(0)
}
const text = readFileSync(ROUTER_PATCH, 'utf-8')
const rules = parseRouterRules(text)
ok.push(`规则表解析 ${rules.length} 条`)

// ── 1) 正则全部可编译 ──────────────────────────────────────────────────────
const badRe = []
for (const r of rules) {
  try { new RegExp(r.pattern, 'i') } catch (error) { badRe.push(`${r.id}: ${error.message}`) }
}
if (badRe.length > 0) fails.push(`正则可编译: ${badRe.length} 条坏规则 —— ${badRe.join('; ')}`)
else ok.push(`正则可编译 ${rules.length}/${rules.length}`)

// ── 2) 卡引用完整性（悬空 = 整条规则静默失效）───────────────────────────────
const refs = [...new Set(rules.flatMap((r) => r.cards ?? []))]
if (!existsSync(SKILLS_ROOT)) {
  ok.push(`卡引用 ${refs.length} 张（卡库不存在，跳过校验）`)
} else {
  const missing = refs.filter((c) => !existsSync(join(SKILLS_ROOT, c, 'SKILL.md')))
  if (missing.length > 0) fails.push(`卡引用: 悬空 ${missing.length} 张 —— ${missing.join(', ')}（这些规则会静默失效）`)
  else ok.push(`卡引用 ${refs.length} 张全部落地`)
}

// ── 3) 死规则：既无 cards 又无 note ⇒ 命中后什么都不会发生 ──────────────────
const dead = rules.filter((r) => (r.cards ?? []).length === 0 && r.hasNote !== true)
if (dead.length > 0) fails.push(`死规则（无 cards 且无 note）: ${dead.map((r) => r.id).join(', ')}`)
else ok.push('死规则 0')

// ── 4) 短词假阳性回归（行为级，不依赖实现细节）────────────────────────────
// 这三个词是 2026-10-17 实测修掉的；它们藏在普通英文词内部时**不得**命中。
const WORD_TRAPS = [
  ['network', 'edr'], ['networking', 'edr'], ['networked', 'edr'],
  ['depth', 'ad-lateral'], ['max_depth', 'ad-lateral'],
  ['getstatus', 'ad-advanced'], ['getstatus', 'impacket-tools'],
]
const regressed = []
for (const [word, ruleId] of WORD_TRAPS) {
  const rule = rules.find((r) => r.id === ruleId)
  if (rule === undefined) continue
  try { if (new RegExp(rule.pattern, 'i').test(word)) regressed.push(`${word}→${ruleId}`) } catch { /* 已在 1) 报 */ }
}
if (regressed.length > 0) fails.push(`短词假阳性回归: ${regressed.join(', ')}`)
else ok.push(`短词假阳性回归 0（${WORD_TRAPS.length} 组对照）`)

// ── 5) 真信号不得因加边界而丢失（防"为了修假阳性把功能改死"）────────────────
const MUST_HIT = [
  ['ntlmrelayx', 'ad-entry'], ['ntlmrelayx', 'ad-advanced'],
  ['s4u2self', 'ad-advanced'], ['getST.py', 'impacket-tools'],
  ['mssqlclient', 'mssql'], ['etw', 'edr'], ['PtH', 'ad-lateral'],
  ['Get-Command chisel', 'tunneling'], ['sudo -l', 'linux-privesc'],
]
const lost = []
for (const [text, ruleId] of MUST_HIT) {
  const rule = rules.find((r) => r.id === ruleId)
  if (rule === undefined) { lost.push(`${ruleId}(规则缺失)`); continue }
  try { if (!new RegExp(rule.pattern, 'i').test(text)) lost.push(`${text}→${ruleId}`) } catch { /* 已在 1) 报 */ }
}
if (lost.length > 0) fails.push(`真信号丢失: ${lost.join(', ')}`)
else ok.push(`真信号保留 ${MUST_HIT.length}/${MUST_HIT.length}`)

// ── 6) 顶层短分支清单（提示性，不失败）──────────────────────────────────
// 该不该加 \b 需要判断：`ntlm` 加边界会漏掉 `ntlmrelayx`（那更糟），
// 所以这里只列清单供人工审查，不自动判定。
const risky = []
for (const r of rules) {
  if (typeof r.pattern !== 'string') continue
  let depth = 0
  let cur = ''
  const parts = []
  for (const ch of r.pattern) {
    if (ch === '(') depth += 1
    if (ch === ')') depth -= 1
    if (ch === '|' && depth === 0) { parts.push(cur); cur = '' } else cur += ch
  }
  parts.push(cur)
  for (const p of parts) {
    const t = p.trim()
    if (/^[A-Za-z][A-Za-z0-9_]{0,4}$/.test(t)) risky.push(`${r.id}:${t}`)
  }
}
ok.push(`顶层短分支 ${risky.length} 个（提示，需人工确认能否被普通英文词包含）`)

// ── 7) 状态驱动规则（stateRules）结构校验（2026-10-17 新增）────────────────
// 它是把路由从"猜"变"知道"的入口。结构写错的失效方式与"悬空卡引用"同类 ——
// **静默**：谓词拼错 ⇒ 条件恒真 ⇒ 每次都误注入；缺 when ⇒ 同上。
const STATE_PREDICATES = ['hasFactKind', 'minFacts', 'noIntentMatching', 'intentStatus']
const srIdx = text.indexOf('\n        stateRules:')
if (srIdx >= 0) {
  const seg = text.slice(srIdx, srIdx + 6000)
  const cut = seg.slice(1).search(/\n {8}[a-zA-Z]/)
  const body = cut < 0 ? seg : seg.slice(0, cut + 1)
  const ids = [...body.matchAll(/^\s+- id: (\S+)/gm)].map((m) => m[1])
  const whens = (body.match(/^\s+when:/gm) ?? []).length
  const cards = (body.match(/^\s+cards:/gm) ?? []).length
  const keys = new Set([...body.matchAll(/^\s{14}([a-zA-Z]+):/gm)].map((m) => m[1]))
  const unknown = [...keys].filter((k) => !STATE_PREDICATES.includes(k))
  if (ids.length === 0) fails.push('stateRules: 段存在但解析不到条目')
  else if (whens < ids.length) fails.push(`stateRules: ${ids.length} 条里只有 ${whens} 条有 when（缺 when = 条件恒真 ⇒ 误触发）`)
  else if (cards < ids.length) fails.push(`stateRules: ${ids.length} 条里只有 ${cards} 条有 cards（无卡可注入）`)
  else if (unknown.length > 0) fails.push(`stateRules: 未知谓词 ${unknown.join(', ')}（拼错 = 条件恒真 ⇒ 静默误触发）`)
  else ok.push(`状态驱动规则 ${ids.length} 条（${ids.join(', ')}），谓词全部已知`)
}

// ── 结论 ───────────────────────────────────────────────────────────────────
for (const line of ok) console.log(`  ok   ${line}`)
for (const line of fails) console.log(`  FAIL ${line}`)
console.log(fails.length === 0
  ? `router-rules-test: PASS（${rules.length} 条规则）`
  : `router-rules-test: FAIL（${fails.length} 项）`)
process.exit(fails.length === 0 ? 0 : 1)
