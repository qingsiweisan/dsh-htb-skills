#!/usr/bin/env node
/**
 * state-score.mjs — 用 baseline 给一次打靶的**事实覆盖率**打分
 *
 * 为什么需要它：这套框架改了很多机制（router 路由、状态层 L1c、证据闸），
 * 但此前**没有任何能力指标** —— 无法回答"这次改动让 agent 变强还是变弱"。
 * 本脚本把 <machine>-state.jsonl（htb_fact 的产出）与 baseline 对比，给出可比较的数字。
 *
 * 用法：
 *   node state-score.mjs Dump
 *   node state-score.mjs --all
 * 参数 / 环境：
 *   --state-root <dir>     默认 $HTB_LOOT_ROOT 或 <cwd>/loot（与插件 stateRoot 一致）
 *   --baseline-root <dir>  默认 <state-root>/_baseline
 *
 * 匹配规则：kind 相同，且 key 规范化（小写、去空白）后做**双向子串**匹配。
 *   宽松是有意的 —— agent 写的 key 是自由的（"cobbler 25151" vs "cobbler"），
 *   严格相等会把真命中判成缺失，指标随即失去意义。
 *
 * exit：0（报告型，不做闸）。
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'

function argValue(name) {
  const i = process.argv.indexOf(name)
  return i >= 0 && process.argv[i + 1] !== undefined ? process.argv[i + 1] : undefined
}
function abs(p) { return isAbsolute(p) ? p : resolve(process.cwd(), p) }

const stateRoot = abs(argValue('--state-root') ?? process.env.HTB_LOOT_ROOT ?? join(process.cwd(), 'loot'))
const baselineRoot = abs(argValue('--baseline-root') ?? join(stateRoot, '_baseline'))

function readFacts(machine) {
  const p = join(stateRoot, `${machine}-state.jsonl`)
  if (!existsSync(p)) return { path: p, facts: [] }
  const facts = []
  for (const line of readFileSync(p, 'utf-8').split('\n')) {
    const t = line.trim()
    if (t === '') continue
    try {
      const r = JSON.parse(t)
      if (r.type === 'fact') facts.push(r)
    } catch { /* 坏行跳过 */ }
  }
  return { path: p, facts }
}

const norm = (s) => String(s ?? '').toLowerCase().replace(/\s+/g, ' ').trim()
const hitKey = (a, b) => {
  const x = norm(a); const y = norm(b)
  if (x === '' || y === '') return false
  return x === y || x.includes(y) || y.includes(x)
}

function scoreOne(machine) {
  const bp = join(baselineRoot, `${machine}.json`)
  if (!existsSync(bp)) return { machine, error: `baseline 不存在: ${bp}` }
  const baseline = JSON.parse(readFileSync(bp, 'utf-8'))
  const required = Array.isArray(baseline.required) ? baseline.required : []
  const { path: sp, facts } = readFacts(machine)

  const used = new Set()
  const rows = []
  let hit = 0
  for (const req of required) {
    const found = facts.find((f, i) => !used.has(i) && f.kind === req.kind && hitKey(f.key, req.key))
    if (found !== undefined) { hit += 1; used.add(facts.indexOf(found)) }
    rows.push({ req, found })
  }
  const extra = facts.filter((_, i) => !used.has(i))
  return { machine, baseline, sp, facts, rows, hit, total: required.length, extra }
}

function render(r) {
  if (r.error !== undefined) return `⚠️ ${r.machine}: ${r.error}`
  const pct = r.total === 0 ? 0 : Math.round((r.hit / r.total) * 1000) / 10
  const out = []
  out.push(`# ${r.machine}  ${r.baseline.difficulty ?? '?'}/${r.baseline.os ?? '?'}  来源: ${r.baseline.source ?? '?'}`)
  out.push(`覆盖率 ${r.hit}/${r.total} = ${pct}%    台账: ${r.sp}（${r.facts.length} 条 fact）`)
  for (const { req, found } of r.rows) {
    const mark = found !== undefined ? '✅' : '❌'
    const detail = found !== undefined
      ? `  ← ${found.id} [${found.confidence}]${found.evidence !== undefined ? ` ${found.evidence}` : ''}`
      : '  ← 缺失'
    out.push(`  ${mark} ${String(req.kind).padEnd(8)} ${req.key}${detail}`)
  }
  if (r.extra.length > 0) {
    out.push(`  额外发现（baseline 之外，${r.extra.length} 条）:`)
    for (const e of r.extra.slice(0, 12)) out.push(`    + [${e.kind}/${e.confidence}] ${e.key}${e.value !== undefined ? ` = ${e.value}` : ''}`)
    if (r.extra.length > 12) out.push(`    … 其余 ${r.extra.length - 12} 条略`)
  }
  return out.join('\n')
}

const argv = process.argv.slice(2)
const stateRootArg = argValue('--state-root')
const baselineRootArg = argValue('--baseline-root')
// 🔴 只从真正的参数里取位置参数 —— process.argv 的前两项是 node 可执行文件与脚本路径，
//    直接在完整 argv 上 find 会把 node.exe 的路径当成 machine 名（本脚本第一版即踩此坑）。
const positional = argv.filter((a) => !a.startsWith('--') && a !== stateRootArg && a !== baselineRootArg)
const target = positional[0]
let machines = []
if (argv.includes('--all')) {
  machines = existsSync(baselineRoot)
    // 下划线开头的是模板/说明文件（_TEMPLATE.json），不是 machine —— 不排除会把它们算成"一台 0% 的机器"
    ? readdirSync(baselineRoot).filter((n) => n.endsWith('.json') && !n.startsWith('_')).map((n) => n.slice(0, -5))
    : []
  if (machines.length === 0) {
    console.log(`⚠️ ${baselineRoot} 下没有 baseline（先按 _TEMPLATE.json 建一份）`)
    process.exit(0)
  }
} else if (target !== undefined) {
  machines = [target]
} else {
  console.log('用法: node state-score.mjs <machine> | --all   [--state-root <dir>] [--baseline-root <dir>]')
  console.log(`      stateRoot  = ${stateRoot}`)
  console.log(`      baselineRoot = ${baselineRoot}`)
  process.exit(0)
}

const results = machines.map(scoreOne)
for (const r of results) console.log(render(r) + '\n')
const scored = results.filter((r) => r.error === undefined)
if (scored.length > 0) {
  const h = scored.reduce((s, r) => s + r.hit, 0)
  const t = scored.reduce((s, r) => s + r.total, 0)
  const x = scored.reduce((s, r) => s + r.extra.length, 0)
  console.log(`合计: ${scored.length} 台  覆盖率 ${h}/${t} = ${t === 0 ? 0 : Math.round((h / t) * 1000) / 10}%  baseline 之外共 ${x} 条发现`)
}
process.exit(0)
