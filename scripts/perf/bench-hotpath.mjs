/**
 * bench-hotpath.mjs — 热路径实测
 *
 * 目标：用真实会话的工具结果序列，测出 post-execute 四个模块各自的开销，
 * 并区分"固定开销（每次调用都要付）"与"数据相关开销（随输出大小增长）"。
 *
 * 用法：node scripts/perf/bench-hotpath.mjs <session.v4.jsonl> [iterations]
 *
 * session.v4.jsonl 是 DSH 导出的会话记录（`dsh-session-*.zip` 里那个）。
 * 它只用来提供**真实的工具结果分布**（大小、错误形态），不涉及任何机器信息。
 */
import { readFileSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

const SESSION = process.argv[2]
const ITER = Number(process.argv[3] ?? 3)
if (!SESSION) {
  console.error('usage: node bench-hotpath.mjs <session.v4.jsonl> [iterations]')
  process.exit(1)
}

import { fileURLToPath } from 'node:url'
const SRC = new URL('../../src/', import.meta.url).href
const mods = {
  hygiene: await import(`${SRC}context-hygiene.js`),
  errs: await import(`${SRC}error-classify.js`),
  auto: await import(`${SRC}auto-state.js`),
  struggle: await import(`${SRC}struggle-watch.js`),
}

// ── 1. 从真实会话抽取工具结果序列 ────────────────────────────────────────
const recs = readFileSync(SESSION, 'utf-8').split('\n').filter(Boolean).map((l) => {
  try { return JSON.parse(l) } catch { return null }
}).filter(Boolean)

const calls = new Map()
for (const r of recs) {
  if (r.type === 'tool/call') calls.set(r.data?.callId, r)
}

const cases = []
for (const r of recs) {
  if (r.type !== 'tool/result') continue
  const call = calls.get(r.data?.message?.toolCallId)
  if (!call) continue
  const name = call.data?.name
  if (!['ssh_exec', 'bash', 'pwsh', 'ssh_cluster'].includes(name)) continue
  const content = r.data?.message?.content ?? []
  let chars = 0
  for (const c of content) if (c?.type === 'text') chars += (c.text ?? '').length
  let args = {}
  try { args = JSON.parse(call.data?.arguments ?? '{}') } catch { /* ignore */ }
  cases.push({
    exec: { name, arguments: args, agent: { id: 'bench' } },
    result: { content },
    chars,
  })
}
console.log(`样本：${cases.length} 条执行类结果，总字符 ${(cases.reduce((a, c) => a + c.chars, 0) / 1024).toFixed(0)} KB`)
const sizes = cases.map((c) => c.chars).sort((a, b) => a - b)
console.log(`  字符分位：p50=${sizes[sizes.length >> 1]} p90=${sizes[Math.floor(sizes.length * 0.9)]} max=${sizes[sizes.length - 1]}`)

// ── 2. 构造真实规模的 loot 目录（这是 artifactMtimeMs 的输入）──────────────
const ROOT = join(tmpdir(), `htb-bench-${Date.now()}`)
const LOOT = join(ROOT, 'loot')
mkdirSync(LOOT, { recursive: true })
const LOOT_FILES = Number(process.env.BENCH_LOOT_FILES ?? 200)
for (let i = 0; i < LOOT_FILES; i++) {
  const sub = i % 10 === 0 ? join(LOOT, `sub${i % 20}`) : LOOT
  if (sub !== LOOT) mkdirSync(sub, { recursive: true })
  writeFileSync(join(sub, `f${i}.txt`), 'x'.repeat(200))
}
console.log(`loot 目录：${LOOT_FILES} 个文件 / 20 个子目录`)

// ── 3. 单模块计时 ────────────────────────────────────────────────────────
const allow = async () => ({ kind: 'accept' })

function mountHygiene() {
  let h
  mods.hygiene.apply({ on: (e, f) => { if (e === 'tools/post-execute') h = f } },
    { logPath: join(ROOT, 'hygiene.jsonl') })
  return h
}
function mountErrs() {
  let h
  mods.errs.apply({ on: (e, f) => { if (e === 'tools/post-execute') h = f } },
    { logPath: join(ROOT, 'errors.jsonl') })
  return h
}
function mountAuto() {
  let h
  mods.auto.apply({ on: (e, f) => { if (e === 'tools/post-execute') h = f } },
    { logPath: join(ROOT, 'auto.jsonl'), stateRoot: LOOT, machine: 'Bench' })
  return h
}
function mountStruggle() {
  let h
  mods.struggle.apply({ on: (e, f) => { if (e === 'tools/post-execute') h = f } },
    { logPath: join(ROOT, 'struggle.jsonl'), artifactDir: LOOT, intervene: false, gate: false })
  return h
}

async function timeIt(label, mount) {
  const h = mount()
  // 预热（JIT + 首次 IO）
  for (let i = 0; i < Math.min(20, cases.length); i++) {
    await h(cases[i].exec, cases[i].result, allow)
  }
  const t0 = process.hrtime.bigint()
  for (let it = 0; it < ITER; it++) {
    for (const c of cases) await h(c.exec, c.result, allow)
  }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6
  const per = ms / (ITER * cases.length)
  console.log(`  ${label.padEnd(22)} ${ms.toFixed(1).padStart(8)} ms  |  ${per.toFixed(3)} ms/次`)
  return per
}

console.log('\n=== 单模块（独立挂载，各跑 ' + ITER + ' 轮）===')
const t = {}
t.hygiene = await timeIt('context-hygiene', mountHygiene)
t.errs = await timeIt('error-classify', mountErrs)
t.auto = await timeIt('auto-state', mountAuto)
t.struggle = await timeIt('struggle-watch', mountStruggle)

// ── 4. 串联（真实部署就是四个都挂）──────────────────────────────────────
const hs = { h: mountHygiene(), e: mountErrs(), a: mountAuto(), s: mountStruggle() }
async function chain(exec, result) {
  // 模拟 Cordis 的 next 链：最后是 allow
  const d4 = await hs.s(exec, result, allow)
  const d3 = await hs.a(exec, result, async () => d4)
  const d2 = await hs.e(exec, result, async () => d3)
  return hs.h(exec, result, async () => d2)
}
for (let i = 0; i < 20; i++) await chain(cases[i].exec, cases[i].result)
const c0 = process.hrtime.bigint()
for (let it = 0; it < ITER; it++) for (const c of cases) await chain(c.exec, c.result)
const cms = Number(process.hrtime.bigint() - c0) / 1e6
console.log('\n=== 四模块串联 ===')
console.log(`  ${cms.toFixed(1)} ms / ${ITER * cases.length} 次  →  ${(cms / (ITER * cases.length)).toFixed(3)} ms/次`)
console.log(`  单次调用固定开销合计：${((t.hygiene + t.errs + t.auto + t.struggle)).toFixed(3)} ms（不含框架本身）`)

// ── 5. 拆解：artifactMtimeMs 单独计时 ───────────────────────────────────
const A = 200
let s0 = process.hrtime.bigint()
for (let i = 0; i < A; i++) mods.struggle.artifactMtimeMs(LOOT)
const ams = Number(process.hrtime.bigint() - s0) / 1e6 / A
console.log('\n=== 单点拆解 ===')
console.log(`  artifactMtimeMs(loot)   ${ams.toFixed(3)} ms/次  ← 每次调用跑一次完整递归`)

// ── 6. 拆解：measure（split 计数 vs 循环计数）───────────────────────────
const big = 'x'.repeat(80) + '\n'
const bigText = big.repeat(1400)   // ≈ 113KB / 1400 行
s0 = process.hrtime.bigint()
for (let i = 0; i < A; i++) mods.hygiene.measure({ content: [{ type: 'text', text: bigText }] })
const mms = Number(process.hrtime.bigint() - s0) / 1e6 / A
console.log(`  measure(113KB 文本)      ${mms.toFixed(3)} ms/次`)

// 对照：纯循环数行
function countLines(s) {
  let n = 1
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) === 10) n++
  return n
}
s0 = process.hrtime.bigint()
for (let i = 0; i < A; i++) countLines(bigText)
const cms2 = Number(process.hrtime.bigint() - s0) / 1e6 / A
console.log(`  countLines(同文本)       ${cms2.toFixed(3)} ms/次  （split 的 ${(mms / cms2).toFixed(1)}× ）`)

rmSync(ROOT, { recursive: true, force: true })
