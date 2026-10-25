#!/usr/bin/env node
/**
 * state-assume-test.mjs — 「假设 / 预算 / 死因 / 换层」四件事的回归闸（2026-10-21 新增）
 *
 * 动机：老手的优势不是知道更多，而是「知道什么时候停止相信当前假设」。
 * 这四项是把那句话变成结构的尝试：
 *   assume/ifWrong —— 假设写成文本才可能被证伪
 *   budget         —— 没有预算的方向不会自己到期
 *   reasonCode     —— 死因枚举才能聚合出"最常死在哪类原因"
 *   换层提示        —— 连续判死不是方法不够，可能是层选错
 *
 * 契约：exit 0 = 通过；任何 FAIL 一律 exit 1。
 */
import { appendFileSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { _internal } from '../src/state-tools.js'

const R = join(tmpdir(), `state-assume-gate-${process.pid}`)
rmSync(R, { recursive: true, force: true })
mkdirSync(R, { recursive: true })
const cfg = { stateRoot: R }
const F = (a) => _internal.runFact(cfg, a)
const I = (a) => _internal.runFrontier(cfg, a)
const ledger = join(R, 'BoxA-state.jsonl')

let fails = 0
const check = (label, cond) => {
  if (!cond) fails += 1
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${label}`)
}

// ── ① add 的假设三件套 ────────────────────────────────────────────────────
const a1 = I({ op: 'add', machine: 'BoxA', action: '打 upload 功能', assume: 'upload 目录可写', ifWrong: '转向 SMB 匿名', budget: 30 })
check('add 带假设成功', a1.startsWith('✅'))

const l1 = I({ op: 'list', machine: 'BoxA' })
check('list 回显假设', l1.includes('假设: upload 目录可写'))
check('list 回显退路', l1.includes('若错则看: 转向 SMB 匿名'))

// 不带假设时给出提示（但不阻断）
const a2 = I({ op: 'add', machine: 'BoxA', action: '随便试试' })
check('无假设仍可 add（不阻断）', a2.startsWith('✅'))
check('无假设时提示无法证伪', a2.includes('没有假设的 intent 无法被证伪'))
check('无预算时提示不会到期', a2.includes('没有预算的方向不会自己到期'))

// ── ② claim 记 claimedAt，list 显示已投入与超预算 ────────────────────────
I({ op: 'claim', machine: 'BoxA', id: 'i1' })
const l2 = I({ op: 'list', machine: 'BoxA' })
check('claim 后显示计时', /⏱\d+\/30min/.test(l2))

// 构造一条 60 分钟前 claim 的记录，验证超预算标记
const old = new Date(Date.now() - 60 * 60 * 1000).toISOString()
appendFileSync(ledger, `${JSON.stringify({
  ts: old, type: 'intent', id: 'i3', action: '老方向', from: [], status: 'todo', budget: 20,
})}\n`)
appendFileSync(ledger, `${JSON.stringify({
  ts: old, type: 'intent-update', id: 'i3', status: 'doing', claimedAt: old,
})}\n`)
const l3 = I({ op: 'list', machine: 'BoxA' })
check('超预算被标出', l3.includes('⚠️超预算'))
check('超预算显示实际/预算', /⏱6\d\/20min/.test(l3))

// ── ③ dead 的 reasonCode ────────────────────────────────────────────────
const d1 = I({ op: 'dead', machine: 'BoxA', id: 'i2', baselineEvidenceId: 'ev-aaaaaaaaaaaa', reason: '试了三次', reasonCode: 'auth-failed' })
check('dead 带 reasonCode 成功', d1.startsWith('✅'))
const l4 = I({ op: 'list', machine: 'BoxA' })
check('list 显示死因枚举', l4.includes('[auth-failed]'))

const d2 = I({ op: 'dead', machine: 'BoxA', id: 'i3', baselineEvidenceId: 'ev-aaaaaaaaaaaa', reason: '没写枚举' })
check('无 reasonCode 仍可 dead（不阻断）', d2.startsWith('✅'))
check('无 reasonCode 时提示无法聚合', d2.includes('自由文本无法聚合'))

// ── ④ 连续判死触发换层提示 ──────────────────────────────────────────────
I({ op: 'add', machine: 'BoxA', action: '第三条路', target: '10.10.11.5' })
I({ op: 'dead', machine: 'BoxA', id: 'i4', baselineEvidenceId: 'ev-aaaaaaaaaaaa', reason: 'x', reasonCode: 'blocked' })
const d3 = I({ op: 'dead', machine: 'BoxA', id: 'i1', baselineEvidenceId: 'ev-aaaaaaaaaaaa', reason: 'y', reasonCode: 'no-path' })
check('连续判死触发换层检查', d3.includes('换层检查'))
check('换层清单含五层', d3.includes('服务层') && d3.includes('网络层'))

// ── ⑤ 向后兼容：旧记录（无新字段）照常渲染 ──────────────────────────────
const l5 = I({ op: 'list', machine: 'BoxA' })
check('旧记录不崩', l5.includes('随便试试'))
check('旧记录不显示假设行', !l5.includes('假设: undefined'))

rmSync(R, { recursive: true, force: true })
console.log(fails === 0 ? 'state-assume-test: PASS' : `state-assume-test: ${fails} FAIL`)
process.exit(fails === 0 ? 0 : 1)
