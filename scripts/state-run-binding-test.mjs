#!/usr/bin/env node
/**
 * state-run-binding-test.mjs — 轮次隔离 + 证据存在性校验的回归闸（2026-10-21 新增）
 *
 * 覆盖两件事，都是"可行性复审"里点名的缺陷：
 *   ① 轮次隔离：reset / 重打后，旧 run 的 fact 与 dead intent 不得混进当前 frontier。
 *      同时必须保证**不调 run-start 时行为与改动前完全一致**（向后兼容）。
 *   ② 证据存在性：evidenceId 形态合法但账本索引里没有 ⇒ 必须拒绝；
 *      账本本身不可读（未装 evidence）⇒ 放行但警告，不能锁死台账。
 *
 * 契约：exit 0 = 通过；任何 FAIL 一律 exit 1。
 */
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { _internal } from '../src/state-tools.js'

const R = join(tmpdir(), `state-run-gate-${process.pid}`)
rmSync(R, { recursive: true, force: true })
mkdirSync(R, { recursive: true })
const cfg = { stateRoot: R }
const F = (a) => _internal.runFact(cfg, a)
const I = (a) => _internal.runFrontier(cfg, a)

let fails = 0
const check = (label, cond) => {
  if (!cond) fails += 1
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${label}`)
}

// ── ① 向后兼容：从未 run-start 时，行为与改动前一致 ──────────────────────
const legacy = F({ op: 'add', machine: 'BoxA', kind: 'host', key: '10.10.11.5', confidence: 'inferred' })
check('无 run-start 时 add 正常', legacy.startsWith('✅'))
const legacyList = F({ op: 'list', machine: 'BoxA' })
check('无 run-start 时 list 可见', legacyList.includes('10.10.11.5'))
check('无 run-start 时不显示 run 标注', !legacyList.includes('[run='))

// ── ② 开新轮次：新记录带 run，默认读取只看本 run ────────────────────────
const start1 = F({ op: 'run-start', machine: 'BoxA', run: 'first', note: '初打' })
check('run-start 成功', start1.includes('run=first'))
const f1 = F({ op: 'add', machine: 'BoxA', kind: 'cred', key: 'svc_web:pw', confidence: 'inferred' })
check('run=first 下 add 带 run 回显', f1.includes('run=first'))

// 开轮次后，开轮次**之前**的 legacy 记录不再默认显示 —— 这是 N2 修复的核心
const afterStart = F({ op: 'list', machine: 'BoxA' })
check('开轮次后 legacy 记录不再默认显示', !afterStart.includes('10.10.11.5'))
const onlyLegacy = F({ op: 'list', machine: 'BoxA', run: 'legacy' })
check('run=legacy 只看未归属记录', onlyLegacy.includes('10.10.11.5') && !onlyLegacy.includes('svc_web:pw'))
const allAfter = F({ op: 'list', machine: 'BoxA', run: 'all' })
check('run=all 仍能看到 legacy', allAfter.includes('10.10.11.5'))

// 本轮就登记一条 intent，用于稍后验证 frontier 的轮次隔离
I({ op: 'add', machine: 'BoxA', action: '初打的路径' })

F({ op: 'run-start', machine: 'BoxA', run: 'second', note: 'reset 后重打' })
F({ op: 'add', machine: 'BoxA', kind: 'cred', key: 'svc_smb:pw', confidence: 'inferred' })
const cur = F({ op: 'list', machine: 'BoxA' })
check('当前 run 可见本轮 fact', cur.includes('svc_smb:pw'))
check('当前 run 不显示上一轮 fact', !cur.includes('svc_web:pw'))
check('当前 run 标注正确', cur.includes('[run=second]'))

// 本轮再登记一条 intent，供稍后的 dead 证据校验使用（i1 属于上一轮，本轮不可改）
I({ op: 'add', machine: 'BoxA', action: '本轮的路径' })

const all = F({ op: 'list', machine: 'BoxA', run: 'all' })
check('run=all 能看到两轮', all.includes('svc_smb:pw') && all.includes('svc_web:pw'))
const back = F({ op: 'list', machine: 'BoxA', run: 'first' })
check('显式指定旧 run 可回看', back.includes('svc_web:pw') && !back.includes('svc_smb:pw'))

// ── ③ 隔离要覆盖 frontier：上一轮登记的 intent 不得出现在本轮 ────────────
const frontierSecond = I({ op: 'list', machine: 'BoxA' })
check('frontier 默认只看当前 run', !frontierSecond.includes('初打的路径'))
const frontierAll = I({ op: 'list', machine: 'BoxA', run: 'all' })
check('frontier run=all 可见历史', frontierAll.includes('初打的路径'))

// ── ④ 证据存在性：编造的 id 必须被拒 ────────────────────────────────────
const ledger = join(R, '.evidence-ledger')
mkdirSync(ledger, { recursive: true })
const REAL = 'ev-aaaaaaaaaaaa'
const FAKE = 'ev-bbbbbbbbbbbb'
writeFileSync(join(ledger, 'index.jsonl'),
  `${JSON.stringify({ id: REAL, hash: 'x', title: 't', origin: 'o', capturedAt: 'now', bytes: 1 })}\n`, 'utf8')

const okEv = F({ op: 'add', machine: 'BoxA', kind: 'cred', key: 'real-ev', evidenceId: REAL, confidence: 'verified' })
check('真实存在的 evidenceId 通过', okEv.startsWith('✅'))

const fakeEv = F({ op: 'add', machine: 'BoxA', kind: 'cred', key: 'fake-ev', evidenceId: FAKE, confidence: 'verified' })
check('编造的 evidenceId 被拒', fakeEv.includes('不存在'))
check('拒绝理由指向索引路径', fakeEv.includes('index.jsonl'))
check('拒绝理由给 inferred 出路', fakeEv.includes('inferred'))

const fakeDead = I({ op: 'dead', machine: 'BoxA', id: 'i2', baselineEvidenceId: FAKE, reason: 'x' })
check('编造的 baselineEvidenceId 被拒', fakeDead.includes('不存在'))

// ── ⑤ 账本不可读时放行但警告（不能因为没装 evidence 锁死台账）───────────
const R2 = join(tmpdir(), `state-run-gate-noleg-${process.pid}`)
rmSync(R2, { recursive: true, force: true })
mkdirSync(R2, { recursive: true })
const cfg2 = { stateRoot: R2 }
const noLedger = _internal.runFact(cfg2, {
  op: 'add', machine: 'BoxB', kind: 'cred', key: 'no-ledger', evidenceId: FAKE, confidence: 'verified',
})
check('账本缺失时仍放行（不锁死）', noLedger.startsWith('✅'))
check('账本缺失时给出未核实警告', noLedger.includes('存在性未核实'))

rmSync(R, { recursive: true, force: true })
rmSync(R2, { recursive: true, force: true })

console.log(fails === 0 ? 'state-run-binding-test: PASS' : `state-run-binding-test: ${fails} FAIL`)
process.exit(fails === 0 ? 0 : 1)
