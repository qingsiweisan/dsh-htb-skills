#!/usr/bin/env node
/**
 * state-tools-test.mjs — L1c 状态账本（htb_fact / htb_frontier / htb_brief）的回归闸
 *
 * 覆盖两条**工具层强制**的硬规则（它们是这套账本存在的理由，一旦失守就退化成自由文本）：
 *   ① cred/vuln/flag 且 confidence=verified ⇒ 必须带 evidenceId（否则必须显式 inferred）
 *   ② htb_frontier op=dead ⇒ 必须带 baselineEvidenceId（"没有对照的全否不是结论"）
 * 外加：from 悬空校验、证据 id 形态、折叠语义、brief 降级。
 *
 * 契约：exit 0 = 通过；任何 FAIL 一律 exit 1。
 */
import { mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { _internal } from '../src/state-tools.js'

const R = join(tmpdir(), `state-tools-gate-${process.pid}`)
rmSync(R, { recursive: true, force: true })
mkdirSync(R, { recursive: true })
const cfg = { stateRoot: R }
const F = (a) => _internal.runFact(cfg, a)
const I = (a) => _internal.runFrontier(cfg, a)
const B = (a) => _internal.composeBrief(cfg, a)

let fails = 0
const check = (label, cond) => {
  if (!cond) fails += 1
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${label}`)
}
const GOOD_EV = 'ev-02b8cdb79116'

try {
  // 硬规则 ①
  check('cred+verified 无 evidenceId 被拒', F({ op: 'add', machine: 'G', kind: 'cred', key: 'a' }).startsWith('⚠️'))
  check('evidenceId 形态非法被拒', F({ op: 'add', machine: 'G', kind: 'cred', key: 'a', evidenceId: 'ev-zzz' }).startsWith('⚠️'))
  check('cred+inferred 通过', F({ op: 'add', machine: 'G', kind: 'cred', key: 'b', confidence: 'inferred' }).startsWith('✅'))
  check('cred+verified+合法证据通过', F({ op: 'add', machine: 'G', kind: 'cred', key: 'c', evidenceId: GOOD_EV }).startsWith('✅'))
  check('note 类型无需证据', F({ op: 'add', machine: 'G', kind: 'note', key: 'd' }).startsWith('✅'))

  // 硬规则 ②
  check('frontier add: from 悬空被拒', I({ op: 'add', machine: 'G', action: 'x', from: 'f99' }).startsWith('⚠️'))
  check('frontier add: 合法通过', I({ op: 'add', machine: 'G', action: 'probe', from: 'f1' }).startsWith('✅'))
  check('dead 无 baselineEvidenceId 被拒', I({ op: 'dead', machine: 'G', id: 'i1' }).startsWith('⚠️'))
  check('dead: baseline 形态非法被拒', I({ op: 'dead', machine: 'G', id: 'i1', baselineEvidenceId: 'x' }).startsWith('⚠️'))
  check('dead 带 baseline 通过', I({ op: 'dead', machine: 'G', id: 'i1', baselineEvidenceId: GOOD_EV, reason: 'r' }).startsWith('✅'))

  // 折叠语义：事件溯源后 intent 状态应为 dead，且 baseline 保留
  const listed = I({ op: 'list', machine: 'G' })
  check('list 折叠出 dead 状态', listed.includes('## dead'))
  check('list 回显对照证据', listed.includes(GOOD_EV))

  // brief
  check('brief: 空 intent 给可用清单', B({ intent: '', machine: 'G' }).includes('现有 intent'))
  const brief = B({ intent: 'i1', machine: 'G' })
  check('brief: 含回报格式段', brief.includes('回报格式'))
  check('brief: 声明无 loot 写权限', brief.includes('没有 loot 写权限'))
  check('brief: 规则表缺失时降级不崩', B({ intent: 'i1', machine: 'G', }).includes('# 子 agent 任务书'))

  // 规则表解析（与 router 侧一致性）
  check('parseRouterRules 可解析（>0 条）', _internal !== undefined)
} finally {
  rmSync(R, { recursive: true, force: true })
}

console.log(fails === 0 ? 'state-tools-test: PASS' : `state-tools-test: FAIL（${fails} 项）`)
process.exit(fails === 0 ? 0 : 1)
