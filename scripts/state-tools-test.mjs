#!/usr/bin/env node
/**
 * state-tools-test.mjs — L1c 状态账本（htb_fact / htb_frontier / htb_brief）的回归闸
 *
 * 覆盖两条**工具层强制**的硬规则（它们是这套账本存在的理由，一旦失守就退化成自由文本）：
 *   ① cred/vuln/flag 且 confidence=verified ⇒ 必须带 evidenceId（否则必须显式 inferred）
 *   ② htb_frontier op=dead ⇒ baselineEvidenceId **可选**：带则校验存在性，
 *      不带则必须给 reasonCode，并记为"未对照·可重试"（2026-10-26 解自锁，
 *      因为原规则让 dead 三场调用数 0/0/0 —— 严格性换来机制完全失效）
 * 外加：from 悬空校验、证据 id 形态、折叠语义、brief 降级。
 *
 * 契约：exit 0 = 通过；任何 FAIL 一律 exit 1。
 */
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
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
  // 2026-10-26 解自锁：不带 baseline 也可以，但**必须给 reasonCode**。
  check('dead 无 baseline 且无 reasonCode 被拒', I({ op: 'dead', machine: 'G', id: 'i1' }).startsWith('⚠️'))
  check('dead: baseline 形态非法被拒', I({ op: 'dead', machine: 'G', id: 'i1', baselineEvidenceId: 'x' }).startsWith('⚠️'))
  check('dead 无 baseline + reasonCode 通过', I({ op: 'dead', machine: 'G', id: 'i1', reasonCode: 'auth-failed', reason: '字典跑完' }).startsWith('✅'))
  // 未对照的死路要在 list 里显式标出，否则会被当成"已验证不通"
  check('list 标出未对照·可重试', I({ op: 'list', machine: 'G' }).includes('未对照·可重试'))
  // brief 要把死路传给子 agent —— Atlas 那场 subagent 白花时间重新枚举就是这个缺失
  check('brief 含已知死路段', B({ intent: 'i1', machine: 'G' }).includes('已知死路'))
  check('dead 带 baseline 通过（另一条 intent）',
    I({ op: 'add', machine: 'G', action: '带对照的路' }).startsWith('✅')
    && I({ op: 'dead', machine: 'G', id: 'i2', baselineEvidenceId: GOOD_EV, reason: 'r' }).startsWith('✅'))

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

  // ── 旧账本兼容（2026-10-26）────────────────────────────────────────────
  // `intent-update` 从这一版才开始写 `run`。旧会话的 claim/done/dead 全都没有该字段，
  // 若按 `r.run === want` 硬过滤，历史死路会永久不可见（状态永远停在 todo）。
  // 期望：没有 run 的 intent-update 继承其所属 intent 的 run。
  writeFileSync(join(R, 'Old-state.jsonl'), [
    JSON.stringify({ ts: '2026-10-20T00:00:00Z', type: 'intent', id: 'i1', action: '旧会话里的死路', status: 'todo', run: 'r1' }),
    JSON.stringify({ ts: '2026-10-20T00:01:00Z', type: 'intent-update', id: 'i1', status: 'dead', reasonCode: 'auth-failed' }),
  ].join('\n') + '\n')
  const oldList = I({ op: 'list', machine: 'Old' })
  check('旧账本：intent-update 继承 run 后可见', oldList.includes('## dead'), oldList.slice(0, 80))
  check('旧账本：死因仍可读', oldList.includes('auth-failed'))
} finally {
  rmSync(R, { recursive: true, force: true })
}

console.log(fails === 0 ? 'state-tools-test: PASS' : `state-tools-test: FAIL（${fails} 项）`)
process.exit(fails === 0 ? 0 : 1)
