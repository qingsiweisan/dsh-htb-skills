// P0-1 验证：干预通道（agent/pre-step 注入 stop 通知）。
import { writeFileSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const m = await import('file:///C:/Users/Administrator/dsh-htb-skills/src/struggle-watch.js')
const log = join(tmpdir(), 'sw-p1-test.jsonl')
try { unlinkSync(log) } catch { /* 首次 */ }
writeFileSync(log, '', 'utf8')

let failed = 0
const check = (name, cond, extra = '') => {
  if (cond) console.log(`  ✓ ${name}`)
  else { failed += 1; console.log(`  ✗ ${name} ${extra}`) }
}

// ---- 干预开启：maxHours=0 让 budget 立刻触发 ----
const handlers = {}
m.apply({ on: (n, f) => { handlers[n] = f } }, {
  logPath: log,
  artifactDir: 'C:/definitely-not-a-real-dir-20261010',
  intervene: true,
  thresholds: { maxHours: 0 },
})

check('注册了 agent/pre-step（干预通道）', typeof handlers['agent/pre-step'] === 'function', Object.keys(handlers).join(','))
check('仍注册 tools/post-execute（观测）', typeof handlers['tools/post-execute'] === 'function')

const call = (id) => handlers['tools/post-execute'](
  { name: 'read', arguments: { x: 1 }, agent: { id } }, { isError: false }, async () => {},
)
const step = async (id, messages = []) => handlers['agent/pre-step'](
  { agent: { id }, messages: [], turn: 1, step: 1 }, async () => ({ kind: 'enter', messages }),
)

await call('A')                       // 第一次：elapsed=0，不触发
await new Promise((r) => setTimeout(r, 30))
await call('A')                       // 第二次：elapsed>0 且 maxHours=0 ⇒ budget ⇒ stop

const d1 = await step('A')
check('stop 后 pre-step 注入 1 条', d1.messages.length === 1, JSON.stringify(d1.messages.length))
if (d1.messages.length === 1) {
  const msg = d1.messages[0]
  console.log('    role =', msg.role, ' source =', JSON.stringify(msg.source))
  check('role = user', msg.role === 'user')
  check("source.kind = 'struggle-watch'（自定义 kind，非假冒 user）", msg.source?.kind === 'struggle-watch', JSON.stringify(msg.source))
  check("source.form = 'notice'", msg.source?.form === 'notice')
  check('summary 存在且 ≤120 字', typeof msg.source?.summary === 'string' && msg.source.summary.length <= 120, msg.source?.summary)
  check('content 是 text block', msg.content?.[0]?.type === 'text' && typeof msg.content[0].text === 'string')
  check('正文含停止协议要点', /停止协议/.test(msg.content[0].text) && /subagent/.test(msg.content[0].text))
}

const d2 = await step('A')
check('第二次 pre-step 不再注入（一次性）', d2.messages.length === 0, JSON.stringify(d2.messages.length))

const dOther = await step('B')
check('未触发的 agent 不受影响（按 agent 定向）', dOther.messages.length === 0, JSON.stringify(dOther.messages.length))

const dReject = await handlers['agent/pre-step']({ agent: { id: 'C' } }, async () => ({ kind: 'reject' }))
check('决策为 reject 时原样返回', dReject.kind === 'reject')

// ---- 干预关闭 ----
const h2 = {}
m.apply({ on: (n, f) => { h2[n] = f } }, {
  logPath: log, artifactDir: 'C:/nope-2', intervene: false, thresholds: { maxHours: 0 },
})
check('intervene:false → 不注册 agent/pre-step', h2['agent/pre-step'] === undefined, Object.keys(h2).join(','))

console.log(failed === 0 ? '\n✅ P0-1 干预通道全部通过' : `\n❌ ${failed} 条失败`)
process.exit(failed === 0 ? 0 : 1)
