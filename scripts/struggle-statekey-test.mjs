// P0-4 验证：状态键从 agent 对象改为 agent.id 字符串。
// 旧实现（WeakMap 按对象）在"同 id、不同对象"时会重置状态；
// 新实现必须复用同一状态 ⇒ 第二次调用的 toolCalls 应为 2（不是 1）。
import { writeFileSync, readFileSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const m = await import('file:///C:/Users/Administrator/dsh-htb-skills/src/struggle-watch.js')
const log = join(tmpdir(), 'sw-key-test.jsonl')
try { unlinkSync(log) } catch { /* 首次运行没有文件 */ }
writeFileSync(log, '', 'utf8')

const handlers = {}
m.apply({ on: (name, fn) => { handlers[name] = fn } }, {
  logPath: log,
  artifactDir: 'C:/definitely-not-a-real-dir-20261010',
})

const call = async (agentObject) => {
  await handlers['tools/post-execute'](
    { name: 'read', arguments: { file_path: 'x' }, agent: agentObject },
    { isError: false },
    async () => {},
  )
}

// 同一个 id，两个**不同的对象** —— 模拟插件重载 / 会话恢复。
await call({ id: 'agent-same-id' })
await call({ id: 'agent-same-id' })
// 另一个 id，用来确认互不串台。
await call({ id: 'agent-other-id' })

const rows = readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
console.log('行数 =', rows.length)
for (const r of rows) {
  console.log(`  agent=${r.agent}  segment=${r.segment}  toolCalls=${r.toolCalls}  hits=${JSON.stringify(r.hits)}  sessionStartedAt=${r.sessionStartedAt ? 'ok' : 'MISSING'}`)
}
const same = rows.filter((r) => r.agent === 'agent-same-id')
const okReuse = same.length === 2 && same[1].toolCalls === 2 && same[1].segment === 1
const okOther = rows[2].toolCalls === 1 && rows[2].segment === 1
const okStartedAt = rows.every((r) => typeof r.sessionStartedAt === 'string')
console.log(`\n同 id 不同对象复用同一状态（toolCalls 1→2，segment 保持 1）: ${okReuse ? '✅' : '❌ ' + JSON.stringify(same.map((r) => [r.segment, r.toolCalls]))}`)
console.log(`不同 id 不串台（各自 toolCalls=1 / segment=1）            : ${okOther ? '✅' : '❌'}`)
console.log(`每行自带 cutoff（sessionStartedAt）                      : ${okStartedAt ? '✅' : '❌'}`)
process.exit(okReuse && okOther && okStartedAt ? 0 : 1)
