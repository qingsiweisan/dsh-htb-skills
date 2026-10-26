/**
 * machine-own-test.mjs — flag 提交工具 + 完成前交付检查
 *
 * 契约：
 *   ① 提交走 `POST /api/v5/machine/own`，body 是 `{id, flag}`
 *   ② 成功后往账本写 `flag-own` 记录
 *   ③ goal 闸：有 flag fact 且无 own 记录 → **拦第一次**，第二次放行
 *   ④ 无 flag fact（不是打靶任务）→ 不拦
 *   ⑤ 已有 own 记录 → 不拦
 *   ⑥ 401 给出可执行的刷新命令
 *
 * 全程打本地 mock server，不触线上。
 */

import { createServer } from 'node:http'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, OWN_PATH } from '../src/machine-own.js'

let failed = 0
const check = (name, ok, extra = '') => {
  if (ok) console.log(`  ✓ ${name}`)
  else { failed += 1; console.log(`  ✗ ${name} ${extra}`) }
}

// ── mock server ─────────────────────────────────────────────────────────
const seen = []
const server = createServer((req, res) => {
  let body = ''
  req.on('data', (c) => { body += c })
  req.on('end', () => {
    seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, body })
    if (req.url !== OWN_PATH) { res.writeHead(404); res.end('{"message":"nope"}'); return }
    if (req.headers.authorization !== 'Bearer good-token') {
      res.writeHead(401); res.end('{"message":"Unauthenticated."}'); return
    }
    let parsed = {}
    try { parsed = JSON.parse(body) } catch { /* ignore */ }
    if (parsed.flag === 'bad-flag') {
      res.writeHead(422); res.end('{"message":"Incorrect flag","success":false}'); return
    }
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({
      message: 'Atlas root is now owned.',
      id: parsed.id, own_type: 'root', success: true, status: 200,
    }))
  })
})
await new Promise((r) => server.listen(0, '127.0.0.1', r))
const baseUrl = `http://127.0.0.1:${server.address().port}`

// ── 环境 ────────────────────────────────────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), 'mown-'))
const tokenPath = join(dir, 'token.txt')
writeFileSync(tokenPath, 'good-token\n')
const stateRoot = join(dir, 'loot')
mkdirSync(stateRoot, { recursive: true })

const tools = new Map()
const guards = []
const ctx = {
  tools: {
    register: (t) => { tools.set(t.name, t) },
    guard: (fn) => { guards.push(fn); return () => {} },
  },
}
apply(ctx, { baseUrl, tokenPath, stateRoot })

console.log('注册与调用')
check('注册了 htb_machine_own', tools.has('htb_machine_own'))
check('注册了 1 道 goal 闸', guards.length === 1)

const own = tools.get('htb_machine_own')
const okRes = await own.execute({ machine_id: '784', flag: '41d9053fbb52ba8616412c375a124fcf' })
check('提交成功返回 ✅', String(okRes).startsWith('✅'), String(okRes).slice(0, 70))
check('打到正确端点', seen[0]?.url === OWN_PATH, seen[0]?.url)
check('body 含 id 与 flag', JSON.parse(seen[0]?.body ?? '{}').id === 784)
check('带 Bearer 头', seen[0]?.auth === 'Bearer good-token')

// 账本记录
const ledger = join(stateRoot, 'unknown-state.jsonl')
const rows = readFileSync(ledger, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
check('账本写了 flag-own', rows.some((r) => r.type === 'flag-own'))
check('记录 own_type', rows.find((r) => r.type === 'flag-own')?.own_type === 'root')

// 失败路径
const badRes = await own.execute({ machine_id: '784', flag: 'bad-flag' })
check('flag 错误返回 ❌', String(badRes).includes('未通过'), String(badRes).slice(0, 60))

writeFileSync(tokenPath, 'expired\n')
const authRes = await own.execute({ machine_id: '784', flag: 'x' })
check('401 给出刷新命令', String(authRes).includes('htb-token-refresh'), String(authRes).slice(0, 60))
writeFileSync(tokenPath, 'good-token\n')

// ── goal 闸 ─────────────────────────────────────────────────────────────
console.log('\ngoal 闸')
const guard = guards[0]
const complete = { name: 'update_goal', arguments: { action: 'complete', goal_id: 'g1' } }

// 已提交过 → 放行
check('已有 own 记录 → 放行', guard(complete) === undefined)

// 换一个没有 own 记录的场景
const dir2 = mkdtempSync(join(tmpdir(), 'mown2-'))
const root2 = join(dir2, 'loot')
mkdirSync(root2, { recursive: true })
writeFileSync(join(root2, 'Atlas-state.jsonl'), JSON.stringify({
  ts: new Date().toISOString(), type: 'fact', id: 'f1', kind: 'flag', key: 'root.txt',
  value: '41d9053fbb52ba8616412c375a124fcf', confidence: 'verified',
}) + '\n')
const guards2 = []
apply({ tools: { register: () => {}, guard: (fn) => { guards2.push(fn); return () => {} } } },
  { baseUrl, tokenPath, stateRoot: root2 })
const g2 = guards2[0]

const first = g2({ name: 'update_goal', arguments: { action: 'complete', goal_id: 'g2' } })
check('有 flag 未提交 → 拦', typeof first === 'string' && first.includes('没有提交'), String(first).slice(0, 60))
check('拒绝理由给出提交命令', typeof first === 'string' && first.includes('htb_machine_own'))
const second = g2({ name: 'update_goal', arguments: { action: 'complete', goal_id: 'g2' } })
check('第二次放行（不死锁）', second === undefined)

// 无 flag fact → 不拦
const dir3 = mkdtempSync(join(tmpdir(), 'mown3-'))
const root3 = join(dir3, 'loot')
mkdirSync(root3, { recursive: true })
writeFileSync(join(root3, 'X-state.jsonl'), JSON.stringify({
  ts: new Date().toISOString(), type: 'fact', id: 'f1', kind: 'service', key: '445', value: 'smb',
}) + '\n')
const guards3 = []
apply({ tools: { register: () => {}, guard: (fn) => { guards3.push(fn); return () => {} } } },
  { baseUrl, tokenPath, stateRoot: root3 })
check('无 flag fact → 不拦', guards3[0]({ name: 'update_goal', arguments: { action: 'complete', goal_id: 'g3' } }) === undefined)

// 非 complete 动作不拦
check('action=block 不拦', guards3[0]({ name: 'update_goal', arguments: { action: 'block', goal_id: 'g3' } }) === undefined)
// 非 update_goal 工具不拦
check('其他工具不拦', guards3[0]({ name: 'bash', arguments: {} }) === undefined)

server.close()
for (const d of [dir, dir2, dir3]) rmSync(d, { recursive: true, force: true })
console.log(failed === 0 ? '\nmachine-own-test: PASS' : `\nmachine-own-test: FAIL (${failed})`)
process.exit(failed === 0 ? 0 : 1)
