/**
 * machine-tools-test.mjs — 7 个生命周期工具的回归闸
 *
 * 全程打本地 mock server，不触线上。
 *
 * 重点覆盖三件"猜错过"的事：
 *   ① `machine/paginated` 只返回 active（retired 参数被静默忽略）—— 输出里必须写明
 *   ② `spawn` 的响应**不含 IP**，必须轮询 —— 用例让 mock 前 2 次返回 ip:null
 *   ③ `terminate` 不接受 machine_id，按当前活跃实例操作
 *
 * 外加：401 给刷新命令、user/info 不含 email、reset 429 的提示。
 */

import { createServer } from 'node:http'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, lifeLeft } from '../src/machine-tools.js'

let failed = 0
const check = (name, ok, extra = '') => {
  if (ok) console.log(`  ✓ ${name}`)
  else { failed += 1; console.log(`  ✗ ${name} ${extra}`) }
}

// ── mock 状态 ───────────────────────────────────────────────────────────
let activeInfo = null          // machine/active 返回的 info
let spawnPolls = 0             // spawn 后第几次查询才给 IP
let resetStatus = 200
const seen = []

const MACHINES = [
  { id: 999, name: 'DutyBound', os: 'Linux', difficulty: 47, difficultyText: 'Medium', authUserInUserOwns: true, authUserInRootOwns: true },
  { id: 784, name: 'Atlas', os: 'Windows', difficulty: 82, difficultyText: 'Hard', authUserInUserOwns: false, authUserInRootOwns: false },
]

const json = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(body))
}

const server = createServer((req, res) => {
  let body = ''
  req.on('data', (c) => { body += c })
  req.on('end', () => {
    seen.push({ method: req.method, url: req.url, body })
    if (req.headers.authorization !== 'Bearer good-token') {
      json(res, 401, { message: 'Unauthenticated.' }); return
    }
    const u = new URL(req.url, 'http://x')
    const p = u.pathname

    if (p === '/api/v4/machine/paginated') {
      const kw = (u.searchParams.get('keyword') ?? '').toLowerCase()
      const rows = MACHINES.filter((m) => kw === '' || m.name.toLowerCase().includes(kw))
      json(res, 200, { data: rows, meta: { total: rows.length, current_page: 1 } }); return
    }
    if (p.startsWith('/api/v4/machine/profile/')) {
      const key = decodeURIComponent(p.split('/').pop())
      const m = MACHINES.find((x) => String(x.id) === key || x.name.toLowerCase() === key.toLowerCase())
      if (!m) { json(res, 404, { message: 'No results for this machine' }); return }
      json(res, 200, { info: { ...m, retired: true, active: false, release: '2025-10-23T14:00:00.000Z', ip: null, playInfo: { isSpawning: false, expires_at: null } } })
      return
    }
    if (p === '/api/v4/machine/active') {
      if (activeInfo === null) { json(res, 200, { info: null }); return }
      // spawn 轮询：前 N 次返回 ip:null，模拟真实启动延迟
      if (activeInfo.isSpawning === true) {
        spawnPolls += 1
        if (spawnPolls > 2) {
          activeInfo = { ...activeInfo, isSpawning: false, ip: '10.129.238.8' }
        }
      }
      json(res, 200, { info: activeInfo }); return
    }
    if (p === '/api/v4/vm/spawn') {
      const { machine_id: id } = JSON.parse(body || '{}')
      if (!id) { json(res, 422, { message: 'The machine id field is required.', errors: { machine_id: ['required'] } }); return }
      const m = MACHINES.find((x) => x.id === id)
      if (!m) { json(res, 404, { message: 'No results for this machine' }); return }
      spawnPolls = 0
      activeInfo = { id, name: m.name, ip: null, isSpawning: true, expires_at: '2099-01-01 00:00:00', vpn_server_id: 695, lab_server: 'dedivip_lab' }
      json(res, 200, { message: 'Machine deployed to lab.', success: true }); return
    }
    if (p === '/api/v4/vm/terminate') {
      if (activeInfo === null) { json(res, 404, { message: 'Active instance not found' }); return }
      activeInfo = null
      json(res, 200, { message: 'Machine terminated.' }); return
    }
    if (p === '/api/v4/vm/reset') {
      if (resetStatus !== 200) { json(res, resetStatus, { message: 'Too many requests' }); return }
      json(res, 200, { message: 'Machine reset submitted.' }); return
    }
    if (p === '/api/v4/user/info') {
      json(res, 200, { info: { id: 1, name: 'qingsi', email: 'secret@example.com', identifier: 'SECRETID', rank_id: 5, subscriptionType: 'pro', isVip: false, isServerVIP: true, server_id: 695, team: null } })
      return
    }
    json(res, 404, { message: 'nope' })
  })
})
await new Promise((r) => server.listen(0, '127.0.0.1', r))
const baseUrl = `http://127.0.0.1:${server.address().port}`

// ── 挂载 ────────────────────────────────────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), 'mtools-'))
const tokenPath = join(dir, 'token.txt')
writeFileSync(tokenPath, 'good-token\n')

const tools = new Map()
apply({ tools: { register: (t) => tools.set(t.name, t) } },
  { baseUrl, tokenPath, spawnPollMs: 10, spawnTimeoutSec: 5 })
const call = (name, args = {}) => tools.get(name).execute(args)

console.log('注册')
check('注册 7 个工具', tools.size === 7, [...tools.keys()].join(','))
for (const n of ['htb_machine_list', 'htb_machine_info', 'htb_machine_spawn', 'htb_machine_status', 'htb_machine_stop', 'htb_machine_reset', 'htb_user_info']) {
  check(`  含 ${n}`, tools.has(n))
}

console.log('\nhtb_machine_list')
{
  const all = await call('htb_machine_list')
  check('列出 2 台', all.includes('DutyBound') && all.includes('Atlas'))
  check('标出已 own', all.includes('user+root'))
  check('提示只含 active', all.includes('retired') || all.includes('active'))
  const kw = await call('htb_machine_list', { keyword: 'atlas' })
  check('keyword 过滤生效', kw.includes('Atlas') && !kw.includes('DutyBound'), kw.slice(0, 80))
  const miss = await call('htb_machine_list', { keyword: 'zzz' })
  check('无匹配时指向 htb_machine_info', miss.includes('htb_machine_info'))
}

console.log('\nhtb_machine_info')
{
  const byName = await call('htb_machine_info', { machine: 'atlas' })   // 小写
  check('名字大小写不敏感', byName.includes('Atlas') && byName.includes('784'), byName.slice(0, 60))
  check('显示 retired', byName.includes('retired'))
  check('显示未 own', byName.includes('user —'))
  const byId = await call('htb_machine_info', { machine: '784' })
  check('id 直传也能查', byId.includes('Atlas'))
  const bad = await call('htb_machine_info', { machine: 'NoSuchBox' })
  check('不存在的机器给 404 提示', bad.includes('404'), bad.slice(0, 60))
  const noArg = await call('htb_machine_info', {})
  check('缺参数给提示', noArg.includes('需要 machine'))
}

console.log('\nhtb_machine_status / spawn / stop')
{
  const empty = await call('htb_machine_status')
  check('无活跃机器', empty.includes('没有活跃机器'))

  const sp = await call('htb_machine_spawn', { machine: 'Atlas' })
  check('spawn 等到 IP', sp.includes('10.129.238.8'), sp.slice(0, 80))
  check('spawn 显示轮询次数', sp.includes('轮询'), sp.slice(0, 120))
  check('spawn 给了 nmap 下一步', sp.includes('nmap'))
  check('确实轮询了 >2 次', spawnPolls > 2, `polls=${spawnPolls}`)

  const st = await call('htb_machine_status')
  check('status 显示 IP', st.includes('10.129.238.8'))
  check('status 显示剩余时间', st.includes('剩余'))

  const sp2 = await call('htb_machine_spawn', { machine: 'DutyBound' })
  check('已有活跃机器时拒绝', sp2.includes('已有活跃机器'), sp2.slice(0, 60))

  const stop = await call('htb_machine_stop')
  check('stop 成功', stop.includes('✅'), stop.slice(0, 60))
  const stop2 = await call('htb_machine_stop')
  check('再 stop 给 404 说明', stop2.includes('404') && stop2.includes('无需释放'), stop2.slice(0, 70))
}

console.log('\nhtb_machine_reset')
{
  activeInfo = { id: 784, name: 'Atlas', ip: '10.0.0.1', isSpawning: false, expires_at: '2099-01-01 00:00:00' }
  const ok = await call('htb_machine_reset', {})
  check('省略 machine 用当前活跃', ok.includes('✅') && ok.includes('784'), ok.slice(0, 60))
  check('提示冷却', ok.includes('冷却'))
  resetStatus = 429
  const rl = await call('htb_machine_reset', { machine: 'Atlas' })
  check('429 给限流提示', rl.includes('429'), rl.slice(0, 60))
  resetStatus = 200
  activeInfo = null
  const none = await call('htb_machine_reset', {})
  check('无活跃且无参数给提示', none.includes('没有活跃机器'))
}

console.log('\nhtb_user_info')
{
  const u = await call('htb_user_info')
  check('显示用户名与排名', u.includes('qingsi') && u.includes('5'))
  check('显示订阅', u.includes('pro'))
  check('🔴 不含 email', !u.includes('secret@example.com') && !u.includes('@'))
  check('🔴 不含 identifier', !u.includes('SECRETID'))
}

console.log('\n401 处理')
{
  writeFileSync(tokenPath, 'bad\n')
  const r = await call('htb_machine_status')
  check('401 给刷新命令', r.includes('htb-token-refresh'), r.slice(0, 80))
  writeFileSync(tokenPath, 'good-token\n')
}

console.log('\nlifeLeft')
{
  check('null → —', lifeLeft(null) === '—')
  check('过期', lifeLeft('2000-01-01 00:00:00') === '已过期')
  const future = new Date(Date.now() + 90 * 60000).toISOString().replace('T', ' ').slice(0, 19)
  check('90 分钟 → 1h 30m', lifeLeft(future).startsWith('1h'), lifeLeft(future))
}

server.close()
rmSync(dir, { recursive: true, force: true })
console.log(failed === 0 ? '\nmachine-tools-test: PASS' : `\nmachine-tools-test: FAIL (${failed})`)
process.exit(failed === 0 ? 0 : 1)
