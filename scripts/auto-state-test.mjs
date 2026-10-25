#!/usr/bin/env node
/**
 * auto-state-test.mjs — 战线自动采集的回归闸（2026-10-25 新增）
 *
 * 这个模块的契约有四条：
 *   ① 推断不出战线时**不猜**（保持当前战线，不切换、不提醒）
 *   ② 切换摘要只在上一条战线"够长"时给（默认 ≥8 次调用），避免一次性命令触发
 *   ③ 写进账本的记录**不含命令原文** —— 命令里可能有 payload 与凭据
 *   ④ **永远不改变工具是否成功**，只在 content 末尾追加文字；且不覆盖别的模块的追加
 *
 * 契约：exit 0 = 通过；任何 FAIL 一律 exit 1。
 */
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, inferFront, labelOf, buildSwitchNotice, FRONTS, EXEC_TOOLS } from '../src/auto-state.js'

const R = join(tmpdir(), `auto-state-gate-${process.pid}`)
rmSync(R, { recursive: true, force: true })
mkdirSync(R, { recursive: true })

let fails = 0
const check = (label, cond) => {
  if (!cond) fails += 1
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${label}`)
}

// ── ① inferFront：能认出来的 ─────────────────────────────────────────────
const CASES = [
  ['recon', 'nmap -p- --min-rate 2500 10.10.11.5'],
  ['recon', 'ffuf -u https://x/FUZZ -w list.txt'],
  ['web', 'curl -sk https://airsnacks.htb/browse'],
  ['web', 'python3 -c "import urllib.request"'],
  ['db', 'psql -h 127.0.0.1 -U app'],
  ['graphical', 'xdpyinfo -display :0'],
  ['creds', 'hashcat -m 16500 jwt.txt rockyou.txt'],
  ['host', 'sudo -l'],
]
for (const [want, cmd] of CASES) {
  check(`inferFront ${want}: ${cmd.slice(0, 28)}`, inferFront(cmd) === want)
}

// 推断不出就不猜
check('inferFront 空串 → null', inferFront('') === null)
check('inferFront 非字符串 → null', inferFront(null) === null)
check('inferFront 通用解释器 → null', inferFront("python3 - <<'PY'\nprint(1)\nPY") === null)
check('inferFront 普通命令 → null', inferFront('ls -la /tmp') === null)

// 顺序：侦察优先于 Web（curl 也可能出现在 nmap 后）
check('recon 优先于 web', inferFront('nmap -sV x && curl http://x') === 'recon')

check('labelOf 已知', labelOf('graphical') === '图形会话')
check('labelOf 未知原样返回', labelOf('weird') === 'weird')
check('FRONTS 覆盖六类', FRONTS.length === 6)

// ── ② buildSwitchNotice ─────────────────────────────────────────────────
const notice = buildSwitchNotice('recon', { calls: 18, facts: 1, enteredAt: Date.now() - 12 * 60_000 }, 'web', Date.now())
check('摘要含上一战线名', notice.includes('侦察'))
check('摘要含调用次数', notice.includes('18 次调用'))
check('摘要含事实数', notice.includes('1 条事实'))
check('摘要含停留时长', notice.includes('12 分钟'))
check('摘要含目标战线', notice.includes('Web'))
check('摘要要求补 dead', notice.includes('reasonCode'))

// ── ③ 挂载：切换摘要的触发条件 ───────────────────────────────────────────
let listener
const logPath = join(R, 'auto.jsonl')
const stateRoot = join(R, 'loot')
mkdirSync(stateRoot, { recursive: true })
apply(
  { on: (e, f) => { if (e === 'tools/post-execute') listener = f } },
  // switchAfterCalls: 1 —— 本段测的是"摘要内容"，不是滞后逻辑（滞后在 ③b 单独测）。
  { logPath, stateRoot, machine: 'TestBox', minCallsForSummary: 2, switchAfterCalls: 1 },
)
check('注册了 post-execute', typeof listener === 'function')

const allow = async () => ({ kind: 'accept' })
const ok = { content: [{ type: 'text', text: 'ok' }] }
const exec = (cmd, agent = 'a1') => ({ name: 'ssh_exec', agent: { id: agent }, arguments: { command: cmd } })

// 第一条命令：建立战线，不提示（没有"上一条"）
const s1 = await listener(exec('nmap -p- 10.0.0.1'), ok, allow)
check('首条命令不提示', s1.content === undefined)

// 同战线继续：不提示
const s2 = await listener(exec('nmap -sV 10.0.0.1'), ok, allow)
check('同战线不提示', s2.content === undefined)

// 切到 web：上一条 recon 已 2 次 ≥ 阈值 → 提示
const s3 = await listener(exec('curl -sk https://x/'), ok, allow)
check('够长时切换给摘要', Array.isArray(s3.content) && s3.content.length === 2)
check('摘要追加而非替换', s3.content[0].text === 'ok')

// web 内 1 次调用 + 1 条事实
await listener(exec('curl -sk https://x/cart'), ok, allow)
await listener({ name: 'htb_fact', agent: { id: 'a1' }, arguments: { op: 'add', kind: 'vuln', key: 'x' } }, ok, allow)

// 切到 db：上一条 web 2 次调用 / 1 条事实 → 提示且数字正确
const s4 = await listener(exec('psql -h 127.0.0.1'), ok, allow)
check('事实数被计入摘要', Array.isArray(s4.content) && s4.content[1].text.includes('1 条事实'))
check('调用数被计入摘要', s4.content[1].text.includes('2 次调用'))

// 推断不出：保持当前战线，不切换不提示
const s5 = await listener(exec("python3 - <<'PY'\nprint(1)\nPY"), ok, allow)
check('推断不出不提示', s5.content === undefined)

// ── ③b 滞后：单条异类命令不该翻转战线（2026-10-25 由重放发现）──────────────
// DutyBound 重放实测：245 次调用切了 39 次，每条摘要都写"停留 0 秒" ——
// 因为真实命令是交替的（curl 看一眼 → nmap 扫一下 → 再 curl）。
let hlistener
apply(
  { on: (e, f) => { if (e === 'tools/post-execute') hlistener = f } },
  { logPath: join(R, 'hyst.jsonl'), stateRoot: join(R, 'hyst-loot'), machine: 'H', minCallsForSummary: 0, switchAfterCalls: 3 },
)
const h = (cmd) => hlistener(exec(cmd), ok, allow)
await h('nmap -p- x')                 // 建立 recon
await h('nmap -sV x')
await h('nmap -sC x')
await h('curl -s http://x/')          // 单条 web：不该切
await h('nmap -p- x')                 // 回到 recon：pending 清零
await h('curl -s http://x/a')         // pending 1
await h('curl -s http://x/b')         // pending 2
const h1 = await h('curl -s http://x/c')  // pending 3 → 切换
check('滞后：连续 3 次才切换', Array.isArray(h1.content))
check('滞后：切换摘要指向 Web', h1.content[1].text.includes('Web'))

// ── ③c 战线内预算告警（2026-10-25 新增）────────────────────────────────
// Watcher 实测：`凭据` 战线 63 次调用 / 0 事实 / 155 分钟，而摘要是**退出时**才结算。
// 改成进战线后按调用数结算，同样一条信息能提前约 2 小时出现。
let blistener
apply(
  { on: (e, f) => { if (e === 'tools/post-execute') blistener = f } },
  {
    logPath: join(R, 'budget.jsonl'),
    stateRoot: join(R, 'budget-loot'),
    machine: 'B',
    switchAfterCalls: 99,     // 本段只测预算，不测切换
    minCallsForSummary: 99,
    frontBudgetCalls: 4,
  },
)
const b = (agent, cmd) => blistener(exec(cmd, agent), ok, allow)

await b('b1', 'nmap x'); await b('b1', 'nmap x'); await b('b1', 'nmap x')
const b4 = await b('b1', 'nmap x')
check('预算到点告警', Array.isArray(b4.content))
check('告警要求回答"更快的原语"', b4.content[1].text.includes('更快的原语'))
check('告警带调用数与事实数', b4.content[1].text.includes('4 次调用') && b4.content[1].text.includes('0 条事实'))

// 有事实就不该打断（说明这条路在推进）
await b('b2', 'nmap x'); await b('b2', 'nmap x'); await b('b2', 'nmap x')
await blistener({ name: 'htb_fact', agent: { id: 'b2' }, arguments: { op: 'add', kind: 'vuln', key: 'k' } }, ok, allow)
const b5 = await b('b2', 'nmap x')
check('有事实时不告警', b5.content === undefined)

// 每条战线最多 2 次
await b('b1', 'nmap x'); await b('b1', 'nmap x'); await b('b1', 'nmap x')   // 5,6,7
const b8 = await b('b1', 'nmap x')                                          // 8 → 第 2 次告警
check('第 2 次预算告警', Array.isArray(b8.content))
await b('b1', 'nmap x'); await b('b1', 'nmap x'); await b('b1', 'nmap x')   // 9,10,11
const b12 = await b('b1', 'nmap x')                                         // 12 → 到点但已达上限
check('第 3 次不再告警（每条战线上限 2）', b12.content === undefined)

// ── ④ 账本：有记录、无命令原文 ───────────────────────────────────────────
const ledgerPath = join(stateRoot, 'TestBox-state.jsonl')
check('账本已创建', existsSync(ledgerPath))
const recs = readFileSync(ledgerPath, 'utf-8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
check('账本写的是 auto-probe', recs.every((r) => r.type === 'auto-probe'))
check('账本含 front', recs.every((r) => typeof r.front === 'string'))
check('账本不含命令原文', !readFileSync(ledgerPath, 'utf-8').includes('nmap -p-'))
check('账本不含凭据形态', !/password|passwd|secret/i.test(readFileSync(ledgerPath, 'utf-8')))

// ── ⑤ 多账本 + 没配 machine：跳过而不是崩 ────────────────────────────────
let listener2
const multiRoot = join(R, 'multi')
mkdirSync(multiRoot, { recursive: true })
for (const n of ['A-state.jsonl', 'B-state.jsonl']) {
  await import('node:fs').then((m) => m.writeFileSync(join(multiRoot, n), ''))
}
apply({ on: (e, f) => { if (e === 'tools/post-execute') listener2 = f } }, { logPath: join(R, 'auto2.jsonl'), stateRoot: multiRoot })
const m1 = await listener2(exec('nmap -p- x'), ok, allow)
check('多账本时静默跳过', m1.content === undefined)
check('多账本时未乱写', readFileSync(join(multiRoot, 'A-state.jsonl'), 'utf-8') === '')

// ── ⑥ 不同 agent 独立 ────────────────────────────────────────────────────
const b1 = await listener(exec('nmap -p- x', 'a2'), ok, allow)
check('不同 agent 独立（首条不提示）', b1.content === undefined)

// ── ⑦ 不覆盖上一条 hook 的追加 ───────────────────────────────────────────
let listener3
apply({ on: (e, f) => { if (e === 'tools/post-execute') listener3 = f } }, { logPath: join(R, 'auto3.jsonl'), stateRoot: join(R, 'loot3'), machine: 'C', minCallsForSummary: 1, switchAfterCalls: 1 })
const upstream = async () => ({ kind: 'accept', content: [{ type: 'text', text: '上游' }] })
await listener3(exec('nmap x'), ok, upstream)
const c2 = await listener3(exec('curl x'), ok, upstream)
check('保留上游追加', c2.content[0].text === '上游' && c2.content.length === 2)

// ── ⑧ enabled:false ─────────────────────────────────────────────────────
let l2
apply({ on: (e, f) => { if (e === 'tools/post-execute') l2 = f } }, { enabled: false })
check('enabled:false 不注册', l2 === undefined)

check('覆盖 ssh_exec', EXEC_TOOLS.includes('ssh_exec'))

rmSync(R, { recursive: true, force: true })
console.log(fails === 0 ? 'auto-state-test: PASS' : `auto-state-test: ${fails} FAIL`)
process.exit(fails === 0 ? 0 : 1)
