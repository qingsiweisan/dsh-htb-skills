#!/usr/bin/env node
/**
 * error-classify-test.mjs — 失败归因的回归闸（2026-10-25 新增）
 *
 * 这个模块的契约有四条，缺一条就会变成噪音或隐患：
 *   ① 分类按**应对方式**分，不按错误来源分（同一句 Permission denied 在文件/数据库里解法一样）
 *   ② 同类第 2 次才提示，第 1 次静默 —— 单次失败是正常的
 *   ③ 第 3 次升级为"停止同类变体"，第 4 次以后不再提示（交给 struggle/budget 收网）
 *   ④ **永远不改变工具是否成功**，只在 content 末尾追加文字；且不覆盖别的模块的追加
 *
 * 契约：exit 0 = 通过；任何 FAIL 一律 exit 1。
 */
import { mkdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, classify, buildHint, snippetOf, MARKER, ERROR_CLASSES, EXEC_TOOLS } from '../src/error-classify.js'

const R = join(tmpdir(), `err-classify-gate-${process.pid}`)
rmSync(R, { recursive: true, force: true })
mkdirSync(R, { recursive: true })

let fails = 0
const check = (label, cond) => {
  if (!cond) fails += 1
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${label}`)
}

// ── ① classify：六类各自能认出来 ─────────────────────────────────────────
const CASES = [
  ['channel', '[exit code: 1] stdout: \nstderr: psql: error'],
  ['permission', 'ls: cannot open directory /root: Permission denied'],
  ['auth', 'SMB login failed: STATUS_LOGON_FAILURE (authentication failed)'],
  ['timeout', '[timed out] error: command timed out after 60000 ms'],
  ['network', 'curl: (7) Failed to connect: Connection refused'],
  ['syntax', 'nmap: unrecognized option --foo\nusage: nmap [options]'],
  ['semantic', 'ERROR: relation "users" does not exist'],
]
for (const [want, text] of CASES) {
  const got = classify(text)
  check(`classify ${want}`, got !== null && got.id === want)
}

// timeout 与 network 必须分开：`grep -r /root` 超时不是"环境坏了"
check('timeout 不归网络类', classify('[timed out] command timed out')?.id === 'timeout')
check('connection refused 不归超时类', classify('Connection refused')?.id === 'network')

// channel 只在"退出码非 0 且几乎没有 stdout"时成立
check('channel 不误判 exit 0', classify('[exit code: 0] stdout: \n') === null)
check('channel 不误判有输出的失败', classify('[exit code: 1] stdout: ' + 'x'.repeat(50)) === null)

// 不是失败就不分类
check('classify 空串 → null', classify('') === null)
check('classify 非字符串 → null', classify(null) === null)
check('classify 正常输出 → null', classify('uid=0(root) gid=0(root)') === null)

// 每个类都有 advice（提示里要用）
check('每个类都有 advice', ERROR_CLASSES.every((c) => typeof c.advice === 'string' && c.advice.length > 4))

// ── ② buildHint：第 2 次给形态，第 3 次升级 ──────────────────────────────
const cls = { id: 'channel', label: '通道', advice: '尾部加 ; true' }
const h2 = buildHint(cls, 2, 'psql: error: exit 1', 3)
check('第 2 次提示带上次形态', h2.includes('psql: error'))
check('第 2 次提示带应对建议', h2.includes('; true'))
check('第 2 次提示要求判断是否同因', h2.includes('同一个原因'))
const h3 = buildHint(cls, 3, '', 3)
check('第 3 次升级为停止同类变体', h3.includes('停止') && h3.includes('换层'))

// ── ③ snippetOf ──────────────────────────────────────────────────────────
check('snippet 取第一行非空', snippetOf('\n\n  boom  \nsecond') === 'boom')
check('snippet 截断超长行', snippetOf('x'.repeat(200), 20).length <= 21)
// 优先取报错行，而不是命令自己的分区标题（DutyBound 重放暴露的问题）
check('snippet 优先取报错行', snippetOf('=== token files ===\nfoo\n[timed out] error: command timed out after 60000 ms').includes('timed out'))
check('snippet 报错行也截断', snippetOf(`x\n${'y'.repeat(200)} error`, 20).length <= 21)

// ── ④ 挂载：静默 → 提示 → 升级 → 静默 ────────────────────────────────────
let listener
const logPath = join(R, 'errors.jsonl')
apply({ on: (e, f) => { if (e === 'tools/post-execute') listener = f } }, { logPath, hintAt: 2, escalateAt: 3, maxHints: 6 })
check('注册了 post-execute', typeof listener === 'function')

const allow = async () => ({ kind: 'accept' })
const fail = (text) => ({ content: [{ type: 'text', text }] })
const call = (text, agent = 'a1') => listener({ name: 'ssh_exec', agent: { id: agent }, arguments: { command: 'x' } }, fail(text), allow)

const e1 = await call('ls: cannot open /root: Permission denied')
check('第 1 次静默', e1.content === undefined)
const e2 = await call('ls: cannot open /root: Permission denied')
check('第 2 次提示', Array.isArray(e2.content) && e2.content.length === 2)
check('提示是追加而非替换', e2.content[0].text.includes('Permission denied'))
const e3 = await call('ls: cannot open /root: Permission denied')
check('第 3 次升级', e3.content[1].text.includes('停止'))
const e4 = await call('ls: cannot open /root: Permission denied')
check('第 4 次静默（交给 struggle 收网）', e4.content === undefined)

// 不同类各自计数
const a1 = await call('Connection refused')
check('不同类独立计数（network 第 1 次静默）', a1.content === undefined)

// 按类限流：一个类用光自己的额度，不该影响别的类
// （DutyBound 重放实测：旧的全局 6 条在第 61 分钟被低价值提示吃光，
//   第 70 分钟真正值钱的 channel 提示一次都没发出来）
let clistener
apply({ on: (e, f) => { if (e === 'tools/post-execute') clistener = f } }, { logPath: join(R, 'perclass.jsonl'), maxHints: 12 })
const pc = (text) => clistener({ name: 'ssh_exec', agent: { id: 'pc' }, arguments: {} }, fail(text), allow)
await pc('Permission denied'); await pc('Permission denied'); await pc('Permission denied')  // 该类 2 条提示
await pc('Connection refused')
check('一个类用光额度后，另一个类仍有额度', Array.isArray((await pc('Connection refused')).content))

// 全局兜底上限仍然生效（防止配置了很多类时刷屏）
let caplistener
apply({ on: (e, f) => { if (e === 'tools/post-execute') caplistener = f } }, { logPath: join(R, 'cap.jsonl'), maxHints: 2 })
const cap = (text) => caplistener({ name: 'ssh_exec', agent: { id: 'cap' }, arguments: {} }, fail(text), allow)
await cap('Permission denied'); await cap('Permission denied'); await cap('Permission denied')
await cap('Connection refused')   // network 第 1 次：本来就静默
check('全局上限：额度用完后新类也提示不出', (await cap('Connection refused')).content === undefined)

// 不同 agent 独立计数
const b1 = await call('Permission denied', 'a2')
check('不同 agent 独立计数', b1.content === undefined)

// 非执行工具不参与
const r1 = await listener({ name: 'read', agent: { id: 'a1' } }, fail('Permission denied'), allow)
check('非执行工具不提示', r1.content === undefined)

// 已带标记的结果不重复追加
const m1 = await listener({ name: 'ssh_exec', agent: { id: 'a3' }, arguments: {} }, fail(`${MARKER}（权限）第 2 次。`), allow)
check('已带标记不重复追加', m1.content === undefined)

// 不覆盖上一条 hook 的追加
const chained = await listener({ name: 'ssh_exec', agent: { id: 'a4' }, arguments: {} }, fail('Permission denied'), async () => ({ kind: 'accept', content: [{ type: 'text', text: '上游模块的提示' }] }))
const chained2 = await listener({ name: 'ssh_exec', agent: { id: 'a4' }, arguments: {} }, fail('Permission denied'), async () => ({ kind: 'accept', content: [{ type: 'text', text: '上游模块的提示' }] }))
check('保留上游追加', chained2.content[0].text === '上游模块的提示' && chained2.content.length === 2)
check('第 1 次不追加（仍透传上游）', chained.content.length === 1)

// ── ⑤ 日志 ───────────────────────────────────────────────────────────────
const lines = readFileSync(logPath, 'utf-8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
check('日志有记录', lines.length >= 6)
check('日志含 class/count', lines.filter((r) => r.event !== 'error').every((r) => typeof r.class === 'string' && typeof r.count === 'number'))
check('日志记录了未提示的那次', lines.some((r) => r.hinted === false))
// 内部异常会被 catch 吞掉（保证不影响工具结果），所以必须单独断言"没有发生过"
check('没有内部异常', lines.every((r) => r.event !== 'error'))

// ── ⑥ enabled:false ─────────────────────────────────────────────────────
let l2
apply({ on: (e, f) => { if (e === 'tools/post-execute') l2 = f } }, { enabled: false })
check('enabled:false 不注册', l2 === undefined)

// ── ⑦ 覆盖范围 ───────────────────────────────────────────────────────────
check('覆盖 ssh_exec', EXEC_TOOLS.includes('ssh_exec'))
check('覆盖 pwsh', EXEC_TOOLS.includes('pwsh'))

rmSync(R, { recursive: true, force: true })
console.log(fails === 0 ? 'error-classify-test: PASS' : `error-classify-test: ${fails} FAIL`)
process.exit(fails === 0 ? 0 : 1)
