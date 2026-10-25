#!/usr/bin/env node
/**
 * scope-observe-test.mjs — 出站目标观测器的回归闸（2026-10-21 新增）
 *
 * 这个模块最容易"好心办坏事"：一旦它开始拒绝调用，就变成了一个
 * 看起来在保护、实际能绕过、且会挡住正常作业的假边界。所以测试的重点
 * 不是"拦得准不准"，而是：
 *   ① 提取够用（IPv4 / URL host / user@host / ssh 参数）
 *   ② 排除项正确（回环、文档网段、链路本地）
 *   ③ **永远不返回拒绝** —— 这是它的契约
 *   ④ 去重生效，不会一次扫描刷几百行
 *   ⑤ registered 标注能区分"登记过的目标"与"没登记过的"
 *
 * 契约：exit 0 = 通过；任何 FAIL 一律 exit 1。
 */
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, extractTargets } from '../src/scope-observe.js'

const R = join(tmpdir(), `scope-observe-gate-${process.pid}`)
rmSync(R, { recursive: true, force: true })
mkdirSync(R, { recursive: true })

let fails = 0
const check = (label, cond) => {
  if (!cond) fails += 1
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${label}`)
}

// ── ① 提取 ────────────────────────────────────────────────────────────────
const t1 = extractTargets({ name: 'bash', arguments: { command: 'nmap -sV 10.10.11.5 -p 445' } })
check('bash 提取 IPv4', t1.includes('10.10.11.5'))

const t2 = extractTargets({ name: 'pwsh', arguments: { command: 'curl http://10.10.11.7:8080/api' } })
check('pwsh 提取 URL host', t2.includes('10.10.11.7'))

const t3 = extractTargets({ name: 'ssh_exec', arguments: { host: '10.10.11.9', command: 'id' } })
check('ssh_exec 从参数取 host', t3.includes('10.10.11.9'))

const t4 = extractTargets({ name: 'bash', arguments: { command: 'ssh root@target.htb' } })
check('提取 user@host 域名', t4.includes('target.htb'))

// ── ② 排除项 ──────────────────────────────────────────────────────────────
const ex1 = extractTargets({ name: 'bash', arguments: { command: 'curl http://127.0.0.1:8080' } })
check('排除回环', ex1.length === 0)

const ex2 = extractTargets({ name: 'bash', arguments: { command: 'curl http://192.0.2.10/x 169.254.169.254' } })
check('排除文档网段与链路本地', ex2.length === 0)

const ex3 = extractTargets({ name: 'read', arguments: { command: '10.10.11.5' } })
check('非出站工具不提取', ex3.length === 0)

const ex4 = extractTargets({ name: 'bash', arguments: { command: 'ping 999.1.1.1' } })
check('非法 IPv4 段被丢弃', ex4.length === 0)

// ── ③ 永不拦截 + ④ 去重 + ⑤ registered 标注 ────────────────────────────
const ledgerDir = R
writeFileSync(join(ledgerDir, 'BoxX-state.jsonl'),
  `${JSON.stringify({ type: 'fact', id: 'f1', kind: 'host', key: '10.10.11.5', confidence: 'inferred' })}\n`,
  'utf8')

let listener
const fakeCtx = {
  on: (evt, fn) => { if (evt === 'tools/pre-execute') listener = fn },
  tools: { guard: () => { throw new Error('scope-observe 不应占用 guard 槽位') } },
}
const logPath = join(R, 'observed.jsonl')
apply(fakeCtx, { stateRoot: R, logPath })

check('apply 注册了 pre-execute listener', typeof listener === 'function')

const allow = async () => ({ kind: 'allow' })
const deny = await listener({ name: 'bash', agent: { id: 'a1' }, arguments: { command: 'nmap 10.10.11.5' } }, allow)
check('透传 next 的决定（不拦截）', deny?.kind === 'allow')

const deny2 = await listener({ name: 'ssh_exec', agent: { id: 'a1' }, arguments: { host: '10.10.11.99' } }, allow)
check('未登记目标也不拦截', deny2?.kind === 'allow')

// 同一 agent + 同一目标，第二次应被去重
await listener({ name: 'bash', agent: { id: 'a1' }, arguments: { command: 'nmap -sV 10.10.11.5' } }, allow)

const lines = readFileSync(logPath, 'utf-8').split('\n').filter(Boolean)
check('去重生效（同目标只记一次）', lines.length === 2)

const rec = lines.map((l) => JSON.parse(l))
const reg = rec.find((r) => r.target === '10.10.11.5')
const unreg = rec.find((r) => r.target === '10.10.11.99')
check('登记过的目标标 registered=true', reg?.registered === true)
check('未登记目标标 registered=false', unreg?.registered === false)
check('记录含 ts/agent/tool/target', rec.every((r) => r.ts && r.agent && r.tool && r.target))

// 不同 agent 访问同一目标应各记一条（去重键含 agent）
await listener({ name: 'bash', agent: { id: 'a2' }, arguments: { command: 'nmap 10.10.11.5' } }, allow)
const lines2 = readFileSync(logPath, 'utf-8').split('\n').filter(Boolean)
check('不同 agent 各自记录', lines2.length === 3)

// 非出站工具不写
await listener({ name: 'read', agent: { id: 'a1' }, arguments: { path: '10.10.11.5' } }, allow)
check('非出站工具不记录', readFileSync(logPath, 'utf-8').split('\n').filter(Boolean).length === 3)

// enabled:false 时不注册
let listener2
apply({ on: (evt, fn) => { if (evt === 'tools/pre-execute') listener2 = fn } }, { enabled: false })
check('enabled:false 不注册 listener', listener2 === undefined)

rmSync(R, { recursive: true, force: true })

console.log(fails === 0 ? 'scope-observe-test: PASS' : `scope-observe-test: ${fails} FAIL`)
process.exit(fails === 0 ? 0 : 1)
