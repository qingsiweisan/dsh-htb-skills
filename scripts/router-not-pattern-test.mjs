#!/usr/bin/env node
/**
 * router-not-pattern-test.mjs — router 负向条件（notPattern）的运行时闸
 *
 * 为什么需要它（2026-10-25）：
 *   DutyBound 那场 6 次注入里 3 次误报，模型两次明确写下 "false route" /
 *   "Router misfired again"。误报的代价不是 token，是**信任** —— 连续判"无关"
 *   之后，真命中的卡也会被扫一眼就过。所以给规则加了 `notPattern`：
 *   关键词对上了但场景不对时不注入。
 *
 *   这是纯静态检查（router-rules-test）覆盖不到的行为，必须真的跑一次事件。
 *
 * 契约：exit 0 = 通过或 SKIP；任何 FAIL 一律 exit 1。
 * SKIP 条件：router 源码不存在，或它依赖的 `@deepseek-ai/dsh-llm` 在本机解析不到
 *           （该包只在装了 harness 的机器上存在）。
 */
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const ROUTER = join(homedir(), 'dsh-htb-router', 'src', 'index.js')
if (!existsSync(ROUTER)) {
  console.log(`SKIP  router 源码不存在: ${ROUTER}`)
  process.exit(0)
}

let apply
try {
  ({ apply } = await import(pathToFileURL(ROUTER).href))
} catch (error) {
  const code = error?.code ?? ''
  if (code === 'ERR_MODULE_NOT_FOUND') {
    console.log(`SKIP  router 依赖不可解析（${error.message.split('\n')[0]}）`)
    process.exit(0)
  }
  console.error(`FAIL  router 导入失败: ${error?.message ?? error}`)
  process.exit(1)
}

let fails = 0
const check = (label, cond) => {
  if (!cond) fails += 1
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${label}`)
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/**
 * 跑一次 tool/call 事件，返回注入的文本。
 * @param rules - 规则表。
 * @param args - 工具参数（即 haystack 的来源）。
 * @param sessionId - 会话 id。
 */
async function runOnce(rules, args, sessionId = 'sess-1') {
  const injected = []
  let handler
  const agents = new Map([[sessionId, { inject: (msg) => injected.push(JSON.stringify(msg)) }]])
  const ctx = {
    on: (event, fn) => { if (event === 'session/event') handler = fn },
    logger: { warn() {}, info() {}, debug() {}, error() {} },
    skills: { get: async (card) => ({ content: `BODY:${card}` }) },
    get: (key) => (key === 'agents' ? agents : undefined),
  }
  apply(ctx, { rules })
  handler({ id: sessionId }, { type: 'tool/call', data: { name: 'ssh_exec', arguments: args } })
  // 注入是 `void (async () => ...)`，等它跑完。
  await sleep(60)
  return injected.join('\n')
}

const RULES = [
  { id: 'base', label: 'base', pattern: 'permission denied', cards: ['linux-privesc'] },
  { id: 'neg', label: 'neg', pattern: 'permission denied', notPattern: 'windows', cards: ['windows-privesc'] },
]

// ① 没有负向词：两条规则都应命中（负向条件只在词出现时抑制，不是常驻禁用）
const plain = await runOnce(RULES, 'cat /etc/shadow 2>&1  # permission denied')
check('正向规则命中', plain.includes('BODY:linux-privesc'))
check('无负向词时负向规则也生效', plain.includes('BODY:windows-privesc'))

// ② 负向条件生效：两个关键词都在，但含 windows → 只注入 base
const withNeg = await runOnce(RULES, 'windows: permission denied for C:/x')
check('负向条件抑制', !withNeg.includes('BODY:windows-privesc'))
check('同条 base 仍注入', withNeg.includes('BODY:linux-privesc'))

// ③ 没有 notPattern 的规则不受影响（对照组）
const noNeg = await runOnce([{ id: 'plain', label: 'plain', pattern: 'permission denied', cards: ['linux-privesc'] }], 'windows permission denied')
check('无负向条件时照常注入', noNeg.includes('BODY:linux-privesc'))

// ④ 负向条件写坏 → fail-open（规则仍然生效，不被丢弃）
const broken = await runOnce(
  [{ id: 'bad', label: 'bad', pattern: 'permission denied', notPattern: '([unclosed', cards: ['linux-privesc'] }],
  'permission denied',
)
check('坏 notPattern 不丢规则（fail-open）', broken.includes('BODY:linux-privesc'))

// ⑤ 完全没命中 → 不注入
const none = await runOnce(RULES, 'ls -la /tmp')
check('无命中不注入', none === '')

console.log(fails === 0 ? 'router-not-pattern-test: PASS' : `router-not-pattern-test: ${fails} FAIL`)
process.exit(fails === 0 ? 0 : 1)
