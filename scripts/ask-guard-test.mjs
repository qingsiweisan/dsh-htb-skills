/**
 * 提问守卫测试：`node scripts/ask-guard-test.mjs`
 *
 * 语料来自真实事故：2026-09-24 ReaperTwo 会话导出里那次被 persona 第 4 条
 * 明令禁止、却仍然发出去的提问。
 */

import { ASK_HINT_RULES, askTextOf, checkAsk } from '../src/ask-guard.js'
import { apply } from '../src/index.js'

let failed = 0
const check = (name, ok, extra = '') => {
  if (ok) console.log(`  ✓ ${name}`)
  else { failed += 1; console.log(`  ✗ ${name} ${extra}`) }
}

/** 造一个 ask_user_question 形状的调用。 */
const ask = (header, question, options = []) => ({
  name: 'ask_user_question',
  arguments: { questions: [{ id: 'q', header, question, options: options.map(o => ({ label: o })) }] },
})

// 真实事故原样复刻：选项里带 Official Writeup 与 payload 细节
const INCIDENT = ask('方向选择', '接下来怎么走？', [
  '继续干：标定 codegen + 写进程内 payload',
  '你提供 HTB 站内 Official Writeup（或告诉我 WP 里的 payload 细节），我直接照做',
])

const DENY = [
  [INCIDENT, 'ask-for-writeup'],
  [ask('求助', '有没有官方 writeup 可以参考？'), 'ask-for-writeup'],
  [ask('求助', '给我一点提示吧'), 'ask-for-hint'],
  [ask('求助', '告诉我下一步该做什么'), 'ask-for-hint'],
  [ask('求助', '能给个 hint 吗'), 'ask-for-hint'],
  [ask('求助', '告诉我 payload 细节'), 'ask-for-payload'],
  [ask('求助', '我需要具体的 exploit'), 'ask-for-payload'],
  [ask('求助', '这题的题解在哪'), 'ask-for-writeup'],
]

const ALLOW = [
  // 这些确实只有用户能拍板 —— 拦了就是把正常协作也堵死
  [ask('靶机已降级', '怎么处理？', ['直接 reset（推荐）', '先等到 05:20 再看', 'terminate + respawn']), 'reset 决策'],
  [ask('需要入口', '你打算怎么给我入口？', ['我给你目标 IP', '你帮我 spawn']), '入口'],
  [ask('耗时确认', '这轮爆破预计 40 分钟，跑吗？', ['跑', '不跑']), '长时任务'],
  [ask('范围', '要不要换一台机器？', ['换', '不换']), '换机器'],
  // 🔴 2026-09-25 修的误伤：问"要不要用 WP"是**策略**，是用户的选择，
  // 跟"把答案要过来"是两回事。原正则裸匹配 `官方 WP`，把这三种都拦了。
  [ask('练习方式', '要不要我参考工作区里的官方 WP？', ['用', '自己打']), 'WP 策略（不是索要）'],
  [ask('练习方式', '这次练习要不要用 writeup，还是你希望我自己打？', ['用', '自己打']), 'WP 策略'],
  [ask('练习方式', '你希望我用 WP 里的 payload 细节吗？', ['用', '不用']), 'WP 策略（提到内容但是问选择）'],
  [ask('产出', 'loot 写到哪个目录？', ['loot/', 'loot/ReaperTwo/']), '路径偏好'],
]

console.log('DENY — 必须拦下')
for (const [call, want] of DENY) {
  const hit = checkAsk(askTextOf(call))
  if (!hit) fail(`漏拦 [${want}] ${JSON.stringify(call.arguments.questions[0].question)}`)
  else if (hit.id !== want) fail(`拦错规则 期望 ${want} 实得 ${hit.id}`)
}
function fail(m) { failed += 1; console.log(`  ✗ ${m}`) }
console.log(`  ${DENY.length} 条`)

console.log('ALLOW — 必须放行')
for (const [call, note] of ALLOW) {
  const hit = checkAsk(askTextOf(call))
  if (hit) fail(`误拦 [${hit.id}] ${note}`)
}
console.log(`  ${ALLOW.length} 条`)

console.log('边界')
check('空入参不炸', checkAsk(askTextOf({ name: 'ask_user_question', arguments: {} })) === undefined)
check('questions 非数组不炸', checkAsk(askTextOf({ arguments: { questions: 'x' } })) === undefined)
check('null exec 不炸', askTextOf(null) === '')
check('规则表有 3 条', ASK_HINT_RULES.length === 3)

console.log('接线（经 apply()）')
{
  const guards = []
  const ctx = {
    on: () => () => {},
    tools: { guard: (g) => { guards.push(g); return () => {} }, register: () => () => {} },
    skills: { registerProvider: () => {} },
  }
  await apply(ctx, { skillsEnabled: false })
  // 2026-10-25：+1 = struggle-watch 的停止协议闸。
  check('apply 注册了四个守卫（红线 + 提问 + WP + 停止协议）', guards.length === 4)
  const askDenied = guards.map(g => g(INCIDENT)).filter(Boolean)
  check('真实事故被拦', askDenied.length === 1 && askDenied[0].includes('[ask-for-writeup]'))
  const legit = ask('靶机已降级', '怎么处理？', ['直接 reset', '等一下'])
  check('合法提问不被拦', guards.map(g => g(legit)).every(r => r === undefined))
  check('红线守卫仍在（pkill）', guards.some(g => typeof g({ name: 'pwsh', arguments: { command: 'pkill -f x' } }) === 'string'))
}
{
  const guards = []
  const ctx = {
    on: () => () => {},
    tools: { guard: (g) => { guards.push(g); return () => {} }, register: () => () => {} },
    skills: { registerProvider: () => {} },
  }
  await apply(ctx, { skillsEnabled: false, askGuard: false })
  check('askGuard:false 只注册三个守卫', guards.length === 3)
}

console.log(failed === 0 ? '\n✅ 提问守卫测试全部通过' : `\n❌ ${failed} 条失败`)
process.exit(failed === 0 ? 0 : 1)
