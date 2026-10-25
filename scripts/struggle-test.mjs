/**
 * Struggle 探测器测试：`node scripts/struggle-test.mjs`
 *
 * 最后一组用 ReaperTwo 那轮的真实参数做回归 —— 那个会话跑了 8.6 小时、
 * 中途 3 次 compaction、loot 数小时未更新，探测器必须判它该停。
 */

import { ACTIONS, DEFAULT_THRESHOLDS, SIGNALS, assessStruggle, renderNotice } from '../src/struggle.js'

let failed = 0
const check = (name, ok, extra = '') => {
  if (ok) console.log(`  ✓ ${name}`)
  else { failed += 1; console.log(`  ✗ ${name} ${extra}`) }
}

const MIN = 60_000
const HOUR = 3_600_000
const obs = (o = {}) => ({
  consecutiveIdenticalCalls: 0,
  msSinceArtifactChange: 0,
  elapsedMs: 5 * MIN,
  // 默认给一个健康密度（ReaperTwo 实测 ≈180 次/小时），免得每条用例都误触
  // 产出比信号；测 output 的用例自己覆盖它。
  toolCalls: 200,
  // 默认为 0 失败（实测基线 2.7%），同理免得误触失败率信号。
  toolFailures: 0,
  ...o,
})

console.log('健康会话 → continue')
{
  const r = assessStruggle(obs())
  check('无信号', r.hits.length === 0 && r.action === ACTIONS.continue)
  check('level 0', r.level === 0)
  check('快照为空也不炸', assessStruggle(undefined).action === ACTIONS.continue)
  check('产物刚改过、时长很短 → 健康', assessStruggle(obs({ msSinceArtifactChange: MIN, elapsedMs: 10 * MIN })).action === ACTIONS.continue)
}

console.log('重复单独命中 → checkpoint（不硬停）')
{
  const r = assessStruggle(obs({ consecutiveIdenticalCalls: 3 }))
  check('命中 repeat', r.hits.includes('repeat'))
  check('只 checkpoint', r.action === ACTIONS.checkpoint && r.level === 1)
}

console.log('重复：滑动窗口口径（2026-09-30 补）')
{
  // 背景：只认"严格连续"时，3271 条真实观测里 repeat **零命中** ——
  // 打靶的重复天然不连续（中间夹一次读台账）或呈 A/B/A/B 摆动。
  const win = assessStruggle(obs({ consecutiveIdenticalCalls: 1, windowRepeatCount: 3 }))
  check('连续只有 1 但窗口内 3 次 → 命中', win.hits.includes('repeat'))
  check('窗口 2 次仍不命中', !assessStruggle(obs({ consecutiveIdenticalCalls: 1, windowRepeatCount: 2 })).hits.includes('repeat'))
  check('两者取较大者（窗口高）', assessStruggle(obs({ consecutiveIdenticalCalls: 1, windowRepeatCount: 9 })).hits.includes('repeat'))
  check('缺省不下结论（老快照不炸）', !assessStruggle(obs({})).hits.includes('repeat'))
}

console.log('停滞 → stop（外部产物不动 = 没在学）')
{
  // 🔴 2026-10-10 由 45 改 90（事件口径标定；1.5–2.2h 有空档、45–90min 是低置信带）。
  // 原 45 的用例改成 90±1：89 分钟必须放行，91 分钟必须命中。
  const r = assessStruggle(obs({ msSinceArtifactChange: 91 * MIN }))
  check('命中 stall（90+1）', r.hits.includes('stall'))
  check('直接 stop', r.action === ACTIONS.stop && r.level === 2)
  check('差一分钟不算（90-1）', assessStruggle(obs({ msSinceArtifactChange: 89 * MIN })).action === ACTIONS.continue)
  check('旧的 45 分钟线不再触发 stall', !assessStruggle(obs({ msSinceArtifactChange: 45 * MIN })).hits.includes('stall'))
  check('刚好落在 90 分钟上算命中（>= 语义）', assessStruggle(obs({ msSinceArtifactChange: 90 * MIN })).hits.includes('stall'))
}

console.log('预算 → stop')
{
  // 2026-09-27 由 4h 改 6h：Layover 实测 3.99h 拿下双旗，距 4h 线不到 2 分钟。
  const r = assessStruggle(obs({ elapsedMs: 6 * HOUR }))
  check('命中 budget', r.hits.includes('budget') && r.action === ACTIONS.stop)
  check('差一点不算', assessStruggle(obs({ elapsedMs: 5.9 * HOUR, msSinceArtifactChange: MIN })).action === ACTIONS.continue)
  check('旧的 4 小时线不再触发 budget', !assessStruggle(obs({ elapsedMs: 4.1 * HOUR, msSinceArtifactChange: MIN })).hits.includes('budget'))
}

console.log('多信号')
{
  const r = assessStruggle(obs({ consecutiveIdenticalCalls: 5, msSinceArtifactChange: 2 * HOUR, elapsedMs: 6 * HOUR }))
  check('三条全中', r.hits.length === 3)
  check('仍然 stop', r.action === ACTIONS.stop)
  const four = assessStruggle(obs({ consecutiveIdenticalCalls: 5, msSinceArtifactChange: 2 * HOUR, elapsedMs: 6 * HOUR, toolCalls: 6 }))
  check('四条全中', four.hits.length === 4)
  check('四条全中仍 stop', four.action === ACTIONS.stop)
  // 五条同时成立需要 output 与 failures 不打架：
  // output 要密度 < 12/h（6h → 调用数 < 72），failures 要 ≥20 次调用且失败率 ≥15%。
  // 取 60 次 / 20 失败 = 10 次/小时（触发 output）+ 33% 失败率（触发 failures）。
  const five = assessStruggle(obs({
    consecutiveIdenticalCalls: 5, msSinceArtifactChange: 2 * HOUR, elapsedMs: 6 * HOUR,
    toolCalls: 60, toolFailures: 20,
  }))
  check('五条全中', five.hits.length === 5, `实得 ${five.hits.length}: ${five.hits.join(',')}`)
  check('五条全中仍 stop', five.action === ACTIONS.stop)
}

console.log('产出比 → checkpoint（最年轻的一条，只诊断不硬停）')
{
  // 真实数据：session-87cb7419 跑了 11.89 小时只发了 8 次工具调用（≈0.67 次/小时）——
  // 那不是在工作，是在空想。社区三条信号全漏掉这个形态。
  const r = assessStruggle(obs({ elapsedMs: 2 * HOUR, toolCalls: 8, msSinceArtifactChange: MIN }))
  check('命中 output', r.hits.includes('output'))
  check('产物是新鲜的 → 不误判为停滞', !r.hits.includes('stall'))
  check('只 checkpoint（不硬停）', r.action === ACTIONS.checkpoint && r.level === 1)
  check('与其它信号正交：只中一条', r.hits.length === 1)
}

console.log('产出比边界')
{
  // 取样下限：会话不到一小时不下结论，避免开局"还在想"被误判
  check('59 分钟不下结论', !assessStruggle(obs({ elapsedMs: 59 * MIN, toolCalls: 0 })).hits.includes('output'))
  check('刚到 60 分钟就判', assessStruggle(obs({ elapsedMs: 60 * MIN, toolCalls: 0 })).hits.includes('output'))
  // 健康密度不误伤：ReaperTwo 实测 487 次 / 2.7 小时 ≈ 180 次/小时
  check('ReaperTwo 密度不误伤',
    !assessStruggle(obs({ elapsedMs: 2.7 * HOUR, toolCalls: 487, msSinceArtifactChange: MIN })).hits.includes('output'))
  check('刚好落在阈值上不算（12/h）',
    !assessStruggle(obs({ elapsedMs: 2 * HOUR, toolCalls: 24, msSinceArtifactChange: MIN })).hits.includes('output'))
  check('略低于阈值就算（11/h）',
    assessStruggle(obs({ elapsedMs: 2 * HOUR, toolCalls: 22, msSinceArtifactChange: MIN })).hits.includes('output'))
  // 缺 toolCalls（老日志、外部调用方）时这条信号不参与判定，而不是当作 0
  check('没给 toolCalls 就不判',
    !assessStruggle({ elapsedMs: 6 * HOUR, msSinceArtifactChange: MIN }).hits.includes('output'))
  check('收窄 minCallsPerHour 生效',
    assessStruggle(obs({ elapsedMs: 2 * HOUR, toolCalls: 200, msSinceArtifactChange: MIN }), { minCallsPerHour: 500 }).hits.includes('output'))
  check('收窄 outputFloorMinutes 生效',
    assessStruggle(obs({ elapsedMs: 5 * MIN, toolCalls: 0 }), { outputFloorMinutes: 1 }).hits.includes('output'))
}

console.log('产出比持续性（2026-10-10 加：瞬时密度会抓到分钟级抖动）')
{
  // 依据（J7 事件口径）：5 个 output 事件的最长低产窗口 = 8/469/98/540/4 分钟 ⇒
  // 要求持续 ≥15 分钟保留 3 个真事件、剔除 2 个分钟级抖动。
  const low = { elapsedMs: 2 * HOUR, toolCalls: 8, msSinceArtifactChange: MIN } // 4 次/小时
  check('① 尖峰：低产只持续 14 分钟 → 不报',
    !assessStruggle(obs({ ...low, msSinceOutputLow: 14 * MIN })).hits.includes('output'))
  check('② 持续：低产 15 分钟 → 报',
    assessStruggle(obs({ ...low, msSinceOutputLow: 15 * MIN })).hits.includes('output'))
  check('② 持续：低产 469 分钟（J7 真事件）→ 报',
    assessStruggle(obs({ ...low, msSinceOutputLow: 469 * MIN })).hits.includes('output'))
  // ③ 兼容性：阈值对象缺 outputSustainMinutes 键、快照缺 msSinceOutputLow 都不炸，
  //    且后者维持旧行为（未知 ≠ 没持续）。
  check('③ 阈值对象缺 outputSustainMinutes 键不炸（回落默认 15）',
    assessStruggle(obs({ ...low, msSinceOutputLow: 20 * MIN }), { minCallsPerHour: 12 }).hits.includes('output'))
  check('③ 快照缺 msSinceOutputLow → 维持旧行为（不因持续性剔除）',
    assessStruggle(obs(low)).hits.includes('output'))
  check('③ 空快照仍不炸', assessStruggle(undefined).action === ACTIONS.continue)
  check('③ 缺 toolCalls 时仍不判 output（老日志）',
    !assessStruggle({ elapsedMs: 6 * HOUR, msSinceArtifactChange: MIN, msSinceOutputLow: 9 * HOUR }).hits.includes('output'))
  // 持续性不改变其它语义：密度健康时 msSinceOutputLow 再大也不报
  check('密度健康（ReaperTwo 180/h）→ 不报',
    !assessStruggle(obs({ elapsedMs: 2.7 * HOUR, toolCalls: 487, msSinceArtifactChange: MIN, msSinceOutputLow: 9 * HOUR })).hits.includes('output'))
  // 可覆盖：把持续性要求抬到 1 小时，98 分钟就保留、20 分钟就剔除
  check('收窄 outputSustainMinutes 生效（20min 报）',
    assessStruggle(obs({ ...low, msSinceOutputLow: 20 * MIN }), { outputSustainMinutes: 10 }).hits.includes('output'))
  check('放宽 outputSustainMinutes 生效（20min 不报）',
    !assessStruggle(obs({ ...low, msSinceOutputLow: 20 * MIN }), { outputSustainMinutes: 60 }).hits.includes('output'))
}

console.log('失败率 → checkpoint（第五条，只诊断不硬停）')
{
  // 真实数据：3 会话 / 764 次调用的基线是 2.7%（21/764），top 失败工具
  // `edit`/`web_search`/`ssh_exec`——其中 `edit` 正是 Layover 那次并发写 loot 撞车。
  const r = assessStruggle(obs({ toolCalls: 100, toolFailures: 20, msSinceArtifactChange: MIN }))
  check('命中 failures', r.hits.includes('failures'))
  check('产物新鲜 → 不误判为停滞', !r.hits.includes('stall'))
  check('只 checkpoint（不硬停）', r.action === ACTIONS.checkpoint && r.level === 1)
  check('与其它信号正交：只中一条', r.hits.length === 1)
}

console.log('失败率边界')
{
  // 观测基线不误伤：2.7% 远低于 15%
  check('基线 2.7% 不误伤',
    !assessStruggle(obs({ toolCalls: 764, toolFailures: 21, elapsedMs: 5.65 * HOUR, msSinceArtifactChange: MIN })).hits.includes('failures'))
  // 刚好落在阈值上算命中（>= 语义）
  check('刚好 15% 算命中',
    assessStruggle(obs({ toolCalls: 100, toolFailures: 15, msSinceArtifactChange: MIN })).hits.includes('failures'))
  check('略低 14% 不算',
    !assessStruggle(obs({ toolCalls: 100, toolFailures: 14, msSinceArtifactChange: MIN })).hits.includes('failures'))
  // 取样下限：调用太少不下结论（3 次里错 3 次 = 100%，但样本不够）
  check('19 次调用不下结论',
    !assessStruggle(obs({ toolCalls: 19, toolFailures: 19, msSinceArtifactChange: MIN })).hits.includes('failures'))
  check('20 次调用才判',
    assessStruggle(obs({ toolCalls: 20, toolFailures: 3, msSinceArtifactChange: MIN })).hits.includes('failures'))
  // 缺 toolFailures（老日志）时不判，而不是当作 0
  check('没给 toolFailures 就不判',
    !assessStruggle({ elapsedMs: 2 * HOUR, msSinceArtifactChange: MIN, toolCalls: 100 }).hits.includes('failures'))
  check('没给 toolCalls 时 failures 也不判',
    !assessStruggle({ elapsedMs: 2 * HOUR, msSinceArtifactChange: MIN, toolFailures: 99 }).hits.includes('failures'))
  check('收窄 failureRate 生效',
    assessStruggle(obs({ toolCalls: 100, toolFailures: 5, msSinceArtifactChange: MIN }), { failureRate: 0.01 }).hits.includes('failures'))
  check('收窄 failureFloorCalls 生效',
    assessStruggle(obs({ toolCalls: 5, toolFailures: 5, msSinceArtifactChange: MIN }), { failureFloorCalls: 5 }).hits.includes('failures'))
}

console.log('阈值可覆盖')
{
  const strict = assessStruggle(obs({ msSinceArtifactChange: 10 * MIN }), { stallMinutes: 10 })
  check('收窄 stallMinutes 生效', strict.action === ACTIONS.stop)
  const loose = assessStruggle(obs({ elapsedMs: 6 * HOUR, msSinceArtifactChange: MIN }), { maxHours: 12 })
  check('放宽 maxHours 生效', loose.action === ACTIONS.continue)
  check('未覆盖的字段仍用默认', assessStruggle(obs({ msSinceArtifactChange: MIN }), { maxHours: 12 }).hits.length === 0)
}

console.log('真实回归：ReaperTwo 那轮')
{
  // 实测：单会话 8.6 小时（2.7h + 5.2h 两段自主运行）、3 次 compaction、
  // loot 只在少数节点更新（第 12 轮那次是重置后）。
  const r = assessStruggle(obs({ elapsedMs: 8.6 * HOUR, msSinceArtifactChange: 3 * HOUR }))
  check('判它该停', r.action === ACTIONS.stop)
  check('命中停滞与预算', r.hits.includes('stall') && r.hits.includes('budget'))
  check('超时 6 小时后 stall 仍独立成立',
    assessStruggle(obs({ elapsedMs: 4.1 * HOUR, msSinceArtifactChange: 95 * MIN })).action === ACTIONS.stop)
  // 45→90 的直接后果：4.1 小时 + 50 分钟静默，在旧线是 stop，在新线必须放行
  // （此时 budget 也没到 ⇒ 这就是"少掐一次会话"的那 45 分钟）。
  check('50 分钟静默不再硬停（45→90 的代价面）',
    assessStruggle(obs({ elapsedMs: 4.1 * HOUR, msSinceArtifactChange: 50 * MIN })).action === ACTIONS.continue)
}

console.log('提醒文本')
{
  const text = renderNotice(assessStruggle(obs({ msSinceArtifactChange: 91 * MIN })))
  check('含信号标签', text.includes('停滞'))
  check('要求写 loot', text.includes('loot'))
  check('要求换新上下文', text.includes('subagent'))
  check('禁"再试一个变体"', text.includes('再试一个变体'))
  // level 1（repeat / output）不该套用"停止协议"那套重话
  const soft = renderNotice(assessStruggle(obs({ elapsedMs: 2 * HOUR, toolCalls: 8, msSinceArtifactChange: MIN })))
  check('产出比走提示级文案', soft.includes('产出比') && !soft.includes('停止协议'))
}

console.log('信号表')
check('五条信号', SIGNALS.length === 5)
check('默认阈值齐全',
  ['repeatCalls', 'repeatWindowCalls', 'stallMinutes', 'maxHours', 'minCallsPerHour', 'outputFloorMinutes',
    'outputSustainMinutes', 'failureRate', 'failureFloorCalls']
    .every(k => k in DEFAULT_THRESHOLDS))
check('maxHours 已按实测改为 6', DEFAULT_THRESHOLDS.maxHours === 6)
// 🔴 2026-10-10 事件口径标定：这两个值有出处（cutoff 见源码 DEFAULT_THRESHOLDS 注释）
check('stallMinutes 已按事件口径改为 90', DEFAULT_THRESHOLDS.stallMinutes === 90)
check('outputSustainMinutes 默认 15', DEFAULT_THRESHOLDS.outputSustainMinutes === 15)

console.log(failed === 0 ? '\n✅ Struggle 探测器测试全部通过' : `\n❌ ${failed} 条失败`)
process.exit(failed === 0 ? 0 : 1)
