#!/usr/bin/env node
/**
 * context-hygiene-test.mjs — 上下文卫生检测的回归闸（2026-10-21 新增）
 *
 * 这个模块的契约有四条，缺一条就会变成噪音或隐患：
 *   ① 只观测执行类工具，且**失败结果不提示**（失败输出通常短，提示会干扰排错）
 *   ② 提示按**滑动窗口**限流（默认每 60 次执行调用最多 2 次）+ 会话绝对上限
 *      —— 旧口径"每会话 3 次"实测在头 40 秒就用完了，等于后 90 分钟没有提示
 *   ③ **永远不改变工具是否成功**，只在 content 末尾追加一段文字
 *   ④ 不覆盖别的模块（如 error-classify）刚追加的内容
 *
 * 契约：exit 0 = 通过；任何 FAIL 一律 exit 1。
 */
import { mkdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, measure, buildNotice, EXEC_TOOLS } from '../src/context-hygiene.js'

const R = join(tmpdir(), `ctx-hygiene-gate-${process.pid}`)
rmSync(R, { recursive: true, force: true })
mkdirSync(R, { recursive: true })

let fails = 0
const check = (label, cond) => {
  if (!cond) fails += 1
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${label}`)
}

// ── ① measure ────────────────────────────────────────────────────────────
const big = 'line\n'.repeat(300)
const m1 = measure({ content: [{ type: 'text', text: big }] })
check('measure 数行数', m1.lines >= 299)
check('measure 数字符', m1.chars === big.length)
check('measure 未截断', m1.truncated === false)

const m2 = measure({ content: [{ type: 'text', text: 'abc\n完整结果见 C:/x.txt' }] })
check('measure 识别 spill 截断标记', m2.truncated === true)

// 2026-10-25：真实 spill 格式是 "(Omitted N bytes. Full formatted result stored at: ...)"，
// 旧正则（full result / saved to）**匹配不到** —— 于是"已截断就跳过"这条保护从未生效，
// DutyBound seq 31 就是"已截断却仍被提示"。这里锁死真实格式。
const m2b = measure({ content: [{ type: 'text', text: 'x\n(Omitted 14743 bytes. Full formatted result stored at: C:/tmp/dsh-spill-x/y)' }] })
check('measure 识别真实 spill 格式（Omitted N bytes）', m2b.truncated === true)
const m2c = measure({ content: [{ type: 'text', text: 'x\ndsh-spill-06tmOa/session-1' }] })
check('measure 识别 dsh-spill 路径', m2c.truncated === true)

const m3 = measure({ content: [{ type: 'image', data: 'x' }] })
check('measure 忽略非文本块', m3.lines === 0 && m3.chars === 0)

const m4 = measure(null)
check('measure 容错 null', m4.lines === 0)

// ── ② buildNotice 给出可执行建议 ─────────────────────────────────────────
const n1 = buildNotice('bash', 340, 200)
check('提示含实际行数', n1.includes('340'))
check('提示含 workflow 建议', n1.includes('workflow'))
check('提示含 subagent 建议', n1.includes('subagent'))
check('提示保留快速验证', n1.includes('curl -I'))

// ── ③ 挂载与阈值 ─────────────────────────────────────────────────────────
let listener
const logPath = join(R, 'hygiene.jsonl')
const fakeCtx = { on: (evt, fn) => { if (evt === 'tools/post-execute') listener = fn } }
// noticeWindowCalls: 0 = 旧的"纯会话上限"模式，保留这段是为了证明向后兼容。
apply(fakeCtx, { logPath, thresholdLines: 200, maxNotices: 3, noticeWindowCalls: 0 })
check('注册了 post-execute', typeof listener === 'function')

const allow = async () => ({ kind: 'accept' })

// 低于阈值：不改结果
const small = { content: [{ type: 'text', text: 'ok\n' }] }
const d1 = await listener({ name: 'bash', agent: { id: 'a1' } }, small, allow)
check('低于阈值不追加', d1.kind === 'accept' && d1.content === undefined)

// 超过阈值：追加一段文字，且原内容保留
const bigResult = { content: [{ type: 'text', text: big }] }
const d2 = await listener({ name: 'bash', agent: { id: 'a1' } }, bigResult, allow)
check('超阈值追加 content', Array.isArray(d2.content) && d2.content.length === 2)
check('原内容仍在', d2.content[0].text === big)
check('追加的是提示', d2.content[1].text.includes('上下文卫生'))
check('仍是 accept（不阻断）', d2.kind === 'accept')

// ── ④ 提示次数上限 ───────────────────────────────────────────────────────
const d3 = await listener({ name: 'bash', agent: { id: 'a1' } }, bigResult, allow)
const d4 = await listener({ name: 'bash', agent: { id: 'a1' } }, bigResult, allow)
check('第 2、3 次仍提示', Array.isArray(d3.content) && Array.isArray(d4.content))
const d5 = await listener({ name: 'bash', agent: { id: 'a1' } }, bigResult, allow)
check('第 4 次静默（不追加）', d5.content === undefined)

// 不同 agent 各自计数
const d6 = await listener({ name: 'bash', agent: { id: 'a2' } }, bigResult, allow)
check('不同 agent 独立计数', Array.isArray(d6.content))

// ── ④b 滑动窗口（2026-10-25 新增口径）────────────────────────────────────
// 背景：旧口径"每会话 3 次"在 DutyBound 头 40 秒就用完了，后 90 分钟零提示。
let wlistener
apply(
  { on: (e, f) => { if (e === 'tools/post-execute') wlistener = f } },
  { logPath: join(R, 'win.jsonl'), thresholdLines: 200, noticeWindowCalls: 4, maxNoticesPerWindow: 1, maxNotices: 8 },
)
const w = (agent, result = bigResult) => wlistener({ name: 'bash', agent: { id: agent } }, result, allow)

check('窗口：第 1 次提示', Array.isArray((await w('w1')).content))
check('窗口：第 2 次静默', (await w('w1')).content === undefined)
check('窗口：第 3 次静默', (await w('w1')).content === undefined)
check('窗口：第 4 次静默', (await w('w1')).content === undefined)
check('窗口：第 5 次滑出窗口后再提示', Array.isArray((await w('w1')).content))

// 低于阈值的调用也要推进窗口 —— 否则"一堆小命令 + 一个大输出"会被当成连续触发
const smallResult = { content: [{ type: 'text', text: 'ok\n' }] }
check('窗口：w2 第 1 次提示', Array.isArray((await w('w2')).content))
await w('w2', smallResult)
await w('w2', smallResult)
await w('w2', smallResult)
check('窗口：小命令也计入窗口（第 5 次才提示）', Array.isArray((await w('w2')).content))

// 绝对上限仍然生效
let clistener
apply(
  { on: (e, f) => { if (e === 'tools/post-execute') clistener = f } },
  { logPath: join(R, 'cap.jsonl'), thresholdLines: 200, noticeWindowCalls: 1, maxNoticesPerWindow: 5, maxNotices: 2 },
)
const c = () => clistener({ name: 'bash', agent: { id: 'c1' } }, bigResult, allow)
check('上限：第 1 次提示', Array.isArray((await c()).content))
check('上限：第 2 次提示', Array.isArray((await c()).content))
check('上限：第 3 次静默', (await c()).content === undefined)

// spill 截断：**仍然提示**，但文案要说明"这是已截断后的实际行数"
// （2026-10-25 改：原来跳过 → DutyBound seq 31 那个 1451 行/49KB 的最大消耗被静默）
const truncResult = { content: [{ type: 'text', text: `${big}\n(Omitted 14743 bytes. Full formatted result stored at: C:/tmp/dsh-spill-x/y)` }] }
const dt = await w('w3', truncResult)
check('spill 截断仍提示', Array.isArray(dt.content))
check('spill 截断文案说明已截断', dt.content[1].text.includes('已被 spill 截断'))
check('buildNotice 默认不含截断说明', !buildNotice('bash', 300, 200).includes('spill'))

// ── ④c 累积检测（2026-10-25 新增）────────────────────────────────────────
// Watcher 实测：286 次 ssh_exec 触发 5 次 compaction，但单次超 200 行的只有 2 个 ——
// 上下文是被"每次几百字符 × 上百次"撑爆的，单次阈值看不见。
let alistener
apply(
  { on: (e, f) => { if (e === 'tools/post-execute') alistener = f } },
  {
    logPath: join(R, 'accum.jsonl'),
    thresholdLines: 99999,      // 关掉单次判定，只测累积
    accumWindowCalls: 5,
    accumChars: 1000,
    accumCooldownCalls: 5,
    maxAccumNotices: 2,
  },
)
const medium = { content: [{ type: 'text', text: 'x'.repeat(300) }] }   // 1 行 / 300 字符
const a = (agent) => alistener({ name: 'ssh_exec', agent: { id: agent } }, medium, allow)

await a('ac1'); await a('ac1'); await a('ac1'); await a('ac1')
const a5 = await a('ac1')
check('累积到点告警（第 5 次）', Array.isArray(a5.content))
check('累积告警含窗口字符数', a5.content[1].text.includes('K 字符'))
check('累积告警说明"单次都不大"', a5.content[1].text.includes('单次都不大'))
check('冷却期内不再告警', (await a('ac1')).content === undefined)
await a('ac1'); await a('ac1'); await a('ac1')
const a10 = await a('ac1')
check('冷却期过后再次告警', Array.isArray(a10.content))
await a('ac1'); await a('ac1'); await a('ac1'); await a('ac1'); await a('ac1')
check('达到会话上限后静默', (await a('ac1')).content === undefined)

// 单次超标的路径不受累积逻辑影响
check('单次路径仍可用（buildNotice）', buildNotice('bash', 300, 200).includes('上下文卫生'))

// ── ⑤ 失败结果 / 非执行工具不提示 ───────────────────────────────────────
const d7 = await listener({ name: 'bash', agent: { id: 'a1' } }, { content: [{ type: 'text', text: big }], isError: true }, allow)
check('失败结果不提示', d7.content === undefined)

const d8 = await listener({ name: 'read', agent: { id: 'a1' } }, bigResult, allow)
check('非执行工具不提示', d8.content === undefined)

// 不覆盖上一条 hook 的追加（error-classify 也会往 content 末尾追加）
const chained = await listener(
  { name: 'bash', agent: { id: 'a9' } },
  bigResult,
  async () => ({ kind: 'accept', content: [{ type: 'text', text: '上游模块的提示' }] }),
)
check('保留上游追加', Array.isArray(chained.content) && chained.content[0].text === '上游模块的提示' && chained.content.length === 2)

// ── ⑥ 日志记录（含静默的那次） ──────────────────────────────────────────
const lines = readFileSync(logPath, 'utf-8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
check('日志有记录', lines.length >= 5)
check('日志含 tool/lines/threshold', lines.every((r) => r.tool && typeof r.lines === 'number' && r.threshold === 200))
check('第 4 次记为未提示', lines.filter((r) => r.noticed === false).length >= 1)

// ── ⑦ enabled:false ─────────────────────────────────────────────────────
let l2
apply({ on: (e, f) => { if (e === 'tools/post-execute') l2 = f } }, { enabled: false })
check('enabled:false 不注册', l2 === undefined)

// ── ⑧ EXEC_TOOLS 覆盖远端 ───────────────────────────────────────────────
check('覆盖 ssh_exec', EXEC_TOOLS.includes('ssh_exec'))
check('覆盖 pwsh', EXEC_TOOLS.includes('pwsh'))

rmSync(R, { recursive: true, force: true })
console.log(fails === 0 ? 'context-hygiene-test: PASS' : `context-hygiene-test: ${fails} FAIL`)
process.exit(fails === 0 ? 0 : 1)
