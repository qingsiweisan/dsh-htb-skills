/**
 * 监视器测试：`node scripts/struggle-watch-test.mjs`
 *
 * 验的是"观测层"——产物 mtime、相同调用链、快照组装、日志落盘、接线。
 * 判定逻辑本身在 struggle-test.mjs。
 */

import { mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  DEFAULT_IGNORE,
  artifactMtimeMs,
  buildObservation,
  createState,
  noteArtifact,
  noteCall,
  noteOutputLow,
  noteResult,
  noteToolArtifact,
} from '../src/struggle-watch.js'
import { ACTIONS, DEFAULT_THRESHOLDS, assessStruggle } from '../src/struggle.js'
import { apply as applyPlugin } from '../src/index.js'

let failed = 0
const check = (name, ok, extra = '') => {
  if (ok) console.log(`  ✓ ${name}`)
  else { failed += 1; console.log(`  ✗ ${name} ${extra}`) }
}

const dir = mkdtempSync(join(tmpdir(), 'struggle-watch-'))
const loot = join(dir, 'loot')
mkdirSync(loot)

const now = 1_800_000_000_000

console.log('artifactMtimeMs')
{
  check('目录不存在 → undefined', artifactMtimeMs(join(dir, 'nope')) === undefined)
  check('空目录 → undefined', artifactMtimeMs(loot) === undefined)
  check('没传路径 → undefined', artifactMtimeMs(undefined) === undefined)
}

// ---------------------------------------------------------------------------
// 🔴 2026-10-10 口径回归：有界递归 depth=2 + 排除清单（J5 实测的两处静默失效）。
//    ① 子目录里的文件要被看见（NTFS 上改子目录内容**不**更新父目录 mtime）；
//    ② `.evidence-ledger/` 必须被排除（否则证据工具一调用 ⇒ 产物永久新鲜 ⇒ stall 永不触发）；
//    ③ depth=3 必须看不见（有界性）；④ 全空必须明确返回 undefined（兜底行为）；
//    ⑤ `traces/` 必须被排除（htb_traces 会写它，与 ② 同病）。
//    每个用例用独立的临时根目录，避免互相污染；用 utimesSync 打一个**特征 mtime**
//    再比对，所以"被看见"是"取到了那个具体值"，不只是"不等于 undefined"。
// ---------------------------------------------------------------------------
console.log('artifactMtimeMs 口径回归：有界递归 + 排除清单（2026-10-10）')
{
  const roots = []
  const mkRoot = () => { const r = mkdtempSync(join(tmpdir(), 'struggle-scope-')); roots.push(r); return r }
  const T = (sec) => sec * 1000 // utimesSync 的 mtimeMs 口径
  const touch = (p, sec) => { writeFileSync(p, 'x'); utimesSync(p, sec, sec) }
  const near = (got, sec) => got !== undefined && Math.abs(got - T(sec)) < 2000

  check('排除清单是必须项：DEFAULT_IGNORE 含 .evidence-ledger 与 traces',
    DEFAULT_IGNORE.includes('.evidence-ledger') && DEFAULT_IGNORE.includes('traces')
    && DEFAULT_IGNORE.includes('.evidence-reports') && DEFAULT_IGNORE.includes('_archive')
    && DEFAULT_IGNORE.includes('_audit') && DEFAULT_IGNORE.includes('_tools'))

  // ① <root>/sub/ 里的文件 ⇒ 被看见（本次修复的目的本身）
  {
    const r = mkRoot()
    mkdirSync(join(r, 'sub'))
    touch(join(r, 'sub', 'notes.md'), 1_700_000_111)
    const got = artifactMtimeMs(r)
    check('① root/sub/ 里的文件被看见', near(got, 1_700_000_111), `实得 ${got}`)
  }

  // ② <root>/.evidence-ledger/ 里的文件 ⇒ 不被看见（防"永久新鲜"）
  {
    const r = mkRoot()
    mkdirSync(join(r, '.evidence-ledger'))
    touch(join(r, '.evidence-ledger', 'index.jsonl'), 1_700_000_222)
    check('② .evidence-ledger/ 里的文件不被看见', artifactMtimeMs(r) === undefined)
  }

  // ③ <root>/a/b/c/（depth=3）⇒ 不被看见；<root>/a/b/（depth=2）⇒ 有对照地被看见
  {
    const r = mkRoot()
    mkdirSync(join(r, 'a', 'b', 'c'), { recursive: true })
    touch(join(r, 'a', 'b', 'c', 'deep.txt'), 1_700_000_333)
    check('③ depth=3（a/b/c/）不被看见', artifactMtimeMs(r) === undefined)
    touch(join(r, 'a', 'b', 'edge.txt'), 1_700_000_444)
    check('③ 对照：depth=2（a/b/）被看见 ⇒ 上界正好是 2', near(artifactMtimeMs(r), 1_700_000_444))
  }

  // ④ 完全为空 ⇒ 明确断言 undefined（兜底口径"这一轮没有观测到任何东西"）
  {
    const r = mkRoot()
    check('④ 完全为空 → undefined（不抛错、不返回 0）', artifactMtimeMs(r) === undefined)
    // 兜底行为：undefined 不会被 noteArtifact 用来清空已建立的基线。
    const s = createState(1_800_000_000_000, 1_700_000_555_000)
    check('④ undefined 不覆盖已知基线（noteArtifact 早退）',
      noteArtifact(s, artifactMtimeMs(r), 1_800_000_060_000) === false
      && s.artifactMtime === 1_700_000_555_000)
  }

  // ⑤ <root>/traces/ 里的文件 ⇒ 不被看见（htb_traces 一调用就写它）
  {
    const r = mkRoot()
    mkdirSync(join(r, 'traces'))
    touch(join(r, 'traces', 'agent.md'), 1_700_000_666)
    check('⑤ traces/ 里的文件不被看见', artifactMtimeMs(r) === undefined)
  }

  // 附加：只有被排除目录 + 一个正常文件时，取到的是正常文件（排除不影响其余分支）
  {
    const r = mkRoot()
    mkdirSync(join(r, '.evidence-ledger')); touch(join(r, '.evidence-ledger', 'a.jsonl'), 1_700_000_777)
    mkdirSync(join(r, 'machine')); touch(join(r, 'machine', 'loot.py'), 1_700_000_888)
    check('排除目录与正常目录并存时取正常文件的 mtime', near(artifactMtimeMs(r), 1_700_000_888))
  }

  for (const r of roots) rmSync(r, { recursive: true, force: true })
}

console.log('createState / noteCall')
{
  const s = createState(now, undefined)
  const a = { name: 'ssh_exec', arguments: { command: 'x', alias: 'kali' } }
  const b = { name: 'ssh_exec', arguments: { alias: 'kali', command: 'x' } } // 键序不同，同一调用
  check('首次 = 1', noteCall(s, a) === 1)
  check('键序不同仍算相同', noteCall(s, b) === 2)
  check('参数不同则重置', noteCall(s, { name: 'ssh_exec', arguments: { command: 'y' } }) === 1)
  check('换工具则重置', noteCall(s, { name: 'pwsh', arguments: { command: 'y' } }) === 1)
  check('连续相同累加', noteCall(s, { name: 'pwsh', arguments: { command: 'y' } }) === 2)
  check('累计调用数（产出比信号用）', s.calls === 5)
}

console.log('noteCall 滑动窗口（2026-09-30 补：连续口径实测零命中）')
{
  const s = createState(now, undefined)
  const X = { name: 'ssh_exec', arguments: { command: 'same' } }
  const Y = { name: 'read', arguments: { file_path: 'loot/x.md' } }
  noteCall(s, X, 8); noteCall(s, Y, 8); noteCall(s, X, 8)
  check('A/B/A 摆动：连续=1', s.identicalCount === 1)
  check('A/B/A 摆动：窗口=2', s.windowRepeatCount === 2)
  noteCall(s, Y, 8); noteCall(s, X, 8)
  check('A/B/A/B/A：窗口=3（连续仍=1）', s.windowRepeatCount === 3 && s.identicalCount === 1)
  check('窗口外的不再计数（窗口=2 时旧 key 被挤掉）',
    noteCall(s, { name: 'grep', arguments: { pattern: 'z' } }, 2) >= 1
    && s.windowRepeatCount === 1)
  check('窗口大小非法时回落 8', noteCall(createState(now, undefined), X, 0) === 1)
}

console.log('noteResult（失败率信号用）')
{
  const s = createState(now, undefined)
  check('初始为 0', (s.failures ?? 0) === 0 && noteResult(s, { isError: false }) === 0)
  check('成功不计', noteResult(s, { isError: false }) === 0)
  check('失败累加', noteResult(s, { isError: true }) === 1)
  check('连续失败累加', noteResult(s, { isError: true }) === 2)
  // 取不到结果时宁可少算：未知 ≠ 失败
  check('空结果不计', noteResult(s, {}) === 2)
  check('undefined 不计', noteResult(s, undefined) === 2)
  check('null 不计', noteResult(s, null) === 2)
  check('老状态对象没有 failures 也能用', noteResult({}, { isError: true }) === 1)
}

console.log('noteToolArtifact（产物主口径：成功 write/edit 即算产出）')
{
  const s = createState(now, undefined)
  const t1 = now + 10 * 60_000
  check('write 成功 → 刷新', noteToolArtifact(s, { name: 'write' }, {}, t1) === true && s.artifactChangedAt === t1)
  const t2 = now + 20 * 60_000
  check('edit 成功 → 刷新', noteToolArtifact(s, { name: 'edit' }, {}, t2) === true && s.artifactChangedAt === t2)
  const t3 = now + 30 * 60_000
  check('write 失败 → 不算产出', noteToolArtifact(s, { name: 'write' }, { isError: true }, t3) === false && s.artifactChangedAt === t2)
  const t4 = now + 40 * 60_000
  check('read 不刷新', noteToolArtifact(s, { name: 'read' }, {}, t4) === false && s.artifactChangedAt === t2)
  check('pwsh 不刷新（改文件走 write/edit）', noteToolArtifact(s, { name: 'pwsh' }, {}, t4) === false)
  check('exec 为 undefined 不炸', noteToolArtifact(s, undefined, {}, t4) === false)
}

console.log('回归：Sherlock 形态（写 22 个文件但一个都不进 loot/）')
{
  // session-7b0cd540 实测：33 分钟通关 17/17，产出 22 个文件（sherlock-work/ + 技能卡），
  // 但 loot/ 目录全程没动。旧口径下 msSinceArtifactChange 涨到 31.8 分钟（阈值 45），
  // 只差 13 分钟就误报 stall。新口径下必须压到很小。
  const loot = join(tmpdir(), `htb-struggle-loot-${process.pid}`)
  mkdirSync(loot, { recursive: true })
  const s = createState(now, artifactMtimeMs(loot))
  // 33 分钟内每 3 分钟写一个文件（Sherlock 的真实节奏），loot 目录始终不变
  for (let i = 1; i <= 11; i++) {
    const t = now + i * 3 * 60_000
    noteCall(s, { name: 'write', arguments: { file_path: `C:\\work\\sasyns\\sec${i}.py` } })
    noteToolArtifact(s, { name: 'write' }, {}, t)
    noteArtifact(s, artifactMtimeMs(loot), t)
  }
  const o = buildObservation(s, now + 33 * 60_000)
  check('产物静默被压到 < 一次写入间隔', o.msSinceArtifactChange < 4 * 60_000, `实得 ${(o.msSinceArtifactChange / 60_000).toFixed(1)}min`)
  check('33 分钟时不会误报 stall', o.msSinceArtifactChange < 45 * 60_000)
  rmSync(loot, { recursive: true, force: true })
}

console.log('noteArtifact')
{
  const s = createState(now, 1000)
  check('mtime 不变 → false', noteArtifact(s, 1000, now + 60_000) === false)
  check('mtime 变了 → true', noteArtifact(s, 2000, now + 120_000) === true)
  check('changedAt 已刷新', s.artifactChangedAt === now + 120_000)
  check('undefined 不覆盖已知值', noteArtifact(s, undefined, now + 180_000) === false && s.artifactMtime === 2000)
}

console.log('buildObservation')
{
  const s = createState(now, undefined)
  s.identicalCount = 4
  s.calls = 7
  s.failures = 3
  s.artifactChangedAt = now + 30_000
  const o = buildObservation(s, now + 90_000)
  check('相同调用次数', o.consecutiveIdenticalCalls === 4)
  check('产物静默时长', o.msSinceArtifactChange === 60_000)
  check('会话时长', o.elapsedMs === 90_000)
  check('工具调用总数', o.toolCalls === 7)
  check('工具失败总数', o.toolFailures === 3)
  check('calls 缺省当 0（老状态对象不炸）', buildObservation({ identicalCount: 0, artifactChangedAt: now, startedAt: now }, now).toolCalls === 0)
  check('failures 缺省当 0（老状态对象不炸）', buildObservation({ identicalCount: 0, artifactChangedAt: now, startedAt: now }, now).toolFailures === 0)
  check('msSinceOutputLow 未在低产时 = undefined（缺省不炸）',
    buildObservation({ identicalCount: 0, artifactChangedAt: now, startedAt: now }, now).msSinceOutputLow === undefined)
  check('msSinceOutputLow 有起点时 = 已持续毫秒',
    buildObservation({ identicalCount: 0, artifactChangedAt: now, startedAt: now, outputLowSince: now - 20 * 60_000 }, now).msSinceOutputLow === 20 * 60_000)
}

// ---------------------------------------------------------------------------
// 🔴 2026-10-10 阈值标定配套：`output` 的**持续性**由状态机累积（判据在 struggle.js）。
//    验收口径：尖峰式低产（<15min）不报；持续 ≥15min 报；密度恢复后重新计时。
// ---------------------------------------------------------------------------
console.log('产出比持续性：状态机口径（2026-10-10 加）')
{
  const MIN = 60_000
  const s = createState(now, undefined)
  s.startedAt = now - 90 * MIN // 会话已跑 90 分钟
  s.calls = 2 // 只发过 2 次调用 ⇒ 密度 ≈1.3/h，稳稳低于 12
  // 推进到 now+min：先按当前密度推进低产起点，再组装快照求判定，最后记一次调用。
  const tick = (min) => {
    const t = now + min * MIN
    const sustained = noteOutputLow(s, buildObservation(s, t), DEFAULT_THRESHOLDS, t)
    const verdict = assessStruggle(buildObservation(s, t), DEFAULT_THRESHOLDS)
    noteCall(s, { name: 'ssh_exec', arguments: { command: `probe-${min}` } })
    return { verdict, sustained }
  }
  const a = tick(0)
  check('① 尖峰：首次观测即低产 → 起点=本次，不报（持续性从 0 起算）',
    !a.verdict.hits.includes('output') && a.sustained === 0)
  const b = tick(12)
  check('① 尖峰：低产 12 分钟（<15）→ 仍不报', !b.verdict.hits.includes('output') && b.sustained === 12 * MIN)
  const c = tick(16)
  check('② 持续：低产 16 分钟（≥15）→ 报 output', c.verdict.hits.includes('output'))
  check('② 持续性不改变等级语义（output 仍只 checkpoint）',
    c.verdict.action === ACTIONS.checkpoint && !c.verdict.hits.includes('stall'))
  // 密度恢复 ⇒ 低产起点被清空（下一次低产必须重新攒 15 分钟）
  s.calls = 200
  const d = tick(20)
  check('密度恢复 → 不报且清空低产起点', !d.verdict.hits.includes('output') && s.outputLowSince === undefined)
  s.calls = 3
  const e = tick(25)
  check('再次低产 → 重新计时（5 分钟不报）', !e.verdict.hits.includes('output') && e.sustained === 0)
}

console.log('接线：apply() 注册监听并落盘')
{
  const logPath = join(dir, 'watch.jsonl')
  // 数组存监听器（与真实 Cordis 一致：同名事件可以有多个 handler）。
  // 2026-10-25：原来是 Map<name, fn>，后注册的会**静默覆盖**前一个 —— 每新增一个
  // post-execute 模块就要回来改这个测试。改成数组后，`[0]` 永远是先注册的
  // struggle-watch，新增模块不会再让本测试失真。
  const listeners = new Map()
  const ctx = {
    on: (name, fn) => {
      const arr = listeners.get(name) ?? []
      arr.push(fn)
      listeners.set(name, arr)
      return () => {}
    },
    tools: { guard: () => () => {}, register: () => () => {} },
    skills: { registerProvider: () => {} },
  }
  await applyPlugin(ctx, {
    skillsEnabled: false,
    struggleLogPath: logPath,
    struggleArtifactDir: loot,
    // 本套只测 struggle-watch：关掉同样挂 tools/post-execute 的模块，
    // 避免它们往临时目录里写观测日志（handler 顺序已由上面的数组保证）。
    contextHygiene: false,
    errorClassify: false,
    autoState: false,
  })
  check('注册了 tools/post-execute', Array.isArray(listeners.get('tools/post-execute')) && listeners.get('tools/post-execute').length > 0)

  const handler = listeners.get('tools/post-execute')[0]
  const agent = { id: 'sess-1' }
  const exec = (cmd) => ({ name: 'ssh_exec', arguments: { command: cmd }, agent })
  const run = (cmd, result = {}) => handler(exec(cmd), result, async () => ({ kind: 'allow' }))

  await run('a')
  await run('a')
  // 第 3 次是"工具真报错"（带结构化 code）；第 4 次是"被守卫拦下"（isError 但无 info）
  await run('b', { isError: true, error: { message: 'boom', info: { name: 'X', code: 'E_BOOM' } } })
  await run('b', { isError: true, error: { message: '操作安全红线 [mkfs]：…' } })
  const lines = readFileSync(logPath, 'utf8').trim().split('\n').map(l => JSON.parse(l))
  check('落了 4 行', lines.length === 4)
  check('行字段齐全', ['ts', 'agent', 'tool', 'toolCalls', 'toolFailures', 'failed', 'errorCode', 'msSinceArtifactChange', 'elapsedMs', 'hits', 'action'].every(k => k in lines[0]))
  // 🔴 2026-10-10：`identical` 已从日志行移除（退化字段，全语料分布 {1: 20298, 2: 3}，
  //    几乎恒为 1、不携带信息；真正有信息量的是 windowRepeat）。
  //    原断言读的是日志字段，字段没了；这里改为 ① 盯住它别被加回来，② 用窗口口径
  //    验证"相同调用确实在累加"。连续链长的**重置**语义由上面的 noteCall 用例守护
  //    （'参数不同则重置' / '换工具则重置' / '连续相同累加'）。
  check('日志不再带退化字段 identical', !('identical' in lines[0]))
  check('相同调用计数正确：a,a → windowRepeat 1→2', lines[0].windowRepeat === 1 && lines[1].windowRepeat === 2)
  check('累计调用数写进日志', lines[0].toolCalls === 1 && lines[3].toolCalls === 4)
  check('失败数只增不减', lines[0].toolFailures === 0 && lines[1].toolFailures === 0 && lines[2].toolFailures === 1 && lines[3].toolFailures === 2)
  check('failed 标记当次', lines[0].failed === false && lines[2].failed === true)
  check('成功的调用 errorCode 为 null', lines[0].errorCode === null)
  check('真报错带 errorCode', lines[2].errorCode === 'E_BOOM')
  check('守卫拒绝的 errorCode 为 null（可据此与真报错区分）', lines[3].errorCode === null && lines[3].failed === true)
  check('健康时 action=continue', lines.every(l => l.action === 'continue'))

  // 无 agent 的调用（直接 ctx.tools.execute）不观测
  await handler({ name: 'ssh_exec', arguments: { command: 'a' } }, {}, async () => ({ kind: 'allow' }))
  check('无 agent 不落盘', readFileSync(logPath, 'utf8').trim().split('\n').length === 4)

  // 下一次调用必须 delegate，不能吞掉下游决策
  const decision = await handler(exec('c'), {}, async () => ({ kind: 'block', feedback: 'x' }))
  check('不吞下游决策', decision.kind === 'block' && decision.feedback === 'x')
}

console.log('闸：stop 触发后拒绝启动长任务（2026-10-25）')
{
  // Watcher 实测：239 分钟 struggle 正确触发 stop，agent 在推理里复述了规则，
  // 然后 "start the rockyou crack ... as a detached process" 又跑了 2 小时。
  // 通知可以被一句"我再跑一会儿"覆盖，闸不行。
  const guards = []
  const listeners = new Map()
  const ctx = {
    on: (name, fn) => {
      const arr = listeners.get(name) ?? []
      arr.push(fn)
      listeners.set(name, arr)
      return () => {}
    },
    tools: { guard: (fn) => { guards.push(fn); return () => {} }, register: () => () => {} },
    skills: { registerProvider: () => {} },
  }
  await applyPlugin(ctx, {
    skillsEnabled: false,
    struggleLogPath: join(dir, 'gate.jsonl'),
    struggleArtifactDir: loot,
    // 注意键名：index.js 透传的是 `struggleThresholds`，不是 `thresholds`
    //（直接调 apply 才用 `thresholds`）。这里走 applyPlugin，所以必须用前者。
    struggleThresholds: { stallMinutes: 0 },   // 任何间隔都算 stall → 立刻 stop
    contextHygiene: false,
    errorClassify: false,
    autoState: false,
  })
  check('注册了 guard', guards.length >= 1)
  // index.js 的挂载顺序是 guard → ask-guard → wp-guard → struggle-watch，
  // 所以停止协议闸是**最后一个**。取 guards[0] 会拿到红线守卫，测出来永远是"放行"。
  const guard = guards[guards.length - 1]
  const agent = { id: 'gate-1' }
  const handler = listeners.get('tools/post-execute')[0]
  const okResult = { content: [{ type: 'text', text: 'ok' }] }
  const allow = async () => ({ kind: 'accept' })

  await handler({ name: 'ssh_exec', arguments: { command: 'ls' }, agent }, okResult, allow)

  const deny = guard({ name: 'ssh_exec', arguments: { command: 'nohup hashcat -m 3200 h w > log 2>&1 &' }, agent })
  check('拦截 nohup 长任务', typeof deny === 'string' && deny.includes('停止协议'))
  check('拒绝理由给出解封路径', typeof deny === 'string' && deny.includes('frontier') && deny.includes('htb_fact'))
  check('短命令放行', guard({ name: 'ssh_exec', arguments: { command: 'ls -la /tmp' }, agent }) === undefined)
  check('只读 hashcat 放行', guard({ name: 'ssh_exec', arguments: { command: 'hashcat -m 3200 h --show' }, agent }) === undefined)
  check('非执行工具不拦', guard({ name: 'read', arguments: { command: 'nohup x &' }, agent }) === undefined)

  // 解封：写一条 frontier dead
  await handler({ name: 'htb_frontier', arguments: { op: 'dead', id: 'i1' }, agent }, okResult, allow)
  check('写 dead 后解封', guard({ name: 'ssh_exec', arguments: { command: 'nohup hashcat -m 3200 h w &' }, agent }) === undefined)

  // 再触发一次 stop 后重新上锁（证明解封不是永久关闭）
  await handler({ name: 'ssh_exec', arguments: { command: 'ls' }, agent }, okResult, allow)
  check('再次 stall 后重新上锁', typeof guard({ name: 'ssh_exec', arguments: { command: 'Start-Sleep -Seconds 900' }, agent }) === 'string')
}

console.log('接线：struggleWatch:false 不注册')
{
  const listeners = new Map()
  const ctx = {
    on: (name, fn) => {
      const arr = listeners.get(name) ?? []
      arr.push(fn)
      listeners.set(name, arr)
      return () => {}
    },
    tools: { guard: () => () => {}, register: () => () => {} },
    skills: { registerProvider: () => {} },
  }
  await applyPlugin(ctx, { skillsEnabled: false, struggleWatch: false, contextHygiene: false, errorClassify: false, autoState: false })
  check('没有 post-execute 监听', listeners.get('tools/post-execute') === undefined)
}

console.log(failed === 0 ? '\n✅ 监视器测试全部通过' : `\n❌ ${failed} 条失败`)
process.exit(failed === 0 ? 0 : 1)
