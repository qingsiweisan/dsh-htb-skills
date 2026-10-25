/**
 * dsh-htb-skills/struggle-watch — 把 {@link assessStruggle} 接到真实会话上。
 *
 * 当前是**记录模式**：只在每次工具调用后往 JSONL 写一条观测，不往会话里注入
 * 任何东西。理由：信号前三条照抄社区，第四、五条来自本项目自己的数据，但
 * **阈值必须来自你自己的数据** —— 直接开干预就是又一次"用没证据的东西防没证据
 * 的问题"。
 *
 * 干预模式要等两件事：① 拿到几台机器的分布定阈值；② 需要一个带 source 标签的
 * 注入通道（`createUserMessage`），那会给本插件引入 `@deepseek-ai/dsh-llm`
 * 依赖 —— 与 sherlock-tools.js 里"不给部署增加包依赖解析面"的取舍冲突，
 * 所以要单独决定。
 *
 * 外部产物口径（🔴 2026-09-27 放宽，见 {@link noteToolArtifact}）：
 *   1. **工具流**：成功的 `write` / `edit` 即算产出（主口径）；
 *   2. **文件系统**：`artifactDir` 下**有界递归**扫描到的文件 mtime 取最大（兜底，
 *      覆盖 subagent / 远程进程落盘这类不经过本会话工具流的情况）。递归上界与
 *      排除清单见 {@link artifactMtimeMs}（🔴 排除 `.evidence-ledger` 是必须项）。
 *   两者取较新者。原先只有第 2 条、且 `artifactDir` 默认 `loot/`，
 *   在一次 33 分钟通关的 Sherlock 上差 13 分钟就误报 `stall`。
 *
 * 🔴 2026-10-10 两处修正（来自独立交验）：
 *
 *   1. **状态键从"agent 对象"改为"agent.id 字符串"，并新增 `segment` 字段。**
 *      原用 `WeakMap` 以 `exec.agent` **对象**为键；插件重载 / 会话恢复会给同一个
 *      agent id 造出**新对象**，于是状态被静默重置。实测 17 个 agent 出现 23 次
 *      `elapsedMs` 回落、20 次 `toolCalls` 回落 ⇒ 那些会话的"会话相对时间"不可比，
 *      而且"toolCalls 极小却 elapsed 极大"那 5 行**是重置伪影，不是空想空转**。
 *      现在每次重建状态会递增 `segment` 并写进日志 —— 于是「(agent, segment)」
 *      就是**状态段**，也正是统计要用的**事件口径**的切分键。
 *
 *   2. **行计数 ≠ 事件计数。** `stop` 在日志里出现过 2,019 **行**，但按 (agent,
 *      segment) 切分只有 **24 个独立事件**（膨胀 84.1×；`budget` 更达 115.7×），
 *      因为 `stop` 是 latch 状态、每条后续调用都会重复落盘。**任何"判定过 N 次"
 *      的说法都必须先按状态段去重**，并且**带上快照 cutoff** —— 该文件是活的
 *      （交验期间 5 次采样从 20,092 涨到 20,397 行），任何总数离开时点就没有意义。
 *
 *   3. **`output` 的持续性由本层累积**（2026-10-10 阈值标定的配套改动）：
 *      `noteOutputLow` 维护"低产已持续多久"，快照多一个 `msSinceOutputLow`
 *      （同时落进 JSONL，便于日后离线复验）。判据与阈值见 `struggle.js` 的
 *      `outputSustainMinutes` / `isLowOutput`。
 *
 * 🔴 2026-10-10 第三组修正：**{@link artifactMtimeMs} 的两处静默失效**（`loot/` 分层
 *    之后才暴露；来源同上，独立交验实测）。原实现是"非递归 + 只统计 `entry.isFile()`"，
 *    在扁平 `loot/` 下能用，一旦按 `loot/<machine>/` 分层就**同时**踩两个坑：
 *
 *   1. **非递归 ⇒ 看不见子目录 ⇒ 误报 `stall`。** NTFS 上改**子目录内**的文件
 *      **不会**更新父目录 mtime（只有增删子目录的**目录项**才会）。所以一旦 `loot/`
 *      根级只剩少数台账（分层之后就是这个状态），在 `loot/<machine>/` 里写 100 个文件
 *      它**完全看不见** ⇒ 产物信号假性静默 ⇒ 误报 `stall`。这与 2026-09-27 那次
 *      "33 分钟通关被误报、只差 13 分钟"是**同一根因**。更糟的是：根级 0 文件时它
 *      返回 `undefined` ⇒ `noteArtifact`（L212 的 `mtime === undefined` 早退）**直接
 *      丢弃观测** ⇒ 兜底口径**彻底死掉，且不写任何日志、不报任何错**。
 *
 *   2. 🔴 **排除清单是必须项，不是优化项。** 扫描一旦变递归，`.evidence-ledger/`
 *      会在**每次** `evidence_add` / `htb_coverage` / `htb_traces` 调用时被写入
 *      （`index/claims/coverage/verdicts.jsonl` + `objects/<sha>`）⇒ 只要会话里调用过
 *      任何一次证据工具，产物 mtime 就被刷新 ⇒ `artifactChangedAt` **永远更新** ⇒
 *      **`stall` 永不触发**。`loot/<machine>/traces/` 同病（`htb_traces` 会写它）。
 *      这与"悬空 bundle 条目被静默跳过""`link:` 未落地 ⇒ 静默不挂载"是**同一族静默
 *      失效模式**：闸全绿、日志无错、行为全错。
 *
 *    所以本函数改为**有界递归 depth=2 + 排除清单**（{@link DEFAULT_IGNORE}）。
 *    `artifactDir` 仍指向 `<cwd>/loot` —— **不改指向**（指向 `_archive` 会让归档伪装成
 *    产出；指向 `loot/_audit` 会让审计伪装成产出；指向某个 `loot/<machine>/` 则换个
 *    机器就失效，而 `cfg.artifactDir` 是启动期配置，不随机器变）。
 */

import { randomUUID } from 'node:crypto'
import { appendFileSync, readdirSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { DEFAULT_THRESHOLDS, assessStruggle, isLowOutput } from './struggle.js'

/** Stable Cordis plugin name. */
export const name = 'htb-struggle-watch'

/** 默认观测日志。 */
export const DEFAULT_LOG_PATH = join(homedir(), '.dsh', 'htb-struggle.jsonl')

/**
 * 递归扫描时**必须**跳过的目录名（照 basename 匹配，与深度无关）。
 *
 * 🔴 逐个理由（缺一条就会重新打开一个静默失效）：
 *   - `.evidence-ledger`：**必须项**。`evidence_add` / `htb_coverage` / `htb_traces`
 *     每次都写它 ⇒ 不排除 = 产物 mtime 永久新鲜 = `stall` 永不触发。
 *   - `traces`：`htb_traces` 的工作路径（`loot/<machine>/traces/<agent>.md`，
 *     工具层硬编码）⇒ 与账本**同病**，一调用就刷新。
 *   - `.evidence-reports`：封存报告目录，同样是**工具/人工元动作**的副产物，
 *     不代表"我正在产出作战结论"。
 *   - `_archive` / `_audit` / `_tools`：归档与审计是**人工元动作**，不该伪装成
 *     "我正在产出"。否则"我在整理归档"会把 `stall` 推后 ⇒ 归档动作本身在掩盖
 *     卡住的事实。
 */
export const DEFAULT_IGNORE = Object.freeze([
  '.evidence-ledger',
  '.evidence-reports',
  '_archive',
  '_audit',
  '_tools',
  'traces',
])

/** 递归下钻的默认层数：`loot/`(0) → `loot/<machine>/`(1) → `loot/<machine>/shots/`(2)。 */
export const DEFAULT_ARTIFACT_MAX_DEPTH = 2

/**
 * 取目录下（**有界递归**）最新的文件 mtime。
 *
 * 口径：`dir` 自身为第 0 层，向下最多下钻 `maxDepth` 层目录；因此可见的文件最深在
 * 第 `maxDepth` 层（`maxDepth=2` ⇒ `loot/<machine>/notes.md` 与
 * `loot/<machine>/shots/x.png` 都可见，`loot/a/b/c/` 里的看不见）。设上界是为了
 * 避免扫进 `chal-115/` 那种大目录树后每轮 `readdir` 变慢（实测当前最深 2 层，够用）。
 *
 * ⚠️ 兜底行为（回归断言 ④ 盯着它）：**整个目录树里一个可见文件都没有**（目录不存在 /
 * 读不动 / 空目录 / 只有被排除的目录）时返回 **`undefined`**，不抛错、不返回 0。
 * 这不是"没问题"，而是"**兜底口径这一轮没有观测到任何东西**"：
 *   - {@link noteArtifact} 对 `undefined` **早退且不覆盖已知值** ⇒ 已经建立过产物
 *     基线的会话不会被空目录清空；
 *   - 但会话**第一次**观测就是 `undefined` 时，`createState` 会把 `artifactChangedAt`
 *     设为 `now`（即"从会话起点算静默"）⇒ 兜底口径这一路等于**不参与**，只剩主口径
 *     （成功的 `write`/`edit`）在撑。所以 `loot/` 根级长期 0 文件是**要避免的状态**，
 *     不是可以依赖的状态。
 * @param dir - 目录路径。
 * @param opts - `{ maxDepth?, ignore? }`；省略用 {@link DEFAULT_ARTIFACT_MAX_DEPTH} /
 *   {@link DEFAULT_IGNORE}。
 * @returns 最新 mtime 的毫秒数；无可见文件返回 undefined。
 */
export function artifactMtimeMs(dir, opts = {}) {
  if (!dir) return undefined
  const maxDepth = Number.isFinite(opts?.maxDepth) && opts.maxDepth >= 0
    ? opts.maxDepth
    : DEFAULT_ARTIFACT_MAX_DEPTH
  const skip = new Set(opts?.ignore ?? DEFAULT_IGNORE)
  let newest
  const walk = (d, depth) => {
    let entries
    try {
      entries = readdirSync(d, { withFileTypes: true })
    } catch {
      return // 单个子目录读不到就跳过，不影响其余分支
    }
    for (const entry of entries) {
      if (skip.has(entry.name)) continue
      const p = join(d, entry.name)
      if (entry.isDirectory()) {
        if (depth < maxDepth) walk(p, depth + 1)
        continue
      }
      // 只统计**常规文件**：符号链接 / 设备 / FIFO 一律跳过（与原实现的
      // `entry.isFile()` 语义保持一致，本次只改"递归"与"排除清单"两件事）。
      if (!entry.isFile()) continue
      try {
        const { mtimeMs } = statSync(p)
        if (newest === undefined || mtimeMs > newest) newest = mtimeMs
      } catch { /* 单个文件读不到就跳过 */ }
    }
  }
  walk(dir, 0)
  return newest
}

/** 深度键排序后序列化，用于判断"两次调用是不是同一个"。 */
function canonicalize(value) {
  const sort = (v) => {
    if (Array.isArray(v)) return v.map(sort)
    if (v !== null && typeof v === 'object') {
      const out = {}
      for (const key of Object.keys(v).sort()) out[key] = sort(v[key])
      return out
    }
    return v
  }
  try {
    return JSON.stringify(sort(value))
  } catch {
    return String(value)
  }
}

/**
 * 建一个 agent 的观测状态。
 * @param now - 当前毫秒时间戳。
 * @param artifactMtime - 初始的产物 mtime。
 * @returns 状态对象。
 */
export function createState(now, artifactMtime) {
  return {
    startedAt: now,
    lastKey: null,
    identicalCount: 0,
    /** 最近 N 次调用的 key 序列（滑动窗口，算"窗口内重复"用，见 noteCall）。 */
    recentKeys: [],
    /** 窗口内同一 key 出现的最大次数。 */
    windowRepeatCount: 0,
    /** 本会话累计工具调用次数 —— 产出比信号（{@link assessStruggle} 的 `output`）用。 */
    calls: 0,
    /** 本会话累计**失败**的工具调用次数 —— 失败率信号（`failures`）用。 */
    failures: 0,
    /**
     * "低产状态"的起点（毫秒时间戳）；密度回到阈值以上时清空。
     *
     * 🔴 2026-10-10 新增。产出比（`output`）的持续性判据用 —— 瞬时密度会抖动
     *    （见 `struggle.js` 的 `outputSustainMinutes`），所以"已经低产了多久"必须
     *    由观察层按调用序列累积，不能由快照单独算出来。缺省 `undefined` = 不低产。
     */
    outputLowSince: undefined,
    artifactMtime,
    artifactChangedAt: artifactMtime === undefined ? now : now,
  }
}

/**
 * 记一次工具调用，推进"相同调用"链并累加总数。
 *
 * 同时维护**滑动窗口**（最近 `windowSize` 次调用的 key）：只算连续相同时，
 * 打靶场景的重复（夹一次读台账、或 A/B/A/B 摆动）永远抓不到 —— 实测 3271 条
 * 观测里 `repeat` 零命中。窗口计数与连续计数取较大者作为 `repeat` 判据。
 * @param state - {@link createState} 的状态。
 * @param exec - 工具调用。
 * @param windowSize - 滑动窗口大小；省略用 8。
 * @returns 更新后的连续相同次数（保持原返回契约，窗口计数在 `state.windowRepeatCount`）。
 */
export function noteCall(state, exec, windowSize = 8) {
  const key = `${exec?.name}\u0000${canonicalize(exec?.arguments)}`
  state.identicalCount = state.lastKey === key ? state.identicalCount + 1 : 1
  state.lastKey = key
  // 滑动窗口：测试里可能手工构造 state 字面量，所以这里兜底初始化。
  if (!Array.isArray(state.recentKeys)) state.recentKeys = []
  state.recentKeys.push(key)
  const size = Number.isFinite(windowSize) && windowSize > 0 ? windowSize : 8
  while (state.recentKeys.length > size) state.recentKeys.shift()
  let max = 0
  for (const k of state.recentKeys) {
    let n = 0
    for (const other of state.recentKeys) if (other === k) n += 1
    if (n > max) max = n
  }
  state.windowRepeatCount = max
  state.calls = (state.calls ?? 0) + 1
  return state.identicalCount
}

/**
 * 记一次工具调用的**结果**，累加失败数。
 *
 * `tools/post-execute` 的 `result` 是 `ToolExecutionResult`：
 *   `{ isError: false, value }` | `{ isError: true, error }`
 * 所以失败判据就是 `result.isError === true`。取不到（例如测试里传 `{}`）
 * 一律**不计**失败 —— 宁可少算，不可把"未知"当成"失败"。
 *
 * ⚠️ 已知特性（2026-09-27 实测）：**守卫拒绝也会被算成失败**。因为守卫拒绝走的是
 * `tools/index.ts` 里 `denialInfo === undefined` 那条路径 —— 只有 pre-execute 的
 * `deny` 决策才带 `info`，`ctx.tools.guard()` 返回的拒绝不带。实测日志：
 *   `{"toolCalls":2,"toolFailures":1,"failed":true}` ← 就是一次被拦的 mkfs 探针。
 * 真实会话里守卫拒绝约 0.2%（Layover 461 次调用里 1 次），远低于 15% 阈值，不构成
 * 误报。但**将来若 permission-rules 开大量 deny 规则**，`failures` 会虚高 ——
 * 届时用日志里的 `errorCode` 区分（守卫拒绝为 null，工具真报错通常带 code）。
 * @param state - {@link createState} 的状态。
 * @param result - 该次调用的调度结果。
 * @returns 累计失败次数。
 */
export function noteResult(state, result) {
  if (result?.isError === true) state.failures = (state.failures ?? 0) + 1
  return state.failures ?? 0
}

/**
 * 推进"低产状态"的起点，返回它已持续多久（毫秒）。
 *
 * 🔴 2026-10-10 新增。`output` 的瞬时密度会行级抖动（189 个命中行里 21 行落在阈值
 *    8% 以内），所以 `assessStruggle` 改判据为"**持续** ≥ `outputSustainMinutes`"，
 *    而"持续了多久"只有观察层知道。判据本身复用 {@link isLowOutput}，避免两边各写
 *    一份而漂移。
 *
 * 语义：
 *   - 低产 且 还没有起点 ⇒ 起点 = `now`，返回 0（**第一次观望不算持续**）；
 *   - 低产 且 已有起点   ⇒ 返回值 = `now - 起点`（单调增，直到密度恢复）；
 *   - 不低产            ⇒ 清空起点，返回 0（下一轮重新攒）。
 * @param state - {@link createState} 的状态。
 * @param obs - 当前快照（用 `elapsedMs` / `toolCalls` 判低产）。
 * @param thresholds - 覆盖 {@link DEFAULT_THRESHOLDS} 的任意字段。
 * @param now - 当前时间。
 * @returns 低产已持续的毫秒数（未在低产 = 0）。
 */
export function noteOutputLow(state, obs, thresholds, now) {
  if (!isLowOutput(obs, thresholds)) {
    state.outputLowSince = undefined
    return 0
  }
  if (typeof state.outputLowSince !== 'number') state.outputLowSince = now
  return now - state.outputLowSince
}

/**
 * 会产出"外部产物"的工具。用于 {@link noteToolArtifact}。
 * 只收 `write` / `edit` —— 它们必然在磁盘上留下东西。
 */
export const ARTIFACT_TOOLS = new Set(['write', 'edit'])

/**
 * 记一次**工具产出**：成功的 write/edit 即视为"有产物"。
 *
 * 🔴 2026-09-27 由实测数据加入。原先只盯 `artifactDir`（默认 `loot/`）的 mtime，
 * 结果在一次 **33 分钟通关 17/17 的 Sherlock**（session-7b0cd540）上，
 * `msSinceArtifactChange` 一路涨到 **31.8 分钟**（阈值 45）——**只差 13 分钟就会
 * 误报 `stall`**。原因是那次会话产出了 **22 个文件**（`sherlock-work/sasyns/` 20 个
 * + 技能卡 2 个），但**一个都没写进 `loot/`**：Sherlock 的工作形式天然不写
 * `loot/<machine>.md`。
 *
 * 所以口径从"loot 目录动过"放宽为"**产出过任何东西**"，两个来源取较新者：
 *   - 工具流：成功的 `write` / `edit`（本函数）
 *   - 文件系统：`artifactDir` 的 mtime（{@link noteArtifact}，兜住"由 subagent
 *     或远程进程落盘"这类不经过本会话工具流的情况）
 * @param state - {@link createState} 的状态。
 * @param exec - 工具调用。
 * @param result - 该次调用的调度结果（失败的写入不算产出）。
 * @param now - 当前时间。
 * @returns 是否刷新了产物时间。
 */
export function noteToolArtifact(state, exec, result, now) {
  if (!ARTIFACT_TOOLS.has(exec?.name)) return false
  if (result?.isError === true) return false
  state.artifactChangedAt = now
  return true
}

/**
 * 记一次产物 mtime 观测；变了就刷新 `artifactChangedAt`。
 * @param state - 状态。
 * @param mtime - 本次观测到的 mtime。
 * @param now - 当前时间。
 * @returns 是否发生了变化。
 */
export function noteArtifact(state, mtime, now) {
  if (mtime === undefined) return false
  if (state.artifactMtime === undefined) {
    state.artifactMtime = mtime
    state.artifactChangedAt = now
    return false
  }
  if (mtime !== state.artifactMtime) {
    state.artifactMtime = mtime
    state.artifactChangedAt = now
    return true
  }
  return false
}

/**
 * 由状态组装 {@link assessStruggle} 要的观测快照。
 * @param state - 状态。
 * @param now - 当前时间。
 * @returns 观测快照。
 */
export function buildObservation(state, now) {
  return {
    consecutiveIdenticalCalls: state.identicalCount,
    windowRepeatCount: state.windowRepeatCount ?? 0,
    msSinceArtifactChange: now - state.artifactChangedAt,
    elapsedMs: now - state.startedAt,
    toolCalls: state.calls ?? 0,
    toolFailures: state.failures ?? 0,
    // 低产已持续的毫秒数（`output` 的持续性判据用）。**没在低产时给 undefined**，
    // 而 `assessStruggle` 对 undefined 取 Infinity —— 但那时 isLowOutput 也是 false，
    // 所以不会因此误命中；反之老状态对象（没有这个字段）也不会被降级。
    msSinceOutputLow: typeof state.outputLowSince === 'number' ? now - state.outputLowSince : undefined,
  }
}

/** 一行观测日志。 */
function logLine(path, row) {
  try {
    appendFileSync(path, `${JSON.stringify(row)}\n`, 'utf8')
  } catch { /* 日志写不动不能影响会话 */ }
}

/**
 * 挂载监视器。
 *
 * Config:
 *   - `enabled`（默认 true）
 *   - `logPath`（默认 {@link DEFAULT_LOG_PATH}）：观测 JSONL。
 *   - `artifactDir`（默认 `<cwd>/loot`）：外部产物目录（兜底口径，**有界递归 +
 *     排除清单**见 {@link artifactMtimeMs}；不改指向，理由见文件头）。
 *   - `thresholds`：覆盖 {@link DEFAULT_THRESHOLDS}。
 * @param ctx - 宿主插件上下文。
 * @param config - 见上。
 */
/** 信号 id → 人话，用于注入通知。 */
const SIGNAL_LABEL = {
  stall: '产物静默超过阈值（说明这几轮没学到东西）',
  budget: '本会话已超过时长上限',
  output: '产出比过低（调用很多、产出很少）',
  failures: '工具失败率过高',
  repeat: '同一个调用反复出现',
}

/**
 * 停止协议闸（2026-10-25 新增）—— 长任务启动模式。
 *
 * 为什么需要它（Watcher 实测）：那一场 239 分钟时 struggle 正确触发了 `stop`，
 * 文案明确写着"不要用『再试一个变体』续命"。agent 在推理里**复述了这条规则**
 * （"the instruction says don't keep burning this session"），然后：
 *
 *     "I'll write the loot, then **start the rockyou crack on Admin's hash
 *      as a detached process**"
 *
 * 又跑了 2 小时。结论：**通知可以被一句"我再跑一会儿"覆盖，闸不行。**
 *
 * 设计边界（刻意收窄，避免误伤正常等待）：
 *   - 只拦**长任务启动**，不拦短命令（`curl -I` / `ls` / 单次探测照常）
 *   - 只拦这五类：nohup 后台、Start-Process、hashcat/john 爆破、≥10 分钟等待、--daemon
 *   - 只读的 `hashcat --show/--status/-I` 放行（那是看结果，不是起任务）
 *   - 解封只需一条 `frontier dead` 或 `htb_fact add` —— 也就是"先说你学到了什么"
 */
export const LONG_JOB_PATTERNS = [
  { id: 'nohup-bg', why: '后台长任务（nohup … &）', test: (c) => /\bnohup\b[\s\S]*&/.test(c) },
  { id: 'start-process', why: '后台进程（Start-Process）', test: (c) => /\bStart-Process\b/i.test(c) },
  {
    id: 'cracking',
    why: '口令爆破（hashcat / john）',
    test: (c) => /\b(hashcat|john)\b/i.test(c) && !/--show|--status|--identify|-I\b|--restore/i.test(c),
  },
  {
    id: 'long-sleep',
    why: '长等待（≥10 分钟）',
    test: (c) => /\bStart-Sleep\s+-Seconds\s+([6-9]\d\d|\d{4,})\b/i.test(c) || /\bsleep\s+([6-9]\d\d|\d{4,})\b/.test(c),
  },
  { id: 'daemon', why: '常驻进程（--daemon）', test: (c) => /--daemon\b/.test(c) },
]

/** 闸只作用于这些执行类工具。 */
const GATE_TOOLS = new Set(['bash', 'pwsh', 'ssh_exec', 'ssh_cluster'])

/** 从工具参数里取命令文本（与 guard.js 的 commandOf 同口径，这里不跨模块依赖）。 */
function commandTextOf(exec) {
  const args = exec?.arguments
  if (typeof args === 'string') return args
  if (args && typeof args === 'object') {
    for (const key of ['command', 'cmd', 'script']) {
      if (typeof args[key] === 'string') return args[key]
    }
  }
  return ''
}

/**
 * 组装闸的拒绝理由：说清状态 + 给三条解封路径。
 * @param state - 会话状态。
 * @param now - 当前时间戳。
 * @returns 拒绝理由。
 */
export function buildGateReason(state, now) {
  const mins = Math.max(0, Math.round((now - state.artifactChangedAt) / 60000))
  return [
    `⛔ 停止协议已触发（stall）：距上次产出 ${mins} 分钟，累计 ${state.calls} 次调用。`,
    '   现在不允许启动新的长任务（爆破 / 后台轮询 / ≥10 分钟等待）。',
    '   三选一即可解封：',
    '     ① 写一条 `htb_frontier op=dead`（带 reasonCode）说明这条路为什么死',
    '     ② 写一条 `htb_fact op=add` 说明你学到了什么',
    '     ③ 直接汇报，把上下文交给新会话',
  ].join('\n')
}

/**
 * 组装**停止协议**通知（level 2 = `stop` 专用）。
 *
 * 形态照 `MessageSource` 的 `form: 'notice'` —— "A one-off account of something
 * that just happened; it supersedes nothing"，正是本场景的语义。
 * @param verdict - {@link assessStruggle} 的判定。
 * @param state - 该 agent 的状态。
 * @param now - 当前时间。
 * @returns `{ text, summary }`；summary 供持久化日志用（≤120 字）。
 */
export function buildNotice(verdict, state, now) {
  const hours = ((now - state.startedAt) / 3_600_000).toFixed(1)
  const idleMinutes = Math.round((now - state.artifactChangedAt) / 60_000)
  const why = verdict.hits.map((hit) => SIGNAL_LABEL[hit] ?? hit).join('；')
  const text = [
    `⛔ 停止协议已触发（Struggle 监视）：${verdict.hits.join(' + ')}`,
    `信号含义：${why}`,
    `本会话已运行 ${hours} 小时，距上次产出 ${idleMinutes} 分钟，累计 ${state.calls} 次工具调用。`,
    '按 preset persona 第 10 条：**不要用"再试一个变体"续命**。动作顺序 ——',
    '① 把结论写进 loot（已排除什么 / 当前最可靠的模型 / 下一步候选）；② 汇报；③ 需要继续就起一个**全新上下文的 subagent**，不要在本会话里接着烧。',
    '（本提示由 dsh-htb-skills 的 Struggle 监视注入；每个状态段只提示一次。）',
  ].join('\n')
  return {
    text,
    summary: `停止协议触发：${verdict.hits.join('+')}（已运行 ${hours}h）`,
  }
}

/**
 * 延迟加载 `@deepseek-ai/dsh-llm` 的 `createUserMessage`。
 *
 * 🔴 刻意**延迟**（而不是顶层 import）：这样本插件不会在加载期多出对 dsh-llm 的
 *    硬依赖 —— 拿不到就退回"只记录、不注入"，与文件头"不给部署增加包依赖解析面"
 *    的取舍一致。
 * @returns 模块；解析失败返回 undefined。
 */
let llmModule
async function loadLlm() {
  if (llmModule === undefined) {
    try {
      llmModule = await import('@deepseek-ai/dsh-llm')
    } catch {
      llmModule = null
    }
  }
  return llmModule ?? undefined
}

/**
 * 自建一条 user 通知消息 —— 只在 `@deepseek-ai/dsh-llm` 解析不到时使用。
 *
 * 🔴 为什么自建是安全的（**已逐行对照 dsh-llm 源码**，2026-10-10）：
 *   `createUserMessage(input)` = `createMessage({ ...input, role: 'user' })`
 *   `createMessage(input)`     = `deepFreeze(structuredClone({ ...input,
 *                                 id: brandString<MessageId>(randomUUID()) }))`
 *   而 `brandString`（brand.ts:16-24）**只是类型层转换，没有运行时校验** ——
 *   所以 `id: randomUUID()` + `role`/`content`/`source` + 冻结，与之等价。
 *
 *   这样做的收益是**不要求部署多一条模块解析路径**：实测从本包 `src/` 解析
 *   `@deepseek-ai/dsh-llm` 是 `ERR_MODULE_NOT_FOUND`（本包 node_modules 下只有
 *   `dsh-skill-filesystem`），与文件头"不给部署增加包依赖解析面"的取舍一致。
 * @param text - 正文。
 * @param summary - 一行摘要（`form: 'notice'` 要求，≤120 字）。
 * @returns 冻结的 user 消息。
 */
function makeUserNotice(text, summary) {
  return Object.freeze({
    id: randomUUID(),
    role: 'user',
    content: Object.freeze([{ type: 'text', text }]),
    source: Object.freeze({ kind: 'struggle-watch', form: 'notice', summary }),
  })
}

/**
 * 挂载监视器。
 *
 * Config:
 *   - `enabled`（默认 true）
 *   - `logPath`（默认 {@link DEFAULT_LOG_PATH}）：观测 JSONL。
 *   - `artifactDir`（默认 `<cwd>/loot`）：外部产物目录（兜底口径，**有界递归 +
 *     排除清单**见 {@link artifactMtimeMs}；不改指向，理由见文件头）。
 *   - `thresholds`：覆盖 {@link DEFAULT_THRESHOLDS}。
 *   - `intervene`（默认 true）：是否开启**干预**（把 `stop` 判定注入会话）。
 *     只注入 level 2（`stop`）—— checkpoint 档不打扰会话。
 *   - `gate`（默认 true）：是否把 `stop` 变成**闸** —— 触发后拒绝启动新的长任务
 *     （爆破 / 后台轮询 / ≥10 分钟等待），直到写出 `frontier dead` 或 `htb_fact add`。
 *     依据见 {@link LONG_JOB_PATTERNS} 头注（Watcher 实测：通知被复述后被绕过）。
 * @param ctx - 宿主插件上下文。
 * @param config - 见上。
 */
export function apply(ctx, config) {
  const cfg = config ?? {}
  if (cfg.enabled === false) return
  const logPath = cfg.logPath ?? DEFAULT_LOG_PATH
  const artifactDir = cfg.artifactDir ?? join(process.cwd(), 'loot')
  const thresholds = { ...DEFAULT_THRESHOLDS, ...(cfg.thresholds ?? {}) }
  const intervene = cfg.intervene !== false
  const gate = cfg.gate !== false
  // 🔴 2026-10-10：键从 agent **对象**（WeakMap）改为 agent.id **字符串**（Map），
  //    并记录 `segment`。理由见文件头修正 1（重置伪影 + 事件口径切分键）。
  const states = new Map()
  const segmentOf = new Map()
  const anonymousKeys = new WeakMap()
  let anonymousSeq = 0
  /** 状态老化：超过此时长没再出现的会话状态可以丢（长跑进程里 Map 不能无限增长）。 */
  const STATE_TTL_MS = 12 * 60 * 60 * 1000

  /** 取 agent 的稳定键：优先 id 字符串；没有 id 时退回对象身份（合成键）。 */
  const keyOf = (agent) => {
    const id = agent?.id
    if (typeof id === 'string' && id !== '') return id
    let key = anonymousKeys.get(agent)
    if (key === undefined) {
      anonymousSeq += 1
      key = `anon-${anonymousSeq}`
      anonymousKeys.set(agent, key)
    }
    return key
  }

  ctx.on('tools/post-execute', async (exec, result, next) => {
    try {
      // 只观测 agent-loop 的调用：直接 ctx.tools.execute() 的调用者没有会话。
      if (exec?.agent) {
        const now = Date.now()
        const agentKey = keyOf(exec.agent)
        let state = states.get(agentKey)
        if (state === undefined) {
          const segment = (segmentOf.get(agentKey) ?? 0) + 1
          segmentOf.set(agentKey, segment)
          state = createState(now, artifactMtimeMs(artifactDir))
          state.segment = segment
          states.set(agentKey, state)
        }
        state.lastSeen = now
        noteCall(state, exec, thresholds.repeatWindowCalls)
        noteResult(state, result)
        // 两个产物口径取较新：工具产出（write/edit）优先，文件系统 mtime 兜底。
        noteToolArtifact(state, exec, result, now)
        noteArtifact(state, artifactMtimeMs(artifactDir), now)
        // 产出比的**持续性**：低产是状态、不是快照 —— 先按当前密度推进低产起点，
        // 再组装快照（这时 `msSinceOutputLow` 才是"已经低产了多久"）。
        noteOutputLow(state, buildObservation(state, now), thresholds, now)
        const verdict = assessStruggle(buildObservation(state, now), thresholds)
        // ---- P0-1 干预：只对 level 2（stop）准备一条通知 ----
        // 🔴 去重：`stop` 是 latch 状态，后续每次调用的 `hits` 都不变，若不去重会**每一步
        //    都注入一次**。按 (状态段 | hits | action) 去重 ⇒ 每个状态段只提示一次。
        if (intervene && verdict.action === 'stop') {
          const dedupeKey = `${state.segment ?? 1}|${verdict.hits.join('+')}|stop`
          if (state.notifiedFor !== dedupeKey) {
            state.notifiedFor = dedupeKey
            state.pendingNotice = buildNotice(verdict, state, now)
          }
        }
        // ---- 闸的锁存与释放（2026-10-25）----
        // 释放优先于锁存：同一次调用如果是 `frontier dead` / `htb_fact add`，
        // 就算 verdict 仍是 stop 也不该重新上锁 —— 否则解封永远无效。
        if (gate) {
          const args = exec.arguments ?? {}
          const op = typeof args === 'object' && args !== null ? args.op : undefined
          const released = (exec.name === 'htb_frontier' || exec.name === 'htb_fact')
            && (op === 'dead' || op === 'add')
          if (released) state.stopLatched = false
          else if (verdict.action === 'stop') state.stopLatched = true
        }
        logLine(logPath, {
          ts: new Date(now).toISOString(),
          agent: agentKey,
          // 🔴 状态段序号：统计**事件**时的切分键（行计数会重复计数，见文件头修正 2）。
          segment: state.segment ?? 1,
          // 该状态段的起点：让每一行自带 cutoff，不必去猜"这份日志截至什么时候"。
          sessionStartedAt: new Date(state.startedAt).toISOString(),
          tool: exec.name,
          // 🔴 2026-10-10 移除退化字段 `identical`（原值 = state.identicalCount）。
          //    依据：独立审计的全语料实测分布 **{1: 20298, 2: 3}** —— 该字段
          //    **从不为 0、几乎恒为 1**，不携带信息（连续相同的"链长"在真实会话里
          //    从不累积）；同一行里真正有信息量的是 `windowRepeat`。
          //    **不要再加回来。** 注意只删日志字段：状态 `state.identicalCount` 仍被
          //    {@link buildObservation} 当作 `consecutiveIdenticalCalls` 使用，是
          //    `assessStruggle` 的 repeat 判据之一，必须保留。
          windowRepeat: state.windowRepeatCount ?? 0,
          toolCalls: state.calls,
          toolFailures: state.failures ?? 0,
          failed: result?.isError === true,
          // 区分"工具真报错"与"被守卫/策略拦下"：后者不带 info（见 noteResult 注释）。
          errorCode: result?.error?.info?.code ?? null,
          msSinceArtifactChange: now - state.artifactChangedAt,
          elapsedMs: now - state.startedAt,
          // 低产已持续的毫秒数（`output` 持续性判据的输入；未在低产 = null）。
          // 记进日志是为了将来能**离线复验** `outputSustainMinutes` —— 段边界
          // 目前仍是推断的（见 struggle.js 的出处块 ⚠️）。
          msSinceOutputLow: typeof state.outputLowSince === 'number' ? now - state.outputLowSince : null,
          hits: verdict.hits,
          action: verdict.action,
        })
        if (states.size > 64) {
          for (const [key, value] of states) {
            if (now - (value.lastSeen ?? value.startedAt) > STATE_TTL_MS) states.delete(key)
          }
        }
      }
    } catch { /* 观测坏了不能影响工具调用 */ }
    return next()
  })

  // ---- P0-1 干预通道（`agent/pre-step`）------------------------------------
  //
  // 🔴 为什么选这个事件：它**按 agent 作用域分发**，且 `payload.agent` 直接可用 ——
  //    于是不需要回答"这次装配属于哪个 agent"（`system-prompt/assemble` 拿不到
  //    agent 身份，只有 scope/signal，会退化成"所有会话共享一条通知"）。
  //    签名与返回类型来自 Inspect：`{kind:'reject'} | {kind:'enter', messages}`。
  //
  // 🔴 注入的 `source`：`kind` 用本插件自己的名字，`form: 'notice'` + 一行 `summary`。
  //    `MessageSource` 是 merge-extensible 的、消费者对未知 kind 会 fall through，
  //    所以**不会**破坏会话持久化（对比：写错 kind 在 required-on-read 的 host 上
  //    会让会话无法恢复）。
  // ---- 停止协议闸（2026-10-25）----
  // 放在 intervene 之外：即使关了"注入通知"，闸仍然独立生效。
  // 只拦长任务启动；短命令、只读查询、解封动作全部放行。
  // 宿主没暴露 tools.guard 时（部分测试桩 / 精简部署）静默跳过 —— 与 fail-open 同原则。
  if (gate && typeof ctx.tools?.guard === 'function') {
    ctx.tools.guard((exec) => {
      try {
        if (!GATE_TOOLS.has(exec?.name)) return undefined
        const state = states.get(keyOf(exec.agent))
        if (state?.stopLatched !== true) return undefined
        const cmd = commandTextOf(exec)
        if (cmd === '') return undefined
        const hit = LONG_JOB_PATTERNS.find((p) => p.test(cmd))
        if (hit === undefined) return undefined
        return buildGateReason(state, Date.now())
      } catch {
        // fail-open：闸坏了也不能锁死工作流（与 guard.js 同原则）。
        return undefined
      }
    })
  }

  if (intervene) {
    ctx.on('agent/pre-step', async (payload, next) => {
      const decision = await next()
      try {
        if (decision?.kind !== 'enter') return decision
        const state = states.get(keyOf(payload?.agent))
        const notice = state?.pendingNotice
        if (!notice) return decision
        // 只送一次：取走即清，避免每步重复。
        state.pendingNotice = undefined
        const llm = await loadLlm()
        // ⚠️ 变量名不能叫 payload —— 那是本处理函数的参数名，同名 const 是语法错误。
        const messageInput = {
          content: [{ type: 'text', text: notice.text }],
          source: { kind: 'struggle-watch', form: 'notice', summary: notice.summary },
        }
        // 官方构造器优先；解析不到就用与之等价的本地实现（见 makeUserNotice）。
        const message = typeof llm?.createUserMessage === 'function'
          ? llm.createUserMessage(messageInput)
          : makeUserNotice(notice.text, notice.summary)
        return { ...decision, messages: [...decision.messages, message] }
      } catch {
        // 注入失败绝不能影响这一步 —— 退回原决定。
        return decision
      }
    })
  }
}
