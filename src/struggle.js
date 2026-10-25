/**
 * Struggle 探测器 —— 判断一个长会话是不是在原地打转。
 *
 * 来源：
 *   - 社区判据（GAIR-NLP, arXiv 2606.29718）把 struggle step 定义为三类信号：
 *     loop-like behavior / repeated tool calls with same params /
 *     reasoning that fails to incorporate previous observations。
 *   - Infinite Agentic Loops（arXiv 2607.01641）：没有 bound 覆盖反馈路径，
 *     循环就会退化成无限循环 —— 所以预算必须是一条硬信号。
 *   - Context Rot 的「35 分钟墙」是**时间**口径的，不是步数口径。
 *
 * 与社区判据的差异（刻意的）：
 *   1. 第三条"reasoning 没吸收前文"**不解析 reasoning**，改用外部硬事实替代 ——
 *      「外部产物连续多久没变」。解析模型输出需要模型自己可靠，而退化时它恰恰
 *      不可靠；文件的 mtime 不需要任何模型参与。
 *   2. 全部信号用**墙钟毫秒**，不用轮次/步数。步数密度在不同阶段差一个数量级
 *      （侦察期每步都调工具，攻坚期一步想十分钟），拿它当预算单位会两头不准。
 *   3. 第四、五条（`output` 产出比 / `failures` 失败率）**不是社区判据**，
 *      来自本项目自己的观测数据，两者都与社区三条正交：
 *      - `output`：session-87cb7419 11.89 小时只发了 8 次工具调用 ——
 *        社区三条全漏掉"压根没动手"这个形态；
 *      - `failures`：3 会话 / 764 次调用的基线 2.7%，其中 `edit` 的失败正是
 *        Layover 那次并发写 loot 撞车 —— 管的是"在动手但一直在撞墙"。
 *      两条都**只 checkpoint**（理由见 {@link assessStruggle}）。`output` 的阈值已于
 *      2026-10-10 按**事件口径**标定（出处块见 {@link DEFAULT_THRESHOLDS}）；
 *      `failures` 仍只有窄带样本（7 个事件全压 0.15–0.20），继续攒数据。
 *
 * 全部是纯函数，便于在拿不到真实会话时先跑测试。
 */

/** 信号定义。id 用于日志与测试，label 给人看。 */
export const SIGNALS = [
  { id: 'repeat', label: '重复：相同工具+参数连续出现' },
  { id: 'stall', label: '停滞：外部产物连续多时未变' },
  { id: 'budget', label: '预算：会话时长超阈' },
  { id: 'output', label: '产出比：工具调用密度过低并持续（在空想，不在工作）' },
  { id: 'failures', label: '失败率：工具调用失败比例过高（在硬撞，不在推进）' },
]

/**
 * 默认阈值。全部可在 config 里覆盖。
 *
 * 🔴 出处与 cutoff：2026-10-10 采集，独立审计 `loot/_audit/J7-thresholds.md` §4；**以事件口径为准，不是行计数**。
 *   cutoff = `~/.dsh/htb-struggle.jsonl` **21,053 行** / sha256 `d30c06cb…`（前缀）/ ts_max `2026-10-10T09:34:20.457Z` / **193 个 agent 键**。
 *   ⚠️ 该报告全部"事件数"依赖**推断**的段边界（该快照里 `segment`/`sessionStartedAt` 出现 **0 次**，段是靠 `elapsedMs`/`toolCalls` 回落反推的）⇒ **`segment` 字段上线后必须复验**。
 *   🔴 行计数 ≠ 事件计数（同一状态段反复落盘）：膨胀倍数 repeat 3.2× / stall 20.5× / budget 115.7× / output 37.8× / failures 7.0×（`stop` 84.1×：2,019 行 = 24 事件）。**禁止用行计数定阈值。**
 *   实测得出（本次改动）：`stallMinutes 45→90` —— 事件 msac 分布 1.5–2.2h 之间有空档，20 个事件里 11 个落在 45–90min 低置信带；stall 属**硬停**集合，误报代价是掐会话 ·
 *     `outputSustainMinutes 15`（新增）—— 5 个 output 事件的最长低产窗口 8/469/98/540/4 分钟 ⇒ 保留 3 个真事件、剔除 2 个分钟级抖动。
 *   沿用旧值（各有实测支持，不动）：`repeatCalls 3`（windowRepeat 实测最大恰为 3；改 4 → **0 事件 = 失效**）· `repeatWindowCalls 8` · `maxHours 6`（4h→17 / 6h→14 / 8h→12，曲线平坦）
 *     · `minCallsPerHour 12`（提到 30 事件数不变，5→5）· `outputFloorMinutes 60` · `failureRate 0.15`（0.10→24 噪声 / 0.25→**0**，7 个事件全压 0.15–0.20）· `failureFloorCalls 20`。
 */
export const DEFAULT_THRESHOLDS = {
  /** 相同 tool+args 连续出现多少次算重复。 */
  repeatCalls: 3,
  /**
   * 滑动窗口大小（最近多少次调用）。
   *
   * 🔴 2026-09-30 新增。原判据只看**严格连续**相同，实测在 3271 条真实观测里
   *    `repeat` **零命中** —— 因为打靶的重复天然不连续：要么中间夹一次别的调用
   *    （读台账、跑一次 ping），要么呈 A/B/A/B 摆动。只看连续等于这条信号不存在。
   *    现在判据是 `max(连续相同, 窗口内相同) >= repeatCalls`，两种形态都能抓到。
   */
  repeatWindowCalls: 8,
  /**
   * 外部产物连续多少分钟未变算停滞。
   *
   * 🔴 2026-10-10 由 45 改 90（事件口径，见 DEFAULT_THRESHOLDS 的出处块）：
   *   20 个 stall 事件的 `msSinceArtifactChange` 分布为
   *   `0.76…1.41 | 2.20 | 4.05 6.41 6.65 6.78 7.59 9.88 16.99 44.88` 小时 ——
   *   **1.5h–2.2h 是一条明显的空档**，而 45–90 分钟那条低置信带吃掉了 11 个事件（55%）。
   *   代价对比：stall 是**硬停**信号，误报 = 掐掉一次可能成功的会话（源码里自记过
   *   "33 分钟通关 Sherlock 差 13 分钟被误报"）；判成 90 之后真卡死的会话多跑 45 分钟
   *   才硬停，而这段时间由 `budget`（6h 硬界）兜底。⇒ 宁可让 budget 收网，不让 stall 误杀。
   */
  stallMinutes: 90,
  /**
   * 单会话时长上限（小时）。
   *
   * 🔴 2026-09-27 由 4 改 6，依据 `dsh-session-insights` 实测数据：
   *   Layover（session-2bfe46ca）**3.99 小时拿下双旗，距 4 小时线不到 2 分钟**。
   *   4 小时这条线差一点就掐掉一次**成功**的会话；而 ReaperTwo 那轮跑了 8.6 小时。
   *   两个样本一低一高，取 6 作为"够 Insane 级多跳机把话说完、又不放弃硬界"的折中。
   *   下次攒到更多分布后按同样口径再校。
   */
  maxHours: 6,
  /** 产出比：工具调用密度低于这个「次/小时」算空想。 */
  minCallsPerHour: 12,
  /** 产出比信号的取样下限（分钟）。会话太短不下结论，避免开局误伤。 */
  outputFloorMinutes: 60,
  /**
   * 产出比信号的**持续性**要求（分钟）：低产必须连续保持这么久才算命中。
   *
   * 🔴 2026-10-10 新增（事件口径标定）。为什么不是改数值：把 `minCallsPerHour`
   *   从 12 提到 30，事件数**一个都不变**（5→5）⇒ 5 个事件都不是"擦边"产生的；
   *   问题在**行级抖动** —— 189 行命中里有 21 行落在阈值 8% 以内（最高 11.9956，
   *   即贴着刀锋）。也就是说"瞬时密度低于 12"会有分钟级的假阳性。
   *   实测代价对比：5 个 output 事件的最长低产窗口为 8/469/98/540/4 分钟 ——
   *   要求持续 ≥15 分钟可**保留 3 个真事件**（469/98/540）并**剔除 2 个分钟级抖动**
   *   （4min/8min）；要求 ≥30/60 分钟结果一样（3 个），但会开始吃掉 98 分钟那个。
   *   ⚠️ `msSinceOutputLow` 缺省时不因持续性剔除（见 {@link assessStruggle}）。
   */
  outputSustainMinutes: 15,
  /**
   * 失败率：工具调用失败比例达到这个值算"在硬撞"。
   * 取样下限见 {@link DEFAULT_THRESHOLDS.failureFloorCalls}。
   *
   * 标定依据（同上，3 会话 / 764 次调用）：观测基线 **2.7%**（21/764），
   * top 失败工具是 `edit` / `web_search` / `ssh_exec`。阈值取 0.15 ≈ 基线的 5.5 倍，
   * 目的是只抓"系统性失败"，不误伤正常的单点报错。
   */
  failureRate: 0.15,
  /** 失败率信号的取样下限（调用次数）。太少不下结论。 */
  failureFloorCalls: 20,
}

/** 判定等级 → 建议动作。 */
export const ACTIONS = {
  continue: 'continue',
  checkpoint: 'checkpoint',
  stop: 'stop',
}

/**
 * **瞬时**口径：这份快照此刻算不算"低产"（会话够长 + 密度低于阈值）。
 *
 * 单独导出是给 `struggle-watch.js` 用：持续性（"低产保持了多久"）是**状态**，
 * 快照本身表达不了 —— 观察层逐次调用地推进低产起点，判定层只消费毫秒数。
 * 抽成一个函数是为了让两边的判据**不会各写一份而漂移**。
 * @param obs - {@link assessStruggle} 的快照。
 * @param thresholds - 覆盖 {@link DEFAULT_THRESHOLDS} 的任意字段。
 * @returns 是否处于低产状态（缺 `toolCalls` = 不判 = false）。
 */
export function isLowOutput(obs, thresholds = DEFAULT_THRESHOLDS) {
  const t = { ...DEFAULT_THRESHOLDS, ...(thresholds ?? {}) }
  const calls = obs?.toolCalls
  const elapsedMs = obs?.elapsedMs ?? 0
  return typeof calls === 'number'
    && elapsedMs >= t.outputFloorMinutes * 60_000
    && calls / (elapsedMs / 3_600_000) < t.minCallsPerHour
}

/**
 * 对一份外部观测快照求 struggle 判定。
 *
 * @param obs - 快照（全部是外部可观测的硬事实）：
 *   - `consecutiveIdenticalCalls`：相同 tool+args 的连续次数
 *   - `msSinceArtifactChange`：外部产物距上次变化的毫秒数
 *   - `elapsedMs`：本会话已进行的毫秒数
 *   - `toolCalls`：本会话累计工具调用次数（算产出比用；缺省视为不判）
 *   - `toolFailures`：本会话累计**失败**的工具调用次数（算失败率用；缺省视为不判）
 *   - `msSinceOutputLow`：低产状态已连续保持的毫秒数（持续性判据用；
 *     缺省 = 未知 ⇒ **不因持续性而剔除**，见 `outputSustainMinutes`）
 * @param thresholds - 覆盖 {@link DEFAULT_THRESHOLDS} 的任意字段。
 * @returns `{ hits, level, action }`；`hits` 是命中的信号 id 列表。
 */
export function assessStruggle(obs, thresholds = DEFAULT_THRESHOLDS) {
  const t = { ...DEFAULT_THRESHOLDS, ...(thresholds ?? {}) }
  const hits = []
  // `repeat` 判据 = max(连续相同, 滑动窗口内相同)。
  // 🔴 2026-09-30：原判据只认**严格连续**，3271 条真实观测里零命中（见 repeatWindowCalls
  //    注释）。加上窗口口径后才抓得到"A B A B"摆动与"夹一次别的调用"的重复。
  const consecutive = obs?.consecutiveIdenticalCalls ?? 0
  const windowRepeat = obs?.windowRepeatCount ?? 0
  if (Math.max(consecutive, windowRepeat) >= t.repeatCalls) hits.push('repeat')
  if ((obs?.msSinceArtifactChange ?? 0) >= t.stallMinutes * 60_000) hits.push('stall')
  if ((obs?.elapsedMs ?? 0) >= t.maxHours * 3_600_000) hits.push('budget')

  // 产出比（2026-09-25 新增，决策 D3；2026-10-10 加持续性要求）。
  // 依据：session-87cb7419 跑了 11.89 小时只发 8 次工具调用（≈0.67 次/小时）——
  // 那不是在工作，是在空想。对照 ReaperTwo 实测 487 次 / 2.7 小时 ≈ 180 次/小时，
  // 两者差两个数量级，所以**检出本身**很可靠。
  //
  // 🔴 2026-10-10：加 `outputSustainMinutes`（瞬时密度会抓到分钟级抖动 —— 189 行
  //    命中里 21 行落在阈值 8% 以内，见 `outputSustainMinutes` 的注释）。
  //    ⚠️ **向后兼容**：`msSinceOutputLow` 缺省（老快照 / 直接调用方 / 手写字面量）时
  //    取 `Infinity` ⇒ 不因持续性而剔除，行为与改动前一致 —— 宁可维持旧行为，
  //    也不把"未知"当成"没持续"。`outputSustainMinutes` 键本身缺省时由上面的
  //    `{ ...DEFAULT_THRESHOLDS, ...thresholds }` 补 15，同样不炸。
  const calls = obs?.toolCalls
  if (
    isLowOutput(obs, t)
    && (obs?.msSinceOutputLow ?? Number.POSITIVE_INFINITY) >= t.outputSustainMinutes * 60_000
  ) hits.push('output')

  // 失败率（2026-09-27 新增，由 insights 实测数据驱动）。
  // 依据：3 会话 / 764 次调用的观测基线是 2.7%（21/764），top 失败工具
  // `edit` / `web_search` / `ssh_exec` / `pwsh`。其中 `edit` 很可能就是
  // Layover 那次 **subagent 与主 agent 并发写 loot 撞车**——也就是说这条信号
  // 同时能兜住"状态外置纪律被破坏"这个形态。
  // 与 `output` 正交：`output` 管"有没有动手"，这条管"动手有没有用"。
  const failures = obs?.toolFailures
  if (
    typeof calls === 'number'
    && typeof failures === 'number'
    && calls >= t.failureFloorCalls
    && failures / calls >= t.failureRate
  ) hits.push('failures')

  // 停滞与预算任一条命中即停：前者说明没在学，后者是硬界。
  // 重复单独命中只 checkpoint —— repeat-tool-reminder 已经在温和提醒，
  // 这里再硬停会误伤正常的重试。
  //
  // 🔴 `output` 与 `failures` 刻意**不**进硬停集合（只 checkpoint）。理由：它们是
  //    五条里最年轻的两条，且"该 checkpoint 还是该 stop"需要比阈值更多的分布数据
  //    （`output` 的阈值已按事件口径标定，但它的"硬停代价"没测过；`failures` 仍只有
  //    0.15–0.20 的窄带样本）。
  //    而且真出现"空想/硬撞"时，外部产物基本也停了，`stall` 会兜住硬停这条线；
  //    这两条当前的价值是**诊断维度**（日志里能一眼区分"忙但没进展""压根没动手"
  //    "在动手但一直在撞墙"）。等攒够几台机器再决定是否升级。
  const hard = hits.includes('stall') || hits.includes('budget')
  const level = hard ? 2 : hits.length > 0 ? 1 : 0
  const action = level === 2 ? ACTIONS.stop : level === 1 ? ACTIONS.checkpoint : ACTIONS.continue
  return { hits, level, action }
}

/**
 * 生成要注入会话的提醒文本。**只在干预模式用**；记录模式不调用它。
 *
 * 🔴 干预模式需要 `createUserMessage`（`@deepseek-ai/dsh-llm`）来给注入打
 *    source 标签 —— 不打标签的 context 会在派生历史里被当成用户提示渲染。
 *    本插件刻意不引入这个依赖（见 sherlock-tools.js 的说明），所以干预模式
 *    留到单独一层做，这里只把文本准备好。
 * @param result - {@link assessStruggle} 的结果。
 * @returns 提醒文本。
 */
export function renderNotice(result) {
  const lines = result.hits.map(id => `- ${SIGNALS.find(s => s.id === id)?.label ?? id}`)
  // 提示级（repeat / output）不该套用"停止协议"那套重话 —— 那两条都只是
  // "先自检"，硬停会误伤正常重试与攻坚期的长思考。
  if (result.level < 2) {
    return [
      '会话健康检查（提示级）：',
      ...lines,
      '',
      '先自检：这一轮到底有没有学到东西？',
      '1. 把结论写进 loot（已排除什么 / 当前最可靠的模型 / 下一步候选）。',
      '2. 不要原样重试同一个调用；换一条还没试过的路径。',
    ].join('\n')
  }
  return [
    '会话健康检查触发：',
    ...lines,
    '',
    '按停止协议收尾，不要再开新的实验变体：',
    '1. 把当前结论写进 loot（已排除什么 / 当前最可靠的模型 / 下一步候选）。',
    '2. 汇报：已拿到什么、卡在哪、已排除什么。不要用"再试一个变体"续命。',
    '3. 需要继续时，起一个 subagent（全新上下文，只传 loot 路径与目标），不要在本会话里接着烧。',
  ].join('\n')
}
