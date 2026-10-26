/**
 * machine-own.js — 靶机 flag 提交 + "完成"判据的交付检查
 *
 * 为什么需要它（2026-10-26，Atlas 会话实测）：
 *   那一场 108.3 分钟 `update_goal complete`，收尾消息写着
 *   "需要我 terminate/reset 或**提交 flag 到平台**的话说一声" —— 它**知道**没提交，
 *   但把它归类成"需要用户授权的可选项"，然后结束了 turn。用户在 270.2 分钟
 *   问"你还没提交吗？"，它才开始试，**试了 15 个端点**（v4/v5/v6 × machine/own /
 *   machine/flag / vm/own …）才在 272.4 分钟撞对 `POST api/v5/machine/own`。
 *
 *   两个根因，各自对应本模块的一半：
 *   ① **提交没有工具封装**。`htb_sherlock_submit` 只处理 Sherlock，machines 只能手写
 *      curl —— 心理上它是"额外工作"，而 flag 已经拿到了，任务看起来就结束了。
 *   ② **"完成"的判据里没有交付**。goal 的 objective 是
 *      `app.hackthebox.com/machines/Atlas`，平台的"完成"定义是 flag 入账，
 *      不是文件里读到。
 *
 * 设计取舍：
 *   - 提交是**线上写操作**（真的标记 own），所以 `baseUrl` 必须可注入，测试打本地。
 *   - goal 闸只拦**一次**：第一次 `update_goal complete` 被拒并给出提交命令，
 *     第二次放行。理由是"不提交 flag"有时是正当的（练习机、已手动提交过），
 *     死锁比漏拦更糟 —— 这是 Watcher 那场"闸被绕过"的反面教训：
 *     闸要么能过，要么会被绕过，不如让它**必须被看见一次**。
 *   - 判据是"账本里有 flag fact 但没 own 记录"，不是"目标 URL 里有没有 hackthebox" ——
 *     后者拿不到（`update_goal` 的参数不含 objective）。
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import { describeError, request } from './htb-api.js'

/** Stable Cordis plugin name. */
export const name = 'htb-machine-own'

/** 依赖工具注册表。 */
export const inject = ['tools']

/** 提交端点。2026-10-25 实测：v4 全是 404，只有 v5 的这个能用。 */
export const OWN_PATH = '/api/v5/machine/own'

/** 账本目录（与 state-tools / auto-state 同口径）。 */
function stateRootOf(config) {
  const raw = typeof config?.stateRoot === 'string' && config.stateRoot.trim() !== ''
    ? config.stateRoot
    : join(process.cwd(), 'loot')
  return isAbsolute(raw) ? raw : resolve(process.cwd(), raw)
}

/**
 * 读账本里与"交付"相关的两件事：
 *   - `flags`: 有没有登记过 flag fact（说明确实打到了）
 *   - `owns` : 有没有提交成功的记录（`type: 'flag-own'`）
 *
 * 只看**最近一个 machine 的账本**：目录下有多个时按修改时间取最新
 * （与 `findLedger` 的"唯一才自动选"不同 —— 这里只做只读检查，选错顶多漏拦一次，
 * 不值得为它引入"必须传 machine"的摩擦）。
 * @param config - 插件配置。
 * @returns `{ machine, flags, owns }`；读不到时 flags/owns 为空。
 */
export function readDeliveryState(config) {
  const root = stateRootOf(config)
  let names = []
  try {
    names = readdirSync(root).filter((n) => n.endsWith('-state.jsonl'))
  } catch { return { machine: undefined, flags: [], owns: [] } }
  if (names.length === 0) return { machine: undefined, flags: [], owns: [] }

  // 取最新修改的那个（单机作战时就是它）
  let newest = names[0]
  let newestMs = -Infinity
  for (const n of names) {
    try {
      const { mtimeMs } = statSync(join(root, n))
      if (mtimeMs > newestMs) { newestMs = mtimeMs; newest = n }
    } catch { /* 跳过读不到的 */ }
  }

  const rows = []
  try {
    for (const line of readFileSync(join(root, newest), 'utf-8').split('\n')) {
      const t = line.trim()
      if (t === '') continue
      try { rows.push(JSON.parse(t)) } catch { /* 坏行跳过 */ }
    }
  } catch { return { machine: newest.replace(/-state\.jsonl$/, ''), flags: [], owns: [] } }

  const flags = rows.filter((r) => r.type === 'fact' && r.kind === 'flag')
  const owns = rows.filter((r) => r.type === 'flag-own')
  return { machine: newest.replace(/-state\.jsonl$/, ''), flags, owns }
}

/**
 * 提交一个 flag。
 *
 * 端点与 body 来自 Atlas 会话的实测（2026-10-25）：
 *   POST /api/v5/machine/own  {"id":784,"flag":"..."}
 *   → {"message":"Atlas root is now owned.","id":784,"own_type":"root","success":true,"status":200}
 * 同一个端点也接受 user flag，返回 `own_type: "user"`。
 * @param config - 插件配置（`baseUrl` / `tokenPath`）。
 * @param machineId - 机器 id（数字或字符串）。
 * @param flag - flag 原文。
 * @returns `{ ok, status, body }` 或 `{ error }`。
 */
export async function submitFlag(config, machineId, flag) {
  const id = Number(machineId)
  if (!Number.isFinite(id) || id <= 0) return { error: `machine_id 需要正整数，收到 "${machineId}"` }
  if (typeof flag !== 'string' || flag.trim() === '') return { error: 'flag 不能为空' }

  // 请求细节统一在 htb-api（token / baseUrl / 401 话术）。
  const r = await request(config, 'POST', OWN_PATH, { id, flag: flag.trim() })
  if (r.error !== undefined) return { error: r.error }
  return { ok: r.status === 200 && r.json?.success === true, status: r.status, body: r.json }
}

/**
 * 挂载工具与"完成前必须交付"的闸。
 *
 * 配置：
 *   - `enabled`（默认 true）：设 false 完全不挂。
 *   - `baseUrl`：API 根（默认 `https://labs.hackthebox.com`；测试传 mock）。
 *   - `tokenPath`：token 文件（默认 `~/.dsh/htb-token.txt`）。
 *   - `stateRoot`：账本目录（默认 `<cwd>/loot`）。
 *   - `goalGate`（默认 true）：是否在 `update_goal action=complete` 前检查交付。
 * @param ctx - 宿主插件上下文。
 * @param config - 见上。
 */
export function apply(ctx, config) {
  const cfg = config ?? {}
  if (cfg.enabled === false) return

  const stateRoot = stateRootOf(cfg)
  const goalGate = cfg.goalGate !== false

  ctx.tools.register({
    name: 'htb_machine_own',
    description:
      '提交靶机 flag 到 HTB 平台（user / root 都走这一个端点，平台自动判定）。'
      + '🔴 拿到 flag 之后**立刻**调它 —— 平台的"完成"是 flag 入账，不是文件里读到。'
      + '成功后会往账本写一条 flag-own 记录，供"完成前交付检查"识别。'
      + '端点: POST /api/v5/machine/own {"id":<machine_id>,"flag":"<flag>"}。',
    parameters: {
      type: 'object',
      properties: {
        machine_id: { type: 'string', description: '机器 id（数字，如 784）' },
        flag: { type: 'string', description: 'flag 原文（32 位 hex）' },
      },
      required: ['machine_id', 'flag'],
    },
    // 🔴 render(args, value) 必须返回 content block 数组，理由见 machine-tools.js 的 strOutput。
    output: { schema: { type: 'string' }, render(_args, value) { return [{ type: 'text', text: String(value) }] } },
    async execute(args) {
      const r = await submitFlag(cfg, args.machine_id, args.flag)
      if (r.error !== undefined) return `⚠️ 提交失败：${r.error}`

      const msg = typeof r.body?.message === 'string' ? r.body.message : JSON.stringify(r.body)
      if (r.ok) {
        // 记一条交付记录：goal 闸据此判断"已提交"。
        try {
          const { appendFileSync, mkdirSync } = await import('node:fs')
          const ds = readDeliveryState(cfg)
          const machine = ds.machine ?? 'unknown'
          const p = join(stateRoot, `${machine}-state.jsonl`)
          if (!existsSync(stateRoot)) mkdirSync(stateRoot, { recursive: true })
          appendFileSync(p, `${JSON.stringify({
            ts: new Date().toISOString(),
            type: 'flag-own',
            machine_id: Number(args.machine_id),
            own_type: r.body?.own_type,
            flag_tail: String(args.flag).slice(-6),
          })}\n`)
        } catch { /* 记录失败不影响提交结果 */ }
        return `✅ ${msg}（own_type=${r.body?.own_type ?? '?'}，HTTP ${r.status}）`
      }
      if (r.status === 401) return describeError(401, r.body, '提交 flag')
      return `❌ 提交未通过（HTTP ${r.status}）：${msg}`
    },
  })

  if (!goalGate) return

  // ── 完成前交付检查 ────────────────────────────────────────────────────
  // 只拦**第一次**：第二次放行。理由见文件头（死锁比漏拦更糟）。
  const warnedGoals = new Set()

  ctx.tools.guard((exec) => {
    try {
      if (exec?.name !== 'update_goal') return undefined
      const args = exec.arguments ?? {}
      if (args.action !== 'complete') return undefined

      const goalId = typeof args.goal_id === 'string' ? args.goal_id : '(unknown)'
      if (warnedGoals.has(goalId)) return undefined   // 第二次放行

      const ds = readDeliveryState(cfg)
      if (ds.flags.length === 0) return undefined     // 没登记过 flag → 不是打靶任务，不管
      if (ds.owns.length > 0) return undefined        // 已经提交过

      warnedGoals.add(goalId)
      const last = ds.flags[ds.flags.length - 1]
      return '⚠️ 完成前检查：账本里有 flag，但**没有提交到平台**的记录。\n'
        + `   flag: ${last?.key ?? '?'}${last?.value !== undefined ? ` = ${String(last.value).slice(0, 12)}…` : ''}\n`
        + '   平台的"完成"是 flag 入账，不是文件里读到 —— Atlas 那场就因此静默了 162 分钟。\n'
        + `   提交：htb_machine_own { machine_id: <id>, flag: "<flag>" }\n`
        + '   如果确实不需要提交（练习机 / 已手动提交），**再调一次 update_goal complete 即放行**。'
    } catch {
      // fail-open：闸坏掉不能锁死工作流。
      return undefined
    }
  })
}
