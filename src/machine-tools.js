/**
 * machine-tools.js — 靶机生命周期工具（7 个）
 *
 * 为什么需要（2026-10-26，三场真实会话统计）：
 *   DutyBound / Watcher / Atlas 三场里，**手写 curl 调 HTB API 共 76 次**，
 *   集中在生命周期端点，而且几乎全是"猜端点"：
 *
 *     · `machine/paginated` 试了 5 种写法（paginate / paginated / list / list/1 / machines）
 *     · `machine/profile/Atlas`、`/profile/784`、`/profile/atlas` 混着试
 *     · `vm/spawn` 之后**手动轮询** `machine/active` 5–10 次（41–94 秒）
 *     · `user/info` 试了 v4 / v5 / v6 三个版本号
 *     · 提交 flag 试了 15 个端点（v4 全 404）—— 已由 machine-own.js 解决
 *
 *   这些不是"知识问题"，是**没有封装**：每个会话都要重新猜一遍，猜错就浪费往返。
 *
 * 端点与 body 全部**实测确认**（2026-10-26，OPTIONS + 空 body 的 422 反推）：
 *
 *   GET  /api/v4/machine/paginated?keyword=&per_page=   → 只含 **active** 机器（retired 参数被静默忽略）
 *   GET  /api/v4/machine/profile/<id|name>              → 单台详情，**名字大小写不敏感**，含 retired
 *   GET  /api/v4/machine/active                         → { info } 或 { info: null }
 *   POST /api/v4/vm/spawn    {"machine_id":N}           → {"message":"Machine deployed to lab.","success":true}
 *   POST /api/v4/vm/terminate  （无 body，按当前活跃实例）  → 无活跃时 404 "Active instance not found"
 *   POST /api/v4/vm/reset    {"machine_id":N}           → 有冷却
 *   GET  /api/v4/user/info                              → { info }
 *
 * 统一约定（与 sherlock-tools / state-tools 一致）：
 *   - 工具名 `htb_machine_*`，一个动作一个工具（不合并成 `action` 参数）
 *   - 输出纯文本（`strOutput`），首行是结论，缩进列是细节
 *   - 失败一律走 {@link describeError}，给"下一步怎么做"而不是原始 JSON
 */

import { describeError, publicUser, request } from './htb-api.js'

/** Stable Cordis plugin name. */
export const name = 'htb-machine-tools'

/** 依赖工具注册表。 */
export const inject = ['tools']

/** spawn 后等 IP 的默认超时（秒）。实测 41–94 秒，留 3 倍余量。 */
export const DEFAULT_SPAWN_TIMEOUT_SEC = 180

/** 轮询间隔（毫秒）。3 秒 ≈ 实测最优：再密会被限流，再疏会白等。 */
export const SPAWN_POLL_MS = 3000

/**
 * 纯文本输出。
 *
 * 🔴 签名必须是 `render(args, value)`，且**返回 content block 数组** ——
 * 不是直接返回字符串。2026-10-26 实测：写成 `render: (s) => s` 时，
 * 框架拿到 `result.content = "<字符串>"`，随后 `result.content.some(...)`
 * 抛 `content.some is not a function`，**8 个工具全部不可用**，
 * 而错误文本被当作正常输出返回（`isError` 为空），模型只能改回手写 curl。
 *
 * 正确形态见 sherlock-tools / state-tools 的同名函数。
 */
function strOutput() {
  return { schema: { type: 'string' }, render(_args, value) { return [{ type: 'text', text: String(value) }] } }
}

/** 简易参数表构造（与 sherlock-tools 的 paramsSpec 同风格）。 */
function paramsSpec(props, required = []) {
  return { type: 'object', properties: props, required }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/**
 * 把"名字或 id"统一成机器 id。
 *
 * 传数字直接返回；传名字走 `profile`（实测大小写不敏感，`Atlas` / `atlas` 都行）。
 * @param config - 插件配置。
 * @param machine - 名字或 id。
 * @returns `{ id, info? }` 或 `{ error }`。
 */
export async function resolveMachine(config, machine) {
  if (machine === undefined || machine === null || String(machine).trim() === '') {
    return { error: '需要 machine 参数（机器名如 "Atlas"，或 id 如 784）' }
  }
  const s = String(machine).trim()
  if (/^\d+$/.test(s)) return { id: Number(s) }

  const r = await request(config, 'GET', `/api/v4/machine/profile/${encodeURIComponent(s)}`)
  if (r.error !== undefined) return { error: r.error }
  const info = r.json?.info
  if (r.status !== 200 || info === null || info === undefined) {
    return { error: describeError(r.status, r.json, `查询机器 "${s}"`) }
  }
  return { id: info.id, info }
}

/** 把 `expires_at`（"2026-10-26 11:03:41"，UTC）渲染成"剩 1h 58m"。 */
export function lifeLeft(expiresAt) {
  if (typeof expiresAt !== 'string' || expiresAt === '') return '—'
  // 该字段没有时区后缀，按 UTC 解析（HTB 服务端就是 UTC）。
  const ms = Date.parse(expiresAt.replace(' ', 'T') + 'Z')
  if (!Number.isFinite(ms)) return expiresAt
  const left = ms - Date.now()
  if (left <= 0) return '已过期'
  const min = Math.floor(left / 60000)
  if (min < 60) return `${min}m`
  return `${Math.floor(min / 60)}h ${min % 60}m`
}

/** 把 difficulty（0–100）与 difficultyText 合成一格。 */
function difficultyCell(m) {
  const t = typeof m?.difficultyText === 'string' ? m.difficultyText : '?'
  const d = Number.isFinite(m?.difficulty) ? ` (${m.difficulty})` : ''
  return `${t}${d}`
}

/** 已 own 状态。 */
function ownCell(m) {
  const u = m?.authUserInUserOwns === true
  const r = m?.authUserInRootOwns === true
  if (u && r) return 'user+root'
  if (u) return 'user'
  if (r) return 'root'
  return '—'
}

/**
 * 挂载 7 个生命周期工具。
 *
 * 配置：
 *   - `enabled`（默认 true）：设 false 完全不挂。
 *   - `baseUrl`：API 根（默认 `https://labs.hackthebox.com`；测试传 mock）。
 *   - `tokenPath`：token 文件（默认 `~/.dsh/htb-token.txt`）。
 *   - `spawnTimeoutSec`：`htb_machine_spawn` 等 IP 的超时（默认 180）。
 *   - `spawnPollMs`：轮询间隔（默认 3000；测试压到 10ms 以免用例变慢）。
 * @param ctx - 宿主插件上下文。
 * @param config - 见上。
 */
export function apply(ctx, config) {
  const cfg = config ?? {}
  if (cfg.enabled === false) return

  const spawnTimeout = Number.isFinite(Number(cfg.spawnTimeoutSec)) && Number(cfg.spawnTimeoutSec) > 0
    ? Number(cfg.spawnTimeoutSec)
    : DEFAULT_SPAWN_TIMEOUT_SEC
  // 轮询间隔也做成可配置：测试要把它压到 10ms，否则一个用例要等 3 秒。
  const pollMs = Number.isFinite(Number(cfg.spawnPollMs)) && Number(cfg.spawnPollMs) > 0
    ? Number(cfg.spawnPollMs)
    : SPAWN_POLL_MS

  const defs = [
    // ── 查 ────────────────────────────────────────────────────────────────
    {
      name: 'htb_machine_list',
      description:
        '列出**当前可打的机器**（active，通常 20 台），可按名字模糊过滤。'
        + '🔴 只覆盖 active：retired 机器（如 Atlas）查不到，要用 htb_machine_info 按名字查。'
        + '（实测 2026-10-26：paginated 端点对 state/retired/filter 参数一律静默忽略。）'
        + '输出含 id / 名字 / OS / 难度 / 你是否已 own —— 用 id 传给 spawn。',
      parameters: paramsSpec({
        keyword: { type: 'string', description: '名字模糊匹配（如 "Duty"），省略则列全部' },
        limit: { type: 'string', description: '返回条数上限，默认 20' },
      }),
      output: strOutput(),
      async execute(args) {
        const kw = typeof args.keyword === 'string' ? args.keyword.trim() : ''
        const limit = Number.isFinite(Number(args.limit)) && Number(args.limit) > 0 ? Number(args.limit) : 20
        const qs = new URLSearchParams({ per_page: String(limit) })
        if (kw !== '') qs.set('keyword', kw)

        const r = await request(cfg, 'GET', `/api/v4/machine/paginated?${qs.toString()}`)
        if (r.error !== undefined) return `⚠️ ${r.error}`
        if (r.status !== 200) return describeError(r.status, r.json, '列出机器')

        const rows = Array.isArray(r.json?.data) ? r.json.data : []
        const total = r.json?.meta?.total ?? rows.length
        if (rows.length === 0) {
          return `# active 机器：0 台${kw !== '' ? `（keyword="${kw}"）` : ''}\n`
            + '   如果找的是 retired 机器，用 htb_machine_info { machine: "<名字>" }。'
        }

        const out = [`# active 机器：${rows.length}/${total} 台${kw !== '' ? `（keyword="${kw}"）` : ''}`]
        out.push('  id    名字                 OS        难度              已 own')
        for (const m of rows) {
          out.push('  ' + String(m.id).padEnd(5)
            + String(m.name ?? '?').padEnd(20)
            + String(m.os ?? '?').padEnd(10)
            + difficultyCell(m).padEnd(17)
            + ownCell(m))
        }
        if (kw !== '' && rows.length === 0) out.push('  （无匹配）')
        out.push('')
        out.push('  下一步：htb_machine_spawn { machine: "<名字或 id>" }')
        return out.join('\n')
      },
    },
    {
      name: 'htb_machine_info',
      description:
        '查单台机器的详情（**含 retired**）。machine 传名字或 id 都行，名字大小写不敏感。'
        + '输出含：OS / 难度 / 是否 retired / 你是否已 own user·root / 当前 IP / 剩余时间。'
        + '🔴 打之前先查一次：authUserInUserOwns/RootOwns 为 true 说明已经做过，别重复。',
      parameters: paramsSpec({
        machine: { type: 'string', description: '机器名（如 "Atlas"）或 id（如 784）' },
      }, ['machine']),
      output: strOutput(),
      async execute(args) {
        const { id, info, error } = await resolveMachine(cfg, args.machine)
        if (error !== undefined) return error

        // 传 id 时 resolveMachine 不返回 info，补一次详情
        let m = info
        if (m === undefined) {
          const r = await request(cfg, 'GET', `/api/v4/machine/profile/${id}`)
          if (r.error !== undefined) return `⚠️ ${r.error}`
          if (r.status !== 200) return describeError(r.status, r.json, '查询机器详情')
          m = r.json?.info
        }
        if (m === null || m === undefined) return `⚠️ 没有 id=${id} 的机器`

        const play = m.playInfo ?? {}
        const out = [`${m.name} (id ${m.id})`]
        out.push(`  OS        ${m.os ?? '?'}`)
        out.push(`  难度      ${difficultyCell(m)}`)
        out.push(`  发布      ${typeof m.release === 'string' ? m.release.slice(0, 10) : '?'}`)
        out.push(`  状态      ${m.retired === true ? 'retired' : m.active === true ? 'active' : '?'}`)
        out.push(`  已 own    user ${m.authUserInUserOwns === true ? '✅' : '—'} / root ${m.authUserInRootOwns === true ? '✅' : '—'}`)
        out.push(`  IP        ${typeof m.ip === 'string' && m.ip !== '' ? m.ip : '（未 spawn）'}`)
        if (play.expires_at !== null && play.expires_at !== undefined) {
          out.push(`  剩余      ${lifeLeft(play.expires_at)}（expires_at ${play.expires_at}）`)
        }
        if (play.isSpawning === true) out.push('  ⏳ 正在启动中')
        out.push('')
        if (m.authUserInUserOwns === true && m.authUserInRootOwns === true) {
          out.push('  两旗都已 own —— 除非要复现，不必再打。')
        } else if (typeof m.ip === 'string' && m.ip !== '') {
          out.push(`  已 spawn，可直接打：${m.ip}`)
        } else {
          out.push(`  下一步：htb_machine_spawn { machine: ${m.id} }`)
        }
        return out.join('\n')
      },
    },
    // ── 开 / 关 ──────────────────────────────────────────────────────────
    {
      name: 'htb_machine_spawn',
      description:
        '启动靶机并**等到 IP 可用**（内部轮询 machine/active，实测 41–94 秒）。'
        + '一步替代"POST vm/spawn 然后手动轮询十几次"。'
        + '🔴 spawn 接口本身只返回 {"success":true}，**不含 IP** —— 所以必须等。'
        + '如果已有活跃机器，会先告诉你（HTB 通常只允许一台）。',
      parameters: paramsSpec({
        machine: { type: 'string', description: '机器名或 id' },
        wait: { type: 'string', description: '是否等 IP，默认 true；false 则只提交启动请求' },
        timeoutSec: { type: 'string', description: `等 IP 的超时秒数，默认 ${DEFAULT_SPAWN_TIMEOUT_SEC}` },
      }, ['machine']),
      output: strOutput(),
      async execute(args) {
        const { id, error } = await resolveMachine(cfg, args.machine)
        if (error !== undefined) return error

        // 先看有没有别的活跃机器 —— 有的话 spawn 会失败或把它顶掉，提前说清
        const act = await request(cfg, 'GET', '/api/v4/machine/active')
        const cur = act.json?.info
        if (cur !== null && cur !== undefined && cur.id !== id) {
          return `⚠️ 已有活跃机器：${cur.name} (id ${cur.id})，IP ${cur.ip ?? '（启动中）'}\n`
            + `   剩余 ${lifeLeft(cur.expires_at)}。HTB 通常只允许一台。\n`
            + '   先 htb_machine_stop 释放，或直接打现有那台。'
        }

        const sp = await request(cfg, 'POST', '/api/v4/vm/spawn', { machine_id: id })
        if (sp.error !== undefined) return `⚠️ ${sp.error}`
        if (sp.status !== 200 || sp.json?.success !== true) {
          return describeError(sp.status, sp.json, '启动机器')
        }

        if (args.wait === 'false' || args.wait === false) {
          return `✅ 启动请求已提交（machine_id=${id}）。IP 稍后用 htb_machine_status 查。`
        }

        const timeout = Number.isFinite(Number(args.timeoutSec)) && Number(args.timeoutSec) > 0
          ? Number(args.timeoutSec)
          : spawnTimeout
        const deadline = Date.now() + timeout * 1000
        let polls = 0
        let last = null
        const startedAt = Date.now()

        while (Date.now() < deadline) {
          polls += 1
          const a = await request(cfg, 'GET', '/api/v4/machine/active')
          const info = a.json?.info
          if (info !== null && info !== undefined) {
            last = info
            if (typeof info.ip === 'string' && info.ip !== '') {
              const secs = Math.round((Date.now() - startedAt) / 1000)
              return [
                `✅ ${info.name} 已就绪`,
                `  IP        ${info.ip}`,
                `  剩余      ${lifeLeft(info.expires_at)}（expires_at ${info.expires_at ?? '?'}）`,
                `  VPN 服务器 ${info.vpn_server_id ?? '?'}`,
                `  耗时      ${secs} 秒（轮询 ${polls} 次）`,
                '',
                `  下一步：nmap -p- --min-rate 2000 -Pn ${info.ip}`,
              ].join('\n')
            }
          }
          await sleep(pollMs)
        }

        return `⏳ 启动请求已提交，但 ${timeout} 秒内没等到 IP（轮询 ${polls} 次）。\n`
          + `   最后一次状态：${last === null ? '（machine/active 仍为空）' : `isSpawning=${last.isSpawning}`}\n`
          + '   HTB 偶尔会慢到 3–5 分钟。稍后用 htb_machine_status 再看，别重复 spawn。'
      },
    },
    {
      name: 'htb_machine_status',
      description:
        '查**当前活跃机器**：IP / 剩余时间 / 是否正在启动 / VPN 服务器。'
        + '打完一台、或 spawn 之后过一会儿，用它确认状态。'
        + '没有活跃机器时返回明确的"无"。',
      parameters: paramsSpec({}),
      output: strOutput(),
      async execute() {
        const r = await request(cfg, 'GET', '/api/v4/machine/active')
        if (r.error !== undefined) return `⚠️ ${r.error}`
        if (r.status !== 200) return describeError(r.status, r.json, '查询活跃机器')

        const info = r.json?.info
        if (info === null || info === undefined) {
          return '# 当前没有活跃机器\n  用 htb_machine_list 找一台，再 htb_machine_spawn。'
        }
        const out = [`# 当前活跃：${info.name} (id ${info.id})`]
        out.push(`  IP        ${typeof info.ip === 'string' && info.ip !== '' ? info.ip : '（尚未分配，仍在启动）'}`)
        out.push(`  剩余      ${lifeLeft(info.expires_at)}（expires_at ${info.expires_at ?? '?'}）`)
        out.push(`  VPN 服务器 ${info.vpn_server_id ?? '?'}　实验室 ${info.lab_server ?? '?'}`)
        if (info.isSpawning === true) out.push('  ⏳ isSpawning=true')
        return out.join('\n')
      },
    },
    {
      name: 'htb_machine_stop',
      description:
        '释放当前活跃机器（归还配额）。打完就调，别让它一直占着。'
        + '🔴 端点不接受 machine_id，只按"当前活跃实例"操作 —— 所以不用传参数。'
        + '没有活跃机器时返回 404 "Active instance not found"，属正常。',
      parameters: paramsSpec({}),
      output: strOutput(),
      async execute() {
        const r = await request(cfg, 'POST', '/api/v4/vm/terminate')
        if (r.error !== undefined) return `⚠️ ${r.error}`
        if (r.status === 404) {
          return '当前没有活跃机器（404 Active instance not found）—— 无需释放。'
        }
        if (r.status !== 200) return describeError(r.status, r.json, '释放机器')
        const msg = typeof r.json?.message === 'string' ? r.json.message : '已释放'
        return `✅ ${msg}`
      },
    },
    {
      name: 'htb_machine_reset',
      description:
        '重置机器到初始状态（清掉你留下的文件、进程、账号改动）。'
        + '🔴 HTB 对 reset 有**冷却**（通常 5 分钟），频繁调用会 429。'
        + '只在"靶机被自己搞坏"时用 —— 一般换思路比 reset 划算。',
      parameters: paramsSpec({
        machine: { type: 'string', description: '机器名或 id；省略则用当前活跃机器' },
      }),
      output: strOutput(),
      async execute(args) {
        let id
        if (args.machine === undefined || String(args.machine).trim() === '') {
          const act = await request(cfg, 'GET', '/api/v4/machine/active')
          const cur = act.json?.info
          if (cur === null || cur === undefined) {
            return '⚠️ 没有活跃机器可重置。传 machine 参数指定，或先 htb_machine_spawn。'
          }
          id = cur.id
        } else {
          const r = await resolveMachine(cfg, args.machine)
          if (r.error !== undefined) return r.error
          id = r.id
        }

        const r = await request(cfg, 'POST', '/api/v4/vm/reset', { machine_id: id })
        if (r.error !== undefined) return `⚠️ ${r.error}`
        if (r.status === 429) return describeError(429, r.json, '重置机器')
        if (r.status !== 200) return describeError(r.status, r.json, '重置机器')

        const msg = typeof r.json?.message === 'string' ? r.json.message : '已提交'
        return `✅ ${msg}（machine_id=${id}）\n`
          + '   HTB 有冷却，约 5 分钟内不能再次 reset。IP 可能变化 —— 用 htb_machine_status 确认。'
      },
    },
    // ── 账号 ─────────────────────────────────────────────────────────────
    {
      name: 'htb_user_info',
      description:
        '当前账号的信息与权限：排名 / 订阅类型 / VPN 服务器 id。'
        + '用于判断"这台机器我能不能打"（VIP 机器需要 isVip）以及确认 VPN 服务器。'
        + '🔴 刻意不返回 email 等与本任务无关的字段。',
      parameters: paramsSpec({}),
      output: strOutput(),
      async execute() {
        const r = await request(cfg, 'GET', '/api/v4/user/info')
        if (r.error !== undefined) return `⚠️ ${r.error}`
        if (r.status !== 200) return describeError(r.status, r.json, '查询账号信息')

        const u = publicUser(r.json?.info)
        if (Object.keys(u).length === 0) return '⚠️ user/info 返回空'

        const out = [`${u.name ?? '?'} (id ${u.id ?? '?'})`]
        out.push(`  排名      ${u.rank_id ?? '?'}`)
        out.push(`  订阅      ${u.subscriptionType ?? '?'}（VIP=${u.isVip === true}，ServerVIP=${u.isServerVIP === true}）`)
        out.push(`  服务器    ${u.server_id ?? '?'}`)
        if (u.team !== null && u.team !== undefined) out.push(`  团队      ${JSON.stringify(u.team).slice(0, 60)}`)
        return out.join('\n')
      },
    },
  ]

  for (const def of defs) ctx.tools.register(def)
}
