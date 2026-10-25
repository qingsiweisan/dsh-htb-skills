/**
 * scope-observe.js — 出站目标**观测器**（只记录，永不拦截）
 *
 * 为什么是"只记录"而不是"强制拦截"（2026-10-21 复审结论）：
 *   授权边界不能靠**命令文本正则**来保证 —— 脚本、重定向、代理、远端执行
 *   都能绕过；而一个看起来在拦截、实际能绕过的机制，比没有机制更危险
 *   （它会给操作者虚假的安全感）。真正强制的授权需要在执行环境层做
 *   （网络 ACL / 容器出网策略 / 远端主机防火墙）。
 *
 *   所以这里做的是**先把事实采集出来**：
 *     · 本会话实际访问了哪些目标（含被 HTB_GUARD_ALLOW 放行的）
 *     · 哪些目标从未出现在台账的 host fact 里（= 未经登记的目标）
 *   攒够数据之后，才有依据决定要不要、以及在哪个层做强制。
 *   这与 Struggle 的演进路径一致：先记录模式，再考虑干预。
 *
 * 边界（刻意的）：
 *   - 挂在 `tools/pre-execute`（不是 `ctx.tools.guard()`）：本模块**不做判定**，
 *     用 waterfall 挂点就不会占用守卫槽位、也不会影响任何"注册了几个守卫"的断言。
 *     因为是放行型 listener，pre-execute 可被重排这件事对本模块无影响。
 *   - 任何异常一律放行（fail-open），并且**永远调用 next()**（不拒绝、不询问），
 *     所以它不可能挡住作业。
 *   - 只观测出站工具，`read`/`write`/`grep` 不参与
 *   - 提取是启发式的：漏报可接受，误报只影响日志质量
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'

/** Stable Cordis plugin name. */
export const name = 'htb-scope-observe'

/** 依赖工具注册表（与 guard 同一个挂点）。 */
export const inject = ['tools']

/** 默认观测的出站工具。 */
export const OUTBOUND_TOOLS = ['pwsh', 'bash', 'ssh_exec', 'ssh_cluster']

/** 默认日志位置。 */
export const DEFAULT_LOG_PATH = join(homedir(), '.dsh', 'htb-scope-observed.jsonl')

/**
 * 不算"目标"的地址：本机回环、通配、以及 RFC 5737 文档网段。
 * 这些出现在命令里通常是本地工具链或示例，记下来只会淹没有效信号。
 */
const IGNORED = [
  /^127\./,
  /^0\.0\.0\.0$/,
  /^::1$/,
  /^::$/,
  /^192\.0\.2\./,
  /^198\.51\.100\./,
  /^203\.0\.113\./,
  /^169\.254\./, // 链路本地：HTB 里通常是 IMDS 演练，不是靶机
]

const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const URL_HOST = /(?:https?|ftp|ssh|smb|ldap|rdp):\/\/([A-Za-z0-9._-]+)/gi
const AT_HOST = /\b[A-Za-z0-9._-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g

function ignored(host) {
  return IGNORED.some((re) => re.test(host))
}

/**
 * 从一次工具调用里提取目标（IP / 主机名）。
 *
 * 刻意**不**排除引号内的字面量：这里只做观测，`grep "10.0.0.1"` 记一条也无害；
 * 而如果按引号豁免，反而会漏掉 `bash -c "curl 10.0.0.1"` 这种最常见的形态。
 * @param exec - 工具执行描述。
 * @returns 去重后的目标字符串数组。
 */
export function extractTargets(exec) {
  const out = new Set()
  const name = exec?.name
  if (typeof name !== 'string' || !OUTBOUND_TOOLS.includes(name)) return []

  // ssh_exec / ssh_cluster 的目标在参数里，直接取，不必解析命令文本。
  const args = exec?.arguments ?? {}
  for (const key of ['host', 'target', 'hostname', 'ip']) {
    const v = args[key]
    if (typeof v === 'string' && v.trim() !== '') {
      const h = v.trim()
      if (!ignored(h)) out.add(h)
    }
  }

  // 命令型工具：把命令文本拼起来扫。
  const text = [
    typeof args.command === 'string' ? args.command : '',
    typeof args.script === 'string' ? args.script : '',
    Array.isArray(args.args) ? args.args.join(' ') : '',
  ].join(' ')

  if (text !== '') {
    for (const m of text.matchAll(IPV4)) {
      const h = m[0]
      // 粗筛：每段 ≤255，排除明显的版本号形态（如 1.2.3.4 之外的 999.1.1.1）
      if (h.split('.').every((p) => Number(p) <= 255) && !ignored(h)) out.add(h)
    }
    for (const m of text.matchAll(URL_HOST)) {
      const h = m[1]
      if (!ignored(h) && !out.has(h)) out.add(h)
    }
    for (const m of text.matchAll(AT_HOST)) {
      const h = m[1]
      if (!ignored(h)) out.add(h)
    }
  }

  return [...out]
}

/**
 * 造一个"已登记 host 集合"的读取器，按账本文件的 `mtime + size` 缓存。
 *
 * 为什么必须缓存（2026-10-21 复审）：本函数在**每次出站工具调用**前都会跑
 * （挂的是 pre-execute）。一个跑了半天的会话，`<machine>-state.jsonl` 可能几万行，
 * 每次 nmap/curl 都全量重读，开销会累积成肉眼可见的延迟。
 * 缓存键用 (文件名, mtime, size) —— 账本是 append-only，任何写入都会改 mtime/size，
 * 所以这个键既能命中、又不会读到陈旧内容。
 * @param stateRoot - 台账根目录。
 * @param machine - 可选：精确绑定某个账本。
 * @returns 读取函数，返回已登记目标的 Set。
 */
function makeRegisteredHostsReader(stateRoot, machine) {
  let cache = { key: '', hosts: new Set() }
  return function read() {
    let names = []
    try {
      names = readdirSync(stateRoot).filter((n) => n.endsWith('-state.jsonl'))
    } catch {
      return new Set()
    }
    if (typeof machine === 'string' && machine.trim() !== '') {
      const want = machine.trim().endsWith('-state.jsonl') ? machine.trim() : `${machine.trim()}-state.jsonl`
      names = names.includes(want) ? [want] : []
    }

    let key = ''
    const paths = []
    for (const n of names) {
      const p = join(stateRoot, n)
      try {
        const st = statSync(p)
        key += `${n}:${st.mtimeMs}:${st.size}|`
        paths.push(p)
      } catch { /* 单个文件读不到就跳过 */ }
    }
    if (key === cache.key) return cache.hosts

    const hosts = new Set()
    for (const p of paths) {
      try {
        for (const line of readFileSync(p, 'utf-8').split('\n')) {
          const t = line.trim()
          if (t === '') continue
          try {
            const r = JSON.parse(t)
            if (r.type === 'fact' && r.kind === 'host' && typeof r.key === 'string') hosts.add(r.key)
          } catch { /* 坏行跳过 */ }
        }
      } catch { /* 单个账本读不到就跳过 */ }
    }
    cache = { key, hosts }
    return hosts
  }
}

/**
 * 挂载观测器。
 *
 * 配置：
 *   - `enabled`（默认 true）：设 false 完全不挂。
 *   - `logPath`：观测日志路径（默认 `~/.dsh/htb-scope-observed.jsonl`）。
 *   - `stateRoot` / `machine`：用于判断目标是否已登记为 host fact。
 *   - `tools`：覆盖观测的工具名列表。
 * @param ctx - host 插件上下文。
 * @param config - 见上。
 */
export function apply(ctx, config) {
  const cfg = config ?? {}
  if (cfg.enabled === false) return
  const logPath = typeof cfg.logPath === 'string' && cfg.logPath.trim() !== ''
    ? (isAbsolute(cfg.logPath) ? cfg.logPath : resolve(process.cwd(), cfg.logPath))
    : DEFAULT_LOG_PATH
  const stateRoot = typeof cfg.stateRoot === 'string' && cfg.stateRoot.trim() !== ''
    ? (isAbsolute(cfg.stateRoot) ? cfg.stateRoot : resolve(process.cwd(), cfg.stateRoot))
    : join(process.cwd(), 'loot')
  const machine = typeof cfg.machine === 'string' ? cfg.machine : undefined
  const tools = new Set(Array.isArray(cfg.tools) && cfg.tools.length > 0 ? cfg.tools : OUTBOUND_TOOLS)

  // 内存去重：同一 agent + 同一目标，10 分钟内只记一次，避免一次扫描刷几百行。
  const seen = new Map()
  const DEDUPE_MS = 10 * 60 * 1000
  const readRegisteredHosts = makeRegisteredHostsReader(stateRoot, machine)

  ctx.on('tools/pre-execute', async (exec, next) => {
    try {
      if (typeof exec?.name === 'string' && tools.has(exec.name)) {
        const targets = extractTargets(exec)
        if (targets.length > 0) {
          const now = Date.now()
          const agentId = typeof exec.agent?.id === 'string' ? exec.agent.id : 'unknown'
          const fresh = []
          for (const t of targets) {
            const key = `${agentId}|${t}`
            const last = seen.get(key)
            if (last !== undefined && now - last < DEDUPE_MS) continue
            seen.set(key, now)
            fresh.push(t)
          }

          if (fresh.length > 0) {
            // 只保留 512 个去重键，防止长会话内存膨胀。
            if (seen.size > 512) {
              for (const [k, ts] of seen) if (now - ts > DEDUPE_MS) seen.delete(k)
            }
            const registered = readRegisteredHosts()
            if (!existsSync(dirname(logPath))) mkdirSync(dirname(logPath), { recursive: true })
            for (const t of fresh) {
              appendFileSync(logPath, `${JSON.stringify({
                ts: new Date(now).toISOString(),
                agent: agentId,
                tool: exec.name,
                target: t,
                registered: registered.has(t),
              })}\n`)
            }
          }
        }
      }
    } catch {
      // fail-open：观测器坏掉绝不能影响工具调用。
    }
    // 🔴 永远放行 —— 本模块不是授权边界，见文件头。
    return next()
  })
}
