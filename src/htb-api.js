/**
 * htb-api.js — HTB Labs API 的共享访问层
 *
 * 为什么抽出来（2026-10-26）：
 *   在它之前，token 读取 / 请求封装 / 401 提示在三处各写了一遍
 *   （`sherlock-tools.js` 自己一份、`machine-own.js` 自己一份、探针脚本又一份）。
 *   新增 machine 生命周期工具时若再抄一遍，就是第四份 —— 改一处 token 路径要改四处。
 *
 * 统一的三件事：
 *   ① token 读取顺序：`config.tokenPath` > `~/.dsh/htb-token.txt`
 *   ② 请求：Bearer 认证 + JSON 编解码 + 状态码透传
 *   ③ 错误话术：401（过期，给可执行的刷新命令）/ 429（限流）/ 404（端点或对象不存在）
 *
 * 刻意**不做**的：
 *   - 不自动重试。HTB 的 429 有窗口，盲目重试只会把窗口拉长；调用方自己决定等多久。
 *   - 不缓存响应。`machine/active` 的 `life_remaining` 每秒都在变，缓存会让"剩余时间"失真。
 *   - 不打印 token / email 等凭据与个人信息（见 {@link publicUser}）。
 */

import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'

/** API 根。可被 `config.baseUrl` 覆盖（测试打本地 mock）。 */
export const DEFAULT_BASE_URL = 'https://labs.hackthebox.com'

/** token 文件默认位置。 */
export function defaultTokenPath() {
  return join(homedir(), '.dsh', 'htb-token.txt')
}

/** 解析 token 路径（相对路径按 cwd 解析）。 */
export function tokenPathOf(config) {
  const raw = typeof config?.tokenPath === 'string' && config.tokenPath !== ''
    ? config.tokenPath
    : defaultTokenPath()
  return isAbsolute(raw) ? raw : resolve(process.cwd(), raw)
}

/**
 * 读 token。
 * @param config - 插件配置（`tokenPath`）。
 * @returns `{ token }` 或 `{ error }`。
 */
export function readToken(config) {
  const p = tokenPathOf(config)
  if (!existsSync(p)) {
    return { error: `token 文件不存在: ${p}\n   刷新: node scripts/htb-token-refresh.mjs --force` }
  }
  const raw = readFileSync(p, 'utf-8').trim()
  if (raw === '') return { error: `token 文件为空: ${p}` }
  return { token: raw.split(/\s+/)[0] }
}

/** 解析 API 根。 */
export function baseUrlOf(config) {
  const raw = typeof config?.baseUrl === 'string' && config.baseUrl !== ''
    ? config.baseUrl
    : DEFAULT_BASE_URL
  return raw.replace(/\/+$/, '')
}

/**
 * 发一次请求。
 *
 * @param config - 插件配置（`tokenPath` / `baseUrl`）。
 * @param method - HTTP 方法。
 * @param path - 以 `/api/` 开头的路径（可含 query）。
 * @param body - 可选 JSON body；`undefined` 表示不带 body。
 * @returns `{ status, json }` 或 `{ error }`（网络层失败 / 无 token）。
 */
export async function request(config, method, path, body) {
  const { token, error } = readToken(config)
  if (error !== undefined) return { error }

  const init = {
    method,
    headers: {
      authorization: 'Bearer ' + token,
      accept: 'application/json',
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  }

  let res
  try {
    res = await fetch(baseUrlOf(config) + path, init)
  } catch (err) {
    return { error: `请求失败: ${err?.message ?? err}` }
  }

  const text = await res.text()
  let json
  try { json = JSON.parse(text) } catch { json = { _raw: text.slice(0, 300) } }
  return { status: res.status, json }
}

/**
 * 把非 2xx 响应翻译成**可执行的**提示。
 *
 * 话术原则：说清"是什么问题"+"下一步怎么做"，而不是把原始 JSON 丢给模型。
 * @param status - HTTP 状态码。
 * @param json - 响应体。
 * @param action - 动作描述（如 "提交 flag"、"启动机器"），用于拼句子。
 * @returns 面向模型的错误文本（不含 token）。
 */
export function describeError(status, json, action = '请求') {
  const msg = typeof json?.message === 'string' ? json.message : JSON.stringify(json).slice(0, 200)
  if (status === 401) {
    return `⚠️ ${action}失败：401 未认证（token 过期或无效）。\n`
      + '   刷新: node scripts/htb-token-refresh.mjs --force\n'
      + '   只查状态不开浏览器: node scripts/htb-token-refresh.mjs --check'
  }
  if (status === 429) {
    return `⚠️ ${action}失败：429 限流。HTB 对多数写操作有冷却（reset 尤其明显），等几分钟再试。`
  }
  if (status === 404) {
    return `⚠️ ${action}失败：404 —— ${msg}\n`
      + '   常见原因：机器未 spawn（先去 htb_machine_spawn）/ id 或名字写错 / 该端点不存在。'
  }
  if (status === 422) {
    const errs = json?.errors
    const detail = errs && typeof errs === 'object'
      ? Object.entries(errs).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join('; ') : v}`).join(' | ')
      : ''
    return `⚠️ ${action}失败：422 参数不合法 —— ${msg}${detail !== '' ? `\n   ${detail}` : ''}`
  }
  return `⚠️ ${action}失败：HTTP ${status} —— ${msg}`
}

/**
 * 用户信息的**可公开子集**。
 *
 * `user/info` 返回 24 个字段，其中 `email` / `identifier` / `avatar` 与本任务无关，
 * 打印出来只会占上下文。只留"影响打靶决策"的几个：
 * 订阅类型（能不能打 VIP 机器）、server_id（VPN 服务器）、rank。
 * @param info - `user/info` 的 `info` 对象。
 * @returns 精简后的对象。
 */
export function publicUser(info) {
  if (info === null || typeof info !== 'object') return {}
  const pick = ['id', 'name', 'rank_id', 'subscriptionType', 'isVip', 'isServerVIP', 'server_id', 'team']
  const out = {}
  for (const k of pick) if (info[k] !== undefined) out[k] = info[k]
  return out
}
