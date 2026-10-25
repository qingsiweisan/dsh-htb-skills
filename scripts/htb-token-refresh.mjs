#!/usr/bin/env node
// HTB token 自动刷新 —— 用持久化浏览器 profile 读 localStorage['htb-token'] 并落盘。
//
// 背景：HTB 会话 token 是 3 天有效期的 JWT，存在 app.hackthebox.com 的
//   localStorage['htb-token']。原流程是手动的（F12 复制 → data:URL 下载 → 手动移动文件）。
//   本脚本把它变成一条命令，可挂计划任务。
//
// 设计要点：
//   - 复用【已有登录态的 profile】(默认 = Playwright MCP 的 user-data-dir)，
//     所以通常【不需要重新登录】，也不需要账号密码。
//   - 幂等且便宜：token 剩余时间 > --min-hours 时直接退出，不开浏览器。
//   - 只在真的需要登录时才弹有头窗口等待人工登录一次，之后长期复用。
//   - 写入是原子的（临时文件 + rename），不会写坏正在被工具读取的 token。
//
// 用法：
//   node htb-token-refresh.mjs                 # 需要时刷新（默认）
//   node htb-token-refresh.mjs --check         # 只看当前 token 状态，不开浏览器
//   node htb-token-refresh.mjs --force         # 强制刷新
//   node htb-token-refresh.mjs --min-hours 24  # 剩余不足 24h 才刷
//   node htb-token-refresh.mjs --profile <dir> # 换 profile
//   node htb-token-refresh.mjs --out <file>    # 换输出路径
//   node htb-token-refresh.mjs --timeout 300   # 等待人工登录的秒数
//   node htb-token-refresh.mjs --no-verify     # 跳过 API 校验（429 限流时用）
//   node htb-token-refresh.mjs -v              # 打印 profile / chromium 路径
//
// 退出码：0 成功/无需刷新；1 失败（含 401）。429 限流不算失败。

import { readFileSync, writeFileSync, renameSync, existsSync, readdirSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { homedir, tmpdir } from 'node:os'

const BASE = process.env.HTB_BASE || 'https://labs.hackthebox.com'
const LOGIN_URL = process.env.HTB_LOGIN_URL || 'https://app.hackthebox.com/login'
const HOME_URL = 'https://app.hackthebox.com/'

/** 默认复用 Playwright MCP 的 profile —— 登录态通常已经在那里。 */
const DEFAULT_PROFILE = join(
  process.env.APPDATA || join(homedir(), 'AppData', 'Roaming'),
  'reasonix', 'mcp-state', 'playwright-profile',
)
const DEFAULT_OUT = join(homedir(), '.dsh', 'htb-token.txt')

// ---------- 参数 ----------
function parseArgs(argv) {
  const o = { check: false, force: false, minHours: 12, profile: DEFAULT_PROFILE, out: DEFAULT_OUT, timeout: 180, headless: true, verbose: false, noVerify: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--check') o.check = true
    else if (a === '--force') o.force = true
    else if (a === '--headed') o.headless = false
    else if (a === '--no-verify') o.noVerify = true
    else if (a === '--verbose' || a === '-v') o.verbose = true
    else if (a === '--min-hours') o.minHours = Number(argv[++i])
    else if (a === '--profile') o.profile = argv[++i]
    else if (a === '--out') o.out = argv[++i]
    else if (a === '--timeout') o.timeout = Number(argv[++i])
    else if (a === '--help' || a === '-h') { console.log(readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1, 30).map(l => l.replace(/^\/\/ ?/, '')).join('\n')); process.exit(0) }
  }
  return o
}

// ---------- JWT ----------
function decodeJwt(token) {
  try {
    const p = token.split('.')[1]
    if (!p) return null
    const b = Buffer.from(p.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
    return JSON.parse(b)
  } catch { return null }
}

function tokenStatus(token) {
  const j = decodeJwt(token)
  if (!j?.exp) return { valid: false, note: '非 JWT 或缺少 exp' }
  const now = Math.floor(Date.now() / 1000)
  const exp = Number(j.exp)
  return {
    valid: now < exp,
    exp,
    iat: Number(j.iat) || 0,
    sub: j.sub,
    hoursLeft: (exp - now) / 3600,
    expLocal: new Date(exp * 1000).toLocaleString(),
    iatLocal: j.iat ? new Date(Number(j.iat) * 1000).toLocaleString() : '?',
  }
}

function readCurrentToken(out) {
  try { return readFileSync(out, 'utf8').trim() } catch { return '' }
}

// ---------- 定位 playwright ----------
async function loadPlaywright() {
  const tries = []
  if (process.env.HTB_PLAYWRIGHT) tries.push(process.env.HTB_PLAYWRIGHT)
  // npx 缓存（@playwright/mcp 跑过就会有）
  const npxRoot = join(process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local'), 'npm-cache', '_npx')
  try {
    for (const d of readdirSync(npxRoot)) {
      tries.push(join(npxRoot, d, 'node_modules', 'playwright', 'index.mjs'))
      tries.push(join(npxRoot, d, 'node_modules', 'playwright-core', 'index.mjs'))
    }
  } catch { /* no npx cache */ }
  // 全局 / 本地 node_modules
  const g = join(process.env.APPDATA || '', 'npm', 'node_modules')
  tries.push(join(g, 'playwright', 'index.mjs'))
  tries.push(join(g, 'playwright-core', 'index.mjs'))

  for (const t of tries) {
    if (!existsSync(t)) continue
    try {
      const m = await import('file:///' + t.replace(/\\/g, '/'))
      if (m.chromium) return m
    } catch { /* try next */ }
  }
  return null
}

/**
 * 找本机已装的 Chromium 可执行文件。
 * 为什么需要：npx 缓存里的 playwright 版本可能与本机 ms-playwright 的浏览器 revision 不一致
 * （例如 playwright 期望 chromium_headless_shell-1237，本机只有 -1234），
 * 直接用默认解析会报 "Executable doesn't exist"。显式指定 executablePath 可绕开。
 */
function findChromiumExecutable() {
  if (process.env.HTB_CHROMIUM && existsSync(process.env.HTB_CHROMIUM)) return process.env.HTB_CHROMIUM
  const root = process.env.PLAYWRIGHT_BROWSERS_PATH
    || join(process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local'), 'ms-playwright')
  const cands = []
  try {
    for (const d of readdirSync(root)) {
      const m = /^chromium-(\d+)$/.exec(d)          // 只认完整 chromium，不要 headless_shell
      if (!m) continue
      for (const rel of [['chrome-win64', 'chrome.exe'], ['chrome-win', 'chrome.exe'], ['chrome-linux', 'chrome']]) {
        const p = join(root, d, ...rel)
        if (existsSync(p)) cands.push({ p, rev: Number(m[1]) })
      }
    }
  } catch { /* no ms-playwright */ }
  cands.sort((a, b) => b.rev - a.rev)
  return cands[0]?.p || null
}

// ---------- 浏览器取 token ----------
async function grabTokenFromBrowser(opts, needLogin) {
  const pw = await loadPlaywright()
  if (!pw) {
    throw new Error(
      '找不到 playwright。先跑一次 `npx @playwright/mcp@latest --help` 让 npx 缓存到位，'
      + '或设 $HTB_PLAYWRIGHT 指向 playwright/index.mjs。'
    )
  }
  if (!existsSync(opts.profile)) mkdirSync(opts.profile, { recursive: true })

  const exe = findChromiumExecutable()
  if (opts.verbose) console.log(`   profile: ${opts.profile}\n   chromium: ${exe || '(用 playwright 默认解析)'}`)

  let ctx
  try {
    ctx = await pw.chromium.launchPersistentContext(opts.profile, {
      headless: opts.headless,
      ...(exe ? { executablePath: exe } : {}),
    })
  } catch (e) {
    const msg = String(e.message || e)
    let hint
    if (/Executable doesn't exist|ENOENT/i.test(msg)) {
      hint = '本机 Chromium 与 playwright 期望的版本不匹配。\n'
        + '  → 要么 `npx playwright install chromium`，要么设 $HTB_CHROMIUM 指向已有的 chrome.exe。'
    } else if (/SingletonLock|ProcessSingleton|already running|正在使用|Access is denied|EBUSY/i.test(msg)) {
      hint = `Playwright MCP 的浏览器正开着，占着这个 profile。\n  → 关掉那个浏览器窗口（或停掉 playwright MCP）再重试；或换 --profile <dir>。`
    } else {
      hint = '检查 profile 路径是否可写、是否有其它进程占用。'
    }
    throw new Error(`打开 profile 失败：${msg.split('\n')[0]}\n  ${hint}`)
  }

  try {
    const page = ctx.pages()[0] || await ctx.newPage()
    await page.goto(HOME_URL, { waitUntil: 'domcontentloaded', timeout: 60000 })

    const read = () => page.evaluate(() => {
      try { return localStorage.getItem('htb-token') || '' } catch { return '' }
    })

    let token = await read()
    if (token) return token

    // 没有 token → 需要人工登录一次
    if (!needLogin) return ''

    console.log(`\n⚠️  profile 里没有 HTB 登录态。`)
    console.log(`   已打开浏览器，请在 ${opts.timeout} 秒内完成登录（${LOGIN_URL}）。`)
    console.log(`   登录成功后本脚本会自动抓取 token，无需其它操作。\n`)
    await page.goto(LOGIN_URL, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(() => {})

    const deadline = Date.now() + opts.timeout * 1000
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 3000))
      token = await read()
      if (token) return token
    }
    throw new Error(`等待登录超时（${opts.timeout}s）。`)
  } finally {
    await ctx.close().catch(() => {})
  }
}

// ---------- 落盘（原子） ----------
function writeTokenAtomic(out, token) {
  mkdirSync(dirname(out), { recursive: true })
  const tmp = join(tmpdir(), `htb-token-${process.pid}.tmp`)
  writeFileSync(tmp, token + '\n', 'utf8')
  renameSync(tmp, out)
}

// ---------- 校验 ----------
// 区分 401（token 真坏）与 429/网络（token 可能没问题）—— 只有 401 才算刷新失败。
async function verify(token) {
  try {
    const res = await fetch(`${BASE}/api/v4/user/info`, {
      headers: { authorization: 'Bearer ' + token, accept: 'application/json' },
    })
    if (res.status === 401) return { ok: false, fatal: true, note: '401 未认证 —— token 无效或已过期' }
    if (res.status === 429) return { ok: false, fatal: false, note: '429 限流（token 本身没问题，稍后重试即可）' }
    if (!res.ok) return { ok: false, fatal: false, note: `HTTP ${res.status}` }
    const ct = res.headers.get('content-type') || ''
    if (!ct.includes('json')) return { ok: false, fatal: false, note: `非 JSON 响应 (${ct})，多半是被 WAF/限流挡了` }
    const j = await res.json().catch(() => ({}))
    const info = j?.info || {}
    return { ok: true, fatal: false, note: `user=${info.name ?? '?'} id=${info.id ?? '?'} rank=${info.ranking ?? '?'}` }
  } catch (e) {
    return { ok: false, fatal: false, note: '网络错误: ' + String(e.message).split('\n')[0] }
  }
}

// ---------- main ----------
async function main() {
  const opts = parseArgs(process.argv.slice(2))
  const cur = readCurrentToken(opts.out)

  if (opts.check || (!opts.force && cur)) {
    const st = tokenStatus(cur)
    if (!cur) {
      console.log(`当前 token: 不存在 (${opts.out})`)
    } else {
      console.log(`当前 token (${opts.out})`)
      console.log(`  iat      : ${st.iatLocal}`)
      console.log(`  exp      : ${st.expLocal}`)
      console.log(`  剩余     : ${st.hoursLeft?.toFixed(1)} 小时`)
      console.log(`  有效     : ${st.valid}`)
    }
    if (opts.check) return 0
    if (st.valid && st.hoursLeft >= opts.minHours) {
      console.log(`\n✅ 剩余 ${st.hoursLeft.toFixed(1)}h ≥ ${opts.minHours}h，无需刷新。`)
      return 0
    }
    console.log(`\n→ 剩余不足 ${opts.minHours}h（或已过期），开始刷新…`)
  }

  const token = await grabTokenFromBrowser(opts, true)
  if (!token) throw new Error('浏览器里没有 localStorage[\'htb-token\'] —— 可能未登录。')

  const st = tokenStatus(token)
  if (!st.valid) throw new Error(`抓到的新 token 已过期（exp=${st.expLocal}），说明登录态本身已失效，请重新登录。`)

  writeTokenAtomic(opts.out, token)
  console.log(`✅ 已写入 ${opts.out}`)
  console.log(`   iat ${st.iatLocal} → exp ${st.expLocal}（剩余 ${st.hoursLeft.toFixed(1)}h）`)

  if (opts.noVerify) { console.log('   API 校验: 已跳过 (--no-verify)'); return 0 }
  const v = await verify(token)
  console.log(`   API 校验: ${v.ok ? '✅' : (v.fatal ? '❌' : '⚠️')} ${v.note}`)
  // 只有 401 才算失败；429/网络问题不该让刷新判为失败。
  return v.fatal ? 1 : 0
}

main()
  .then(code => {
    process.exitCode = code ?? 0
    // 安全网：playwright 有时会留下 libuv 句柄导致进程不退出（Windows 上甚至会断言崩溃）。
    // unref 的定时器不阻止事件循环自然结束；只有循环被残留句柄卡住时它才会兜底强退。
    setTimeout(() => process.exit(process.exitCode), 2000).unref()
  })
  .catch(e => {
    console.error(`\n❌ ${String(e.message || e)}`)
    process.exitCode = 1
    setTimeout(() => process.exit(1), 2000).unref()
  })
