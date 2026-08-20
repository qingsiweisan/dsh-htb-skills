/**
 * HTB Sherlock 工具组(host half)— 让 DSH 会话直接调用,不用再猜 API。
 *
 * 注册 6 个模型 Tool:
 *   htb_sherlock_info       场景 + 任务(hint/mask)一屏拿全
 *   htb_sherlock_tasks      只列任务 id/hint/mask
 *   htb_sherlock_download   拿签名链接下载附件(可解压)
 *   htb_sherlock_submit     交单题
 *   htb_sherlock_submit_file 批量交 JSON
 *   htb_sherlock_progress   owned / 进度 / rank
 *
 * 认证: token 读取顺序 = config.tokenPath > $HTB_TOKEN > ~/.dsh/htb-token.txt
 *   (3 天 JWT; 过期后用浏览器 localStorage htb-token 刷新落盘,零转写:
 *    页面上下文 data:URL 下载 htb-token.txt → 移到 ~/.dsh/htb-token.txt)
 *
 * 端点(BASE = https://labs.hackthebox.com, Bearer 认证):
 *   GET  /api/v4/sherlocks/{slug}              -> {data:{id,...}}
 *   GET  /api/v4/sherlocks/{id}/play           -> {data:{scenario,file_name,file_size}}
 *   GET  /api/v4/sherlocks/{id}/tasks          -> {data:[{id,title,description,hint,masked_flag}]}
 *   GET  /api/v4/sherlocks/{id}/download_link  -> {url,expires_in} 签名重定向
 *   GET  {url}                                  -> 跟随 302 下载 zip
 *   POST /api/v4/sherlocks/{id}/tasks/{tid}/flag {"flag":"..."} -> "Task flag owned!" / "Incorrect task flag!"
 *   GET  /api/v4/sherlocks/{id}/progress       -> {data:{is_owned,progress,tasks_answered,own_rank}}
 *
 * 工具定义手写(JSON Schema 直给),不 import @deepseek-ai/dsh-tools —
 * 避免给部署增加新的包依赖解析面。register() 校验的是
 * output{schema,render} + 可选 timeoutMs,参数 JSON Schema 由调用侧校验。
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { execFileSync } from 'node:child_process'

const BASE = 'https://labs.hackthebox.com'
const DEFAULT_PASSWORD = 'hacktheblue'

function tokenPath(config) {
  if (typeof config?.tokenPath === 'string' && config.tokenPath) return config.tokenPath
  return join(homedir(), '.dsh', 'htb-token.txt')
}

function resolveToken(config) {
  if (typeof config?.token === 'string' && config.token) return config.token
  if (typeof process.env.HTB_TOKEN === 'string' && process.env.HTB_TOKEN) return process.env.HTB_TOKEN
  const file = tokenPath(config)
  try {
    const t = readFileSync(file, 'utf8').trim()
    if (t) return t
  } catch {
    /* fall through to error */
  }
  throw new Error(
    `HTB token 未找到。请用浏览器 localStorage htb-token 刷新 ${file} (零转写: data:URL 下载 htb-token.txt 后移入),`
    + ' 或传 config.token / 设 $HTB_TOKEN。'
  )
}

async function api(pathname, token, opts = {}) {
  const res = await fetch(BASE + pathname, {
    headers: { authorization: 'Bearer ' + token, accept: 'application/json', ...(opts.headers || {}) },
    ...opts,
  })
  return res
}

async function apiJson(pathname, token, opts = {}) {
  const res = await api(pathname, token, opts)
  const text = await res.text()
  let json
  try { json = JSON.parse(text) } catch { json = { _raw: text } }
  if (res.status === 401) {
    throw new Error(`401 未认证: htb-token 过期或无效。重新登录 HTB 后刷新 ${tokenPath()}`)
  }
  return { status: res.status, json }
}

async function resolveId(slug, token) {
  const { status, json } = await apiJson(`/api/v4/sherlocks/${encodeURIComponent(slug)}`, token)
  if (status !== 200 || !json.data) {
    throw new Error(`解析 sherlock '${slug}' 失败 (status ${status})`)
  }
  return json.data
}

async function listTasks(id, token) {
  const { status, json } = await apiJson(`/api/v4/sherlocks/${id}/tasks`, token)
  if (status !== 200 || !json.data) throw new Error(`获取任务列表失败 (status ${status})`)
  return json.data
}

function fmtTasks(tasks) {
  return tasks.map((t, i) =>
    `${i + 1}. [id ${t.id}] ${t.description}`
    + (t.hint ? `\n   hint: ${t.hint}` : '')
    + `\n   mask: ${t.masked_flag ?? ''}`,
  ).join('\n')
}

function renderText(value) {
  return [{ type: 'text', text: value }]
}

function strOutput() {
  return { schema: { type: 'string' }, render(_args, value) { return renderText(String(value)) } }
}

function paramsSpec(props, required) {
  return { type: 'object', properties: props, required }
}

async function runInfo(config, slug) {  const token = resolveToken(config)
  const meta = await resolveId(slug, token)
  const { json: play } = await apiJson(`/api/v4/sherlocks/${meta.id}/play`, token)
  const tasks = await listTasks(meta.id, token)
  const p = play.data || {}
  return `# ${meta.name} (id ${meta.id}, ${meta.difficulty}${meta.rating ? ', rating ' + meta.rating : ''})\n`
    + `附件: ${p.file_name ?? '?'} (${p.file_size ?? '?'})\n\n## 场景\n${p.scenario ?? '(无)'}\n\n## 任务\n${fmtTasks(tasks)}`
}

async function runTasks(config, slug) {
  const token = resolveToken(config)
  const meta = await resolveId(slug, token)
  const tasks = await listTasks(meta.id, token)
  return tasks.map((t, i) => `${i + 1}\t${t.id}\t${t.masked_flag ?? ''}\t${t.description}${t.hint ? `  [hint: ${t.hint}]` : ''}`).join('\n')
}

async function runDownload(config, slug, outDir) {
  const token = resolveToken(config)
  const meta = await resolveId(slug, token)
  const { status, json } = await apiJson(`/api/v4/sherlocks/${meta.id}/download_link`, token)
  if (status !== 200 || !json.url) throw new Error(`获取下载链接失败 (status ${status})`)
  const res = await fetch(json.url, { headers: { authorization: 'Bearer ' + token } })
  if (!res.ok) throw new Error(`下载失败: HTTP ${res.status}`)
  const buf = Buffer.from(await res.arrayBuffer())
  const dir = outDir || './sherlock-work'
  mkdirSync(dir, { recursive: true })
  const zipPath = join(dir, 'sherlock.zip')
  writeFileSync(zipPath, buf)
  let lines = [`已下载 ${buf.length} 字节 -> ${zipPath}`]
  // 尽力解压: 7z / 7zz / unzip
  const pw = config?.password || DEFAULT_PASSWORD
  for (const [cmd, args] of [
    ['7z', ['x', `-p${pw}`, `-o${dir}`, zipPath, '-y']],
    ['7zz', ['x', `-p${pw}`, `-o${dir}`, zipPath, '-y']],
    ['unzip', ['-P', pw, '-o', zipPath, '-d', dir]],
  ]) {
    try {
      execFileSync(cmd, args, { stdio: 'ignore' })
      lines.push(`已用 ${cmd} 解压 (密码 ${pw})`)
      break
    } catch {
      /* try next */
    }
  }
  return lines.join('\n')
}

async function runSubmit(config, slug, task, answer) {
  const token = resolveToken(config)
  const meta = await resolveId(slug, token)
  const tasks = await listTasks(meta.id, token)
  const target = tasks.find(t => String(t.id) === String(task)) || tasks[Number(task) - 1]
  if (!target) {
    return `找不到任务 '${task}'。可用:\n${tasks.map((t, i) => `  ${i + 1} (id ${t.id}): ${t.title}`).join('\n')}`
  }
  const res = await api(`/api/v4/sherlocks/${meta.id}/tasks/${target.id}/flag`, token, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ flag: answer }),
  })
  const text = await res.text()
  let json
  try { json = JSON.parse(text) } catch { json = { _raw: text } }
  if (res.status === 201 && /owned/i.test(json.message || '')) return `✅ ${target.title} 通过: ${answer}`
  if (res.status === 429) return `⚠️ 限流 (30/分钟), 稍后重试`
  return `❌ ${target.title} 错误: ${answer}  (${json.message || text})`
}

async function runSubmitFile(config, slug, answersJson) {
  const token = resolveToken(config)
  const meta = await resolveId(slug, token)
  const tasks = await listTasks(meta.id, token)
  const data = typeof answersJson === 'string' ? JSON.parse(answersJson) : answersJson
  const lines = []
  for (const [k, v] of Object.entries(data)) {
    const t = tasks.find(x => String(x.id) === String(k)) || tasks[Number(k) - 1]
    if (!t) { lines.push(`跳过未知任务键 '${k}'`); continue }
    lines.push(await runSubmit(config, slug, t.id, String(v)))
  }
  return lines.join('\n')
}

async function runProgress(config, slug) {
  const token = resolveToken(config)
  const meta = await resolveId(slug, token)
  const { json } = await apiJson(`/api/v4/sherlocks/${meta.id}/progress`, token)
  const d = json.data || {}
  return `${meta.name}: owned=${d.is_owned}  ${d.tasks_answered}/${d.total_tasks}  progress=${d.progress}%  rank=${d.own_rank}`
}

/** 在 apply() 里调用: 注册全部 htb_sherlock_* 工具。返回注册函数数组。 */
export function registerSherlockTools(ctx, config) {
  const defs = [
    {
      name: 'htb_sherlock_info',
      description:
        'HTB Sherlock 题目信息: 元数据 + 场景 + 全部任务(含 hint 和掩码)。'
        + '做 Sherlock 的第一步: 用 slug(题名, 如 Baggage) 拉全题面。',
      parameters: paramsSpec({ slug: { type: 'string', description: 'Sherlock 名称/slug' } }, ['slug']),
      output: strOutput(),
      async execute(args) { return runInfo(config, args.slug) },
    },
    {
      name: 'htb_sherlock_tasks',
      description: '只列某 Sherlock 的任务 id / hint / 掩码, 便于对照答案文件。',
      parameters: paramsSpec({ slug: { type: 'string' } }, ['slug']),
      output: strOutput(),
      async execute(args) { return runTasks(config, args.slug) },
    },
    {
      name: 'htb_sherlock_download',
      description:
        '下载 Sherlock 附件 zip(走官方 download_link 签名链接, 无需 Playwright)。'
        + '有 7z/unzip 时自动解压(zip 密码默认 hacktheblue)。',
      parameters: paramsSpec({
        slug: { type: 'string' },
        outDir: { type: 'string', description: '输出目录, 默认 ./sherlock-work' },
      }, ['slug']),
      output: strOutput(),
      async execute(args) { return runDownload(config, args.slug, args.outDir) },
    },
    {
      name: 'htb_sherlock_submit',
      description:
        '提交某 Sherlock 一道题的答案。task 可以是任务 id(数字) 或 1-based 序号。'
        + '返回 ✅ 通过 / ❌ 错误 / ⚠️ 限流。',
      parameters: paramsSpec({
        slug: { type: 'string' },
        task: { type: 'string', description: '任务 id 或 1-based 序号' },
        answer: { type: 'string', description: '答案原文' },
      }, ['slug', 'task', 'answer']),
      output: strOutput(),
      async execute(args) { return runSubmit(config, args.slug, args.task, args.answer) },
    },
    {
      name: 'htb_sherlock_submit_file',
      description:
        '批量提交: 传 JSON 字符串或对象, 键 = 任务 id 或 1-based 序号, 值 = 答案。'
        + '如 {"1":"1.zip","2":"Everything 1.4.1.1028"}。串行提交避免限流。',
      parameters: paramsSpec({
        slug: { type: 'string' },
        answers: { type: 'object', description: '{任务: 答案} 映射' },
      }, ['slug', 'answers']),
      output: strOutput(),
      async execute(args) { return runSubmitFile(config, args.slug, args.answers) },
    },
    {
      name: 'htb_sherlock_progress',
      description: '查某 Sherlock 的完成度: owned / 已答 / 总题 / 排名。',
      parameters: paramsSpec({ slug: { type: 'string' } }, ['slug']),
      output: strOutput(),
      async execute(args) { return runProgress(config, args.slug) },
    },
  ]
  return defs.map(def => ctx.tools.register(def))
}

// 导出 runner 供测试与复用(注册函数 registerSherlockTools 已在上面导出)。
export { runInfo, runTasks, runDownload, runSubmit, runSubmitFile, runProgress }
