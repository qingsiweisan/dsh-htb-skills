#!/usr/bin/env node
/**
 * doc-drift-test.mjs — 框架文档的关键数字漂移闸
 *
 * 为什么需要它：2026-10-17 一个会话里**靠人眼**发现两处"文档说谎"——
 *   ① dsh-htb-skills 的 package 描述写 "112 distilled technique cards"，实际 163 张
 *   ② htb-framework.md 写"十九道闸"，实际已 21 道
 * 文档是接手者的唯一入口，它说谎的代价是"接手者按错数字做判断"。而这类错误
 * **完全可以机器检测**：把文档里断言的硬数字与实际状态对照即可。
 *
 * 契约：exit 0 = 通过；任何 FAIL 一律 exit 1；文档不存在时 SKIP（与 router-rules-test 同风格）。
 * 环境变量：HTB_FRAMEWORK_DOC / HTB_SKILLS_ROOT / HTB_ROUTER_PATCH / HTB_Htb_SKILLS_DIR。
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { parseRouterRules } from '../src/state-tools.js'

const DOC = process.env.HTB_FRAMEWORK_DOC
  ?? join(homedir(), 'AppData', 'Roaming', 'reasonix', 'global-workspace', 'htb-framework.md')
const SKILLS = process.env.HTB_SKILLS_ROOT ?? join(homedir(), '.dsh', 'skills')
const ROUTER_PATCH = process.env.HTB_ROUTER_PATCH ?? join(homedir(), 'dsh-htb-router', 'cordis.patch.yml')
const SKILLS_PKG = process.env.HTB_SKILLS_DIR ?? join(homedir(), 'dsh-htb-skills')

if (!existsSync(DOC)) {
  console.log(`SKIP  框架文档不存在: ${DOC}`)
  process.exit(0)
}
const doc = readFileSync(DOC, 'utf-8')
const fails = []
const ok = []

/**
 * 断言文档里的某个数字与实际一致。
 * 找不到任何候选表述时**也记 FAIL** —— 因为那说明表述被改写、闸已失锚
 * （静默通过比误报更危险：闸会以为自己还在守着）。
 */
function assertNumber(label, patterns, actual) {
  for (const re of patterns) {
    const m = re.exec(doc)
    if (m === null) continue
    const claimed = Number(m[1])
    if (claimed === actual) {
      ok.push(`${label}: 文档 ${claimed} = 实测 ${actual}`)
    } else {
      fails.push(`${label}: 文档写 ${claimed}，实际 ${actual}（锚点 "${m[0].trim().slice(0, 40)}"）`)
    }
    return
  }
  fails.push(`${label}: 文档里找不到可校验的表述（期望 ${patterns.map(String).join(' 或 ')}）—— 闸已失锚`)
}

// ① 技能卡数
if (existsSync(SKILLS)) {
  // 排除隐藏目录（.git / .skills-archive 等）—— 它们不是技能卡。
  // 2026-10-22：卡库纳入 git 后 `.git` 被算成第 164 张卡，闸误报。
  const n = readdirSync(SKILLS, { withFileTypes: true })
    .filter((d) => d.isDirectory() && !d.name.startsWith('.')).length
  assertNumber('技能卡数', [/(\d+)\s*张技能卡/, /(\d+)\s*个目录全部含/], n)
}

// ② router 规则数
if (existsSync(ROUTER_PATCH)) {
  const n = parseRouterRules(readFileSync(ROUTER_PATCH, 'utf-8')).length
  assertNumber('router 规则数', [/(\d+)\s*条技术关键词正则/, /(\d+)\s*条规则/, /rules=(\d+)/], n)
}

// ③ 闸数 = scripts 下 test*.mjs + 3 道 python + 2 道 evidence（与 framework-check 的收集口径一致）
const SCRIPTS = join(SKILLS_PKG, 'scripts')
if (existsSync(SCRIPTS)) {
  const mjs = readdirSync(SCRIPTS).filter((n) => /test.*\.mjs$/.test(n)).length
  assertNumber('框架闸数', [/(\d+)\s*道闸/, /(\d+)\s*道全绿/], mjs + 5)
}

// ④ htb_* 工具数（数 src 里注册的工具定义）
const SRC = join(SKILLS_PKG, 'src')
if (existsSync(SRC)) {
  let n = 0
  for (const f of readdirSync(SRC).filter((x) => x.endsWith('.js'))) {
    n += (readFileSync(join(SRC, f), 'utf-8').match(/name: 'htb_/g) ?? []).length
  }
  assertNumber('htb_* 工具数', [/(\d+)\s*个工具/], n)
}

for (const line of ok) console.log(`  ok   ${line}`)
for (const line of fails) console.log(`  FAIL ${line}`)
console.log(fails.length === 0
  ? 'doc-drift-test: PASS（文档数字与现状一致）'
  : `doc-drift-test: FAIL（${fails.length} 处漂移）`)
process.exit(fails.length === 0 ? 0 : 1)
