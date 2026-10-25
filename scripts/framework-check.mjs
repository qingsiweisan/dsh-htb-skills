/**
 * HTB 框架一键闸。
 *
 * 把散在各处的自检收成一条命令 —— 每次改动后跑它，绿了才算没改坏。
 *
 *   node scripts/framework-check.mjs
 *   node ... --quiet        # 只在失败时打细节
 *
 * 覆盖：
 *   · dsh-htb-skills/scripts/*test*.mjs      12 个 node 套件（含守卫 134 条探针的验收闸）
 *   · 卡库三闸 fix_yaml → triage → audit      ⚠️ 前两个是**改写型**（幂等，已实测 rewritten:0）
 *   · dsh-htb-evidence/verify-htb.mjs        增补工具 + 挂载面 + id 唯一性
 *   · dsh-htb-evidence/verify-composition.mjs 组合闸（**必须在 profile 目录里跑**）
 */
import { existsSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * 路径全部可移植（2026-10-25）：
 * 原来 4 个常量写死了 `C:/Users/Administrator/...`，导致
 *   · 在别人机器上：`readdirSync` 直接 ENOENT，闸跑不起来
 *   · 在本机跑新克隆：读的其实是**本机仓库**，得到假绿（最坏的一种失败）
 * 现在：包根由 `import.meta.url` 推导，其余可用环境变量覆盖。
 *
 * 覆盖方式：
 *   HTB_SKILLS_DIR    卡库目录（默认 <包根>/skills）
 *   HTB_EVIDENCE_REPO 可选的证据插件仓库（默认 <包根>/../dsh-htb-evidence；不存在则跳过）
 *   HTB_PROFILE_DIR   profile 目录（默认 ~/.dsh/profiles/desktop；不存在则跳过）
 */
const HERE = path.dirname(fileURLToPath(import.meta.url))
const SKILLS_REPO = path.resolve(HERE, '..')
const SKILLS_DIR = process.env.HTB_SKILLS_DIR ?? path.join(SKILLS_REPO, 'skills')
const EVIDENCE_REPO = process.env.HTB_EVIDENCE_REPO ?? path.resolve(SKILLS_REPO, '..', 'dsh-htb-evidence')
const PROFILE_DIR = process.env.HTB_PROFILE_DIR ?? path.join(homedir(), '.dsh', 'profiles', 'desktop')
const quiet = process.argv.includes('--quiet')

const gates = []

// 1) node 套件：dsh-htb-skills/scripts 下所有 *test*.mjs
const scriptsDir = path.join(SKILLS_REPO, 'scripts')
for (const name of readdirSync(scriptsDir).filter((f) => /test.*\.mjs$/.test(f)).sort()) {
  gates.push({ name: `suite/${name.replace(/\.mjs$/, '')}`, cwd: SKILLS_REPO, cmd: process.execPath, args: [path.join(scriptsDir, name)] })
}

// 2) 卡库三闸（argv 传卡库路径；audit 额外要求 SUMMARY: 0 errors）
if (existsSync(SKILLS_DIR)) {
  for (const [name, script, expect] of [
    ['cards/fix_yaml', 'fix_yaml.py', /checked: \d+ {2}rewritten: \d+ {2}bad: 0/],
    ['cards/triage', 'triage_skills.py', /processed: \d+/],
    ['cards/audit', 'audit_routing.py', /SUMMARY: 0 errors/],
  ]) {
    gates.push({ name, cwd: scriptsDir, cmd: 'python', args: [path.join(scriptsDir, script), SKILLS_DIR], expect, rewrite: name !== 'cards/audit' })
  }
} else {
  console.log(`↷ 跳过卡库三闸（卡库目录不存在: ${SKILLS_DIR}）`)
}

// 3) evidence 两道（可选组件：仓库不在就跳过，不让别人 clone 后被卡住）
if (existsSync(path.join(EVIDENCE_REPO, 'verify-htb.mjs'))) {
  gates.push({ name: 'evidence/verify-htb', cwd: EVIDENCE_REPO, cmd: process.execPath, args: [path.join(EVIDENCE_REPO, 'verify-htb.mjs')] })
  gates.push({ name: 'evidence/composition', cwd: PROFILE_DIR, cmd: process.execPath, args: [path.join(EVIDENCE_REPO, 'verify-composition.mjs')] })
} else {
  console.log(`↷ 跳过 evidence 两道闸（未找到 ${EVIDENCE_REPO}；它是可选的 Apache-2.0 伴随仓库）`)
}

let failed = 0
console.log(`HTB 框架闸：${gates.length} 道\n`)
for (const gate of gates) {
  const r = spawnSync(gate.cmd, gate.args, { cwd: gate.cwd, encoding: 'utf8' })
  const out = `${r.stdout ?? ''}${r.stderr ?? ''}`
  const code = r.status ?? -1
  const tail = out.trim().split('\n').filter((l) => l.trim() !== '').slice(-1)[0]?.trim() ?? ''
  let ok = code === 0
  let why = ok ? '' : `exit ${code}`
  if (ok && gate.expect && !gate.expect.test(out)) { ok = false; why = `输出未匹配 ${gate.expect}` }
  if (!ok) {
    failed += 1
    console.log(`  ✗ ${gate.name}${gate.rewrite ? '（改写型·幂等）' : ''}  ${why}`)
    for (const line of out.split('\n').filter((l) => l.trim() !== '').slice(-14)) console.log(`      ${line}`)
  } else if (!quiet) {
    console.log(`  ✓ ${gate.name}${gate.rewrite ? '（改写型·幂等）' : ''}  ${tail.slice(0, 96)}`)
  }
}
console.log(failed === 0 ? `\n✅ HTB 框架 ${gates.length} 道闸全绿` : `\n❌ ${failed}/${gates.length} 道闸失败`)
process.exit(failed === 0 ? 0 : 1)
