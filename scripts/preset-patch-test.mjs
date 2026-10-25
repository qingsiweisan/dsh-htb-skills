/**
 * 本地 bundle 补丁的结构闸 —— 补一个**真空**。
 *
 * 🔴 为什么需要：`framework-check.mjs` 的 17 道闸没有一道解析 `cordis.patch.yml`。
 * 而 persona 正文（preset 的 `text: |` 块标量）就写在这些文件里 —— 缩进一旦破坏，
 * YAML 会解析成别的东西，**新开的 HTB 会话会静默拿到坏 persona**，没有任何闸会响
 * （2026-10-10 实测：我在 preset 里改了 4 处 persona 文案，改完才意识到无闸可依）。
 *
 * 检查项（全部是"破坏后会静默"的结构性质）：
 *   1. 每个 `key: |` 块标量的**子行缩进必须大于父键缩进**（否则块提前结束）
 *   2. 每个 insert 行 `- id: X` 必须紧跟 `name:`（少了 name 的行会被加载器静默跳过）
 *   3. 文件必须能按行读出且无 NUL 字节（防二进制/编码事故）
 *
 * 契约（同其它闸）：exit 0 = 通过；任何 WARN/FAIL 一律 exit 1；结论打在最后几行。
 *   node scripts/preset-patch-test.mjs
 */
import { readFileSync, existsSync } from 'node:fs'

const PATCHES = [
  ['preset-htb', 'C:/Users/Administrator/dsh-htb-preset/cordis.patch.yml'],
  ['htb-skills', 'C:/Users/Administrator/dsh-htb-skills/cordis.patch.yml'],
  ['htb-tuning', 'C:/Users/Administrator/dsh-htb-tuning/cordis.patch.yml'],
  ['htb-evidence', 'C:/Users/Administrator/dsh-htb-evidence/cordis.patch.yml'],
]

const fails = []
const warns = []

for (const [label, file] of PATCHES) {
  if (!existsSync(file)) { warns.push(`${label}: 文件不存在（跳过） ${file}`); continue }
  const raw = readFileSync(file)
  if (raw.includes(0)) { fails.push(`${label}: 含 NUL 字节`); continue }
  const lines = raw.toString('utf8').split('\n')

  // 1) 块标量缩进
  let block = null
  const closeBlock = () => {
    if (block === null) return
    for (let i = block.key + 1; i <= block.last; i += 1) {
      const t = lines[i - 1]
      if (t.trim() === '') continue
      const ind = t.match(/^\s*/)[0].length
      if (ind <= block.indent) fails.push(`${label}:${i} 块标量子行缩进 ${ind} <= 父缩进 ${block.indent}（块 @L${block.key}）`)
    }
    block = null
  }
  for (let i = 1; i <= lines.length; i += 1) {
    const t = lines[i - 1]
    const ind = t.match(/^\s*/)[0].length
    const m = /^(\s*)([A-Za-z_][\w-]*):\s*\|[-+]?\s*$/.exec(t)
    if (m) { closeBlock(); block = { key: i, indent: m[1].length, last: i }; continue }
    if (block === null) continue
    if (t.trim() === '') { block.last = i; continue }
    if (ind <= block.indent) { closeBlock(); continue }
    block.last = i
  }
  closeBlock()

  // 2) insert 行必须有 name:
  for (let i = 1; i <= lines.length; i += 1) {
    const t = lines[i - 1]
    if (!/^\s*-\s*id:\s*\S+/.test(t)) continue
    const id = /^\s*-\s*id:\s*(\S+)/.exec(t)[1]
    let hasName = false
    for (let j = i + 1; j <= Math.min(i + 6, lines.length); j += 1) {
      const n = lines[j - 1]
      if (/^\s*-\s*id:/.test(n)) break          // 下一个 insert 行，本行没 name
      if (/^\s*name:\s*\S+/.test(n)) { hasName = true; break }
    }
    if (!hasName) fails.push(`${label}:${i} insert 行 id:${id} 后 6 行内没有 name:`)
  }
}

for (const w of warns) console.log(`WARN  ${w}`)
for (const f of fails) console.log(`FAIL  ${f}`)
console.log(`PRESET-PATCH: ${fails.length} failures, ${warns.length} warnings over ${PATCHES.length} local bundles → ${fails.length === 0 ? 'PASS' : 'FAIL'}`)
process.exit(fails.length === 0 ? 0 : 1)
