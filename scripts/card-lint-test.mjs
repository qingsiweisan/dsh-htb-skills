/**
 * 卡内一致性 lint（低噪声机械闸）—— 由 K2 九域普查实测出的两类缺陷固化而来：
 *   ① 卡内 Python 2 遗留（Python 3 下必炸）
 *      (a) 语法级：python/py 标记块里的 Py2 print 语句；以及块内 `python -c "…"` 内联片段
 *          ⇒ 交给**本机 Python 3 的 compile()** 当裁判，只认 "Missing parentheses in call to 'print'"
 *      (b) API 级：`.decode('hex')` / `.encode('hex')`（Py2 专有，Py3 已移除）
 *   ② `nuclei -t cves/…` 缺 `http/` 前缀（nuclei-templates 里 cves/ 挂在 http/ 下）
 *   ③ `wc -c … | grep -v "^0 "` **定宽填充陷阱**（来源：第二轮九域内容普查实测，零误报）：
 *      `wc -c` 的计数列**右对齐**（`1000 big/   0 empty/`）⇒ 锚定行首的 `^0 ` 匹配不到 `   0 `，
 *      0 字节文件（解密/导出失败）被留下来当"成功候选"。正确写法：`awk '$1!=0'` / `grep -vE '^ *0 '`。
 *      仅在**同一条逻辑行**（反斜杠续行合并后）同时出现 `wc -c` 与该 grep 时命中 ⇒ 普通 `grep -v "^0 "` 不误报。
 *
 * ⚠️ 卡库是**只读**的：已实测存在的缺陷不改卡，而是登记在下方 BASELINE 里
 *    （锚定 卡:行 + 该行原文片段）。闸只对**基线之外**的新缺陷报红；基线条目若
 *    消失/漂移会打印 note 但不报红（fail-closed：同一行内容变了就不再豁免）。
 *
 * 用法：
 *   node scripts/card-lint-test.mjs              # 基线模式（framework-check 用）
 *   node scripts/card-lint-test.mjs --strict     # 忽略基线，列出全部命中并 exit 1
 *   node scripts/card-lint-test.mjs --selftest   # 反例自检（正确片段必须放行）
 *   node scripts/card-lint-test.mjs --skills <dir>   # 换卡库根（fixture 反证用；只读）
 *
 * 契约：exit 0 = 通过；任何 WARN/新缺陷一律 exit 1。不改任何文件（纯读）。
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import path from 'node:path'

const DEFAULT_SKILLS = 'C:/Users/Administrator/.dsh/skills'

// ── 已登记基线（K2-domains.md §最该立刻处理的 5 条 / §需要 parent 决策第 3 条，实测真阳性）──
// card 目录名 : 行号 : 缺陷码 : 该行原文（trim + 空白折叠后比对）
// ── 已登记基线 ────────────────────────────────────────────────────────────────
// 2026-10-10：原先登记 6 条已实测缺陷（来源 `loot/_audit/K2-domains.md`），**当天已全部修好**：
//   · `weak-rsa-key-recovery:72 / :86` —— Py2 `print` + `.decode('hex')` → 改成该卡 `:80` 本已有的 Py3 写法
//   · `crypto-classic-attack-patterns:85` —— Py2 `print` → `python3 -c "print('A' * 15000)"`
//   · `apache-struts-rce:39` / `pgadmin-cve-2025-2945-rce:40` —— nuclei 路径补 `http/` 前缀
//     （`pgadmin` 另加注：2025-12-30 的模板快照里**没有** CVE-2025-2945，见卡内 ⚠️ 行）
// ⇒ 现为**空表**：闸应在 0 命中下通过，且 `--strict`（忽略基线）亦为 0 命中 —— **两者都 0 才算真修好**。
// ⚠️ 今后若再出现"已确认但暂不修"的缺陷，按 `card / line / code / snippet` 四元组登记：
//    锚定**该行原文** ⇒ 卡内容一变锚即失效并报 `note（可移除）`（本次 6 条正是这样失效的）。
const BASELINE = []

// nuclei-templates 顶层协议目录（带这些前缀 = 合法路径）
const NUCLEI_PROTO = new Set(['http', 'network', 'dns', 'file', 'headless', 'ssl', 'javascript', 'iot', 'cloud', 'workflows'])
// 挂在 http/ 下的分类目录：裸写它们（如 cves/…）必缺 http/ 前缀
const NUCLEI_CATEGORY = new Set([
  'cves', 'vulnerabilities', 'exposures', 'misconfiguration', 'misconfigurations',
  'default-logins', 'technologies', 'fuzzing', 'token-spray', 'exposed-panels', 'takeovers', 'helpers',
])

const norm = (s) => s.replace(/\s+/g, ' ').trim()

// ── fenced code block 抽取（``` 围栏；记录每行真实行号）──
function fencesOf(lines) {
  const out = []
  let cur = null
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*```(.*)$/.exec(lines[i])
    if (m) {
      if (cur) { out.push(cur); cur = null } else { cur = { tag: m[1].trim().toLowerCase(), start: i + 2, lines: [], lineNos: [] } }
      continue
    }
    if (cur) { cur.lines.push(lines[i]); cur.lineNos.push(i + 1) }
  }
  return out
}

const isPyTag = (tag) => /^(py|python)\d*(\.\d+)?$/.test(tag)
// Py2 print 语句的**操作数首字符**必须是真代码，排除伪代码/变量占位（print <flag> / print $var / print 结果）
const PRINT_OPERAND = /^(>>|['"[\-~]|[A-Za-z0-9_])/
// 内联 python -c 片段：只认 python / python3[.x]（`python2 -c …` 是**有意**用 Py2，见 waf-filter-bypass-patterns:43 ⇒ 不查）
const INLINE_PY = /\bpython3?(?:\.\d+)?\s+-c\s+(?:"([^"]*)"|'([^']*)')/g
const HEX_API = /\.(?:decode|encode)\(\s*['"]hex['"]\s*\)/
const NUCLEI_T = /\bnuclei\b[^\n]*?\s-t\s+(\S+)/g
// ③ `wc -c … | grep -v "^0 "`：wc 计数列定宽右对齐 ⇒ 行首锚定 `^0 ` 漏掉 0 字节文件
const WC_C = /\bwc\s+-[A-Za-z]*c[A-Za-z]*\b/
// 只认**反选**grep（-v / -vE / --invert-match），且模式紧跟引号就是 `^0 `（`'^ *0 '` 这类带前导空格的正确写法不匹配）
const GREP_INV_ZERO = /\bgrep\s+(?:-[A-Za-z]*v[A-Za-z]*|--invert-match)\s+[^\n|]*?(['"])\^0\s*\1/

/** 逻辑行：把以 `\` 续行的物理行并成一条（记起始物理行号），以便识别跨行管道 */
function logicalLines(lines) {
  const out = []
  for (let i = 0; i < lines.length; i++) {
    let text = lines[i]
    const line = i + 1
    while (/\\\s*$/.test(text) && i + 1 < lines.length) text = text.replace(/\\\s*$/, ' ') + lines[++i]
    out.push({ line, text })
  }
  return out
}

/** 纯规则层：产出候选（不含 Python 裁决），返回 {findings, pyCandidates} */
function scanText(card, text) {
  const lines = text.split('\n').map((l) => l.replace(/\r$/, ''))
  const findings = []
  const pyCands = [] // {card,line,code,snippet,origin}
  const push = (f) => findings.push({ card, ...f })

  // ① (a1) 仅 python/py 标记的块：Py2 print 语句
  for (const f of fencesOf(lines)) {
    if (!isPyTag(f.tag)) continue
    f.lines.forEach((raw, k) => {
      const m = /^\s*print\s+(?!\()(\S.*)$/.exec(raw)
      if (!m) return
      if (!PRINT_OPERAND.test(m[1].trim())) return
      pyCands.push({ card, line: f.lineNos[k], code: 'py2-print', snippet: raw.trim(), origin: `python 块(${f.tag})` })
    })
  }
  // ① (a2) 任意位置（含 bash 块/注释/表格）的 `python -c "…"` 内联片段
  lines.forEach((raw, i) => {
    INLINE_PY.lastIndex = 0
    let m
    while ((m = INLINE_PY.exec(raw)) !== null) {
      const inner = (m[1] ?? m[2] ?? '').trim()
      if (!inner || inner.includes('...')) continue
      pyCands.push({ card, line: i + 1, code: 'py2-print', snippet: raw.trim(), origin: 'python -c 内联', probe: inner })
    }
  })
  // ① (b) API 级：全卡扫（Py3 已移除的专有 API，无歧义；weak-rsa:86 就在表格行里）
  lines.forEach((raw, i) => { if (HEX_API.test(raw)) push({ line: i + 1, code: 'py2-hex', snippet: raw.trim() }) })
  // ② nuclei 模板路径缺协议前缀（全卡扫；不做"模板是否存在"检查）
  lines.forEach((raw, i) => {
    NUCLEI_T.lastIndex = 0
    let m
    while ((m = NUCLEI_T.exec(raw)) !== null) {
      const p = m[1].replace(/^["'`]|["'`]$/g, '').replace(/[),;]+$/, '')
      const seg = p.split('/')
      if (seg.length < 2 || !/\.ya?ml$/i.test(seg[seg.length - 1])) continue
      if (NUCLEI_PROTO.has(seg[0].toLowerCase())) continue
      if (!NUCLEI_CATEGORY.has(seg[0].toLowerCase())) continue
      push({ line: i + 1, code: 'nuclei-prefix', snippet: raw.trim(), detail: `模板路径 \`${p}\` 缺 \`http/\` 前缀` })
    }
  })
  // ③ `wc -c … | grep -v "^0 "`（同一逻辑行内含 `wc -c` 与该反选 grep）
  for (const { line, text } of logicalLines(lines)) {
    if (!WC_C.test(text)) continue
    const g = GREP_INV_ZERO.exec(text)
    if (!g) continue
    push({
      line,
      code: 'wc-zero',
      snippet: text.trim(),
      detail: `wc -c 的计数列定宽右对齐（\`1000 big/   0 empty/\`）⇒ ${g[1]}^0 ${g[1]} 匹配不到 \`   0 \`，0 字节文件被误判为成功候选；改用 \`awk '$1!=0'\` 或 \`grep -vE '^ *0 '\``,
    })
  }
  return { findings, pyCands }
}

const PY_ORACLE = `
import sys, json
sys.stdin.reconfigure(encoding='utf-8')
sys.stdout.reconfigure(encoding='utf-8')
items = json.load(sys.stdin).get('items', [])
out = []
for it in items:
    rec = {'id': it['id'], 'ok': True, 'err': ''}
    try:
        compile(it['code'], '<card>', 'exec')
    except SyntaxError as e:
        rec['ok'] = False
        rec['err'] = '%s: %s' % (type(e).__name__, e.msg)
    except Exception as e:
        rec['ok'] = False
        rec['err'] = '%s: %s' % (type(e).__name__, e)
    out.append(rec)
json.dump({'results': out}, sys.stdout, ensure_ascii=False)
`

/** 用本机 Python 3 的 compile() 裁决 Py2 print（只认那条专属报错） */
function py2PrintVerdict(cands) {
  // 喂给 compile() 的是**整条语句**（不是操作数），并去掉缩进避免 IndentationError 抢在 Py2 报错前
  const probes = cands.map((c) => (c.probe ? c : { ...c, probe: c.snippet.trimStart() }))
  const items = probes.map((c, i) => ({ id: String(i), code: c.probe }))
  if (!items.length) return []
  const r = spawnSync('python', ['-c', PY_ORACLE], {
    input: JSON.stringify({ items }),
    encoding: 'utf8',
    env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
    maxBuffer: 32 * 1024 * 1024,
  })
  if (r.error || r.status !== 0) {
    console.error(`card-lint：Python 3 裁决器不可用（${r.error ? r.error.message : `exit ${r.status}`}）`)
    console.error(String(r.stderr ?? '').trim().split('\n').slice(-3).join('\n'))
    process.exit(1)
  }
  const res = JSON.parse(r.stdout).results
  const hits = []
  res.forEach((rec, i) => {
    if (rec.ok) return
    if (!/Missing parentheses in call to 'print'/.test(rec.err)) return // 其余 SyntaxError 一律不算 Py2（shell/C 伪代码会乱报）
    hits.push({ ...probes[i], detail: rec.err })
  })
  return hits
}

const key = (f) => `${f.card}|${f.line}|${f.code}`
const snippet = (f) => norm(f.snippet)

function lintRoot(root) {
  const cards = []
  for (const d of readdirSync(root).sort()) {
    const p = path.join(root, d, 'SKILL.md')
    try { if (!statSync(p).isFile()) continue } catch { continue }
    cards.push({ name: d, text: readFileSync(p, 'utf8') })
  }
  const findings = []
  const cands = []
  let fenceCount = 0
  for (const c of cards) fenceCount += fencesOf(c.text.split('\n')).length
  for (const c of cards) {
    const { findings: f, pyCands } = scanText(c.name, c.text)
    findings.push(...f)
    cands.push(...pyCands)
  }
  findings.push(...py2PrintVerdict(cands))
  const uniq = new Map()
  for (const f of findings) uniq.set(key(f) + '|' + snippet(f), f)
  return { cards: cards.length, fenceCount, findings: [...uniq.values()].sort((a, b) => a.card.localeCompare(b.card) || a.line - b.line || a.code.localeCompare(b.code)) }
}

// ── 反例自检：正确片段必须全部放行，缺陷片段必须全部命中 ──
function selftest() {
  const good = [
    ['py3 正确写法（weak-rsa:80 原文）', '```python\nd = pow(E, -1, (P-1)*(Q-1))\nm = pow(int(open(\'output.txt\').read()), d, P*Q)\nprint(bytes.fromhex(format(m, \'x\')))\n```'],
    ['py3 正确写法（crypto:85 的修法）', '```python\nprint(\'A\' * 15000)\n```'],
    ['py3 -c 内联（cloud-attacks:34 原文）', '```bash\npython3 -c "import sys,json; print(json.load(sys.stdin)[\'access_token\'])"\n```'],
    ['py3 -c 内联（command-injection:52）', '```bash\n$(python3 -c "print(chr(46))")\n```'],
    ['**有意** python2 -c（waf-filter:43）', '```bash\npython2 -c "i=raw_input(); print \'\'.join(\'\\\\\\\\u00\'+hex(ord(c)).split(\'x\')[1] for c in i)"\n```'],
    ['shell 块里的 exec（living-off-the-land:89）', '```bash\nexec 3<>/dev/tcp/10.0.0.1/80 && echo -e "GET / HTTP/1.0\\r\\n" >&3 && cat <&3\n```'],
    ['C/伪代码块', '```c\nfor (i=0;i<n;i++) printf("%d", a[i]);\n```'],
    ['占位符伪代码 print（非 Py2）', '```python\nprint <flag>\n```'],
    ['python -c 省略号占位（weak-rsa:99）', '```bash\npython3 -c "...解析出 e 与 N..."\n```'],
    ['nuclei 带 http/ 前缀（对照组）', '```bash\nnuclei -t http/cves/2021/CVE-2021-31805.yaml -u http://target/\n```'],
    ['nuclei 合法协议目录 network/', '```bash\nnuclei -t network/detection/redis-unauth.yaml -u 1.2.3.4\n```'],
    ['wc -c + awk 数值比较（aws-kms:37 的修法）', '```bash\nwc -c *.out | awk \'$1!=0\'\n```'],
    ['wc -c + grep -vE 允许前导空格（aws-kms:37 的等价修法）', '```bash\nwc -c *.out | grep -vE \'^ *0 \'\n```'],
    ['跨行管道 + 正确写法（续行合并后仍放行）', '```bash\nwc -c *.out \\\n  | awk \'$1!=0\'\n```'],
    ['**非** wc -c 的普通 grep -v "^0 "（对照组：必须放行）', '```bash\ncat list.txt | grep -v "^0 "\n```'],
  ]
  const bad = [
    ['py2 print（crypto-classic-attack-patterns:85 原文）', 'py2-print', '```bash\n# Kryptos: python -c "print \'A\' * 15000" > message1\n```'],
    ['py2 print（weak-rsa-key-recovery:72 原文）', 'py2-print', '```bash\npython -c "print format(<DECIMAL NUMBER>, \'x\').decode(\'hex\')"\n```'],
    ['py2 print 在 python 块里', 'py2-print', '```python\nprint \'A\' * 15000\n```'],
    ['py2 hex API（weak-rsa:86 表格行）', 'py2-hex', '| Brainfuck | 解密后 `format(x,\'x\').decode(\'hex\')` 得明文 |'],
    ['nuclei 缺 http/ 前缀（pgadmin:40 原文）', 'nuclei-prefix', '```bash\nnuclei -t cves/2025/CVE-2025-2945.yaml -u https://target\n```'],
    ['wc -c | grep -v "^0 "（aws-kms:37 原文，定宽填充漏掉 0 字节文件）', 'wc-zero', '```bash\nwc -c *.out | grep -v "^0 "\n```'],
    ['wc -c 跨行管道 | grep -v "^0 "（续行合并后仍命中）', 'wc-zero', '```bash\nwc -c *.out \\\n  | grep -v "^0 "\n```'],
  ]
  let bad_ = 0
  console.log('card-lint --selftest（反例自检）\n')
  for (const [label, body] of good) {
    const { findings, pyCands } = scanText('fixture', body)
    const hits = [...findings, ...py2PrintVerdict(pyCands)]
    const ok = hits.length === 0
    if (!ok) bad_++
    console.log(`  ${ok ? '✅' : '❌ 误报'} 放行 ${label}${ok ? '' : ' → ' + JSON.stringify(hits.map((h) => h.code))}`)
  }
  console.log('')
  for (const [label, code, body] of bad) {
    const { findings, pyCands } = scanText('fixture', body)
    const hits = [...findings, ...py2PrintVerdict(pyCands)]
    const ok = hits.some((h) => h.code === code)
    if (!ok) bad_++
    console.log(`  ${ok ? '✅' : '❌ 漏报'} 命中 ${label}  [${code}]`)
  }
  console.log(`\n${bad_ === 0 ? `✅ 反例自检全过：正确片段 ${good.length}/${good.length} 放行，缺陷片段 ${bad.length}/${bad.length} 命中` : `❌ 自检失败 ${bad_} 项`}`)
  process.exit(bad_ === 0 ? 0 : 1)
}

// ── main ──
const argv = process.argv.slice(2)
const strict = argv.includes('--strict')
if (argv.includes('--selftest')) selftest()
const si = argv.indexOf('--skills')
const root = si >= 0 && argv[si + 1] ? argv[si + 1] : (process.env.CARD_LINT_SKILLS_DIR || DEFAULT_SKILLS)
const { cards, fenceCount, findings } = lintRoot(root)

const baseMap = new Map(BASELINE.map((b) => [key(b), b]))
const baseHits = []
const fresh = []
const stale = []
for (const f of findings) {
  const b = baseMap.get(key(f))
  if (b && norm(b.snippet) === snippet(f)) baseHits.push(f)
  else fresh.push(f)
}
const seen = new Set(baseHits.map(key))
for (const b of BASELINE) if (!seen.has(key(b))) stale.push(b)

const render = (f) => `  ${f.card}:${f.line}  [${f.code}]  ${norm(f.snippet).slice(0, 120)}${f.detail ? `\n      ↳ ${f.detail}` : ''}`

if (strict) {
  console.log(`card-lint --strict（忽略基线）· 卡 ${cards} · 代码块 ${fenceCount} · 命中 ${findings.length}\n`)
  for (const f of findings) console.log(render(f))
  console.log(`\n${findings.length ? `❌ 命中 ${findings.length} 处（--strict 一律红）` : '✅ 无命中'}`)
  process.exit(findings.length ? 1 : 0)
}

console.log(`card-lint · 卡库 ${root} · 卡 ${cards} · 代码块 ${fenceCount}`)
console.log(`  已登记基线命中 ${baseHits.length}/${BASELINE.length} 条（卡库只读，不改卡；锚定 卡:行+原文，内容一变即失效）`)
for (const f of baseHits) console.log(render(f))
for (const b of stale) console.log(`  note  基线条目已失效（可移除）：${b.card}:${b.line} [${b.code}]`)
if (fresh.length) {
  console.log(`\n  新增缺陷 ${fresh.length} 处：`)
  for (const f of fresh) console.log(render(f))
}
console.log(fresh.length
  ? `\n❌ 卡内 lint 新增 ${fresh.length} 处缺陷（Py2 遗留 / nuclei 路径 / wc 零字节过滤），见上`
  : `\n✅ 卡内 Py2 遗留 + nuclei 模板前缀 + wc 零字节过滤 lint：卡 ${cards} · 基线 ${baseHits.length} 条 · 新增 0`)
process.exit(fresh.length ? 1 : 0)
