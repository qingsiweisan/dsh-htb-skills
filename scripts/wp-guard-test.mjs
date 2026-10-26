/**
 * WP 守卫测试：`node scripts/wp-guard-test.mjs`
 *
 * 语料来自真实事故（2026-09-25 决策 D1）：ReaperTwo 新会话 31 分钟拿到 root，
 * 靠的是读工作区里的官方 WP（`htb-wp/txt/772_ReaperTwo.txt`）—— 用户在备考
 * OSCP，这条路对他是负收益。守卫要保证这条"顺手 read 一下"不再可用。
 */

import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  CONTENT_READ_VERBS,
  DEFAULT_UNLOCK_PATH,
  GUARDED_TOOLS,
  READONLY_META_VERBS,
  checkWpAccess,
  denyReason,
  hasContentReadVerb,
  isReadonlyMetaCommand,
  pathTextsOf,
  referencesWp,
} from '../src/wp-guard.js'
import { apply } from '../src/index.js'

let failed = 0
const check = (name, ok, extra = '') => {
  if (ok) console.log(`  ✓ ${name}`)
  else { failed += 1; console.log(`  ✗ ${name} ${extra}`) }
}

/** 造一个 read 调用。 */
const read = (filePath) => ({ name: 'read', arguments: { file_path: filePath } })
/** 造一个 glob 调用。 */
const glob = (pattern, path) => ({ name: 'glob', arguments: { pattern, ...(path ? { path } : {}) } })
/** 造一个 grep 调用。 */
const grep = (pattern, path) => ({ name: 'grep', arguments: { pattern, ...(path ? { path } : {}) } })
/** 造一个 shell 调用。 */
const shell = (command, name = 'pwsh') => ({ name, arguments: { command } })

// 事故原样复刻：那次就是这么读的
const INCIDENT = read('C:/Users/Administrator/AppData/Roaming/reasonix/global-workspace/htb-wp/txt/772_ReaperTwo.txt')

const DENY = [
  [INCIDENT, 'wp-read', '事故原样：绝对路径读 772_ReaperTwo.txt'],
  [read('htb-wp/txt/772_ReaperTwo.txt'), 'wp-read', '相对路径'],
  [read('htb-wp\\txt\\772_ReaperTwo.txt'), 'wp-read', '反斜杠路径'],
  [glob('htb-wp/**/*.txt'), 'wp-read', 'glob pattern 直指 WP'],
  [glob('**/*.txt', 'htb-wp/txt'), 'wp-read', 'glob path 直指 WP'],
  [grep('ReaperTwo', 'htb-wp/txt'), 'wp-read', 'grep path 直指 WP'],
  [shell('cat htb-wp/txt/772_ReaperTwo.txt'), 'wp-shell', 'shell cat'],
  [shell('Get-Content htb-wp/txt/772_ReaperTwo.txt'), 'wp-shell', 'shell Get-Content'],
  [shell('Get-ChildItem -Recurse htb-wp | Select-String content'), 'wp-shell', 'shell 列目录'],
  [shell('cd /home/kali/htb-wp && ls'), 'wp-shell', 'shell cd 进去'],
  [shell('grep -rn payload htb-wp/', 'bash'), 'wp-shell', 'bash grep'],
  // 🔴 2026-09-30 新增：`HTB_GUARD_ALLOW=1` 前缀**不再**解锁本守卫。
  //    原实现与红线守卫共用那个逃生口 ⇒ 前缀是**模型自己**写进命令里的，
  //    于是"用户动一次手解锁"退化成"模型声明一下"，D1 的保证归零。
  //    这三条用例存在的意义就是锁住它别被改回去（此前无任何测试覆盖该行为，
  //    所以删掉旁路时 7 套单测全绿 —— 这本身就是个警示）。
  [shell('HTB_GUARD_ALLOW=1 cat htb-wp/txt/772_ReaperTwo.txt'), 'wp-shell', '🔴 逃生口不再解锁 WP 守卫'],
  [shell('  HTB_GUARD_ALLOW=1 Get-Content htb-wp/txt/x.txt'), 'wp-shell', '前导空白也不行'],
  [shell('HTB_GUARD_ALLOW=1 grep -rn x htb-wp/', 'bash'), 'wp-shell', 'bash 同样不解锁'],
  // 🔴 2026-10-01 新增：远程 shell 与本地同口径（原 SHELL_TOOLS 只有 pwsh/bash，
  //    `ssh_exec` 里 `cat htb-wp/...` 完全不拦 —— 与 guard.js 不一致的公开漏面）。
  [shell('cat /path/htb-wp/txt/x.txt', 'ssh_exec'), 'wp-shell', '🔴 ssh_exec 引用 WP'],
  [shell('cat /home/kali/htb-wp/txt/772_ReaperTwo.txt', 'ssh_cluster'), 'wp-shell', '🔴 ssh_cluster 引用 WP'],
  [shell("ssh host 'cat /path/htb-wp/txt/x.txt'"), 'wp-shell', '本地 shell 里再套一层 ssh'],
  // 🔴 只读元数据白名单**不许当掩护**：命令里任何位置出现内容读取/枚举动词一律拦。
  [shell('Test-Path htb-wp/txt; cat htb-wp/txt/x.txt'), 'wp-shell', '🔴 只读元数据 + 内容读取同时出现'],
  [shell('Get-Item htb-wp/txt | Get-Content'), 'wp-shell', '🔴 管道把只读结果接给内容读取'],
  [shell('stat htb-wp/txt/x.txt && cat htb-wp/txt/x.txt', 'bash'), 'wp-shell', '🔴 bash: stat + cat'],
  [shell('Test-Path htb-wp/txt/x.txt; Get-ChildItem htb-wp/txt'), 'wp-shell', '🔴 存在性打头 + 枚举跟上'],
  [shell('Get-Item htb-wp/txt/x.txt > copy.txt'), 'wp-shell', '🔴 重定向：动作不再是"看一眼属性"'],
  [shell('Test-Path $(cat htb-wp/txt/x.txt)'), 'wp-shell', '🔴 子表达式里读内容'],
  // 🔴 通配符把"看一眼属性"变成枚举：PowerShell 的 Get-Item 带 * 等价 Get-ChildItem
  [shell('Get-Item htb-wp/txt/*'), 'wp-shell', '🔴 Get-Item 通配符退化成枚举'],
  [shell('stat htb-wp/txt/*', 'bash'), 'wp-shell', '🔴 bash stat 通配符'],
  [shell('Test-Path htb-wp/txt/*.txt'), 'wp-shell', '🔴 Test-Path 通配符'],
  // 枚举仍拦：会暴露"这台机器有没有 writeup"
  [shell('Get-ChildItem htb-wp/txt'), 'wp-shell', '🔴 枚举目录仍拦'],
  [shell('ls htb-wp/txt', 'bash'), 'wp-shell', '🔴 bash ls 仍拦'],
  [shell('Test-Path htb-wp/txt; ls htb-wp/txt'), 'wp-shell', '🔴 存在性 + ls 组合'],
]

const ALLOW = [
  // 🔴 这些拦了就是把正常工作堵死
  [read('htb-mode-handoff.md'), '相邻文件名不是 WP 目录'],
  [read('loot/ReaperTwo.md'), 'loot'],
  [read('C:/Users/Administrator/AppData/Roaming/reasonix/global-workspace/AGENTS.md'), 'AGENTS.md'],
  [read('htb-wps/notes.md'), '前缀相似但不是（htb-wps）'],
  [read('htb-wp2/notes.md'), '前缀相似但不是（htb-wp2）'],
  [read('my-htb-wp.md'), '文件名里带 htb-wp 但不是目录（后跟 .）'],
  // grep 的 pattern 是检索正则，不是目标路径 —— 扫它会把正当检索拦掉
  [grep('htb-wp', 'loot/ReaperTwo.md'), 'grep 搜 htb-wp 这个字符串'],
  [grep('official writeup', 'notes/'), '普通 grep'],
  // 不传 path = 扫整个工作区。拦它会把 loot/notes 全文检索一起堵死（已知缺口）
  [grep('ReaperTwo'), 'grep 未指定 path'],
  [glob('**/*.md'), 'glob 未指定 path'],
  // 非守卫工具
  [{ name: 'write', arguments: { file_path: 'htb-wp/x.md' } }, 'write 不在守卫集'],
  [{ name: 'todo_write', arguments: { todos: [] } }, 'todo'],
  // ssh_* 已在守卫集，但**不引用 WP** 时照放行（守卫只拦提到 WP 的调用）
  [shell('ls -la /tmp && id', 'ssh_exec'), 'ssh_exec 不引用 WP'],
  [{ name: 'ssh_cluster', arguments: { command: 'whoami', aliases: ['kali'] } }, 'ssh_cluster 不引用 WP'],
  // 🔓 只读元数据白名单（2026-10-01）：存在性/属性检查放行 ——
  //    拒它只会把模型逼去拼接路径绕开守卫，与 persona 第 9 条矛盾。
  [shell('Test-Path htb-wp/txt'), '🔓 Test-Path 存在性检查'],
  [shell('Test-Path -Path htb-wp/txt/772_ReaperTwo.txt'), '🔓 Test-Path 带 -Path'],
  [shell('TEST-PATH htb-wp'), '🔓 大小写不敏感'],
  [shell('Get-Item htb-wp/txt/772_ReaperTwo.txt'), '🔓 Get-Item 属性'],
  [shell('stat htb-wp/txt/772_ReaperTwo.txt', 'bash'), '🔓 bash stat'],
  [shell('file htb-wp/txt/772_ReaperTwo.txt', 'bash'), '🔓 bash file'],
  [shell('stat -c %s htb-wp/txt/772_ReaperTwo.txt', 'bash'), '🔓 stat 带参数'],
  [shell('sudo stat htb-wp/txt/x.txt', 'bash'), '🔓 壳前缀（sudo）后仍是白名单动作'],
  [shell('Test-Path htb-wp/txt && stat htb-wp/txt/x.txt', 'bash'), '🔓 两段都是只读元数据'],
  [shell('Test-Path htb-wp; echo done'), '🔓 尾段不引用 WP，不影响判定'],
  [shell('Test-Path htb-wp/txt/x.txt', 'ssh_exec'), '🔓 远程也只读元数据'],
]

console.log('DENY — 必须拦下')
for (const [call, want, note] of DENY) {
  const hit = checkWpAccess(call)
  if (!hit) check(`漏拦 [${note}]`, false)
  else if (hit.id !== want) check(`拦错规则 ${note} 期望 ${want} 实得 ${hit.id}`, false)
  else check(note, true)
}

console.log('ALLOW — 必须放行')
for (const [call, note] of ALLOW) {
  const hit = checkWpAccess(call)
  check(note, hit === undefined, hit ? `误拦 [${hit.id}] ${hit.detail}` : '')
}

console.log('referencesWp 边界')
{
  check('裸目录名', referencesWp('htb-wp') === true)
  check('带斜杠', referencesWp('htb-wp/txt') === true)
  check('绝对 Windows 路径', referencesWp('C:\\a\\b\\htb-wp\\txt\\x.txt') === true)
  check('大小写不敏感', referencesWp('HTB-WP/TXT') === true)
  check('htb-wps 不算', referencesWp('htb-wps/x') === false)
  check('htb-wp2 不算', referencesWp('htb-wp2/x') === false)
  check('notes-htb-wp.md 不算', referencesWp('notes-htb-wp.md') === false)
  check('htb-mode-handoff 不算', referencesWp('htb-mode-handoff.md') === false)
  check('空串不炸', referencesWp('') === false)
  check('非字符串不炸', referencesWp(null) === false)
}

console.log('pathTextsOf 按工具取参')
{
  check('read 取 file_path', pathTextsOf(read('a'), 'read').join() === 'a')
  check('glob 两个都取', pathTextsOf(glob('p', 'q'), 'glob').join() === 'q,p')
  check('grep 只看 path（不看 pattern）', pathTextsOf(grep('pat', 'q'), 'grep').join() === 'q')
  check('grep 无 path 返回空', pathTextsOf(grep('pat'), 'grep').length === 0)
  check('缺 arguments 不炸', pathTextsOf({ name: 'read' }, 'read').length === 0)
  check('null 不炸', pathTextsOf(null, 'read').length === 0)
}

console.log('只读元数据白名单：成分与边界')
{
  check('白名单只含存在性/属性动作', READONLY_META_VERBS.join() === 'test-path,get-item,stat,file')
  check('白名单不含枚举 Get-ChildItem', !READONLY_META_VERBS.includes('get-childitem'))
  check('黑名单含枚举 ls/dir/Get-ChildItem', ['ls', 'dir', 'get-childitem'].every(v => CONTENT_READ_VERBS.includes(v)))
  check('黑名单含内容读取 cat/Get-Content', ['cat', 'get-content'].every(v => CONTENT_READ_VERBS.includes(v)))
  check('两表不交叉', READONLY_META_VERBS.every(v => !CONTENT_READ_VERBS.includes(v)))
  check('hasContentReadVerb 命中 cat', hasContentReadVerb('cat htb-wp/x') === true)
  check('hasContentReadVerb 命中 Get-Content', hasContentReadVerb('Get-Content htb-wp/x') === true)
  check('hasContentReadVerb 词边界：htb-wp/cat.txt 不算 cat', hasContentReadVerb('Test-Path htb-wp/cat.txt') === false)
  check('hasContentReadVerb 词边界：directory 不算 dir', hasContentReadVerb('Test-Path htb-wp/directory') === false)
  check('hasContentReadVerb 空串不炸', hasContentReadVerb('') === false)
  check('isReadonlyMetaCommand：Test-Path 放行', isReadonlyMetaCommand('Test-Path htb-wp/txt') === true)
  check('isReadonlyMetaCommand：cat 不放行', isReadonlyMetaCommand('cat htb-wp/txt/x.txt') === false)
  check('isReadonlyMetaCommand：枚举不放行', isReadonlyMetaCommand('Get-ChildItem htb-wp/txt') === false)
  check('isReadonlyMetaCommand：不引用 WP 返回 false', isReadonlyMetaCommand('Test-Path loot/') === false)
  check('isReadonlyMetaCommand：通配符不放行（会退化成枚举）', isReadonlyMetaCommand('Get-Item htb-wp/txt/*') === false)
  check('isReadonlyMetaCommand：非字符串不炸', isReadonlyMetaCommand(null) === false)
}

console.log('拒绝理由')
{
  const text = denyReason(checkWpAccess(INCIDENT))
  check('含规则 id', text.includes('[wp-read]'))
  check('说清为什么（备考负收益）', text.includes('负收益'))
  check('给了正向替代动作', text.includes('假设') && text.includes('3 条'))
  check('给了解锁办法与路径', text.includes(DEFAULT_UNLOCK_PATH))
  check('说明只读元数据本不必绕（别逼模型规避）', text.includes('Test-Path') && text.includes('枚举'))
}

console.log('接线（经 apply()）')
{
  const guards = []
  const ctx = {
    on: () => () => {},
    tools: { guard: (g) => { guards.push(g); return () => {} }, register: () => () => {} },
    skills: { registerProvider: () => {} },
  }
  await apply(ctx, { skillsEnabled: false })
  // 2026-10-25：+1 = struggle-watch 的停止协议闸；2026-10-26：+1 = machine-own 的交付检查。
  check('apply 注册了五个守卫（红线 + 提问 + WP + 停止协议 + 交付检查）', guards.length === 5)
  const denied = guards.map(g => g(INCIDENT)).filter(Boolean)
  check('真实事故被拦', denied.length === 1 && denied[0].includes('[wp-read]'))
  check('合法读文件不被拦', guards.map(g => g(read('loot/x.md'))).every(r => r === undefined))
  check('红线守卫仍在（pkill）', guards.some(g => typeof g(shell('pkill -f x')) === 'string'))
  check('提问守卫仍在', guards.some(g => typeof g({
    name: 'ask_user_question',
    arguments: { questions: [{ question: '给我提示' }] },
  }) === 'string'))
}

console.log('接线：unlocked 强制放行 / wpGuard:false 不注册')
{
  const guards = []
  const ctx = {
    on: () => () => {},
    tools: { guard: (g) => { guards.push(g); return () => {} }, register: () => () => {} },
    skills: { registerProvider: () => {} },
  }
  await apply(ctx, { skillsEnabled: false, wpGuard: false })
  check('wpGuard:false 只注册四个守卫', guards.length === 4)
  check('wpGuard:false 后不再拦 WP', guards.map(g => g(INCIDENT)).every(r => r === undefined))

  const guards2 = []
  const ctx2 = {
    on: () => () => {},
    tools: { guard: (g) => { guards2.push(g); return () => {} }, register: () => () => {} },
    skills: { registerProvider: () => {} },
  }
  await apply(ctx2, { skillsEnabled: false, wpGuardUnlockPath: null, wpGuardTools: ['read'] })
  check('收窄工具集后只有 read 被守卫', guards2.some(g => typeof g(INCIDENT) === 'string'))
  check('收窄后 shell 不再被守卫', guards2.map(g => g(shell('cat htb-wp/x'))).every(r => r === undefined))
}

console.log('解锁标记文件')
{
  const dir = mkdtempSync(join(tmpdir(), 'wp-guard-'))
  const unlock = join(dir, 'unlock')
  const guards = []
  const ctx = {
    on: () => () => {},
    tools: { guard: (g) => { guards.push(g); return () => {} }, register: () => () => {} },
    skills: { registerProvider: () => {} },
  }
  await apply(ctx, { skillsEnabled: false, wpGuardUnlockPath: unlock })
  const wpGuard = guards.find(g => typeof g(INCIDENT) === 'string')
  check('未创建标记时拦', typeof wpGuard(INCIDENT) === 'string')
  writeFileSync(unlock, '')
  check('创建标记后放行（复盘）', wpGuard(INCIDENT) === undefined)
  check('标记存在时其它守卫不受影响', wpGuard(shell('cat htb-wp/x')) === undefined)
}

console.log('fail-open')
{
  const guards = []
  const ctx = {
    on: () => () => {},
    tools: { guard: (g) => { guards.push(g); return () => {} }, register: () => () => {} },
    skills: { registerProvider: () => {} },
  }
  await apply(ctx, { skillsEnabled: false })
  const wpGuard = guards.find(g => typeof g(INCIDENT) === 'string')
  const evil = { name: 'read', get arguments() { throw new Error('boom') } }
  let threw = false
  let result
  try { result = wpGuard(evil) } catch { threw = true }
  check('守卫抛错时不外泄异常', !threw)
  check('守卫抛错时放行', result === undefined)
}

console.log('守卫集')
check('默认含 read/glob/grep', ['read', 'glob', 'grep'].every(t => GUARDED_TOOLS.includes(t)))
check('默认含本地 shell', ['pwsh', 'bash'].every(t => GUARDED_TOOLS.includes(t)))
// 🔴 2026-10-01：与 guard.js 的 SHELL_TOOLS 对齐（原实现漏掉远程两条）
check('默认含远程 shell ssh_exec/ssh_cluster', ['ssh_exec', 'ssh_cluster'].every(t => GUARDED_TOOLS.includes(t)))
check('默认不含 write', !GUARDED_TOOLS.includes('write'))

console.log(failed === 0 ? '\n✅ WP 守卫测试全部通过' : `\n❌ ${failed} 条失败`)
process.exit(failed === 0 ? 0 : 1)
