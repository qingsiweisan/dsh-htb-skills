/**
 * 外置规则文件的合并语义测试：`node scripts/guard-rules-test.mjs`
 *
 * 覆盖：缺失 / 覆盖 / 关闭 / 追加 / JSON 坏掉 / 单条正则编译失败 /
 *       mtime 变化重载 / 通过 apply() 接线。
 *
 * 全部在临时目录里跑，不碰 ~/.dsh。
 */

import { mkdtempSync, writeFileSync, utimesSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { RED_LINES, activeRules, checkCommand } from '../src/guard.js'
import { apply } from '../src/index.js'

let failed = 0
const check = (name, ok, extra = '') => {
  if (ok) console.log(`  ✓ ${name}`)
  else { failed += 1; console.log(`  ✗ ${name} ${extra}`) }
}

const dir = mkdtempSync(join(tmpdir(), 'htb-guard-rules-'))
let seq = 0

/** 写一个规则文件并保证 mtime 与上一次不同。 */
function writeRules(content) {
  const path = join(dir, `rules-${seq += 1}.json`)
  writeFileSync(path, content, 'utf8')
  utimesSync(path, new Date(), new Date(Date.now() + seq * 1000))
  return path
}

const ids = rules => rules.map(r => r.id)

/**
 * 造一个能收集全部守卫的最小 ctx，并挑出红线守卫。
 * apply() 会注册两个守卫（红线 + 提问），所以不能只留最后一个。
 */
function fakeGuardCtx() {
  const guards = []
  const ctx = {
    on: () => () => {},
    tools: { guard: (g) => { guards.push(g); return () => {} }, register: () => () => {} },
    skills: { registerProvider: () => {} },
  }
  const redLine = (exec) => guards.find(g => typeof g(exec) === 'string')?.(exec)
  return { ctx, guards, redLine }
}

// 1. 文件缺失 → 内置表
{
  const rules = activeRules(join(dir, 'does-not-exist.json'))
  check('缺失文件 → 内置表', ids(rules).join() === ids(RED_LINES).join())
}

// 2. rulesPath: null → 内置表
{
  const rules = activeRules(null)
  check('rulesPath=null → 内置表', ids(rules).join() === ids(RED_LINES).join())
}

// 3. 覆盖单条
{
  const path = writeRules(JSON.stringify({
    rules: [{ id: 'pkill-f', re: '\\bPROBE_VERB\\b', why: 'w', fix: 'f' }],
  }))
  const rules = activeRules(path)
  check('覆盖后条数不变', rules.length === RED_LINES.length)
  check('覆盖后新正则生效', checkCommand('run PROBE_VERB now', rules)?.id === 'pkill-f')
  check('覆盖后旧正则失效', checkCommand("pkill -f 'x'", rules) === undefined)
}

// 4. enabled:false 关掉单条
{
  const path = writeRules(JSON.stringify({ rules: [{ id: 'pkill-f', enabled: false }] }))
  const rules = activeRules(path)
  check('关闭后少一条', rules.length === RED_LINES.length - 1)
  check('关闭后该条不再命中', checkCommand("pkill -f 'x'", rules) === undefined)
  check('关闭后其它条不受影响', checkCommand('rm -rf /', rules)?.id === 'rm-rf-root')
}

// 5. 追加新 id
{
  const path = writeRules(JSON.stringify({
    rules: [{ id: 'probe-only', re: '\\bZZZ_PROBE\\b', why: 'w', fix: 'f' }],
  }))
  const rules = activeRules(path)
  check('追加后多一条', rules.length === RED_LINES.length + 1)
  check('追加的排在表尾', rules.at(-1).id === 'probe-only')
  check('追加的能命中', checkCommand('say ZZZ_PROBE', rules)?.id === 'probe-only')
  check('内置的仍能命中', checkCommand('rm -rf /', rules)?.id === 'rm-rf-root')
}

// 6. JSON 坏掉 → 回落内置表（不能变成空表）
{
  const path = writeRules('{ this is not json')
  const rules = activeRules(path)
  check('坏 JSON → 内置表', ids(rules).join() === ids(RED_LINES).join())
}

// 7. 没有 rules 键 → 内置表
{
  const path = writeRules(JSON.stringify({ nope: 1 }))
  check('无 rules 键 → 内置表', ids(activeRules(path)).join() === ids(RED_LINES).join())
}

// 8. rules: [] → 内置表（不是空表）
{
  const path = writeRules(JSON.stringify({ rules: [] }))
  check('空 rules 数组 → 内置表', ids(activeRules(path)).join() === ids(RED_LINES).join())
}

// 9. 单条正则编译失败 → 保留内置版本，不静默删掉守卫
{
  const path = writeRules(JSON.stringify({
    rules: [
      { id: 'pkill-f', re: '([unclosed', why: 'w', fix: 'f' },
      { id: 'probe-only', re: '\\bZZZ\\b' },
    ],
  }))
  const rules = activeRules(path)
  check('坏正则不删掉该条', ids(rules).includes('pkill-f'))
  check('坏正则回落到内置版本', checkCommand("pkill -f 'x'", rules)?.id === 'pkill-f')
  check('同文件里好的那条仍生效', checkCommand('ZZZ', rules)?.id === 'probe-only')
}

// 10. 缺 id / re 的条目被跳过，不影响其它
{
  const path = writeRules(JSON.stringify({
    rules: [{ re: '\\bx\\b' }, { id: 'no-re' }, null, { id: 'ok', re: '\\bOK_PROBE\\b' }],
  }))
  const rules = activeRules(path)
  check('残缺条目被跳过', rules.length === RED_LINES.length + 1)
  check('同文件里完整的仍生效', checkCommand('OK_PROBE', rules)?.id === 'ok')
}

// 11. mtime 变化 → 重新加载
{
  const path = writeRules(JSON.stringify({ rules: [{ id: 'v1', re: '\\bV1\\b' }] }))
  check('第一版生效', checkCommand('V1', activeRules(path))?.id === 'v1')
  writeFileSync(path, JSON.stringify({ rules: [{ id: 'v2', re: '\\bV2\\b' }] }), 'utf8')
  utimesSync(path, new Date(), new Date(Date.now() + 60_000))
  const reloaded = activeRules(path)
  check('mtime 变化后重载', checkCommand('V2', reloaded)?.id === 'v2')
  check('重载后旧版失效', checkCommand('V1', reloaded) === undefined)
}

// 12. 通过 apply() 接线：config.guardRulesPath 真的被用上
{
  const path = writeRules(JSON.stringify({ rules: [{ id: 'wired', re: '\\bWIRED_PROBE\\b' }] }))
  const ctx = fakeGuardCtx()
  await apply(ctx.ctx, { skillsEnabled: false, guardRulesPath: path })
  const call = cmd => ctx.redLine({ name: 'pwsh', arguments: { command: cmd } })
  check('apply 用了外置规则', (call('WIRED_PROBE') ?? '').includes('[wired]'))
  check('内置规则仍在', (call('rm -rf /') ?? '').includes('[rm-rf-root]'))
}

// 13. guardRulesPath: null 时 apply 忽略文件
{
  const path = writeRules(JSON.stringify({ rules: [{ id: 'wired', re: '\\bWIRED_PROBE\\b' }] }))
  const ctx = fakeGuardCtx()
  await apply(ctx.ctx, { skillsEnabled: false, guardRulesPath: null })
  check('guardRulesPath=null → 只用内置表',
    ctx.redLine({ name: 'pwsh', arguments: { command: 'WIRED_PROBE' } }) === undefined)
  void path
}

console.log(failed === 0 ? '\n✅ 规则文件测试全部通过' : `\n❌ ${failed} 条失败`)
process.exit(failed === 0 ? 0 : 1)
