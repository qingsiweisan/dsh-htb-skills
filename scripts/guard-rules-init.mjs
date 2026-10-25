/**
 * 把当前内置规则表导出成外置规则文件：`node scripts/guard-rules-init.mjs [--force]`
 *
 * 目标路径见 src/guard.js 的 DEFAULT_RULES_PATH（默认 ~/.dsh/htb-guard-rules.json）。
 * 导出后改这个文件**存盘即生效**，不用重启 dsh web。
 */

import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { DEFAULT_RULES_PATH, RED_LINES } from '../src/guard.js'

const force = process.argv.includes('--force')

if (existsSync(DEFAULT_RULES_PATH) && !force) {
  console.log(`规则文件已存在，未覆盖：${DEFAULT_RULES_PATH}`)
  console.log('要覆盖请加 --force（会丢掉你改过的内容）。')
  process.exit(1)
}

const doc = {
  _readme: [
    '内置表是基线，本文件按 id 覆盖或追加。',
    '覆盖单条：给出同名 id + 新的 re/why/fix。',
    '关掉单条：{ "id": "<内置id>", "enabled": false }。',
    '新增一条：给一个内置表里没有的 id。',
    're 是正则字符串；flags 省略则为空。写错了只影响那一条，整体回落内置表。',
  ],
  rules: RED_LINES.map(rule => ({
    id: rule.id,
    re: rule.re.source,
    flags: rule.re.flags,
    why: rule.why,
    fix: rule.fix,
  })),
}

mkdirSync(dirname(DEFAULT_RULES_PATH), { recursive: true })
writeFileSync(DEFAULT_RULES_PATH, `${JSON.stringify(doc, null, 2)}\n`, 'utf8')
console.log(`已写出 ${doc.rules.length} 条规则 → ${DEFAULT_RULES_PATH}`)
console.log('改完存盘即生效（守卫按 mtime 重载），不用重启 dsh web。')
