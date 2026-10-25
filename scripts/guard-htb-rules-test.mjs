/**
 * 外置 HTB 规则表的回归测试：`node scripts/guard-htb-rules-test.mjs`
 *
 * 测的是**本机真实规则文件**（src/guard.js 的 DEFAULT_RULES_PATH，
 * 默认 ~/.dsh/htb-guard-rules.json）里那批「对靶机的不可逆破坏」规则。
 * 文件不存在 ⇒ 跳过（退出 0），因为它是主机档案、不是插件的一部分。
 *
 * 四组用例，与 guard-test.mjs 同构：
 *   DENY   —— 必须拦下的（删库 / 清缓存 / DELETE / 删除类端点）
 *   ALLOW  —— 必须放行的（**误拦防线**：相似前缀的正常路径 + 引号内纯文本）
 *   QUOTED_EXEC —— 引号内文本被交给解释器执行时必须照拦
 *   OVERRIDE —— 逃生口 HTB_GUARD_ALLOW=1 必须有效
 *
 * 🔴 为什么 ALLOW 组要写这么重：这批规则的锚点是 curl/psql/redis-cli 这类
 *    **常见命令词**，天然比内置那批（pkill/losetup/mkfs）更容易误伤。
 *    ARTEX 的同一批规则就是被 /delivery /details /delta /delegate 反复绊倒的，
 *    所以这里把那几个词原样搬来当防线。
 */

import { existsSync } from 'node:fs'
import { DEFAULT_RULES_PATH, OVERRIDE_PREFIX, RED_LINES, activeRules, checkCommand } from '../src/guard.js'

if (!existsSync(DEFAULT_RULES_PATH)) {
  console.log(`SKIP：规则文件不存在 —— ${DEFAULT_RULES_PATH}`)
  console.log('（这是主机档案，不是插件的一部分；本机未启用该批规则。）')
  process.exit(0)
}

const rules = activeRules(DEFAULT_RULES_PATH)

const EXPECTED = [
  'http-delete-method',
  'destructive-endpoint-path',
  'sql-destructive',
  'nosql-cache-flush',
  'http-client-delete',
]

const DENY = [
  // ── DELETE 方法 ────────────────────────────────────────────────
  ['curl -X DELETE http://10.10.11.5/api/user/1', 'http-delete-method'],
  ['curl --request DELETE http://t/api/user/1', 'http-delete-method'],
  ['wget --method=DELETE http://t/api/user/1', 'http-delete-method'],
  ['curl -sS -XDELETE http://t/api/item/9', 'http-delete-method'],
  // ── 删除类端点：GET/POST 也能触发（ARTEX v3 的核心教训）────────
  ["curl -s 'http://t/api/user/delete?id=1'", 'destructive-endpoint-path'],
  ['curl -X POST http://t/admin/delete -d id=1', 'destructive-endpoint-path'],
  ["curl 'http://t/admin/destroyAll'", 'destructive-endpoint-path'],
  ['curl http://t/api/remove?id=2', 'destructive-endpoint-path'],
  ['curl -s http://t/api/factory-reset', 'destructive-endpoint-path'],
  ['curl http://t/files/unlink/3', 'destructive-endpoint-path'],
  // ── SQL ───────────────────────────────────────────────────────
  ['psql -h t -U u -c "DROP TABLE users"', 'sql-destructive'],
  ["mysql -e 'TRUNCATE TABLE t'", 'sql-destructive'],
  ['sqlite3 app.db "DROP TABLE x"', 'sql-destructive'],
  ['sqlcmd -S t -Q "DROP DATABASE prod"', 'sql-destructive'],
  // ── NoSQL / 缓存 ──────────────────────────────────────────────
  ['mongosh --eval "db.dropDatabase()"', 'nosql-cache-flush'],
  ['redis-cli -h t FLUSHALL', 'nosql-cache-flush'],
  ['redis-cli -h t -n 0 FLUSHDB', 'nosql-cache-flush'],
  // ── 脚本化 DELETE ─────────────────────────────────────────────
  ['python3 -c "import requests; requests.delete(\'http://t/x\')"', 'http-client-delete'],
  ['node -e "require(\'axios\').delete(\'http://t/x\')"', 'http-client-delete'],
  // 内置表仍在（回归）
  ['rm -rf /', 'rm-rf-root'],
  ['losetup /dev/loop0 /tmp/root.img', 'losetup'],
]

const ALLOW = [
  // 🔴 误拦防线：与删除动词**共享前缀**的正常路径（ARTEX 实测被这几个绊过）
  ['curl http://t/api/delivery', 'delivery'],
  ['curl http://t/order/details', 'details'],
  ['curl http://t/api/delta/sync', 'delta'],
  ['curl http://t/user/delegate', 'delegate'],
  ['curl http://t/api/clearance', 'clearance 不在表内'],
  // 🔴 误拦防线：本地路径里的删除词（-o 落盘）。端点规则要求 :// 上下文，
  //    就是为了挡住这一组；不挡的话 `curl -o /tmp/purge_report.html` 会被拦。
  ['curl -o /tmp/purge_report.html http://t/', '本地路径含 purge'],
  ['curl -o /tmp/delete.log http://t/', '本地路径含 delete'],
  ['curl -o "/tmp/remove-me.txt" http://t/', '本地路径含 remove（带引号）'],
  // 正常读写
  ['curl -X GET http://t/api/user/1', '普通 GET'],
  ['curl -X OPTIONS http://t/api/user/1 -i', 'OPTIONS 探测'],
  ['curl -s http://t/api/users?limit=10 | jq .', '普通读 + 管道'],
  ['psql -h t -c "SELECT version()"', '只读 SQL'],
  ['psql -h t -c "SELECT * FROM users LIMIT 5"', '只读 SQL'],
  ['sqlite3 app.db ".tables"', '只读'],
  ['redis-cli -h t INFO', '只读'],
  ["redis-cli -h t KEYS '*'", '只读'],
  ['mongosh --eval "db.stats()"', '只读'],
  // 危险动词落在引号字面量里 ⇒ 是文本，不是执行（guard 的既有契约）
  ['echo "curl -X DELETE http://t/x"', '引号内的 curl'],
  ['echo "redis-cli FLUSHALL"', '引号内的 FLUSHALL'],
  ['grep -rn "dropDatabase" .', 'grep 引号内的 dropDatabase'],
  ['grep -rn "FLUSHALL" ./notes/', 'grep 引号内的 FLUSHALL'],
  ['grep -rn "DROP TABLE" ./db/', 'grep 引号内的 DROP'],
  ["grep -rn \"method: 'DELETE'\" src/", 'grep 引号内的 method:DELETE'],
]

const QUOTED_EXEC = [
  ['bash -c "curl -X DELETE http://t/x"', 'http-delete-method'],
  ["sh -c 'redis-cli FLUSHALL'", 'nosql-cache-flush'],
  ['python3 -c "import os; os.system(\'psql -c \\"DROP TABLE x\\"\')"', 'sql-destructive'],
]

const OVERRIDE = [
  ['HTB_GUARD_ALLOW=1 redis-cli FLUSHALL', '确认过才放行'],
  ['HTB_GUARD_ALLOW=1 curl -X DELETE http://t/x', '确认过才放行'],
  [OVERRIDE_PREFIX + ' psql -h t -c "DROP TABLE x"', '用导出的常量也对'],
]

let failed = 0
const fail = (msg) => {
  failed += 1
  console.log(`  ✗ ${msg}`)
}

console.log(`规则表：${DEFAULT_RULES_PATH}`)
console.log(`  生效 ${rules.length} 条（内置 ${RED_LINES.length} + 外置）`)
for (const id of EXPECTED) {
  if (!rules.some(r => r.id === id)) fail(`缺规则 ${id}（文件被改动或写坏了？）`)
}
if (!failed) console.log(`  ✓ ${EXPECTED.length} 条外置规则都在`)

console.log('DENY — 必须拦下')
for (const [cmd, want] of DENY) {
  const hit = checkCommand(cmd, rules)
  if (!hit) fail(`漏拦 [${want}] ${cmd}`)
  else if (hit.id !== want) fail(`拦错规则 期望 ${want} 实得 ${hit.id}: ${cmd}`)
}
console.log(`  ${DENY.length} 条`)

console.log('ALLOW — 必须放行（误拦防线）')
for (const [cmd, note] of ALLOW) {
  const hit = checkCommand(cmd, rules)
  if (hit) fail(`误拦 [${hit.id}] ${cmd}  (${note})`)
}
console.log(`  ${ALLOW.length} 条`)

console.log('QUOTED_EXEC — 引号内文本被解释器执行')
for (const [cmd, want] of QUOTED_EXEC) {
  const hit = checkCommand(cmd, rules)
  if (!hit) fail(`漏拦 [${want}] ${cmd}`)
  else if (hit.id !== want) fail(`拦错规则 期望 ${want} 实得 ${hit.id}: ${cmd}`)
}
console.log(`  ${QUOTED_EXEC.length} 条`)

console.log('OVERRIDE — 逃生口')
for (const [cmd, note] of OVERRIDE) {
  const hit = checkCommand(cmd, rules)
  if (hit) fail(`逃生口失效 [${hit.id}]: ${cmd}`)
}
console.log(`  ${OVERRIDE.length} 条`)

console.log(failed === 0 ? '\n✅ HTB 外置规则全部通过' : `\n❌ ${failed} 条失败`)
process.exit(failed === 0 ? 0 : 1)
