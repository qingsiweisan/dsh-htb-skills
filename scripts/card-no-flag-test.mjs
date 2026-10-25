#!/usr/bin/env node
/**
 * card-no-flag-test.mjs — 卡库不得含真实 flag 的准入闸（2026-10-22 新增）
 *
 * 为什么需要它：
 *   2026-10-22 扫描发现 4 处**实战取得的真实答案**被写进技术卡
 *   （string-replace-dollar-sequence-xss 与 challenge-blockchain-web3）。
 *   卡会被 `skill` 工具加载进上下文 —— 等于把答案直接递给模型，
 *   违背「打靶会话不读官方 WP」的同一条纪律（D1：拿 flag 的同时把练习价值清零）。
 *
 * 判据：
 *   · 匹配 `HTB{...}` 形态
 *   · 白名单：脱敏占位符、明确标注为示例的（F4k3/LOCAL_TEST/EXAMPLE/DUMMY）
 *   · 不检查 32/40 位 hex —— 空 LM hash、MD5 碰撞魔法数、htpasswd 示例都是技术常量，
 *     误判代价高于漏报
 *
 * 契约：exit 0 = 通过；发现疑似真实 flag 一律 exit 1。
 */
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'

const SKILLS = process.env.HTB_SKILLS_ROOT ?? join(homedir(), '.dsh', 'skills')

const FLAG = /HTB\{[^}\n]{4,}\}/g
// 允许出现的形态：脱敏占位符、明确示例标记
const ALLOW = [
  /^HTB\{<redacted>\}$/i,
  /^HTB\{\.{3}\}$/,
  /F4k3|FAKE|LOCAL_TEST|EXAMPLE|DUMMY|<[^>]+>/i,
]

let scanned = 0
const bad = []

let dirs = []
try {
  dirs = readdirSync(SKILLS, { withFileTypes: true })
    .filter((d) => d.isDirectory() && !d.name.startsWith('.'))
    .map((d) => d.name)
} catch {
  console.log(`SKIP  卡库不存在: ${SKILLS}`)
  process.exit(0)
}

for (const name of dirs) {
  const f = join(SKILLS, name, 'SKILL.md')
  let text
  try {
    text = readFileSync(f, 'utf-8')
  } catch {
    continue
  }
  scanned += 1
  for (const m of text.matchAll(FLAG)) {
    const val = m[0]
    if (ALLOW.some((rx) => rx.test(val))) continue
    // 真 flag 不会含中文 / 空格 / 反引号。含这些的多半是正则示例或说明文字，
    // 例如 "HTB{` 零命中 ≠ 没有旗" 这类跨了反引号的误匹配。
    if (/[\u4e00-\u9fa5\s`]/.test(val)) continue
    const line = text.slice(0, m.index).split('\n').length
    bad.push({ card: name, line, val })
  }
}

if (bad.length > 0) {
  console.log(`❌ 发现 ${bad.length} 处疑似真实 flag：`)
  for (const b of bad) {
    // 只显示前缀，避免闸本身的输出再次泄露
    console.log(`   ${b.card}:${b.line}  ${b.val.slice(0, 12)}…`)
  }
  console.log('\n处理方式：替换为 HTB{<redacted>}，保留题号/日期等上下文。')
  process.exit(1)
}

console.log(`card-no-flag-test: PASS（扫描 ${scanned} 张卡，无真实 flag）`)
process.exit(0)
