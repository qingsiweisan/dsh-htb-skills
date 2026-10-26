/**
 * tool-render-contract-test.mjs — 所有工具的 `output.render` 契约闸
 *
 * 为什么需要它（2026-10-26 真实事故）：
 *   `machine-tools.js` / `machine-own.js` 把 render 写成 `(s) => s`（返回字符串），
 *   而框架要求 `render(args, value)` **返回 content block 数组**。
 *   后果：8 个工具全部抛 `content.some is not a function`，且 `isError` 为空 ——
 *   错误文本被当成**正常输出**返回给模型。模型看到"工具坏了"后改回手写 curl，
 *   整场会话 141 次 ssh_exec 里有一半是本来可以被工具替代的。
 *
 *   为什么原有测试没抓到：`machine-tools-test` / `machine-own-test` 都直接调
 *   `tools.get(name).execute(args)`，**绕过了 render**。execute 返回字符串是对的，
 *   错的是 render 把它包成什么。
 *
 * 契约（三条，缺一即失败）：
 *   ① `output.render` 是函数，且接受 `(args, value)` 两个参数
 *   ② 返回值必须是**数组**（content blocks）
 *   ③ 数组每一项是 `{ type: 'text', text: <string> }`
 */

import { registerStateTools } from '../src/state-tools.js'
import { registerSherlockTools } from '../src/sherlock-tools.js'
import { apply as applyMachineTools } from '../src/machine-tools.js'
import { apply as applyMachineOwn } from '../src/machine-own.js'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

let failed = 0
const check = (name, ok, extra = '') => {
  if (ok) console.log(`  ✓ ${name}`)
  else { failed += 1; console.log(`  ✗ ${name} ${extra}`) }
}

// 用一个不触网的配置把所有工具注册进来
const dir = mkdtempSync(join(tmpdir(), 'render-'))
const cfg = {
  stateRoot: dir,
  baseUrl: 'http://127.0.0.1:1',      // 不会真的发请求：只测 render
  tokenPath: join(dir, 'tok.txt'),
}

const tools = new Map()
const ctx = {
  tools: {
    register: (t) => tools.set(t.name, t),
    guard: () => () => {},
  },
  skills: { registerProvider: () => {} },
  on: () => () => {},
  logger: { warn: () => {}, info: () => {}, debug: () => {} },
}

registerStateTools(ctx, cfg)
registerSherlockTools(ctx, cfg)
applyMachineTools(ctx, cfg)
applyMachineOwn(ctx, cfg)

console.log(`注册工具：${tools.size} 个\n`)
check('至少注册了 17 个工具', tools.size >= 17, `实际 ${tools.size}`)

const SAMPLE = '示例输出 line1\nline2 ✅ 中文'
for (const [name, def] of tools) {
  const out = def.output
  if (out === undefined || typeof out !== 'object') {
    check(`${name}: 声明了 output`, false)
    continue
  }
  if (typeof out.render !== 'function') {
    check(`${name}: output.render 是函数`, false)
    continue
  }
  if (out.render.length < 2) {
    // 不是硬性错误（可用 arguments 取），但签名不对通常意味着写错了
    check(`${name}: render 接受 (args, value)`, false, `arity=${out.render.length}`)
    continue
  }

  let rendered
  try {
    rendered = out.render({}, SAMPLE)
  } catch (err) {
    check(`${name}: render 不抛异常`, false, String(err?.message ?? err))
    continue
  }

  if (!Array.isArray(rendered)) {
    check(`${name}: render 返回数组`, false, `实际 ${typeof rendered}`)
    continue
  }
  if (rendered.length === 0) {
    check(`${name}: render 返回非空数组`, false)
    continue
  }
  const allText = rendered.every((b) => b !== null && typeof b === 'object' && b.type === 'text' && typeof b.text === 'string')
  if (!allText) {
    check(`${name}: 每项是 {type:'text',text:string}`, false, JSON.stringify(rendered).slice(0, 100))
    continue
  }
  // 内容要能回读到原值（避免 render 把 value 丢掉）
  const joined = rendered.map((b) => b.text).join('')
  check(`${name}: 内容完整回读`, joined.includes('示例输出') && joined.includes('中文'))
}

rmSync(dir, { recursive: true, force: true })
console.log(failed === 0 ? '\ntool-render-contract-test: PASS' : `\ntool-render-contract-test: FAIL (${failed})`)
process.exit(failed === 0 ? 0 : 1)
