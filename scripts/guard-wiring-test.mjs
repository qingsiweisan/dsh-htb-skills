/**
 * 接线测试：`node scripts/guard-wiring-test.mjs`
 *
 * guard.js 的规则表由 guard-test.mjs 覆盖。这里只验**接线**：
 *   1. index.js 的 apply() 真的把守卫注册进了 ctx.tools；
 *   2. config.guard === false 时**不**注册；
 *   3. guardTools 能收窄被守卫的工具集；
 *   4. 非命令型工具（read/grep…）直接放行；
 *   5. 守卫抛错时 fail-open（放行），不锁死工作流。
 */

import { apply } from '../src/index.js'

let failed = 0
const check = (name, ok, extra = '') => {
  if (ok) console.log(`  ✓ ${name}`)
  else { failed += 1; console.log(`  ✗ ${name} ${extra}`) }
}

/** 造一个只记录 guard 注册的最小 ctx。 */
function fakeCtx() {
  const state = { guards: [], providers: 0, tools: 0 }
  return {
    state,
    ctx: {
      on: () => () => {},
      tools: {
        guard: (g) => { state.guards.push(g); return () => {} },
        register: () => { state.tools += 1; return () => {} },
      },
      skills: { registerProvider: () => { state.providers += 1 } },
    },
  }
}

const call = (g, name, command) => g({ name, arguments: command === undefined ? {} : { command } })

/**
 * 红线守卫 = 会对命令型工具拒绝的那个（提问守卫只碰 ask_user_question）。
 * apply() 现在注册两个守卫，所以不能靠"最后一个"来取；用行为识别，
 * 收窄过工具集时传入实际被守卫的工具名。
 */
const redLineGuard = (state, tool = 'pwsh') =>
  state.guards.find(g => typeof g({ name: tool, arguments: { command: 'rm -rf /' } }) === 'string')

// 1. 默认注册
{
  const { ctx, state } = fakeCtx()
  await apply(ctx, { skillsEnabled: false })
  const g = redLineGuard(state)
  check('apply() 注册了红线守卫', typeof g === 'function')
  check('命中红线 → 拒绝', typeof call(g, 'pwsh', 'dd if=x of=/dev/sda') === 'string')
  check('引号内的文本 → 放行', call(g, 'pwsh', 'echo "dd if=x of=/dev/sda"') === undefined)
  check('普通命令 → 放行', call(g, 'pwsh', 'nmap -sV 10.10.11.5') === undefined)
  check('非命令型工具 → 放行', call(g, 'read', undefined) === undefined)
  check('拒绝理由含规则 id', (call(g, 'pwsh', 'pkill -f x') ?? '').includes('[pkill-f]'))
  check('拒绝理由含逃生口提示', (call(g, 'pwsh', 'pkill -f x') ?? '').includes('HTB_GUARD_ALLOW=1'))
}

// 2. guard: false 关掉红线守卫（提问守卫不受影响）
{
  const { ctx, state } = fakeCtx()
  await apply(ctx, { skillsEnabled: false, guard: false })
  check('guard:false 不注册红线守卫', redLineGuard(state) === undefined)
  // 2026-10-25 +1「停止协议闸」；2026-10-26 +1「交付检查」（machine-own）⇒ 4。
  check('guard:false 不影响提问 / WP / 停止协议 / 交付检查', state.guards.length === 4)
}

// 3. guardTools 收窄
{
  const { ctx, state } = fakeCtx()
  await apply(ctx, { skillsEnabled: false, guardTools: ['ssh_exec'] })
  const g = redLineGuard(state, 'ssh_exec')
  check('收窄后 pwsh 不拦', call(g, 'pwsh', 'pkill -f x') === undefined)
  check('收窄后 ssh_exec 仍拦', typeof call(g, 'ssh_exec', 'pkill -f x') === 'string')
}

// 4. disabledGuardRules
{
  const { ctx, state } = fakeCtx()
  await apply(ctx, { skillsEnabled: false, disabledGuardRules: ['pkill-f'] })
  const g = redLineGuard(state)
  check('禁用单条规则生效', call(g, 'pwsh', 'pkill -f x') === undefined)
  check('其它规则不受影响', typeof call(g, 'pwsh', 'rm -rf /') === 'string')
}

// 5. fail-open：喂一个会让 commandOf/规则表炸的入参
{
  const { ctx, state } = fakeCtx()
  await apply(ctx, { skillsEnabled: false })
  const g = redLineGuard(state)
  const evil = { name: 'pwsh', get arguments() { throw new Error('boom') } }
  let threw = false
  let result
  try { result = g(evil) } catch { threw = true }
  check('守卫抛错时不外泄异常', !threw)
  check('守卫抛错时放行（fail-open）', result === undefined)
}

console.log(failed === 0 ? '\n✅ 接线测试全部通过' : `\n❌ ${failed} 条失败`)
process.exit(failed === 0 ? 0 : 1)
