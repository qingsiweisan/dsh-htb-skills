/**
 * dsh-htb-skills — HTB pentesting skill library plugin for DeepSeek Harness.
 *
 * Host half only. It registers a package-local skill provider named `htb`
 * over the bundled `skills/` tree through the official
 * `@deepseek-ai/dsh-skill-filesystem` provider implementation:
 *
 *   - single source of truth: skills live in this package, versioned by git;
 *   - `includeDefaultRoots: false` so this provider lists ONLY the bundled
 *     cards (the deployment's own `skill-filesystem` row keeps discovering
 *     project/user skills);
 *   - Chokidar watches the package tree, so edits hot-reload without a
 *     harness restart;
 *   - T1 cards stay model-invocable and appear in the session catalog;
 *     T2/T3 cards carry `disable-model-invocation: true` and are loaded by
 *     name (see the `htb-skill-index` card for the full domain x tier table).
 *
 * No browser half, no routes.
 */

import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { registerSherlockTools } from './sherlock-tools.js'
import { registerStateTools } from './state-tools.js'
import { apply as applyGuard } from './guard.js'
import { apply as applyAskGuard } from './ask-guard.js'
import { apply as applyWpGuard } from './wp-guard.js'
import { apply as applyStruggleWatch } from './struggle-watch.js'
import { apply as applyScopeObserve } from './scope-observe.js'
import { apply as applyContextHygiene } from './context-hygiene.js'
import { apply as applyErrorClassify } from './error-classify.js'
import { apply as applyAutoState } from './auto-state.js'
import { apply as applyMachineOwn } from './machine-own.js'
import { apply as applyMachineTools } from './machine-tools.js'

/** Stable Cordis plugin name. */
export const name = 'htb-skills'

/** Wait for the host composition's skill registry and tool registry before mounting. */
export const inject = ['skills', 'tools']

/** Absolute path of the bundled skills tree inside this package. */
export function bundledSkillsRoot() {
  return join(fileURLToPath(new URL('..', import.meta.url)), 'skills')
}

/**
 * Mount the plugin: register the `htb` skill provider over the package's
 * own skills directory, plus the htb_sherlock_* model tools.
 *
 * Config:
 *   - `skillsEnabled` (default true): set false on deployments that already
 *     serve the same cards from another skill provider (~/.dsh/skills), so
 *     only the tools mount and the card names never collide.
 *   - `tokenPath` / `token`: HTB bearer token source (default
 *     ~/.dsh/htb-token.txt or $HTB_TOKEN).
 *   - `guard` (default true): 注册操作安全红线守卫（见 guard.js）。红线保护的是
 *     「自己的会话/工具链」，任何模式下都可能踩，所以默认全局开启；要关就
 *     `guard: false`。
 *   - `guardTools` / `disabledGuardRules`: 透传给 guard.js 的 config。
 *   - `askGuard` (default true): 注册提问守卫（见 ask-guard.js），拦掉"把
 *     writeup/提示/payload 细节当选项"这类把解题责任推回用户的提问。
 *   - `askGuardTools`: 透传给 ask-guard.js 的 config。
 *   - `wpGuard` (default true): 注册官方 WP 读取守卫（见 wp-guard.js）。拦掉
 *     `read`/`glob`/`grep` 与本地 shell 对 `htb-wp/` 的**显式**引用 —— 用户备考
 *     OSCP，读官方 WP 是负收益（决策 D1，2026-09-25）。复盘要用时由用户创建
 *     解锁标记 `~/.dsh/htb-wp-unlock`。
 *   - `wpGuardTools` / `wpGuardDirname` / `wpGuardUnlockPath`: 透传。
 *   - `struggleWatch` (default true): 挂 Struggle 监视器（见 struggle-watch.js）。
 *     **当前是记录模式**：只往 JSONL 写观测，不注入会话。
 *   - `struggleLogPath` / `struggleArtifactDir` / `struggleThresholds`: 透传。
 *   - `scopeObserve` (default true): 挂**出站目标观测器**（见 scope-observe.js）。
 *     只往 `~/.dsh/htb-scope-observed.jsonl` 记录"本会话打过哪些目标、哪些未登记为
 *     host fact"，**永不拦截** —— 它不是授权边界，强制的 scope 必须在执行环境层做。
 *     要关就 `scopeObserve: false`。
 *   - `scopeObserveLogPath` / `scopeObserveTools`: 透传。
 *   - `contextHygiene` (default true): 挂**上下文卫生检测**（见 context-hygiene.js）。
 *     执行类工具单次输出超过 `thresholdLines`（默认 200 行）时，在结果末尾追加
 *     一次分流建议（**滑动窗口**：默认每 60 次执行调用最多 2 次，会话绝对上限 8），
 *     并把用量写进 `~/.dsh/htb-context-hygiene.jsonl`。**不阻断、不改变谁能执行**。
 *   - `contextHygieneThresholdLines` / `contextHygieneMaxNotices` /
 *     `contextHygieneNoticeWindowCalls` / `contextHygieneMaxNoticesPerWindow` /
 *     `contextHygieneLogPath`: 透传。
 *   - `errorClassify` (default true): 挂**失败归因**（见 error-classify.js）。
 *     把执行类工具的失败归到 6 类（channel / permission / auth / network /
 *     syntax / semantic），同类第 2 次出现时提示"是不是同一个原因"，
 *     第 3 次升级为"停止同类变体、换层或换通道"。**只提示，不阻断**。
 *   - `errorClassifyHintAt` / `errorClassifyEscalateAt` / `errorClassifyMaxHints` /
 *     `errorClassifyLogPath`: 透传。
 *   - `autoState` (default true): 挂**战线自动采集**（见 auto-state.js）。
 *     从命令推断当前战线（侦察/Web/数据库/图形会话/凭据/主机），战线切换时给一条
 *     摘要（上一战线多少次调用、几条事实、停留多久），并把 `type:"auto-probe"`
 *     写进 `<stateRoot>/<machine>-state.jsonl`。**不写命令原文**。
 *   - `autoStateLogPath` / `autoStateMinCallsForSummary`: 透传。
 *
 * 🔴 守卫**不能**用 `dsh-htb-skills/guard` 这样的子路径单独挂一行：
 * loader 的插件解析不走 package `exports`，会报 "failed to import"（2026-09-24
 * 实测）。所以它折在 index.js 里。将来若要按 preset 只作用于打靶会话，做法是在
 * preset bundle 里放一个三行 shim（`export * from 'dsh-htb-skills/guard'`）并用
 * 相对路径挂载 —— 普通 Node 解析是认 exports 的，只有 loader 不认。
 *
 * The skills provider is imported lazily: tools-only mounts (skillsEnabled:
 * false) resolve no external packages, so a link/junction into a deployment
 * whose node_modules lacks @deepseek-ai/dsh-skill-filesystem still loads.
 * @param ctx - host plugin context carrying `skills` and `tools`.
 */
export async function apply(ctx, config) {
  config = config ?? {}
  if (config.skillsEnabled !== false) {
    const { FileSystemSkillProvider } = await import('@deepseek-ai/dsh-skill-filesystem')
    const root = bundledSkillsRoot()
    ctx.skills.registerProvider((control) =>
      new FileSystemSkillProvider(ctx, control, {
        providerName: 'htb',
        includeDefaultRoots: false,
        customSkillDirs: [root],
        // Schema-required fields that are inert with includeDefaultRoots:false;
        // bundledSkillDir must resolve to an empty path so nothing is mounted
        // under the trusted `bundled` source.
        dshHome: root,
        agentsHome: root,
        bundledSkillDir: join(root, '..', '.bundled-empty'),
        watch: true,
      }),
    )
  }
  registerSherlockTools(ctx, config)
  // 作战状态账本（fact 节点 / intent 边）。与 dsh-htb-router 的 state 事件共用
  // <stateRoot>/<machine>-state.jsonl —— 两边合起来是"全局黑板"（见 state-tools.js 头注）。
  registerStateTools(ctx, config)
  if (config.guard !== false) {
    applyGuard(ctx, {
      ...(config.guardTools ? { tools: config.guardTools } : {}),
      ...(config.disabledGuardRules ? { disabledRules: config.disabledGuardRules } : {}),
      ...(config.guardRulesPath !== undefined ? { rulesPath: config.guardRulesPath } : {}),
    })
  }
  // 靶机生命周期工具（2026-10-26）：list / info / spawn / status / stop / reset / user_info。
  // 依据：三场会话手写 curl 调 HTB API 共 76 次，几乎全在猜端点（paginated 试了 5 种写法、
  // spawn 后手动轮询 5–10 次、user/info 试了 v4/v5/v6）。封装后一步到位。
  if (config.machineTools !== false) {
    applyMachineTools(ctx, {
      ...(config.machineToolsBaseUrl ? { baseUrl: config.machineToolsBaseUrl } : {}),
      ...(config.machineToolsTokenPath ? { tokenPath: config.machineToolsTokenPath } : {}),
      ...(config.machineToolsSpawnTimeoutSec !== undefined ? { spawnTimeoutSec: config.machineToolsSpawnTimeoutSec } : {}),
    })
  }
  // 靶机 flag 提交 + 完成前交付检查（2026-10-26）。
  // 位置刻意在 registerStateTools 之后 —— 它要读同一份 <machine>-state.jsonl。
  if (config.machineOwn !== false) {
    applyMachineOwn(ctx, {
      ...(config.machineOwnBaseUrl ? { baseUrl: config.machineOwnBaseUrl } : {}),
      ...(config.machineOwnTokenPath ? { tokenPath: config.machineOwnTokenPath } : {}),
      ...(config.stateRoot ? { stateRoot: config.stateRoot } : {}),
      ...(config.machineOwnGoalGate === false ? { goalGate: false } : {}),
    })
  }
  if (config.askGuard !== false) {
    applyAskGuard(ctx, {
      ...(config.askGuardTools ? { tools: config.askGuardTools } : {}),
    })
  }
  if (config.wpGuard !== false) {
    applyWpGuard(ctx, {
      ...(config.wpGuardTools ? { tools: config.wpGuardTools } : {}),
      ...(config.wpGuardDirname ? { dirname: config.wpGuardDirname } : {}),
      ...(config.wpGuardUnlockPath !== undefined ? { unlockPath: config.wpGuardUnlockPath } : {}),
    })
  }
  applyStruggleWatch(ctx, {
    ...(config.struggleWatch === false ? { enabled: false } : {}),
    ...(config.struggleLogPath ? { logPath: config.struggleLogPath } : {}),
    ...(config.struggleArtifactDir ? { artifactDir: config.struggleArtifactDir } : {}),
    ...(config.struggleThresholds ? { thresholds: config.struggleThresholds } : {}),
    ...(config.struggleGate === false ? { gate: false } : {}),
    // 2026-10-26：产物扫描节流。测试要把它调大来逼出"write 强制重扫"这条路径，
    // 所以必须能透传；生产默认 1000ms，设 0 退回每次重扫。
    ...(config.struggleArtifactScanIntervalMs !== undefined ? { artifactScanIntervalMs: config.struggleArtifactScanIntervalMs } : {}),
    ...(config.struggleIntervene === false ? { intervene: false } : {}),
  })
  // 出站目标观测（2026-10-21 新增）：只记录，永不拦截。
  // 它不是授权边界 —— 强制的 scope 必须在执行环境层做，理由见 scope-observe.js 头注。
  if (config.scopeObserve !== false) {
    applyScopeObserve(ctx, {
      ...(config.scopeObserveLogPath ? { logPath: config.scopeObserveLogPath } : {}),
      ...(config.stateRoot ? { stateRoot: config.stateRoot } : {}),
      ...(config.machine ? { machine: config.machine } : {}),
      ...(config.scopeObserveTools ? { tools: config.scopeObserveTools } : {}),
    })
  }
  // 上下文卫生（2026-10-21 新增）：执行类工具输出超标时给一次分流建议。
  // 不改变谁能执行，只让"这次吃了多少上下文"可见 —— 理由见 context-hygiene.js 头注。
  if (config.contextHygiene !== false) {
    applyContextHygiene(ctx, {
      ...(config.contextHygieneThresholdLines ? { thresholdLines: config.contextHygieneThresholdLines } : {}),
      ...(config.contextHygieneMaxNotices !== undefined ? { maxNotices: config.contextHygieneMaxNotices } : {}),
      ...(config.contextHygieneNoticeWindowCalls !== undefined ? { noticeWindowCalls: config.contextHygieneNoticeWindowCalls } : {}),
      ...(config.contextHygieneMaxNoticesPerWindow !== undefined ? { maxNoticesPerWindow: config.contextHygieneMaxNoticesPerWindow } : {}),
      ...(config.contextHygieneAccumWindowCalls !== undefined ? { accumWindowCalls: config.contextHygieneAccumWindowCalls } : {}),
      ...(config.contextHygieneAccumChars !== undefined ? { accumChars: config.contextHygieneAccumChars } : {}),
      ...(config.contextHygieneAccumCooldownCalls !== undefined ? { accumCooldownCalls: config.contextHygieneAccumCooldownCalls } : {}),
      ...(config.contextHygieneMaxAccumNotices !== undefined ? { maxAccumNotices: config.contextHygieneMaxAccumNotices } : {}),
      ...(config.contextHygieneLogPath ? { logPath: config.contextHygieneLogPath } : {}),
    })
  }
  // 失败归因（2026-10-25 新增）：同类错误第 2 次就提示"是不是同一个原因"。
  // 直接解掉 DutyBound 那场"COPY FROM PROGRAM 空结果被当成新问题反复推理"的损耗。
  if (config.errorClassify !== false) {
    applyErrorClassify(ctx, {
      ...(config.errorClassifyHintAt !== undefined ? { hintAt: config.errorClassifyHintAt } : {}),
      ...(config.errorClassifyEscalateAt !== undefined ? { escalateAt: config.errorClassifyEscalateAt } : {}),
      ...(config.errorClassifyMaxHints !== undefined ? { maxHints: config.errorClassifyMaxHints } : {}),
      ...(config.errorClassifyLogPath ? { logPath: config.errorClassifyLogPath } : {}),
    })
  }
  // 战线自动采集（2026-10-25 新增）：不要求模型申报，从命令推断战线并在切换时摘要。
  // 状态层不能靠"模型记得调用"活着 —— 理由见 auto-state.js 头注。
  if (config.autoState !== false) {
    applyAutoState(ctx, {
      ...(config.stateRoot ? { stateRoot: config.stateRoot } : {}),
      ...(config.machine ? { machine: config.machine } : {}),
      ...(config.autoStateMinCallsForSummary !== undefined ? { minCallsForSummary: config.autoStateMinCallsForSummary } : {}),
      ...(config.autoStateSwitchAfterCalls !== undefined ? { switchAfterCalls: config.autoStateSwitchAfterCalls } : {}),
      ...(config.autoStateFrontBudgetCalls !== undefined ? { frontBudgetCalls: config.autoStateFrontBudgetCalls } : {}),
      ...(config.autoStateStaleCallsForReview !== undefined ? { staleCallsForReview: config.autoStateStaleCallsForReview } : {}),
      ...(config.autoStateStaleMinutesForReview !== undefined ? { staleMinutesForReview: config.autoStateStaleMinutesForReview } : {}),
      ...(config.autoStateLogPath ? { logPath: config.autoStateLogPath } : {}),
    })
  }
}
