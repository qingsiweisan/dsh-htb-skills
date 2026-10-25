/**
 * dsh-htb-skills/wp-guard — 官方 WP 语料读取守卫。
 *
 * 由来（2026-09-25 复盘，用户决策 D1）：
 *   ReaperTwo 那台，旧会话 8.6 小时没拿到 root；新会话 **31 分钟拿到**，
 *   但它是读了工作区里的官方 WP（`htb-wp/txt/772_ReaperTwo.txt`）才做到的。
 *   用户在备考 OSCP —— 读 WP 对他**是负收益**，而 agent 天然会走最省事的路。
 *   所以规则选 A：**打靶会话禁止读 htb-wp/，只在复盘时用**。
 *
 * 为什么是机制而不是 persona 一句话：
 *   preset persona 早就写过"绝不问提示"，照样被违反（见 ask-guard.js 的由来）。
 *   提示词只能降低概率，机制才能保证 —— 这条结论在本项目里已经付过两次学费。
 *
 * 设计边界（同 guard.js，别当安全边界用）：
 *   - 它拦的是**调用文本**。把 WP 复制成别的名字再读、用 subagent 间接读、
 *     `pwsh` 里 base64 解开路径……都绕得过去。它挡的是"顺手 `read` 一下"，
 *     而那正是 31 分钟那次实际发生的事。
 *   - **只拦显式提到 WP 路径的调用**。`grep`/`glob` 不传 `path`（等价于扫整个
 *     工作区）时放行 —— 拦它会把「loot / notes 的全文检索」一起堵死，误报代价
 *     高于漏报。这是已知缺口，写在这里而不是留给下一个人踩。
 *   - 守卫自身抛错时放行（fail-open），与 guard.js 一致。
 *   - **远程 shell 与本地 shell 同等守卫**（2026-10-01 补）。原 `SHELL_TOOLS`
 *     只有 `pwsh`/`bash`，而**同一个仓库**的 guard.js 是四条；于是
 *     `ssh_exec`/`ssh_cluster` 里引用 `htb-wp/` 完全不拦（如
 *     `ssh host "cat /path/htb-wp/txt/x.txt"`）。"不读 WP"的意图显然覆盖远程读，
 *     所以两边对齐为 {@link SHELL_TOOLS}。代价：远端另有同名目录时会误拦 ——
 *     认了，见下面"只读元数据白名单"给的回退口。
 *
 * 只读元数据白名单（2026-10-01 补，{@link READONLY_META_VERBS}）：
 *   - 由来：审计实测，守卫只想 `Test-Path` 一个目录（**不读内容**）就被
 *     `[wp-shell]` 拒掉，最后**只能拼接目录名**才完成核对 —— 而 preset persona
 *     第 9 条要求"被拒就回到自主排查，**不要想办法绕**"。机制把模型逼向规避，
 *     与纪律自相矛盾，所以补一层"存在性/属性"白名单。
 *   - 放行：`Test-Path`、`Get-Item`（仅属性）、`stat`、`file`。
 *   - 不放行**枚举**（`ls`/`dir`/`Get-ChildItem`/`find`/`tree`）——"这台机器上
 *     有没有 writeup"是实质信息泄露，正是要挡的东西。
 *   - 不放行**内容读取**（`cat`/`Get-Content`/`head`/`grep`/`Select-String`…）。
 *   - 放行条件是两个**同时**成立：①整条命令里**任何位置**都没有内容读取/枚举
 *     动词；②引用了 WP 的那一段本身就是白名单动作。所以
 *     `Test-Path htb-wp/txt; cat htb-wp/txt/x.txt` 与
 *     `Get-Item htb-wp/txt | Get-Content` 都仍然拦 —— 白名单不许当掩护。
 *   - 已知边界与漏面（照旧写在这里，别留给下一个人踩）：
 *     · 白名单段里出现 `|`/`>`/`>>` 或通配符 `*`/`?` 一律不放行：
 *       `Get-Item x > copy.txt` 已是搬运动作；而 `Get-Item htb-wp\txt\*`
 *       在 PowerShell 里**退化成枚举**（等价 `Get-ChildItem`）。要查就查
 *       具体名字（`Test-Path htb-wp/txt/772_ReaperTwo.txt`）。
 *     · 动词扫描是**整条命令行**的粗粒度匹配：`Test-Path htb-wp; ls loot`
 *       也会被拦。过拦在拦的一侧，认了 —— 拆成两条调用即可。
 *     · `Test-Path` 本身是**存在性预言机**：能逐名猜出 WP 里有没有某个文件
 *       （大小、时间戳同理）。它不泄露内容、也不能列目录，但确实泄露
 *       "某文件存在"。判断是：不读内容 = 不构成"看答案"，而堵死存在性检查
 *       的代价是机制把模型逼回拼接路径/编码路径的规避路线上（本次修的正是
 *       这条）。若将来判定存在性也算答案，替代方案是**放行但改写结果**：
 *       在 guard 里返回固定文案（如"WP 语料目录按设计不可探测"），而不是
 *       报错 —— 报错只是把模型推向绕路。
 *     · 只认"命令词就是白名单动作"（可跳过 `&`/`sudo`/`command`/`env`/`exec`
 *       前缀）。`powershell -c "Test-Path ..."`、`bash -c '...'`、`xargs`、
 *       变量/`$( )` 拼接都不在白名单里，按默认拦。
 *
 * 解锁（复盘 / 语料整理要用）：
 *   默认锁定；存在解锁标记文件（见 {@link DEFAULT_UNLOCK_PATH}）时整条守卫让路。
 *   刻意做成"要用户动一次手"的动作，而不是配置文件里一个随手能翻的开关 ——
 *   跟红线守卫的 `HTB_GUARD_ALLOW=1 ` 是同一个思路：让"我知道我在干什么"
 *   变成一个动作，而不是一句心里话。
 */

import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/** Stable Cordis plugin name（将来若单独挂一行用得上）。 */
export const name = 'htb-wp-guard'

/** 依赖工具注册表。 */
export const inject = ['tools']

/** 被守卫的**路径型**工具：入参里带文件路径，没有命令前缀可用。 */
export const PATH_TOOLS = ['read', 'glob', 'grep']

/** 本地命令型工具：能 `cat`/`Get-Content` 绕过 `read`。 */
export const LOCAL_SHELL_TOOLS = ['pwsh', 'bash']

/**
 * 远程命令型工具（2026-10-01 补）：命令文本同样会引用 WP 路径。
 *
 * 与 guard.js 的 `SHELL_TOOLS` **保持同一口径** —— 两边不一致时，
 * "远程读"就是守卫的公开漏面（审计已确认：`ssh_exec` 里 `cat htb-wp/...` 不被拦）。
 */
export const REMOTE_SHELL_TOOLS = ['ssh_exec', 'ssh_cluster']

/** 被守卫的**命令型**工具：入参里是命令文本，含本地与远程。 */
export const SHELL_TOOLS = [...LOCAL_SHELL_TOOLS, ...REMOTE_SHELL_TOOLS]

/** 默认被守卫的全部工具。 */
export const GUARDED_TOOLS = [...PATH_TOOLS, ...SHELL_TOOLS]

/** 默认受保护的目录名（相对工作区）。 */
export const DEFAULT_WP_DIRNAME = 'htb-wp'

/**
 * 默认解锁标记文件。**存在即解锁**，内容不解析。
 * 复盘时由用户创建，用完删除：
 *   `New-Item -ItemType File $HOME\.dsh\htb-wp-unlock`
 */
export const DEFAULT_UNLOCK_PATH = join(homedir(), '.dsh', 'htb-wp-unlock')

/**
 * ⚠️ 历史遗留常量：红线守卫的显式放行前缀。
 *
 * 🔴 **本守卫已不再采信它**（2026-09-30）。保留导出只为不破坏既有 import。
 * 原因见 {@link checkWpAccess}：解锁通道只能是用户创建的标记文件
 * {@link DEFAULT_UNLOCK_PATH}，不能是模型自己写进命令里的前缀。
 */
export const OVERRIDE_PREFIX = 'HTB_GUARD_ALLOW=1'

/** 匹配缓存的键：目录名 → 正则。 */
const matcherCache = new Map()

/**
 * 造一个"这段文本提到了受保护目录"的正则。
 *
 * 边界处理刻意区分两件事：
 *   - 前后必须是**非标识符字符**（`/`、`\`、空白、引号…），
 *     所以 `htb-wp/txt/x.txt`、`C:\...\htb-wp\txt` 都算命中；
 *   - `htb-wps`、`htb-wp2` 这类**不算**（目录名后面还跟着字母数字）。
 *   另外把 `.` 也算进"后面不能跟"，免得 `notes-htb-wp.md` 这种文件名误伤。
 * @param dirname - 受保护的目录名。
 * @returns 匹配正则（带 `i` 标志）。
 */
export function wpMatcher(dirname = DEFAULT_WP_DIRNAME) {
  const key = String(dirname)
  const cached = matcherCache.get(key)
  if (cached) return cached
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const re = new RegExp(`(?:^|[^A-Za-z0-9_.-])${escaped}(?![A-Za-z0-9_.-])`, 'i')
  matcherCache.set(key, re)
  return re
}

/**
 * 这段文本是否提到了受保护目录。
 * @param text - 命令文本或路径参数。
 * @param dirname - 受保护的目录名。
 * @returns 提到则为 true。
 */
export function referencesWp(text, dirname = DEFAULT_WP_DIRNAME) {
  if (typeof text !== 'string' || !text) return false
  return wpMatcher(dirname).test(text)
}

/**
 * 🔓 只读**元数据**动词白名单（小写，动词规范化后比较）。
 *
 * 取向：只放行"存在性 / 属性"这类**不返回语料内容**的动作。
 * 加一个进来之前先问：它的输出能不能替代读 WP？`stat` 只给大小/时间，
 * `Get-Item` 的属性里没有正文 —— 可以。`ls` 会列出"有没有 writeup" —— 不行。
 */
export const READONLY_META_VERBS = ['test-path', 'get-item', 'stat', 'file']

/**
 * 🔴 内容读取 / 枚举动词黑名单（小写）。
 *
 * 这条表**不看它落在哪一段**：整条命令行里任何位置出现一个，白名单立刻失效。
 * 理由：`Get-Item htb-wp/x | Get-Content` 里真正读内容的那一段**不带 WP 路径**，
 * 只看"引用 WP 的那一段"必然漏掉 —— 白名单会被当成掩护。宁可过拦。
 */
export const CONTENT_READ_VERBS = [
  // 内容读取
  'cat', 'type', 'get-content', 'gc', 'read', 'head', 'tail', 'less', 'more',
  'grep', 'rg', 'select-string', 'sls', 'findstr', 'awk', 'sed', 'strings',
  'xxd', 'od', 'hexdump', 'base64', 'certutil', 'tee', 'out-file',
  'set-content', 'add-content', 'tee-object',
  // 目录枚举
  'ls', 'dir', 'get-childitem', 'gci', 'find', 'tree',
  // 搬运（把语料复制出去等价于读）
  'cp', 'copy', 'move', 'mv', 'scp', 'curl', 'wget', 'tar', 'zip',
]

/** 允许出现在白名单动词之前的壳前缀（`sudo stat …` 与 `stat …` 同义）。 */
const VERB_PREFIXES = ['&', 'sudo', 'command', 'env', 'exec']

/** 白名单动词匹配器（词边界：`cat` 不匹配 `htb-wp/cat.txt`）。 */
const CONTENT_READ_RE = new RegExp(
  `(?:^|[^A-Za-z0-9_.-])(?:${CONTENT_READ_VERBS.map((v) => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})(?![A-Za-z0-9_.-])`,
  'i',
)

/**
 * 把命令切成"段"：`;` `\n` `|` `||` `&&`。白名单按段判定。
 * @param command - 命令文本。
 * @returns 段数组。
 */
function segmentsOf(command) {
  return String(command).split(/(?:&&|\|\||[;\n|])/)
}

/**
 * 取一个 token 的"命令词"：去掉引用符、取路径基名、去 `.exe`、转小写。
 * @param token - 命令行里的一个词。
 * @returns 规范化后的命令词。
 */
export function verbOf(token) {
  const stripped = String(token).replace(/^[&"'(]+/, '').replace(/["'),]+$/, '')
  const base = stripped.split(/[\\/]/).pop() ?? ''
  return base.replace(/\.exe$/i, '').toLowerCase()
}

/**
 * 命令里是否出现内容读取 / 枚举动词（**整条命令行**扫描，不看段）。
 * @param command - 命令文本。
 * @returns 出现则为 true。
 */
export function hasContentReadVerb(command) {
  if (typeof command !== 'string' || !command) return false
  return CONTENT_READ_RE.test(command)
}

/**
 * 单独一段是否是"对着 WP 的只读元数据动作"。
 *
 * 三个条件同时成立才为真：段内引用了 WP、命令词在白名单里、段内没有
 * `|`/`>`/通配符。后两条都是"白名单动作被改写成别的动作"的入口：
 *   - `|`/`>`：`Get-Item x > copy.txt` 不再是"看一眼属性"；
 *   - `*`/`?`：PowerShell 的 `Get-Item htb-wp\txt\*` 在通配符下**退化成枚举**
 *     （等于 `Get-ChildItem`），正是本白名单要挡的"暴露有没有 writeup"。
 * @param segment - 一段命令。
 * @param dirname - 受保护的目录名。
 * @returns 是则 true。
 */
export function isReadonlyMetaSegment(segment, dirname = DEFAULT_WP_DIRNAME) {
  if (typeof segment !== 'string' || !referencesWp(segment, dirname)) return false
  if (/[>|*?]/.test(segment)) return false
  const tokens = segment.trim().split(/\s+/).filter(Boolean)
  while (tokens.length && VERB_PREFIXES.includes(verbOf(tokens[0]))) tokens.shift()
  if (!tokens.length) return false
  return READONLY_META_VERBS.includes(verbOf(tokens[0]))
}

/**
 * 整条命令是否落在只读元数据白名单里（放行 = true）。
 *
 * 两个条件**同时**成立：①整条命令没有内容读取/枚举动词；
 * ②所有引用了 WP 的段都是白名单动作。任何一段不是 ⇒ 不放行。
 * @param command - 命令文本。
 * @param dirname - 受保护的目录名。
 * @returns 可放行则为 true。
 */
export function isReadonlyMetaCommand(command, dirname = DEFAULT_WP_DIRNAME) {
  if (typeof command !== 'string' || !referencesWp(command, dirname)) return false
  if (hasContentReadVerb(command)) return false
  const wpSegments = segmentsOf(command).filter((s) => referencesWp(s, dirname))
  if (!wpSegments.length) return false
  return wpSegments.every((s) => isReadonlyMetaSegment(s, dirname))
}

/**
 * 取命令型工具的入参文本。命令型工具的入参一律叫 `command`（同 guard.js）。
 * @param exec - 待分发的工具调用。
 * @returns 命令文本；取不到时返回空串。
 */
export function commandOf(exec) {
  const command = exec?.arguments?.command
  return typeof command === 'string' ? command : ''
}

/**
 * 取一个调用里"可能指向文件"的字符串参数。
 *
 * 按工具取不同字段，而不是无脑扫全部字符串 —— 对 `grep` 来说 `pattern` 是
 * **搜索用的正则**，扫它会把 `grep -e "htb-wp" loot/notes.md` 这种正当检索拦掉。
 * @param exec - 待分发的工具调用。
 * @param toolName - 工具名。
 * @returns 待检文本数组。
 */
export function pathTextsOf(exec, toolName) {
  const args = exec?.arguments
  if (!args || typeof args !== 'object') return []
  const pick = (key) => (typeof args[key] === 'string' ? args[key] : undefined)
  if (toolName === 'read') {
    return [pick('file_path')].filter(Boolean)
  }
  if (toolName === 'glob') {
    // glob 的 `pattern` 也能直接指向 WP（`htb-wp/**`），所以两个都看。
    return [pick('path'), pick('pattern')].filter(Boolean)
  }
  if (toolName === 'grep') {
    // 只看 `path`：`pattern` 是检索正则，不是目标路径。
    return [pick('path')].filter(Boolean)
  }
  return []
}

/**
 * 对一次调用求判定结果。
 *
 * 命中判定与解锁判定**分开**：本函数只看"这次调用是否指向 WP"，不看是否解锁。
 * 解锁在 {@link apply} 里判，这样纯函数部分可以独立测试。
 * @param exec - 待分发的工具调用。
 * @param cfg - `{ tools?, dirname? }`。
 * @returns 命中信息 `{ id, reason, detail }`；未命中返回 undefined。
 */
export function checkWpAccess(exec, cfg = {}) {
  const dirname = cfg.dirname ?? DEFAULT_WP_DIRNAME
  const guarded = new Set(cfg.tools ?? GUARDED_TOOLS)
  const toolName = exec?.name
  if (!toolName || !guarded.has(toolName)) return undefined

  if (PATH_TOOLS.includes(toolName)) {
    for (const text of pathTextsOf(exec, toolName)) {
      if (referencesWp(text, dirname)) {
        return { id: 'wp-read', reason: `${toolName} 的目标路径落在 ${dirname}/ 内`, detail: text }
      }
    }
    return undefined
  }

  const command = commandOf(exec)
  if (!command) return undefined
  // 🔴 2026-09-30 起**刻意不认** `HTB_GUARD_ALLOW=1` 前缀（原实现与 guard.js 共用那个逃生口）。
  //    理由：红线守卫的逃生口语义是"确属任务要求、且已确认靶机可重置"的危险操作；
  //    而本守卫要挡的是"看答案"，D1 的设计是**让用户动一次手**（创建 ~/.dsh/htb-wp-unlock）。
  //    共用前缀等于给模型留了一个自己就能开的旁路 —— 前缀是模型自己写进命令里的，
  //    于是"用户解锁"退化成"模型声明一下"，D1 的保证归零。解锁通道只保留标记文件。
  if (referencesWp(command, dirname)) {
    // 🔓 只读元数据白名单（2026-10-01）：`Test-Path htb-wp/txt` 这类"存在性/属性"
    //    检查放行 —— 拒它只会把模型逼去拼接路径绕开守卫（审计实测），
    //    与 persona 第 9 条"不要想办法绕"自相矛盾。内容读取与目录枚举照拦。
    if (isReadonlyMetaCommand(command, dirname)) return undefined
    return { id: 'wp-shell', reason: `命令里引用了 ${dirname}/`, detail: command }
  }
  return undefined
}

/**
 * 组装给模型看的拒绝理由。
 *
 * 理由必须自带**正向替代动作**和**解锁办法** —— 只说"不行"会让模型换个姿势再试，
 * 那正是要避免的循环。
 * @param hit - {@link checkWpAccess} 的结果。
 * @param cfg - `{ dirname?, unlockPath? }`。
 * @returns 拒绝理由文本。
 */
export function denyReason(hit, cfg = {}) {
  const dirname = cfg.dirname ?? DEFAULT_WP_DIRNAME
  const unlockPath = cfg.unlockPath ?? DEFAULT_UNLOCK_PATH
  return [
    `官方 WP 读取被拒 [${hit.id}]：打靶会话不读官方 writeup（${hit.reason}）。`,
    'ReaperTwo 实测：旧会话 8.6 小时没拿到 root，新会话 31 分钟拿到 —— 但那是靠读这份 WP 才做到的。你在备考 OSCP，读它对你**是负收益**：拿到 flag 的同时把练习价值清零。',
    '改成这样：回到自主排查 —— 写出当前假设 → 列 ≥3 条还没试的路径 → 每条估时 → 挑最短的先做。',
    '（只读的"存在性/属性"核对**本来就不必绕**：`Test-Path` / `Get-Item` / `stat` / `file` 直接放行；被拒的是**内容读取**与**目录枚举**。）',
    `（复盘 / 语料整理确实要读时，由**用户**创建解锁标记：\`New-Item -ItemType File "${unlockPath}"\`，用完删除。）`,
  ].join('\n')
}

/**
 * 挂载 WP 守卫。
 *
 * Config:
 *   - `tools`（默认 {@link GUARDED_TOOLS}）：要守卫的工具名列表。
 *   - `dirname`（默认 {@link DEFAULT_WP_DIRNAME}）：受保护的目录名。
 *   - `unlockPath`（默认 {@link DEFAULT_UNLOCK_PATH}）：解锁标记文件；传 `null`
 *     表示不提供解锁通道（永远拦）。
 *   - `unlocked`（默认 undefined）：强制解锁/锁定，供测试与临时放行用。
 * @param ctx - 带 `tools` 的宿主插件上下文。
 * @param config - 见上。
 */
export function apply(ctx, config) {
  const cfg = config ?? {}
  const lockCfg = { tools: cfg.tools ?? GUARDED_TOOLS, dirname: cfg.dirname ?? DEFAULT_WP_DIRNAME }
  const unlockPath = cfg.unlockPath === undefined ? DEFAULT_UNLOCK_PATH : cfg.unlockPath

  ctx.tools.guard((exec) => {
    try {
      const unlocked = typeof cfg.unlocked === 'boolean'
        ? cfg.unlocked
        : Boolean(unlockPath) && existsSync(unlockPath)
      if (unlocked) return undefined
      const hit = checkWpAccess(exec, lockCfg)
      return hit ? denyReason(hit, { dirname: lockCfg.dirname, unlockPath }) : undefined
    } catch {
      // fail-open：守卫坏了不能把读文件的能力整个锁死。
      return undefined
    }
  })
}
