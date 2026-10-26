/**
 * dsh-htb-skills/guard — 操作安全红线守卫（ToolGuard）。
 *
 * 把 `command-safety-red-lines` 卡里「一次就能造成事故」的命令从"提示词里的
 * 一句叮嘱"变成"工具层的硬拦截"：命中即拒绝，拒绝理由直接回到模型。
 *
 * 设计边界（重要，别把它当安全边界用）：
 *   - 它拦的是**命令文本**。`write` 一个含 pkill -f 的脚本、再 `bash script.sh`
 *     是绕得过去的。它挡的是"当场手打"这条路 —— 而事故正是这么发生的。
 *   - 只在**误报代价低、漏报代价灾难性**的模式上 deny。宁可少拦，不可乱拦。
 *   - 危险动词落在引号字面量里就放行（见 {@link checkCommand}），否则
 *     `echo "dd ..."`、`grep -rn "mount /dev/loop"` 这类纯文本会天天误伤。
 *   - 守卫自身抛错时放行（fail-open）：一个坏掉的守卫若 fail-closed，会锁死
 *     所有 shell 命令，比它要防的风险更糟。
 *
 * 未覆盖（刻意）：卡片 §2 多行 heredoc。该风险的前提是 PTY；本 harness 的
 * pwsh/bash 工具每次调用都是独立进程，不存在这个死锁。卡片是通用的，代码要
 * 按本 harness 的具体工具形态裁剪。
 *
 * 规则表可外置：见 {@link DEFAULT_RULES_PATH}。改规则存盘即生效，不用重启
 * dsh web —— 插件 JS 改动必须重启（ESM 缓存），规则文件不必。
 */

import { readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/** Stable Cordis plugin name. */
export const name = 'htb-guard'

/** 依赖工具注册表。 */
export const inject = ['tools']

/** 默认被守卫的命令型工具。 */
export const SHELL_TOOLS = ['pwsh', 'bash', 'ssh_exec', 'ssh_cluster']

/**
 * 显式放行前缀。规则分两类：
 *   - 对自己会话/工具链的伤害（pkill -f、mount /dev/loop…）：永远有正确改写，
 *     直接 deny。
 *   - 对靶机的合法但不可逆操作（mkfs 块设备、dd 写裸设备）：真的可能是任务要求。
 *     这类不该被硬堵死，所以给一个**必须刻意写出来**的逃生口 —— 命令以
 *     `HTB_GUARD_ALLOW=1 ` 开头即放行。
 * 逃生口存在的意义是：让"我知道我在干什么"变成一个动作，而不是一句心里话。
 */
export const OVERRIDE_PREFIX = 'HTB_GUARD_ALLOW=1'

/**
 * 规则文件的默认位置。文件不存在时零开销地回落到内置表。
 *
 * 语义（合并，不是替换）：内置表是基线，文件按 `id` 覆盖或追加。
 *   { "rules": [
 *       { "id": "pkill-f", "re": "...", "flags": "i", "why": "...", "fix": "..." },
 *       { "id": "killall-generic", "enabled": false }
 *   ] }
 * 用 `node scripts/guard-rules-init.mjs` 可以把当前内置表导出成这个格式。
 *
 * 🔴 这个文件是可写的 —— 也就是说守卫能被它自己关掉。它本来就不是安全边界
 *    （`write` 一个脚本再跑同样绕得过去），这是换取"免重启迭代"的代价。
 */
export const DEFAULT_RULES_PATH = join(homedir(), '.dsh', 'htb-guard-rules.json')

/**
 * 规则表。每条：id（测试/日志用）、re（匹配整条命令文本）、
 * why（为什么危险）、fix（怎么改写 —— 拒绝理由里带上正向替代）。
 *
 * 🔴 参数扫描一律用 `[^\n;|&]*?` 而**不是** `[^\n]*?`：必须止步于命令分隔符。
 *    否则 `pkill -x ffuf; …; cp -f a b` 会因为**后面**那条 `cp -f` 被误判成
 *    `pkill -f` —— 2026-09-27 Layover 会话（session-2bfe46ca）实测误拦，而被拦的
 *    `pkill -x` 恰恰就是本表 fix 里推荐的写法。六条规则统一这个口径。
 */
export const RED_LINES = [
  {
    id: 'pkill-f',
    // `--full` 是 `-f` 的长选项，等价危险，必须一起认。
    // 🔴 2026-10-10 加固（独立交审计）：原式只认字面的 `-f`/`--full`，于是
    //    `pkill -ef ffuf`（getopt 聚集）与 `pkill --fu ffuf`（长选项缩写）都漏了。
    re: /\bpkill\b[^\n;|&]*?\s(?:--f[a-zA-Z]*\b|-[a-zA-Z]*f[a-zA-Z]*\b)/,
    why: 'pkill -f 的模式会匹配到「执行这条 pkill 的 shell 自己的命令行」，把承载它的会话一起杀掉。',
    fix: '按端口取 PID：`lsof -ti tcp:8000 | xargs -r kill -9`，或 `ss -lntpH "sport = :8000"` 取 pid=；要锚定就用 `pgrep -f \'^完整命令$\' | xargs -r kill -9`。',
  },
  {
    id: 'killall-generic',
    re: /\bkillall\b[^\n;|&]*?\b(python3?|node|bash|sh|zsh|ruby|perl|nc|ncat|socat)\b/,
    why: 'killall 按进程名杀，会连带杀掉你自己和其他辅助脚本。',
    fix: '同样按端口或精确 PID 定位后再 kill。',
  },
  {
    id: 'killall-sweep',
    // 🔴 2026-10-10 新增：`killall5`（等价于杀全系统）与 `killall -r/--regexp`
    //    （正则模式，`killall -r .` 即杀一切）原本一条规则都不覆盖。
    //
    // 🔴 本轮收窄（依据 loot/_audit/J3-getopt.md §2.3 / §3 / §4，远端 Kali 实测 +
    //    `man 8 killall5`）：裸 `killall5` 是**程序名锚点**，而 normalizeCommand 会把
    //    "只包一个词"的引号剥掉（`"killall5"` → `killall5`），于是 `man killall5`、
    //    `grep -rn killall5 x`、`echo "killall5"` 这类**纯文本**全被误拦
    //    （J3 自己在取证时被这条规则拦了 2 次）。对照实测：`echo "killall5"` BLOCK、
    //    `echo "killall5 kills every process"` ALLOW（含空白的引号内容才受保护）。
    //    修法：`killall5` 分支收窄为「**不在只读动词的参数位**」——
    //      · 命令位（行首 / `;` `&` `|` 之后 / `sudo` 之后）照拦；
    //      · 解释器执行（`bash -c "killall5 -9"`）照拦 —— 它不在命令位，靠的正是
    //        checkCommand 的 viaInterpreter 那条口径；
    //      · 管道交给 shell（`echo "killall5 -9" | sh`）照拦，与 guard-test.mjs
    //        里 `echo "dd if=x of=/dev/sda" | sh` 同源（判据：文本被解释器执行）。
    //    ⚠️ 刻意**不**采用「命令位正向匹配」那种写法（`(?:^\s*|[;&|]\s*|\bsudo\s+)…`）：
    //       实测推演它会漏掉 `bash -c "killall5 -9"` —— 引号把命令位吃掉了，
    //       而裸 `killall5` 又在引号里，正向式一条都匹配不上 ⇒ 真绕过。
    //       负向豁免式（本式）只在「只读动词同段且在其前」时豁免，代价更小。
    //    只读动词表 = 只输出数据的命令；`find`（-exec）、`rg`（--pre）、`sed`/`awk`
    //    （可执行）、编辑器（`:!`）这类**能借参数执行**的一律不收，宁可少豁免。
    re: /(?:(?<!\b(?:man|grep|egrep|fgrep|zgrep|echo|printf|ls|cat|less|more|head|tail|od|xxd|wc|file|stat|strings|dpkg|dpkg-query|apt-cache|which|type|whatis|apropos)\b[^\n;|&]*)|(?=[^\n;|&]*\|\s*(?:sh|bash|zsh|dash|ksh)\b))\bkillall5\b|\bkillall\b[^\n;|&]*?\s(?:-r\b|--regexp\b)/,
    // 🔴 文案两处纠正（J3 §2.3、§4，依据 `man 8 killall5` 原文）：
    //    1. 旧文案写「包括承载本次会话的那条链」——**与自家 man page 矛盾**。man 原文：
    //       it sends a signal to all processes *except kernel threads and the
    //       processes in its own session*, so it won't kill the shell that is
    //       running the script it was called from。即它**排除本会话**，通常不是
    //       立刻杀掉你这条 shell，而是杀掉本会话之外的一切（含 sshd 等）⇒ 靶机被打挂。
    //    2. `killall -r` 的危害**取决于 pattern**：`.` 是 ERE 任意单字符，进程名恒
    //       ≥1 字符 ⇒ 杀一切；但锚定的 `-r '^ffuf$'` 只杀精确匹配者。
    //       按 J3 建议**保留拦截**（正则杀属灾难档，正确改写是 `pkill -x ffuf`），
    //       只改文案，**不加**"锚定就放行"的例外（解释锚定语义会放大绕过面）。
    why: 'killall5 向「除内核线程与它自己所在会话之外」的所有进程发信号（man 8 killall5）—— 它排除本会话，所以通常**不是**立刻杀掉你这条 shell，而是杀掉本会话之外的一切（含 sshd 等），靶机等于被打挂。killall -r 把 NAME 当扩展正则，危害取决于你给的 pattern：`killall -r .` 里的 `.` 匹配任意单字符 ⇒ 等于杀一切。',
    fix: '按端口或精确 PID 定位后再 kill：`lsof -ti tcp:8000 | xargs -r kill -9`；要按名字杀单个目标用精确匹配 `pkill -x ffuf`（不要在 killall 上用 -r 赌 pattern）。',
  },
  {
    id: 'mount-loop',
    re: /\bmount\b[^\n;|&]*?\/dev\/loop/,
    why: '对已挂载的文件系统造第二个 superblock 会触发 journal 错误，内核按 errors=remount-ro 把设备置为只读 —— Reddish 就是这么把整台靶机打废的。',
    fix: '只读读宿主文件系统用 `mknod` + `debugfs -R "cat /path"`，不要 mount。',
  },
  {
    id: 'mount-o-loop',
    // 一行版 loop 挂载（`mount -o loop img /mnt`）与 `mount /dev/loopN` 是同一个隐患，
    // 但写法上完全不出现 `/dev/loop`，所以 mount-loop 那条抓不到。2026-09-30 实测补漏。
    // 🔴 只认 `-o` 后面的 `loop` 选项本身，不认路径里恰好含 "loop" 的字（如 /var/loopdata）。
    // 🔴 2026-10-10 加固：长选项写法 `--options loop` / `--opt loop` 原本漏。
    // 🔴 本轮收窄（依据 loot/_audit/J3-getopt.md §2.2、§4）：**删掉 `--opt`**。
    //    远端 Kali（util-linux 2.42.2）纯解析实测：`getopt -o o: -l <mount 真实 44 项
    //    长选项> -- --opt loop` → rc=1，`option '--opt' is ambiguous; possibilities:
    //    '--options' '--options-mode' '--options-source' '--options-source-force'`
    //    ⇒ `mount` 拿到的只是 `'?'`，打印用法后退出，**走不到 mount(2)** ⇒
    //    `mount --opt loop img /mnt` 永远不可能是有效挂载 —— 这条分支是**死分支**。
    //    保留的 `--options loop` ≡ `-o loop`：同一实测 → ` --options -- 'loop'`（rc=0）。
    // ⚠️ 边界（J3 §5.2）：这条收窄依赖该版本的长选项表；若某系统的 mount 缺
    //    --options-mode/source/source-force，`--opt` 会重新变成合法缩写。
    re: /\bmount\b[^\n;|&]*?\s(?:-o|--options)\s*[^\s;|&]*\bloop\b/,
    why: '与 `mount /dev/loop0` 同类：会给已挂载的文件系统再建一个 superblock，触发 journal 错误 → 宿主只读 → 整台靶机报废。',
    fix: '同 mount-loop：用 `mknod` + `debugfs -R "cat /path"` 只读读；确实要挂镜像就先确认靶机可以重置。',
  },
  {
    id: 'losetup',
    // 🔴 这是 Reddish 事故的**第一步**：losetup 先把镜像挂成 loop 设备，随后 mount 才建出
    //    第二个 superblock。原守卫只覆盖了 mount 那一半（见 command-safety-red-lines §6）。
    // 放行纯列举用法（`losetup -a` / `-l` / `--list` / `--help`）—— 看现状是排查手段，不该拦。
    // 其余用法（attach 到 /dev/loopN、`-f` 自动挑设备、`-d` 拆卸在用设备）一律拦。
    re: /\blosetup\b(?![^\n;|&]*\s(?:-a|-l|--list|--help|-h)\b)/,
    why: 'losetup 把文件挂成 loop 设备，配合 mount 就是 Reddish 那次把宿主打成只读的第一步（errors=remount-ro，三个容器 overlay 全部不可写）。',
    fix: '要读宿主文件系统内容：`mknod` + `debugfs -R "cat /path"`（纯用户态只读）。只想知道现有 loop 关联：`losetup -a`（这条放行）。',
  },
  {
    id: 'mkfs',
    // 只拦「格式化块设备」。`mkfs --help` 或格式化自己造的镜像文件是安全的。
    // （引号写法 `mkfs.ext4 "/dev/sda"` 由 normalizeCommand 的单词去引号吃掉。）
    re: /\bmkfs(\.\w+)?\b[^\n;|&]*?\s\/dev\//,
    why: '格式化块设备不可逆。',
    fix: '确认这真的是任务要求，并先确认靶机可以重置。',
  },
  {
    id: 'dd-raw-device',
    // 🔴 2026-10-10 加固（独立交审计）：原式把设备名写成白名单
    //    （sd|nvme|vd|loop|mmcblk），于是 `of=/dev/hda`、`of=/dev/dm-0`、
    //    `of=/dev/mapper/vg-lv` 全漏。改为**反向白名单**：除已知无害设备外一律拦。
    re: /\bdd\b[^\n;|&]*?\bof=\/dev\/(?!(?:null|zero|stdout|stderr|random|urandom|tty|full)\b)\S/,
    why: '直接写裸设备会覆盖分区表或文件系统，不可逆。',
    fix: '写到普通文件里；真要写设备，先确认靶机可以重置。',
  },
  {
    id: 'rm-rf-root',
    // 两种参数顺序都要认（-rf / -fr），路径两侧允许带引号（rm -rf "/"）。
    // 🔴 2026-09-30 补漏：路径后面必须允许再跟 `/`、`/*`、`*` —— 原来的 `(?:\s|$)`
    //    要求路径后立刻是空白或结尾，于是 `rm -rf /*`（经典删根）和 `rm -rf ~/`
    //    都从缝里漏了过去。
    // 🔴 2026-10-10 加固（独立交审计）：原式还要求 r 与 f **同簇**，于是
    //    `rm -r -f /`、`rm -rf -- /`、`rm --recursive --force /`、
    //    `rm -rf --no-preserve-root /` 全漏。改用两个前瞻 —— 只要「本次调用里
    //    同时出现递归选项与 force 选项」即可，与顺序、是否同簇、是否夹 `--` 无关。
    re: /\brm\b(?=[^\n;|&]*?(?:\s-[a-zA-Z]*r[a-zA-Z]*\b|\s--recursive\b))(?=[^\n;|&]*?(?:\s-[a-zA-Z]*f[a-zA-Z]*\b|\s--force\b))[^\n;|&]*?\s+['"]?(?:\/|\$HOME|\$\{HOME\}|~)['"]?(?:\/\*|\/|\*)?(?:\s|$)/,
    why: '递归删除根目录或家目录，不可逆。',
    fix: '把路径限定到具体目录。',
  },
  {
    id: 'ps-remove-recurse-root',
    // 🔴 2026-10-10 新增（独立交审计）：内置表原本**全是 bash 语义**，而 `pwsh`
    //    就在 SHELL_TOOLS 里。本机是 Windows —— PowerShell 毁盘是最现实的路径，
    //    却零覆盖（`Remove-Item -Recurse -Force C:\` 实测放行）。
    //    刻意只锚「盘根 / 系统盘环境变量」，不吃普通子目录，避免误伤
    //    `Remove-Item -Recurse -Force .\loot\<machine>`。
    re: /\b(?:Remove-Item|ri|rd|rmdir|rm)\b[^\n;|&]*?\s-(?:Recurse|r)\b[^\n;|&]*?\s['"]?(?:[A-Za-z]:[\\/]\*?|\$env:(?:SystemDrive|SystemRoot|windir))['"]?(?:\s|$)/i,
    why: '递归删除盘根或系统目录（PowerShell 语义），不可逆，且会连宿主数据一起毁掉。',
    fix: '把路径限定到具体目录，例如 `Remove-Item -Recurse -Force .\\loot\\<machine>`。',
  },
  {
    id: 'ps-format-volume',
    // 🔴 2026-10-10 新增：磁盘级 cmdlet 的**任何**用法都是破坏性的（没有"看现状"的用法）。
    re: /\b(?:Clear-Disk|Format-Volume|Initialize-Disk|Remove-Partition)\b/i,
    why: '磁盘级破坏操作，会清掉整块盘（含宿主数据），不可逆。',
    fix: '确认真的是任务要求，并先确认宿主机/靶机可以重建；不确定就停下来问。',
  },
  {
    id: 'cmd-del-tree',
    // 🔴 2026-10-10 新增：cmd.exe 的 `del /s` / `rd /s` 递归删树，同样零覆盖。
    re: /\b(?:del|rd|rmdir)\b[^\n;|&]*?\s\/s\b[^\n;|&]*?\s['"]?[A-Za-z]:[\\/]/i,
    why: '`del /s`、`rd /s` 递归删除整个目录树，不可逆。',
    fix: '把路径限定到具体目录，或改用可复核的显式文件列表。',
  },
]

/**
 * 已解析规则文件的缓存：path -> { mtimeMs, entries }。
 * 按 mtime 失效，所以存盘即生效；解析失败也缓存，避免每次调用都重啃坏文件。
 */
const fileCache = new Map()

/**
 * 把一条文件规则编译成内置表的形状。id 或 re 不合法、正则编译失败都返回
 * undefined —— 调用方据此跳过这一条，**保留内置版本**，而不是把守卫删掉。
 * @param raw - 文件里的一条规则。
 * @returns 编译后的规则；不合法返回 undefined。
 */
function compileRule(raw) {
  if (!raw || typeof raw.id !== 'string' || !raw.id) return undefined
  if (typeof raw.re !== 'string' || !raw.re) return undefined
  try {
    return {
      id: raw.id,
      re: new RegExp(raw.re, typeof raw.flags === 'string' ? raw.flags : ''),
      why: typeof raw.why === 'string' ? raw.why : '',
      fix: typeof raw.fix === 'string' ? raw.fix : '',
      // 见 checkCommand：true = 这条规则**刻意不受引号豁免**。
      raw: raw.raw === true,
    }
  } catch {
    return undefined
  }
}

/**
 * 读取并解析规则文件。
 * @param path - 规则文件路径。
 * @returns 规则数组；文件缺失、读不动或 JSON 不合法时返回 undefined。
 */
function loadFileRules(path) {
  let mtimeMs
  try {
    mtimeMs = statSync(path).mtimeMs
  } catch {
    return undefined
  }
  const cached = fileCache.get(path)
  if (cached && cached.mtimeMs === mtimeMs) return cached.entries

  let entries
  try {
    const raw = JSON.parse(readFileSync(path, 'utf8'))
    entries = Array.isArray(raw?.rules) ? raw.rules : undefined
  } catch {
    entries = undefined
  }
  fileCache.set(path, { mtimeMs, entries })
  return entries
}

/**
 * 求当前生效的规则表 = 内置表 ⊕ 规则文件。
 *
 * 任何异常（文件坏了、某条正则编译不过）都只影响那一条，整体回落到内置表，
 * 绝不返回空表 —— 空表等于守卫静默失效。
 * @param path - 规则文件路径；省略则用 {@link DEFAULT_RULES_PATH}。
 * @returns 生效的规则数组。
 */
/**
 * `activeRules` 的结果缓存：`path → { entries, rules }`。
 *
 * 为什么需要（2026-10-26 实测）：本函数在**每次工具调用**都被 `apply` 里的
 * guard 调用一次，而它每次都重建 `Map(RED_LINES)`、逐条 `compileRule`
 * （= `new RegExp`）、再 filter+concat。18 条规则下这部分实测约 0.05 ms/次，
 * 全是重复劳动 —— 规则文件没变时结果必然相同。
 *
 * 失效判据用 `entries` 的**引用相等**：`loadFileRules` 已按 mtime 缓存，
 * 文件不变则返回同一个数组；文件改了 mtime 变、重新解析出新数组，引用不等 ⇒ 重建。
 */
const activeCache = new Map()

export function activeRules(path = DEFAULT_RULES_PATH) {
  const entries = path ? loadFileRules(path) : undefined
  const cached = activeCache.get(path)
  if (cached !== undefined && cached.entries === entries) return cached.rules

  let rules
  if (!entries) {
    rules = RED_LINES
  } else {
    const byId = new Map(RED_LINES.map(rule => [rule.id, rule]))
    const disabled = new Set()
    const appended = []
    for (const raw of entries) {
      if (!raw || typeof raw.id !== 'string') continue
      if (raw.enabled === false) { disabled.add(raw.id); continue }
      const compiled = compileRule(raw)
      if (!compiled) continue
      if (byId.has(compiled.id)) byId.set(compiled.id, compiled)
      else appended.push(compiled)
    }
    rules = [...byId.values()].filter(rule => !disabled.has(rule.id)).concat(appended)
  }
  activeCache.set(path, { entries, rules })
  return rules
}

/**
 * 取出待检命令文本。命令型工具的入参一律叫 `command`。
 * @param exec - 待分发的工具调用。
 * @returns 命令文本；取不到时返回空串。
 */
export function commandOf(exec) {
  const args = exec?.arguments
  if (!args || typeof args !== 'object') return ''
  const command = args.command
  return typeof command === 'string' ? command : ''
}

/**
 * 扫出所有引号字面量的 [start, end) 区间。支持单/双引号与反斜杠转义；
 * 未闭合的引号一直延伸到命令结尾。
 * @param command - 命令文本。
 * @returns 区间数组。
 */
export function quotedSpans(command) {
  const spans = []
  let quote = null
  let start = -1
  for (let i = 0; i < command.length; i += 1) {
    const ch = command[i]
    if (quote) {
      if (ch === '\\') { i += 1; continue }
      if (ch === quote) { spans.push([start, i + 1]); quote = null }
      continue
    }
    if (ch === '"' || ch === "'") { quote = ch; start = i }
  }
  if (quote) spans.push([start, command.length])
  return spans
}

/**
 * 位置 index 是否落在某个引号字面量内。
 * @param spans - {@link quotedSpans} 的结果。
 * @param index - 待判定位置。
 * @returns 落在引号内为 true。
 */
export function isQuoted(spans, index) {
  return spans.some(([s, e]) => index >= s && index < e)
}

/**
 * 整个匹配区间是否落在**同一个**引号字面量内。
 *
 * 🔴 2026-10-10 加固（独立交审计）：原来只看匹配的**起点**是否在引号内，于是
 *    `"rm" -rf /` 这种「动词加引号、参数在引号外」的写法被整体豁免 —— 而引号
 *    在 shell 里只是词引用，命令照跑。改为要求锚点**整段**在引号内。
 * @param spans - {@link quotedSpans} 的结果。
 * @param start - 匹配起点。
 * @param end - 匹配终点（不含）。
 * @returns 整段都在引号内为 true。
 */
export function fullyQuoted(spans, start, end) {
  return spans.some(([s, e]) => start >= s && end <= e)
}

/**
 * 归一化命令文本，把等价写法压成同一种形态。
 *
 * 🔴 2026-10-10 加固（独立交审计）：原引擎直接对原文匹配，于是「给动词加引号」
 *    成了**通用绕过** —— `"rm" -rf /`、`"dd" if=/dev/zero of=/dev/sda`、
 *    `mkfs.ext4 "/dev/sda"`、`dd of="/dev/sda"` 全部漏过。做两件事：
 *
 *    1. 拼掉 `\` + 换行的续行；
 *    2. 去掉**只包住单个词**的引号（`"rm"` → `rm`、`of="/dev/sda"` → `of=/dev/sda`）。
 *       含空白的引号内容**保留** —— 那才是 `echo "dd ..."` 这类真正要豁免的文本。
 *
 * 归一化在匹配**之前**做，所以引号区间也在归一化后的文本上计算。
 * @param command - 原始命令文本。
 * @returns 归一化后的文本。
 */
export function normalizeCommand(command) {
  if (typeof command !== 'string' || !command) return ''
  return command
    .replace(/\\\r?\n/g, ' ')
    .replace(/(['"])([^\s'"]+)\1/g, '$2')
}

/**
 * 是否带显式放行前缀。
 *
 * 🔴 2026-10-10 修：原来用 `startsWith(OVERRIDE_PREFIX)`，**没有词边界**，于是
 *    `HTB_GUARD_ALLOW=1evil; rm -rf /`、`HTB_GUARD_ALLOW=10 dd if=/dev/zero of=/dev/sda`
 *    都被当成"显式放行"。现在要求前缀后**紧跟空白或行尾**。
 *    刻意**不接受 `;`**：`HTB_GUARD_ALLOW=1; rm -rf /` 里那个赋值是条空语句，
 *    放行它等于给了一个"看起来声明了、其实没声明"的绕过。
 * @param command - 命令文本。
 * @returns 带前缀为 true。
 */
export function isOverridden(command) {
  if (typeof command !== 'string') return false
  return OVERRIDE_RE.test(command.trimStart())
}

/** 前缀 + 词边界。见 {@link isOverridden}。 */
const OVERRIDE_RE = new RegExp(`^${OVERRIDE_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?=\\s|$)`)

/**
 * 这条命令是否把字符串交给解释器**执行**。命中时引号里的内容不再是"文本"。
 * `grep -e` 不算 —— 只认解释器名后面的 -c / -e / -Command。
 *
 * 🔴 2026-10-10 扩面（独立交审计实测会**真执行**却放行的构造）：
 *    `bash<<<"…"`（here-string）、`awk 'BEGIN{system("…")}'`、`php -r '…'`、
 *    `lua -e '…'`、PowerShell `$c='…'; & $c`。原式只认 eval/iex/`| bash`/`名 -c|-e`。
 */
const INTERPRETER = /\b(?:eval|iex|Invoke-Expression)\b|\|\s*(?:sh|bash|zsh|pwsh|powershell)\b|\b(?:python3?|perl|ruby|node|sh|bash|zsh|pwsh|powershell|lua)\b[^\n]*\s-(?:c|e|Command)\b|\bphp\b[^\n]*\s-r\b|\b(?:awk|gawk|mawk)\b[^\n]*\bsystem\s*\(|<<<|&\s*\$/i

/**
 * 对一条命令文本求首个命中规则。
 *
 * 判定分两层，压掉"引号里的文本被误伤"这类误报：
 *   - 危险**动词**落在引号内 ⇒ 视为文本，放行。
 *     `echo "dd if=x of=/dev/sda"`、`grep -rn "mount /dev/loop" ./writeups/` 放行。
 *   - 但整条命令若把文本交给解释器执行（`bash -c`、`eval`、`python -c`…），
 *     引号就不再是保护，照拦。
 *   - 只有**路径**被引号包住不算文本：`rm -rf "/"` 的 `rm` 在引号外 ⇒ 照拦。
 *
 * 这是速度档，不是安全边界：`bash<<<"pkill -f x"` 这类刻意构造仍绕得过去。
 * @param command - 命令文本。
 * @param rules - 生效规则表；省略则用内置 {@link RED_LINES}。
 * @returns 命中的规则；未命中或已显式放行时返回 undefined。
 */
export function checkCommand(command, rules = RED_LINES) {
  if (!command) return undefined
  if (isOverridden(command)) return undefined
  // 先归一化再匹配：见 normalizeCommand（吃掉"给动词加引号"这类通用绕过）。
  const normalized = normalizeCommand(command)
  // 再过一遍百分号解码后的形态：`curl http://h/%64elete` 这类 URL 编码绕过
  // （2026-10-10 独立交审计列出）。索引会变，所以引号区间在各自形态上重算。
  const decoded = decodePercent(normalized)
  const variants = decoded === normalized ? [normalized] : [normalized, decoded]
  for (const text of variants) {
    const spans = quotedSpans(text)
    const viaInterpreter = INTERPRETER.test(text)
    for (const rule of rules) {
      // 逐条扫全部匹配：同一条命令里可能既有引号内的假命中、也有引号外的真命中。
      // 🔴 2026-10-26：扫描用的 `g` 版本**按规则惰性缓存**（见 scannerOf）。
      //    原来每次调用都 `new RegExp(rule.re.source, flags)` —— 18 条规则 × 1~2 个
      //    变体 = 每次工具调用 18~36 次正则编译，实测占守卫链 0.116 ms 的绝大部分。
      //    本函数是同步的，单线程内不会有两个扫描同时进行，所以复用 lastIndex 安全；
      //    每次进入前显式归零。
      const scan = scannerOf(rule)
      scan.lastIndex = 0
      let match
      while ((match = scan.exec(text)) !== null) {
        // 🔴 判据是「匹配**整段**落在引号内」，不是「起点落在引号内」（见 fullyQuoted）。
        // 🔴 `rule.raw` 表示这条规则**刻意不受引号豁免**：它的锚点本身就要求
        //    「原始 HTTP 请求行 + 管道给网络客户端」这种形态，引号在这里是载体而非保护。
        if (rule.raw || viaInterpreter || !fullyQuoted(spans, match.index, match.index + match[0].length)) return rule
        if (match.index === scan.lastIndex) scan.lastIndex += 1
      }
    }
  }
  return undefined
}

/**
 * 取某条规则的「全局扫描版」正则（惰性创建 + 复用）。
 *
 * 为什么需要单独一份：`checkCommand` 要 `exec` 循环扫出**全部**匹配，因此需要 `g`；
 * 而规则自带的正则可能是非全局的。原来每次现编译一份，成本在热路径上很显眼。
 *
 * 用 WeakMap 缓存：规则对象被替换（改规则文件后 `activeRules` 返回新对象）时，
 * 旧缓存随对象一起被 GC，不会泄漏，也不需要手动失效。
 * @param rule - 规则对象（含 `re`）。
 * @returns 带 `g` 标志的正则（同一个对象，调用方负责重置 lastIndex）。
 */
const SCANNERS = new WeakMap()
function scannerOf(rule) {
  let scan = SCANNERS.get(rule)
  if (scan === undefined) {
    const flags = rule.re.flags.includes('g') ? rule.re.flags : `${rule.re.flags}g`
    scan = new RegExp(rule.re.source, flags)
    SCANNERS.set(rule, scan)
  }
  return scan
}

/**
 * 百分号解码（只解可打印 ASCII）。
 *
 * 🔴 2026-10-10 新增（独立交审计）：`curl http://h/%64elete` 里 `%64` 就是 `d`，
 *    规则在原文上永远匹配不到。只解 `0x20`–`0x7e`，避免把 `%00` 解成控制字符。
 * @param text - 命令文本。
 * @returns 解码后的文本；没有 `%` 时原样返回。
 */
export function decodePercent(text) {
  if (typeof text !== 'string' || !text.includes('%')) return text
  return text.replace(/%([0-9a-fA-F]{2})/g, (whole, hex) => {
    const code = parseInt(hex, 16)
    return code >= 0x20 && code <= 0x7e ? String.fromCharCode(code) : whole
  })
}

/**
 * 组装给模型看的拒绝理由：说清为什么 + 怎么改写 + 怎么刻意放行。
 * @param rule - 命中的规则。
 * @returns 单条拒绝理由。
 */
export function denyReason(rule) {
  return `操作安全红线 [${rule.id}]：${rule.why}\n改成这样：${rule.fix}`
    + `\n（确属任务要求、且已确认靶机可重置：在命令最前面加 \`${OVERRIDE_PREFIX} \` 重发。）`
}

/**
 * 挂载守卫。
 *
 * Config:
 *   - `tools`（默认 {@link SHELL_TOOLS}）：要守卫的工具名列表。
 *   - `disabledRules`（默认 []）：要关掉的规则 id 列表。
 *   - `rulesPath`（默认 {@link DEFAULT_RULES_PATH}）：外置规则文件；改它存盘即
 *     生效，不必重启。传 `null` 则完全忽略文件，只用内置表。
 * @param ctx - 带 `tools` 的宿主插件上下文。
 * @param config - 见上。
 */
export function apply(ctx, config) {
  const cfg = config ?? {}
  const guarded = new Set(cfg.tools ?? SHELL_TOOLS)
  const disabled = new Set(cfg.disabledRules ?? [])
  const rulesPath = cfg.rulesPath === undefined ? DEFAULT_RULES_PATH : cfg.rulesPath

  ctx.tools.guard((exec) => {
    try {
      if (!guarded.has(exec?.name)) return undefined
      // 规则表在每次调用时求值（内部按 mtime 缓存），所以改文件不用重启。
      const hit = checkCommand(commandOf(exec), activeRules(rulesPath))
      if (!hit || disabled.has(hit.id)) return undefined
      return denyReason(hit)
    } catch {
      // fail-open：守卫坏了也不能锁死工作流。
      return undefined
    }
  })
}
