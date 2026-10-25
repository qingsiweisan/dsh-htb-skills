# dsh-htb-preset

DSH 的 **HTB preset**：一个可在会话里选择的"攻击性操作员模式"。

装在 `~/.dsh/profiles/web/`，通过 `plugin_manager install_bundle` 安装，声明见
[`cordis.patch.yml`](./cordis.patch.yml)。机制那一半在
[`dsh-htb-skills`](file:///C:/Users/Administrator/dsh-htb-skills)（Host 层插件）；
**环境那一半**（把 `dsh-permission-rules` 的 `builtin` / `network` / `enforce` 掰成不打靶
对打）在 [`dsh-htb-tuning`](file:///C:/Users/Administrator/dsh-htb-tuning) —— 少了它，
`approval policy: never` 下规则的 `ask` 会 fail-closed 成拒绝，武器投递与凭据路径全被拦。

## 它做了什么

| 项 | 内容 |
|---|---|
| persona | 10 条规则（分【状态】【说话】【行动】【收尾】四组）+ 四道机制的用法说明 |
| 工具集 | 沿用 `standard`，去掉 planning 组（plan-mode）与 `present` |
| 其余 | 逐字沿用 `standard.patch.yml`（compaction / delegation / web / todo / goal） |

persona 里真正承重的是第 6 条：**卡住不问提示、也不把 writeup 当选项**。它与 DSH
默认人格的"多问澄清"直接冲突——这才是需要独立 preset、而不是再加一张技能卡的核心
理由。

## 从实战里学到的：什么样的 persona 规则才生效

### 失败那轮（2026-09-24，ReaperTwo）

单轮 2.7 小时 / 454 步 / 487 次工具调用，逐条回核命中率：

| 条 | 写法 | 实测 |
|---|---|---|
| 状态外置 | 点名了**具体产物** `loot/<machine>.md` | ✅ 完整生效 |
| 只问用户自有的选择 | 点名了**具体边界** | ⚠️ 大体生效，但有一次把 Official Writeup 当选项发出去了 |
| 侦察丢 subagent | 只说了**偏好**，无触发条件 | ❌ 0 次 subagent，356 次侦察命令全压主上下文 |
| 汇报先说结果 | 只说了**偏好**，无时刻 | ❌ 454 步里 0 条 assistant 文本 |

结论：**规则点名了具体东西就生效，只表达偏好就不生效。** 所以 v2 里每条都补上了
触发条件——产物（第 1 条）、时刻（第 2/3 条）、判断线（第 6/7 条）。

而且第 6 条**已经写明"绝不问提示"却仍被违反**，说明提示词只能降低概率、不能保证。
所以给它配了机制：`dsh-htb-skills/src/ask-guard.js`，与红线守卫共用
`ctx.tools.guard()`，把"writeup / 提示 / payload 细节当选项"的提问直接拒绝，拒绝理由
里带正确做法。语料就是那次真实提问的原样复刻。

另一条因果：**第 6 条失败直接导致了 compaction** —— 356 次侦察命令的原始输出灌满
主上下文，2.3 小时就触发压缩。这不是巧合。

### 🔴 成功那轮（2026-09-25，ReaperTwo 重打）—— 这条最容易被误读

同一个 preset，另开一个新会话，**31 分钟拿到 root**（对比旧会话 8.6 小时没有）。
表面上像是"干净上下文恢复了推理质量"的能力突破。

**不是。那次是读了工作区里的官方 WP 才做到的**（`htb-wp/txt/772_ReaperTwo.txt`）。

必须把这段记下来，因为**两种解读会导出完全相反的结论**：

| 解读 | 会导出 | 对不对 |
|---|---|---|
| "干净上下文让模型能解题了" | 去优化上下文管理、去做 compaction 策略 | ❌ 事实是照抄答案 |
| "模型顺手抓了触手可及的答案" | 把答案从触手可及的地方拿掉 | ✅ 这就是决策 D1 |

顺带一提：当时记下的上下文密度对比是 **0.013（新会话）vs 0.44（旧会话末尾）**，
但那**只说明"新会话的上下文更干净"**，不能推出"能从零解题"——那轮有现成 WP。
（这个"密度"的口径没有留在仓库里，所以别拿它继续做推论。）

## 决策 D1：打靶会话禁读官方 WP（2026-09-25 用户拍板）

选项 A：**打靶会话禁止读 `htb-wp/`，只在复盘时用。** 理由：用户在备考 OSCP，
读 WP 对他是**负收益**——拿到 flag 的同时把练习价值清零。

**实现方式是机制，不是 persona 一句话**（persona 第 9 条只是把规则显性化）：

- 新增 `dsh-htb-skills/src/wp-guard.js`，拦 `read` / `glob` / `grep` 对 `htb-wp/`
  的**显式**引用，以及本地 shell（`pwsh` / `bash`）里引用该路径的命令。
- 拒绝理由自带正向替代动作（回到自主排查流程）与解锁办法。
- **复盘解锁**：存在 `~/.dsh/htb-wp-unlock` 即整条守卫让路，由**用户**创建、用完删除。
  刻意做成"要动一次手"的动作，而不是配置文件里随手能翻的开关。

刻意留下的缺口（写在这里，不留给下一个人踩）：`grep` / `glob` **不传 `path`** 时
放行——那等价于扫整个工作区，拦它会把 loot / notes 的全文检索一起堵死，误报代价高于
漏报。守卫拦的是"顺手 `read` 一下"，而 31 分钟那次正是这么发生的。

## 决策 D3：Struggle 第四、五条信号（产出比 / 失败率）

community 的三条信号（重复 / 停滞 / 预算）都漏掉两种形态，两者都与它正交：

**① 「压根没在动手」→ `output`。** 依据是本项目自己的数据——`session-87cb7419`
跑了 **11.89 小时只发了 8 次工具调用**（≈0.67 次/小时）。对照 ReaperTwo 实测
487 次 / 2.7 小时 ≈180 次/小时，两者差两个数量级。判据：
`工具调用数 / 小时 < 12`（会话满 60 分钟才判）。

**② 「在动手但一直在撞墙」→ `failures`（2026-09-27 新增）。** 由
`dsh-session-insights` 实测驱动：3 会话 / 764 次调用的观测基线是 **2.7%**（21/764），
top 失败工具 `edit` / `web_search` / `ssh_exec` / `pwsh`——其中 **`edit` 正是
Layover 那次 subagent 与主 agent 并发写 loot 撞车**。判据：
`失败数 / 调用数 ≥ 15%`（≥20 次调用才判），取基线的约 5.5 倍，只抓系统性失败。

**两条都刻意只到 checkpoint，不进硬停集合**：它们是五条里最年轻、最没校准的两条，
"该提示还是该停"需要分布数据来定。真出现空想/硬撞时外部产物基本也停了，`stall`
会兜住硬停那条线；这两条当前的价值是**诊断维度**——日志里能一眼区分
"忙但没进展""压根没动手""在动手但一直在撞墙"。

### 同批按数据校准的第三条：`maxHours` 4 → 6

Layover 实测 **3.99 小时拿下双旗，距 4 小时线不到 2 分钟**——4 小时差一点就掐掉
一次**成功**的会话。另一个样本 ReaperTwo 跑了 8.6 小时。一低一高，取 6 作为
"够 Insane 级多跳机把话说完、又不放弃硬界"的折中。

⚠️ `stallMinutes: 45` **仍未校准** —— insights 报告里没有"产物静默间隔"这项指标，
它继续是拍脑袋值。

## 仍未决

- **D2. Struggle 干预模式**：现在是**记录模式**（只写 `~/.dsh/htb-struggle.jsonl`，
  不往会话注入）。开干预需要 `createUserMessage`（`@deepseek-ai/dsh-llm`），与插件
  "不给部署增加包依赖解析面"的取舍冲突。**分布数据现已攒够（2026-09-30，3271 条观测）**：
  `budget` 120 / `stall` 61 / `output` 52 / `failures` 26 / **`repeat` 0** ——
  除 `output` 外都被极少数长会话主导，说明这些信号当前的价值是**诊断维度**而非干预触发器；
  `repeatCalls: 3` 零命中需单独定夺。详见 `htb-mode-handoff.md` §3.D2。
- **D4. 技能目录裁剪**：**已论证不做**，见下。

## 为什么技能目录**没有**裁剪

原本的第 3 步是把技能目录指到 `dsh-htb-skills` 包内的 `skills/`，让非打靶会话
不吃 HTB 卡目录。**2026-09-24 核查后放弃**，2026-09-25 复核数字，**2026-09-30 复算**：

| | 数量 |
|---|---|
| `~/.dsh/skills` | **153** |
| `dsh-htb-skills/skills`（包内） | 117 |
| 只在 `~/.dsh/skills` | **38** |
| 只在包内 | 2 |

差集里包含 `command-safety-red-lines`（开局必载）和 `htb-machine-reset-recovery`。
指到包内会**静默丢掉**这两张——正是 AGENTS.md 里记录过的那类事故（方法论随卡被
移出技能库而丢失）。

而且收益比想象的小：默认模型上下文窗口 1,048,576 token，整份卡目录大约占
0.5–1%。为省这点空间引入一份需要持续同步的副本，不划算。

**将来真要做，唯一可接受的做法是 junction farm**：建 `~/.dsh/skills-htb/`，
里面用目录 junction 指向 `~/.dsh/skills` 的子集。单一真源不变（`~/.dsh/skills`
仍是唯一被编辑的地方），子集由"哪些链接存在"定义。**不要用复制**——包里已经
漂移了 38 张，这就是复制路线的实证。

## 验收

装完必须**开新会话**：已存在的会话固定启动时的 plugin revision，改 preset 不会
影响它们。新会话里选 HTB preset（会话头部的 preset chip，或设置页），然后确认：

1. 自我介绍里出现"HTB 靶机操作员"
2. 工具列表里**没有** `exit_plan_mode` / `present`
3. `exit_plan_mode` 相关提示词段不出现
4. 让它读 `htb-wp/txt/772_ReaperTwo.txt` —— 应被**硬拒**，拒绝理由里提到备考负收益
   与解锁办法

机制侧（`cd C:\Users\<user>\dsh-htb-skills`）：

| 项 | 怎么验 |
|---|---|
| 全部单测 | `node scripts/{guard,guard-wiring,guard-rules,ask-guard,wp-guard,struggle,struggle-watch}-test.mjs`（7 套） |
| 红线拦截实际生效 | 跑 `mkfs.ext4 /dev/nonexistent-probe-xyz`，应被拒并给改写建议 |
| WP 拦截实际生效 | 让 agent `read htb-wp/txt/<任一份>.txt`，应被拒 |
| Struggle 记录 | `Get-Content ~\.dsh\htb-struggle.jsonl -Tail 5`（看 `toolCalls` 与 `hits` 里有没有 `output`） |

🔴 **插件 JS 改动必须重启 `dsh web` 才生效**——`set_plugin` 不重跑 `apply()`，
禁用→启用也不重跑。只有 `skills/` 下的卡片是 chokidar 热重载。改的是 `src/*.js`
就一定得重启。

## 卸载

`plugin_manager` `remove_bundle`，target 为 `@local/dsh-htb-preset`。
