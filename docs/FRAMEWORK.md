# 框架总览（分层 · 职责 · 装配 · 生效）

> 本文回答三个问题：**每层是什么**、**改了什么要重启**、**怎么验证它真的在工作**。
> 想改代码先看 [`ARCHITECTURE.md`](ARCHITECTURE.md)（变异点地图：该碰哪里、不该碰哪里）。

---

## 1. 六层模型

按"离模型思维的距离"排。**越靠后越可靠**——因为不依赖模型"想起来"。

| 层 | 干预什么 | 机制 | 触发点 |
|---|---|---|---|
| **L1 输入** | 它看到什么 | `router` 93 条规则按阶段注入卡片；`htb_brief` 把主 agent 的假设与退路传给子 agent | `session/event`（tool/call） |
| **L2 动作** | 它能做什么 | 4 道守卫：红线 / 提问 / WP / 停止协议；`htb_frontier dead` 必须带对照证据 | `tools.guard` |
| **L3 反馈** | 做完看到什么 | 上下文卫生（单次 + 累积）/ 失败归因（6 类）/ 战线采集（切换 + 预算） | `tools/post-execute` |
| **L4 时间** | 什么时候停 | `struggle`：stall 90 分钟 / budget 6 小时 → 注入提醒 + **上闸** | `tools/post-execute` · `agent/pre-step` · `tools.guard` |
| **L5 结构** | 什么离开脑子 | `state.jsonl`（fact / intent / intent-update / auto-probe）+ loot 台账 + evidence 账本 | 工具写入 |
| **L6 采样** | 换起点 | **未实现**（见 §7） | — |

### 为什么是这个顺序

同一件事，三种干预的可靠性差一个量级：

```
提示（软）  → 会被忽略。实测：persona 写了"先登记意图"，frontier 0 次调用
反馈（中）  → 改变输入，不改动作。实测：卫生 / 归因有效
闸（硬）    → 不改动作就过不去。实测：dead 必须带 baseline、pkill 被拦、停止协议
```

规则：**能确定性判定的做成闸；需要推断但结论是事实的做成反馈；两者都不能的才写提示，并预期它会被忽略。**

---

## 2. 模块清单

### 2.1 工具（9 个 `htb_*`）

| 工具 | 作用 |
|---|---|
| `htb_fact` | 事实节点：host / service / cred / vuln / flag / note；`cred·vuln·flag` + `verified` 必须带 evidenceId |
| `htb_frontier` | 意图边：`add / claim / done / dead`；`dead` 必须带 `baselineEvidenceId`；支持 `assume / ifWrong / budget / reasonCode` |
| `htb_brief` | 把主 agent 的假设与退路写成子 agent 的任务书 |
| `htb_sherlock_*`（6 个） | HTB Labs API：info / tasks / download / submit / submit-file / progress |

### 2.2 守卫（4 道，`tools.guard`）

| 守卫 | 拦什么 | 可关 |
|---|---|---|
| `guard.js` | 会杀掉自己 / 打挂靶机的命令（12 条内置 + 外置规则表，按 mtime 热重载） | `guard: false` |
| `ask-guard.js` | 把 writeup / 提示 / payload 细节当选项的提问 | `askGuard: false` |
| `wp-guard.js` | 打靶会话读官方 writeup | `wpGuard: false` |
| `struggle-watch.js` | 停止协议触发后启动长任务（爆破 / 后台轮询 / ≥10 分钟等待） | `struggleGate: false` |

### 2.3 观测与反馈（5 个，`tools/post-execute`）

| 模块 | 做什么 | 默认阈值 |
|---|---|---|
| `struggle.js` + `struggle-watch.js` | 停滞 / 重复 / 超预算判定；停止协议注入与闸；产物 mtime **按 1s 节流**（write/edit 强制重扫） | stall 90 min · budget 6 h · repeat 3 · scan 1 s |
| `scope-observe.js` | 记录出站目标（只记录，**永不拦截**） | — |
| `context-hygiene.js` | 单次输出超标 + **累积超标** | 200 行 · 60 次窗口 ≤2 · 20 次窗口 ≥40K 字符 |
| `error-classify.js` | 失败归 6 类（channel / permission / auth / timeout / network / syntax / semantic）；同类第 2 次提示"是否同因"，第 3 次升级"换层/换通道" | 每类 ≤2 条 |
| `auto-state.js` | 从命令推断战线（连续 3 次才切）；切换摘要；**战线内 40 次调用零事实 → 当场问"有没有更快的原语"** | 40 次 |

---

## 3. 装配顺序（`src/index.js`）

顺序有依赖，不要随意调换：

```
1. registerSherlockTools / registerStateTools     工具先注册
2. guard → askGuard → wpGuard                     → 三道确定性守卫
3. struggle-watch                                  → 观测 + 停止协议闸（第 4 道守卫）
4. scope-observe                                   → 只记录
5. context-hygiene → error-classify → auto-state    → 三个 post-execute 反馈模块
```

**为什么守卫在观测前**：守卫要拦"还没发生"的动作；观测只能看"已经发生"的结果。

---

## 3.1 热路径开销（2026-10-26 实测）

四个 `post-execute` 模块 + 守卫链在**每次工具调用**都要跑一遍，所以它们的时间是
"每次调用都付"的税。用真实会话（Atlas，332 条执行结果 / 474 KB）实测：

| 环节 | 优化前 | 优化后 |
|---|---|---|
| `struggle-watch` | 1.942 ms | **0.009 ms** |
| `error-classify` | 0.044 ms | 0.012 ms |
| `auto-state` | 0.016 ms | 0.016 ms |
| `context-hygiene` | 0.007 ms | 0.003 ms |
| **四模块串联** | **2.007 ms** | **0.041 ms** |
| `guard` 链（pre-execute） | 0.121 ms | 0.104 ms |

两处改动：

1. **产物扫描从 O(文件数) 变成 O(1)**。`artifactMtimeMs` 是有界递归 + 每文件一次
   `statSync`，实测 200 文件 1.45 ms、1000 文件 6.76 ms、**3000 文件 20.96 ms**，
   而它原本每次调用都跑。改为按 `artifactScanIntervalMs`（默认 1 s）节流，
   `write`/`edit` 强制重扫。下游阈值是分钟级（stall 45 min / budget 6 h），
   1 秒的缓存误差在判定上不可见。
   规模化差距：loot 3000 文件时，一次 365 次调用的会话从 **7.6 s** 降到 0.4 s。

2. **日志写入复用 fd**（`log-sink.js`）。`appendFileSync` 每次 open+write+close，
   Windows 实测 0.397 ms；改成首次 `openSync` + 之后 `writeSync` 后 0.0019 ms。
   语义不变：`writeSync` 同步落内核，写完即可读。

**不做的事**：`guard` 里 12 条正则对整条命令的扫描占它 93% 的时间（0.091 ms），
但那属于必要成本 —— 加"关键词预筛"能再省 0.08 ms，相对一次 `ssh_exec`（数百 ms）
是 0.03%，属于过度优化。

**为什么 struggle 在 hygiene 之前**：`post-execute` 的 handler 是链式的（各自 `await next()`），
前面的先跑。struggle 需要看到原始结果（它要数失败率），所以排在会往 content 里追加东西的模块之前。

---

## 4. 状态账本

文件：`<stateRoot>/<machine>-state.jsonl`（默认 `<cwd>/loot/`），append-only。

| 事件型 | 写入方 | 用途 |
|---|---|---|
| `fact` | `htb_fact` | 事实节点（可被 evidence 追溯） |
| `intent` / `intent-update` | `htb_frontier` | 意图边（todo / doing / done / dead） |
| `auto-probe` | `auto-state` | 战线切换记录（**不含命令原文**） |
| `access` | `router` | 规则命中即由插件直接 append（模型零参与） |

**读取方按 `type` 过滤**，未知类型被忽略——所以新增事件型不会破坏旧读取方。

---

## 5. 生效条件（改了什么要重启什么）

| 改的东西 | 生效方式 |
|---|---|
| `src/**` 代码 | **重启 `dsh web`** |
| `skills/**/SKILL.md` | 热重载（chokidar 监听，无需重启） |
| `router/cordis.patch.yml` 规则表 | 随插件加载；改完需重载插件 |
| `preset/cordis.patch.yml`（persona） | **开新会话** |
| `~/.dsh/htb-guard-rules.json` 外置红线 | 按 mtime 热重载，无需重启 |

---

## 6. 验证

```sh
node scripts/framework-check.mjs        # 30 道闸，绿了才算没改坏
node scripts/framework-check.mjs --quiet # 只输出失败项
```

覆盖：卡片元数据一致性 / 路由引用可解析 / 守卫接线 / 状态账本 / 上下文卫生 /
失败归因 / 战线推断 / 停止协议闸 / 文档数字与实际一致（防止 README 说 164 而实际 163）。

单跑某一套：`node scripts/<name>-test.mjs`。

---

## 7. 已知欠账（诚实清单）

| 欠账 | 说明 |
|---|---|
| **L6 采样未实现** | 没有"多战线并行 / 换起点重来"的能力。卡住只能换方法，不能同时试三条 |
| **L2 动作未封装** | 命令还是原始形态，参数正确性靠模型记忆。封装成 `scan_ports(target,'full')` 这类语义工具是下一步 |
| **闸的误伤率未实测** | `long-sleep` 会拦 `Start-Sleep -Seconds 900`，但正常轮询也可能用它。需要真机日志判断 |
| **战线推断会错** | `curl` 可能属于侦察也可能属于利用。当前只当"标签"用，不做闸 |
| **失败归因对"没报错但没进展"是盲的** | 那类失败交给 struggle 的 stall 判定 |
| **判定层语义复核仍是人工** | 卡里写了流程，但没有脚本化 |

---

## 8. 一句话

> 框架的目标不是让模型知道更多，而是让它在**正确的时刻**想起该想起的东西、
> **该停的时候**停得下来。
>
> 判断标准：**换一个更弱的模型，这个机制还成立吗？** 成立才是结构性的。
