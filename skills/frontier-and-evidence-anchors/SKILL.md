---
name: 'frontier-and-evidence-anchors'
description: 'DSH 持久化探索层（ARTEX 双图概念迁移）：frontier 共享待办（跨子代理/跨会话，含停摆底线）+ 资产覆盖矩阵 + 证据锚点（role=baseline/proof/verification/supporting）+ 否证条目纪律（四元组 probe/primitive/semantics/control + retest_cost，过 htb_coverage 的 baseline 硬闸）+ 全否型结论的 retester 独立复核 + 探针 liveness 断言 + 卡住二分推进。治三件事：计划随会话丢失、结论与资产脱钩、假否证把正确路永久排除。（检索词：frontier/todolist/共享待办/停摆/standstill/asset coverage matrix/资产覆盖矩阵/anchor/anchors/锚点/血缘/derived_from/证据角色/evidence role/baseline/proof/verification/supporting/对照/retester/复测/独立复核/假否证/false negative/traces/过程检索/htb_traces/htb_coverage/否证/negation/查询原语/primitive/阳性对照/control/retest_cost/重测成本/易腐/absence of evidence/探针/liveness/先证探针/二分/结构性/穷举/orchestration/persistence/持久化）'
whenToUse: '多步链开局建 frontier 时；派子代理前后（派单前读、派单后写）；把任何结论落台账时（尤其"全否/已证否"）；收尾复核时。单机短任务可只用 §1 的精简版。'
metadata: { domain: meta, tier: T1 }
---

# frontier 与证据锚点（DSH 持久化探索层）

> 🔷 **来源**：ARTEX 双图架构（全局资产图 / 每任务探索图 + 锚点 + 跨唤醒共享 todolist）的**概念迁移**，不是代码移植。
> DSH 用**文件**实现同一目的——**不引入数据库**。
>
> 三条机制对症三种实测过的失败模式：

| 症状 | 机制 | 节 |
|---|---|---|
| 计划随会话/子代理丢失，续做时重建 | **frontier 文件** | §1 |
| 结论与资产脱钩 → 漏测、重做、说不出"为什么放弃" | **资产覆盖矩阵 + 证据锚点** | §2 |
| 假否证把正确路**永久排除** | **retester 独立复核** | §3 |

**为什么必须落文件**：`todo_write` 是**会话状态**——子代理看不到、续做 agent 会重建、主上下文压缩后可能丢。
ARTEX 在无状态会话里走通多步链，靠的就是把"计划"从会话状态提升为**任务级持久状态**。
DSH 的等价物是文件，不是工具。

---

## §0 三个固定文件

```
loot/<machine>.md                    # 作战台账（既有约定，职责不变）
loot/<machine>-frontier.md           # 🆕 本卡主产出：共享待办 + 覆盖矩阵 + 证据锚点
loot/<machine>/traces/<agent>.md     # 🆕 每个子代理的过程留痕（边做边写，不攒）
```

> 🔴 三者的分工与 ARTEX 双图一一对应：
> `loot/<machine>.md` = **资产真值库**（事实）· `-frontier.md` = **探索图**（方向与血缘）· `traces/` = **过程库**（worker 间交换的原料）。

---

## §1 frontier：两个机制各管一半（2026-10-10 按实测语义修正）

> 🔴 **修正说明**：本卡初版让 frontier 自建状态表 —— 那是重复建设。
> 但我上一轮又建议"整体迁到 task board" —— 那是**过度纠正**。
> 实测 task board 的语义（见下表右列）决定了它**只能装无依赖的并行批次，装不了依赖序**。
> 正解是**按语义分工**，不是二选一：

| 信息 | 落点 | 依据（本机实测） |
|---|---|---|
| **无依赖的并行探测批次** | **task board** | `run` 的语义本就是"**整棵子树并发**"，正好匹配；另有 durable 状态 + 执行历史 + 排期 |
| **串行依赖链**（注入→凭据→横向→提权） | **frontier 文件** | `maxSubtaskDepth: 1` 建不出多层树；`run` 会把整条链**并发**展开（正是要避免的失败模式）；列由**执行**驱动，**没有**手动勾选 done 的动作 |
| 证据锚点 / 结论台账 | frontier 文件（§2） | task board 不表达"证据角色 / 喂了什么输入" |
| 过程留痕 | `traces/`（§4） | 同上 |
| 已证否 / 已收敛 | frontier 文件 | 否证不是"任务"，是结论 |

### 1.1 并行批次 → task board（含三个硬约束）

```
[ ] 建链根    task_board_create(title="<machine> 侦察批次", tags=[{name:"<machine>"}])
[ ] 建子卡    task_board_create(title="22/80/443 指纹", parentId=<链根>, tags=[{name:"<machine>"},{name:"A3"}])
[ ] 派前读    task_board_list(tag="<machine>", status="running")   # 谁在跑，一次拿全
[ ] 执行      task_board_run(<链根>)    # ✅ 仅对**无依赖批次**用；N 个子卡并发跑
[ ] 收尾盘点  task_board_list(tag="<machine>")
```

🔴 **三个硬约束**（都是实测出来的，不知道就会踩）：

1. **`maxSubtaskDepth: 1`** —— 只能"链根 + 一层子卡"，子卡的子卡会被拒。所以**依赖链塞不进去**。
2. **没有"手动移到 done"** —— `task_board_manage` 的动作只有「移到 todo / 移到 backlog / archive / restore / delete / settle」；
   `running`/`done`/`failed` 由**执行结算**驱动。⇒ 手工派子代理做的步骤，看板**不会**自动标记完成。
3. **`sessionDefaultPermission: read-only`**（本机看板默认）—— 跑卡需要**权限绑定 + 看板 UI 里人工确认**，
   `task_board_run` **自己不能确认**。所以"顺手 run 一批"在默认配置下会被拒。

🔴 **绝不要对串行链的链根调 `task_board_run`。** 它的语义是"把整棵子树**并发**跑起来"，
而攻击链是有前后依赖的串行序列 —— 对链根 run = 把整条链一次性并行展开，**正是 ARTEX 共享 todolist 要解决的那个失败模式**。

### 1.2 串行链 → frontier 文件（只剩依赖序 + 证据指针）

```markdown
# <machine> frontier

> 分工：**无依赖的并行批次**在 task board（`task_board_list(tag="<machine>")`）；
> 本文件管**它表达不了的两样**：串行依赖序 + 证据指针。
> 🔴 本文件的「状态」是**手维护**的 —— 看板的 done 由执行结算驱动，串行链上的手工步骤只能在这儿勾。

## 串行依赖链（按依赖逐条派；🔴 不对链根 run）
| # | 任务卡 id | 步骤 | 前置依赖（具体到 fact） | 状态 | owner | 产出证据（文件:行） |
|---|-----------|------|------------------------|------|-------|---------------------|
| 1 | 41 | 入口侦察 | — | done | A1 | traces/A1.md:40-88 |
| 2 | 42 | Web 初始访问 | #1 的 fact「存在 /upload，无类型校验」 | running | A2 | — |
| 3 | 43 | 凭据横向 | #2 拿到可用凭据 | blocked | — | — |
| 4 | 44 | 提权 | #3 立足 | blocked | — | — |

## 已收敛（不再派单的方向，附理由与依据）
| 方向 | 结论 | 依据（文件:行） |
|---|---|---|
| 445 SMB 匿名 | 已证否 | traces/A1.md:12-30 |
```

### 1.3 三条纪律（落点分两处）

```
[ ] 🔴 派单前必读：并行批次看 task_board_list(tag=…, status="running")；
    串行步骤看本文件依赖链 —— 确认没在跑、前置 fact 已存在、全局独占资源不冲突
[ ] 🔴 派单后必写：并行批次建子卡（task_board_create … parentId=<链根>）；
    串行步骤在依赖链表补一行（步骤 ↔ 任务卡 id ↔ owner）
[ ] 🔴 完成即签收：把产出证据的行号填进依赖链表 —— **空着等于没做完**
```

### 1.4 停摆底线（防"安静地卡住"）

> ARTEX planner 的硬底线：**只要目标未达成、且 frontier 与运行中都没有任何意图，
> 本轮就必须产出至少一个向目标推进的意图**——产出 0 个 = 停摆。

DSH 落地为一条**派单前自检**（判据一次调用就能查）：

```
[ ] 🔴 停摆自检：若「目标未达成」且
    task_board_list(tag=…, status="running") 为空 且 依赖链无 running 行
    ⇒ 本轮必须产生一个具体下一步（建卡 / 换 oracle 重派 / 显式宣布放弃并写理由）。
    禁止既不派单也不宣布终止。
```

**静默卡死是自主链最贵的失败模式**：它不报错、不产生否证、不烧 token，只是不再前进。
人不在环时必须靠这条机械检查发现它。

> 旁证：本机的 **Struggle 监视器**已经在为这件事收数据（`~/.dsh/htb-struggle.jsonl`，
> 按产物目录 mtime 判活，阈值 `stallMinutes/maxHours/repeatCalls/failureRate`），当前**只记录不干预**。
> ⇒ 与其再加一层文字，不如先看它攒的分布，再决定是否升级为干预。

### 1.5 与既有机制的关系

- **`todo_write`**：会话内的短期清单，**继续用**（对用户可见、便于签收）。它的持久化落点是 **task board（并行批次）+ frontier 文件（串行链）**，不再是手搓的大表格。
- **「在跑任务表」**（`htb-workflow` §7）：降级为**纸质投影**；并行批次的权威是 `task_board_list`。
- **收尾**：frontier 的「已收敛」与依赖链是复盘与 `loot/` 的原料；不要把结论只留在对话里。

---

## §2 证据锚点：结论必须绑资产、绑角色、绑到"喂了什么输入"

### 2.1 为什么（两个实测教训）

1. **结论与资产脱钩 ⇒ 漏测**。写着"某段没有主机"却不记是哪一段、用什么对照得出的，
   下一个 agent 无法复用，只能重跑；更糟的是**误把已测当未测、或把未测当已测**。
2. **否证的可信度取决于 oracle，不取决于扫描量**（`htb-workflow` §10③ 的最贵误判：
   oracle 拿内存镜像自身字节当密文，产出**看起来极严谨**的假否证，差点让正确路被永久排除）。

### 2.2 资产覆盖矩阵（锚点：每条结论必须落在某个资产行上）

```markdown
## 资产覆盖矩阵
| 资产（host:port / domain / path） | 已测方向 | 结论 | 证据角色 | 时间 / 版本 |
|---|---|---|---|---|
| 10.10.10.5:80 | 指纹 / 目录 / 参数 | PHP 8.1 + 自研 upload | proof | 2026-10-10 |
| 10.100.1.0/24 | 存活扫描 | 无主机（网关代答 RST） | baseline + proof | 2026-10-10 |
```

> 🔴 **未落在此表的结论视为不存在**。列「资产」的技能卡：`engagement-inventory-and-triage`（三轴台账）、
> `prolab-engagement-playbook`（负结论也必须写进台账）。

### 2.3 证据角色（role）—— 四值，来自 ARTEX 的流量证据模型

| role | 含义 | 何时必填 |
|---|---|---|
| `baseline` | **正常对照**：证明"应该不一样的东西确实不一样" | 🔴 **判活 / 判"不存在" / 判"被拦" 时强制** |
| `proof` | 直接证明结论的请求或输出 | 任何"命中"型结论 |
| `verification` | 补充验证（第二条独立路径） | 结论影响战略转向时 |
| `supporting` | 辅助（默认值） | 其余 |

> 🔴 **`baseline` 是把 `htb-methodology` 的"对照组法"变成必填字段**：
> 判"这个段不存在"要拿「必然不存在的地址 + 广播地址」做对照；
> 判"无响应"要拿一个**确实存在**的文件做对照（`Store` 教训：LFI 判死前必须让 payload 指向真实存在的文件）。
> **没有对照的"全否"不是结论，是猜测。**

### 2.4 结论台账（血缘：这条结论派生自哪条观察）

```markdown
## 结论台账
| 结论 | 派生自（哪个观察/哪条 fact） | 证据（命令 + 关键输出片段） | role | 可复核到"喂了什么输入"? |
|---|---|---|---|---|
| 该段无主机 | 对照组与目标行为完全一致 | `tcpdump -e` 源 MAC 全是网关 | baseline+proof | ✅ 输入=对照探测清单 |
| LFI 不可用 | — | 仅"无响应" | supporting | ❌ **输入未记录 ⇒ 不可信，须重跑** |
```

> 🔴 **最后一列的判据**：能指着某一行说出"喂进去的是什么数据"，才算复核得了。
> 只有结论、没有输入来源的排除，**一律标记不可信**并在收尾时交给 §3 的 retester。

🔴 **「无结果」型观察的前置断言（先证探针，再报结果）**：任何"没收到 / 没命中 / 端口关 / 无回连"
在落台账前，必须先证明**采集证据的工具还活着** —— 三选一即可：
`ps -ef | grep -c <工具名>`（中继/监听器是否已静默退出）· `ss -tlnp | grep <port>` ·
`stat -c %s <log>` 隔 30 秒再看一次（字节数在涨否）。
实测：把"中继日志没有 Received connection"读成"coercion 没落到中继上"，真相是**中继进程早已静默退出**
（`ss` 里 445 已无监听）—— 20 分钟 + 一次方向误判。
⇒ 一句话：**absence of evidence ≠ evidence of absence；先证探针，再报结果。**

### 2.5 否证条目纪律：四元组 + 重测成本（缺项不许进否证表）

> 依据：一条**裸结论**式否证（"查过 net user，无果"）代价 2.5 小时可达窗口 ——
> 查询原语用错（`match_phrase` 打 Elastic **wildcard** 字段**恒返回 0**）+ 没设阳性对照。
> 🔴 工具层**已有**硬闸：`htb_coverage` 对 `conclusion=negative` 强制要求 `role=baseline` 的证据 id。
> **闸存在却被绕过**（否证一条都没记进去）⇒ 纪律第一条不是"要谨慎"，而是"**先过闸**"。

**判据（每条否证必须能写出这 5 格，写不出 = 不许进否证表）**：

| 格 | 内容 | 反例（Ifrit 的 N29） |
|---|---|---|
| `probe` | 具体探测命令/请求 | `match_phrase {"process.command_line":"net user"}` |
| `primitive` | **查询原语**（不是"工具名"） | `match_phrase` |
| `semantics` | 字段类型 / 协议语义 | `process_command_line` 是 wildcard ⇒ 该原语恒 0 |
| `control` | **阳性对照**：同一原语打一个**必然命中**的样本 | 无 ← 缺此格，否证无效 |
| `retest_cost` | 换原语重测的秒数 | 一条 curl（< 60 s） |

```
[ ] 🔴 落否证前先调 htb_coverage record(conclusion="negative", role="baseline", evidenceIds=[…])
    —— 拿不到 baseline 证据 id ⇒ 该否证**无效**，不许写进台账（工具会直接拒绝）
[ ] 🔴 `control` 缺失 ⇒ 一律标 [不可信]，收尾交 §3 retester（不是"存疑留档"）
[ ] 🔴 `retest_cost < 60s` 的否证是**易腐品**：出现新原语/新工具/新通道/新凭据时**全部重跑一遍**
[ ] 🔴 禁止无原语表述："查过 X 无果" ⇒ 改写成"用 <原语> 打 <字段/端口/路径>，对照 <样本> 命中、
    目标 0 命中，retest_cost=<n>s"
```

---

## §3 retester：全否型结论的独立复核

> 来源：ARTEX 预置的独立「漏洞复测」Agent（三态结论：仍可复现 / 已修复 / 无法确认）。

**触发条件**（🔴 两条，第一条是 2026-10-16 新增，**不是收尾才做**）：

```
[1] 🔴 卡住信号一出现就派 —— 不等预算烧完、不等收尾：
    同一路径失败 ≥3 次 / 换过 ≥2 个方向仍不通 / 未决队列为空 / idle > 20 min
    ⇒ 立刻派 fresh-context retester。实测：本次第二个子代理 04:37 才起、05:05 出货，
      只剩 25 分钟余量 —— **胜负手靠的是它的独立性，不是我的设计**。
[2] 收尾 / 复盘阶段，对 frontier「已收敛」表与结论台账里所有
    结论 ∈ {全否, 已证否, 已排除, 无响应, 不存在} 的条目。
```

**做法**：派 **一个独立子代理**（不要复用做这件事的 agent——它复现不了自己的盲区），任务书照抄：

```markdown
【任务】独立复核以下"否证型"结论，逐条判定。
【要复核的条目】<从 frontier「已收敛」+ 结论台账 粘贴，含证据文件:行>
  🔴 每条必须写成这个形状，**不许只给结论**：
     "believed <结论>，probed with <原语/命令> —— please re-test with a **different primitive**"
  （实测：把裸结论交下去，子代理只能靠自觉才重测；写成上面这行，可证伪性才被传下去）
【判据】🔴 复核到"喂了什么输入"那一行。只有结论、没有输入来源的排除，直接判【不可信】。
【三态回报（逐条）】
  - 仍成立：给出你独立复现的命令与输出
  - 已推翻：给出反证 + 正确的输入来源
  - 无法确认：说明缺什么（缺证据 / 缺环境 / 缺时间盒）
【🔴 显式邀请一步到位的变体】若发现能**一步**替代我给的 N 步方案的变体，优先用一步的并回报
  （实测：我给的是"PKINIT → 再 certipy req -upn"两步，它发现 `--altname` 一步做 ESC1）
【纪律】不重跑已确认的成功路径；不动他人 owner 的目标；只读为主，需要写先回报。
```

**为什么单开一个 agent**：否证的**成本极低、破坏力极大**——它会把一条正确的路从
搜索空间里划掉，而且划得"有理有据"。让**产出否证的人**去复核是否证，等于没复核。

**三态之后**：任一条判「已推翻」⇒ 立刻回写 frontier（把该行从「已收敛」移回「待办链」）
并派单；判「不可信」⇒ 同样移回，但**换一个正确 oracle 重派一轮**再下结论。

---

## §4 跨 agent 过程检索（等价 search_all_worker_traces）

### 4.1 留痕规范（先有规范，才检索得到）

```
[ ] 🔴 每个子代理：loot/<m>/traces/<agent>.md，**一个实验一行、边做边写**
    （教训：三次"攒着写"导致失败即丢推理，最长丢了 14 分钟关键进展）
[ ] 格式：`## <时间> <命令/动作>` + 原始输出（可截断到关键片段）+ 一句结论
[ ] 任务书里必须写死这条 —— 子代理不会自己想到要留痕
```

🔴 **首选落盘工具是 `htb_traces`（等价 search_all_worker_traces），不是手写文件**：
`htb_traces(op="append", machine=…, agent=…, label=…, text=…)` 边做边写；
`htb_traces(op="search", machine=…, query="<关键词>")` 开工/接手/换方向**前**先查
（默认按文件内的会话标记排除自己，`excludeAgent=""` 才含自己）。
报错、响应片段、可疑参数都算 —— **"够不上一条 fact"的观察正是它要收的东西**。

> 🔴 实测代价（Ifrit）：`htb_traces` **一次都没用过**（连 `op=search` 都没跑）。
> 而 `match_phrase → 0 命中` 这种观测正是它设计要收的：当时若写成一条 trace，
> 子代理 `op=search "match_phrase"` 就能直接看到并换原语 —— **1 次检索省 2.5 小时**。
> ⚠️ 它的写路径就是 `loot/<m>/traces/`，而子代理对 `loot/**` **无写权限** ⇒
> **append 由主代理（或获授权的 agent）执行**，子代理把原文**文本回报**给主代理落盘。

### 4.2 检索配方

**首选**：`grep` 工具，path 指向 traces 目录，可精确到「排除自己那条」：

```
grep(pattern="preauth|KDC_ERR|403|stack trace", path="loot/<m>/traces")
```

**需要在会话归档里考古时**（会话是 zstd 压缩的，直接 grep 扫不到）：

```powershell
$z = "C:\Users\<user>\Miniconda3\Library\bin\zstd.exe"
$f = Get-ChildItem "$env:USERPROFILE\.dsh\sessions\<工作区目录>" -Recurse -Filter 'session.v4.jsonl.zstd' |
     Sort-Object LastWriteTime -Descending | Select-Object -First 1
& $z -d -c $f.FullName | Select-String '<错误码/技术词>'
```

> 实测基准：34 个会话里 5 个出现过 `KDC_ERR_PREAUTH_FAILED` —— **这条查是有效的，不是形式主义**。

### 4.3 使用时机

- **卡住时**的三查（`htb-workflow` §2）之外**加第四查**：`traces` 全库检索。
  很多有价值的观察（某段报错、某段响应、某个可疑参数）**够不上一条 fact**，
  但足以让另一个方向的 worker 少走一小时。
- 派新任务书时，把查到的相关 `traces/<agent>.md:行` 作为**已知现状**写进去——
  别让新 agent 从零重踩。

### 4.4 🔴 卡住时的二分推进

**腿 ① 结构性突破**（信任方向 / 网络 ACL / 加密 / 端口占用 / 通道落地）与
**腿 ② 已有数据源的穷举**（"拿到全量读权限的那个源，被无过滤 + 全保留期 + 换原语地扫过一遍了吗"）
交替推进，任一条停滞 ≥20 min 就切另一条。
🔴 实测（Ifrit）：65 分钟全压在腿 ①，而同一时段**没人问腿 ②** —— 那时 SIEM 里就摆着 Master 的明文口令，
**可达而未知 2.5 小时**。腿 ② 便宜且常常决定性（通常 <10 分钟），卡住时先做它。
完整判据与 5 Whys 追问链见 `debug-5whys` §⓪。

---

## §5 自设约束的表述纪律（防止 agent 绕自己的规矩）

> 来源：ARTEX 审批门的一段设计。被平台拦截时，返回给模型的**不是**干巴巴的"禁止/用户拒绝"——
> 因为那种措辞**读起来和目标返回的 403 一模一样**，而渗透 agent 的本能是**绕过它**：
> 改写命令、换 payload、重新编码、重试。这既徒劳（策略拦的是**这一类动作**，不是一个字符串），
> 也搞错了对象（这是**我方的政策决定**，不是待攻克的障碍）。

**DSH 落地**：在 frontier / 台账 / 任务书里，凡是写**自设约束**，加固定前缀：

```
⛔ [平台策略，非目标防御] 此约束来自我方纪律（越界白名单 / 共享 lab 互斥 /
   command-safety-red-lines），**不是靶标的防护**。不可绕过、不可换编码重试。
   遇此约束请转向其他路径，或回报请求裁决。
```

对应到 DSH 的具体场景：
- **越界网段白名单**（`prolab-engagement-playbook`：VPN 推来的其它 lab 网段一律不碰）
- **共享 lab 互斥**（不动别的玩家的进程与文件）
- **红线卡拦截**（`command-safety-red-lines`）

> 🔴 反面模式：把红线写成"目标不允许这样做" ⇒ 下一个 agent 会尝试"绕过目标限制"。
> 正解：写成"**我们不允许这样做**" ⇒ agent 转向，而不是攻击自己的纪律。

---

## §6 最小可用版（单机短任务）

不必全套上。单台靶机、单人、一次会话内跑完的场子，只做两件：

```
[ ] loot/<machine>-frontier.md 只留「待办链」表 + 停摆自检（§1.1 精简 + §1.3）
[ ] 结论落台账时至少填 role 一列；出现"全否"型结论 ⇒ 收尾必跑 §3 的一条复核
[ ] 🔴 否证条目填不出 §2.5 的 5 格 ⇒ 不许写进否证表（先过 htb_coverage 的 baseline 闸）
[ ] 🔴 卡住时先走 §4.4 腿 ②（已有数据源穷举），再回头啃腿 ①
```

多网段 / Pro Lab / 长周期 / 多子代理 —— 才上完整三件套（frontier + 矩阵 + traces）。

---

## §7 关联

| 需要什么 | 去哪 |
|---|---|
| 三轴台账（资产/凭据/网络）+ 依赖链模板 | `engagement-inventory-and-triage` |
| 子代理分发协议（自包含任务书 / owner 互斥 / 邀请反驳 / 时间盒机制化） | `htb-workflow` §子代理分发协议 |
| 阶段主线与放弃判据 | `prolab-engagement-playbook`、`challenge-insane-playbook` |
| 判活对照法 / 三态探测 / RST 源 MAC | `htb-methodology` §判活铁律 |
| 会被自设约束拦住的破坏性操作 | `command-safety-red-lines` |
| 主方法论索引 | `htb-skill-index` |
