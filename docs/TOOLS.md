# 工具参考（17 个 `htb_*`）

按用途分四组。所有工具的共同约定：

- **参数**：字符串为主（`machine_id` 也接受数字，内部转）；可选参数省略即用默认值。
- **输出**：纯文本。首行是结论，缩进是细节。失败一律给"下一步怎么做"，不回原始 JSON。
- **错误**：401 给 token 刷新命令；429 给冷却提示；404 区分"端点不存在"与"对象不存在"；422 回显字段级错误。
- **不打印**：token、email、`identifier` 等与本任务无关的凭据与个人信息。

---

## 一、靶机生命周期（6 个）

> 依据：三场真实会话手写 curl 调这些端点共 76 次，几乎全是猜 ——
> `machine/paginated` 试了 5 种写法、`user/info` 试了 v4/v5/v6、spawn 后手动轮询 5–10 次。

### `htb_machine_list`

**用途**：列当前可打的机器，按名字模糊过滤。打之前先看一眼有哪些、哪些已经 own 过。

| | |
|---|---|
| 输入 | `keyword?`（名字模糊匹配，如 `"Duty"`）、`limit?`（默认 20） |
| 输出 | `id / 名字 / OS / 难度(分值) / 已 own 状态`，表格式 |
| 端点 | `GET /api/v4/machine/paginated?keyword=&per_page=` |
| 🔴 边界 | **只含 active 机器**（通常 20 台）。`state` / `retired` / `filter[...]` 参数被服务端**静默忽略**（实测）。查 retired 用 `htb_machine_info` |

```
htb_machine_list { keyword: "Duty" }
→ # active 机器：1/1 台（keyword="Duty"）
    id    名字                 OS        难度              已 own
    999   DutyBound            Linux     Medium (47)      user+root
```

### `htb_machine_info`

**用途**：单台机器的完整状态。**打之前必查**——`authUserInUserOwns/RootOwns` 为 true 说明已经做过。

| | |
|---|---|
| 输入 | `machine`（名字或 id；名字**大小写不敏感**） |
| 输出 | OS / 难度 / 发布日 / active\|retired / 已 own user·root / 当前 IP / 剩余时间 |
| 端点 | `GET /api/v4/machine/profile/<id\|name>` |
| 特点 | **支持 retired**（`paginated` 查不到的历史机器只能走这里） |

### `htb_machine_spawn`

**用途**：启动机器**并等到 IP 可用**。一步替代"POST spawn + 手动轮询十几次"。

| | |
|---|---|
| 输入 | `machine`（名字或 id）、`wait?`（默认 true）、`timeoutSec?`（默认 180） |
| 输出 | IP / 剩余时间 / VPN 服务器 / 耗时 / 轮询次数，以及一句 `nmap` 起手式 |
| 端点 | `POST /api/v4/vm/spawn {"machine_id":N}` + 轮询 `GET /api/v4/machine/active` |
| 🔴 关键 | spawn 的响应**不含 IP**（只有 `{"message":"Machine deployed to lab.","success":true}`），实测要等 **41–94 秒** |
| 保护 | 已有别的活跃机器时**直接拒绝**并告知现状（HTB 通常只允许一台） |

```
htb_machine_spawn { machine: "Atlas" }
→ ✅ Atlas 已就绪
     IP        10.129.238.8
     剩余      1h 58m（expires_at 2026-10-26 11:03:41）
     VPN 服务器 695
     耗时      94 秒（轮询 10 次）

     下一步：nmap -p- --min-rate 2000 -Pn 10.129.238.8
```

### `htb_machine_status`

**用途**：查当前活跃机器。打完一台、或 spawn 之后过一会儿确认状态。

| | |
|---|---|
| 输入 | 无 |
| 输出 | 机器名 / IP / 剩余时间 / VPN 服务器 / 实验室；无机器时明确返回"当前没有活跃机器" |
| 端点 | `GET /api/v4/machine/active` |

### `htb_machine_stop`

**用途**：释放机器，归还配额。**打完就调**，否则一直占着。

| | |
|---|---|
| 输入 | 无（端点按"当前活跃实例"操作，不接受 id） |
| 输出 | 成功消息；无活跃机器时说明 404 属正常，无需释放 |
| 端点 | `POST /api/v4/vm/terminate`（无 body） |

### `htb_machine_reset`

**用途**：重置机器到初始态（清掉你留下的文件、进程、账号改动）。

| | |
|---|---|
| 输入 | `machine?`（省略则用当前活跃机器） |
| 输出 | 提交结果 + 冷却提醒（IP 可能变，用 `htb_machine_status` 确认） |
| 端点 | `POST /api/v4/vm/reset {"machine_id":N}` |
| 🔴 注意 | HTB 有**冷却**（约 5 分钟），频繁调用 429。一般换思路比 reset 划算 |

---

## 二、交付（1 个）

### `htb_machine_own`

**用途**：提交 flag 到平台。**拿到 flag 立刻调**——平台的"完成"是 flag 入账，不是文件里读到。

| | |
|---|---|
| 输入 | `machine_id`（如 `784`）、`flag`（32 位 hex） |
| 输出 | `own_type`（user / root）+ HTTP 状态；成功时往账本写一条 `flag-own` |
| 端点 | `POST /api/v5/machine/own {"id":N,"flag":"..."}` |
| 🔴 注意 | **v4 全是 404**，只有 v5 这个端点能用（Atlas 那场试了 15 个才撞对） |

配套：`htb_fact` 写 `kind=flag` 时会立刻提示"还没提交"；`update_goal complete` 前有一道闸，
有 flag 无提交记录会**拦第一次**（第二次放行，避免死锁）。

---

## 三、状态账本（3 个）

### `htb_fact`

**用途**：登记事实节点（`host / service / cred / vuln / flag / note`），形成可验证的攻击图。

| | |
|---|---|
| 输入 | `op`（`add` / `run-start` / `list` / `query`）、`kind`、`key`、`value?`、`evidenceId?`、`confidence?` |
| 输出 | 记录 id + 类型 + 值 + 落盘路径；`kind=flag` 时附加"还没提交"提示 |
| 🔴 硬规则 | `cred/vuln/flag` 且 `confidence=verified` 必须带 `evidenceId`，否则必须显式写 `inferred` |

### `htb_frontier`

**用途**：登记意图边（要试的路径），记录状态与死因。

| | |
|---|---|
| 输入 | `op`（`add` / `claim` / `done` / `dead` / `list`）、`id`、`action`、`from?`、`target?`、`assume?`、`ifWrong?`、`budget?`、`reasonCode?`、`baselineEvidenceId?` |
| 输出 | 变更确认；`list` 时显示状态、预算、死因、`[未对照·可重试]` |
| 🔴 2026-10-26 | `dead` 的 `baselineEvidenceId` **可选**：带则校验存在性；不带则必须给 `reasonCode`，记为"未对照·可重试" |

### `htb_brief`

**用途**：把一条 intent（含主 agent 的假设、退路、**已知死路**）写成子 agent 的任务书。

| | |
|---|---|
| 输入 | `machine`、`intent`（intent id 或一句自然语言）、`facts?`（显式指定前置事实） |
| 输出 | 任务书：任务 / 假设与退路 / 已知事实 / **已知死路** / 建议加载的卡 / 回报格式 / 边界 |
| 特点 | 任务书由工具生成，不占主 agent 上下文；子 agent 无 loot 写权限，结论以文本回报 |

---

## 四、Sherlock（6 个）

| 工具 | 用途 | 输入 |
|---|---|---|
| `htb_sherlock_info` | 题目元数据 + 场景 + 全部任务（含 hint 与掩码） | `slug` |
| `htb_sherlock_tasks` | 只列任务 id / hint / mask | `slug` |
| `htb_sherlock_download` | 拿签名链接下载附件（可解压） | `slug`、`outDir?` |
| `htb_sherlock_submit` | 交单题答案 | `slug`、`task`、`answer` |
| `htb_sherlock_submit_file` | 批量交（JSON：任务 id → 答案） | `slug`、`answers` |
| `htb_sherlock_progress` | owned / 进度 / rank | `slug` |

---

## 配置键

| 键 | 作用 | 默认 |
|---|---|---|
| `machineTools: false` | 不挂生命周期工具 | 挂 |
| `machineToolsBaseUrl` | API 根（测试打本地 mock） | `https://labs.hackthebox.com` |
| `machineToolsTokenPath` | token 文件 | `~/.dsh/htb-token.txt` |
| `machineToolsSpawnTimeoutSec` | spawn 等 IP 超时 | 180 |
| `machineOwn: false` | 不挂提交工具与交付闸 | 挂 |
| `machineOwnGoalGate: false` | 关掉"完成前交付检查" | 开 |

---

## 典型调用序列

```
htb_machine_list { keyword: "Atlas" }        # 1. 找机器（active）
htb_machine_info { machine: "Atlas" }        # 2. 确认没打过 + 看难度
htb_machine_spawn { machine: "Atlas" }       # 3. 启动并等 IP
# ... 打 ...
htb_fact { op:"add", kind:"flag", key:"user.txt", value:"…" }   # 4. 落账（会提示提交）
htb_machine_own { machine_id: 784, flag: "…" }                  # 5. 提交
htb_machine_stop                             # 6. 归还配额
```

> 全流程 6 步、0 次手写 curl。改造前同样的流程要 10+ 次 curl（含猜端点与手动轮询）。
