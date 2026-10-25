---
name: 'debug-5whys'
description: '改编自丰田5 Whys：攻防卡住时的强制追问框架。卡住先二分（结构性突破 × 已有数据源穷举）→定义失败点→5 Whys追问→假设审计（含探针 liveness 断言与"查过无果"四格）→二分验证（检索词：5whys/debug/root-cause/hypothesis/blocked/root cause/卡住/二分/结构性/穷举/liveness/探针/先证探针/absence of evidence/查询原语/primitive/阳性对照/control/假否证）'
whenToUse: '攻击卡住时强制追问：定义失败点→5 Whys→假设审计→二分验证。'
metadata: { domain: meta, tier: T1 }
---

# Skill: 5-Whys HTB

改编自丰田 5 Whys 根因分析。攻防卡住时的强制追问框架。

## 来源
Taiichi Ohno, Toyota Production System, 1988.
https://en.wikipedia.org/wiki/Five_whys

## 触发
- 同一攻击路径失败 ≥ 3 次
- 换了 2 个以上替代方向仍不通
- 🔴 候选路径已穷尽 / "下一步清单为空" —— 不是反复失败，而是**没东西可试**。
  这通常意味着某个错误前提把正确路径**提前排除**了，比反复失败更危险（失败会留下证据，误排除不会）。
- 🔴 事后复盘：某条路径事后被证明可达、而当时被自己排除了 → 直接进 §④

## 流程

### ⓪ 🔴 卡住时先二分（禁单线死磕）

追问之前先确认**两条腿都动过**——否则 5 Whys 会在一棵死树上追问到底：

```
[ ] 腿 ① 结构性突破：信任方向 / 网络 ACL / 加密 / 端口占用 / 通道落地
[ ] 腿 ② 已有数据源的穷举：**已经拿到全量读权限的那个源，扫干净了吗**？
    判据：它有没有被"无过滤 + 覆盖完整保留期 + 换过原语"地扫过一遍？
```

🔴 实测（Ifrit，Pro Lab 7/7）：02:30–03:35 的 65 分钟**全压在腿 ①**（怎么进内网 / 怎么拿证书），
同一时段没人问腿 ② —— 那时手里已有全量只读的 SIEM，9 台机器的管理员明文口令就在里面，
**可达而未知的窗口 2.5 小时**。腿 ② 通常 **<10 分钟且常决定性**，卡住时先做它。

### ① 定义失败点（精确到一步）
```
❌ "容器逃逸失败"
✅ "CodeBuild BUILD phase: Exit code 128 OCI runtime exec failed"
```

### ② 5 Whys 追问链
```
Why 1: 为什么 BUILD 失败？
  → OCI runtime exec failed: 容器已停止

Why 2: 为什么容器停止了？
  → init 命令没有成功保持容器 alive

Why 3: 为什么 init 命令 (tail -f /dev/null) 没成功？
  → 前面的 mkdir -p /codebuild 失败了

Why 4: 为什么 mkdir 失败？
  → 没有权限在 / 下创建目录

Why 5: 为什么没有权限？容器不是 privileged mode 吗？
  → entrypoint.sh 用 gosu floci 降权了，privileged 只给 cap 不改 uid
```

### ③ Why 5 改造 — 追问到"可操作的根因"
```
标准 5 Whys 可能在 Why 5 停住（"entrypoint 降权了"）
HTB 版继续:

Why 6: 有没有东西能绕过 entrypoint 降权？
  → 检查 entrypoint.sh: 它用 id 命令检查当前用户

Why 7: 能不能控制 id 的返回值？
  → BASH_FUNC_id%% 可以注入 bash 函数劫持 id

Why 8: BASH_FUNC_id%% 在原始脚本里吗？
  → 在。但我把它删了，以为是 cosmetic。
```

### ④ 假设审计（5 Whys 的补充）
5 Whys 的已知弱点：无法超越当前知识边界。补一个步骤：
```
🔴 前置（先做这一条）：任何"没收到 / 没命中 / 端口关 / 无回连"的观察，先证**探针还活着**：
   [ ] ps 进程在否    [ ] ss 端口在听否    [ ] 日志/输出文件字节数涨否
   （实测：把"中继日志没有 Received connection"读成"coercion 没落到中继上"，
     真相是**中继进程早已静默退出** —— 读的是"证据的缺席"，却先没证采集工具活着）
   一句话：absence of evidence ≠ evidence of absence；先证探针，再报结果。
列出所有"已被排除的假设"及其排除依据:
[ ] BASH_FUNC_id%% → 依据: "看起来是cosmetic" → 🔴 弱！重新验证
[ ] 镜像问题 → 依据: "旧session能跑" → 🟡 需要确认版本
[ ] 🔴 任何"查过 X，无果"型排除 → 必须写全四格，缺任一格即为假否证候选：
    probe（探测命令）· primitive（查询原语，不是工具名）· semantics（字段类型/协议语义）· control（阳性对照）
    实测：`match_phrase` 打 Elastic **wildcard** 字段**恒返回 0**，被记成"查过 net user 无果"
    → 换 query_string 一条命中 9 台机器管理员明文口令，代价 2.5 小时可达窗口
```

### ④-b 量词审计（与证据强度同等重要）
证据强度只回答"这条证据硬不硬"，**不回答"它覆盖多宽"**。这是两根独立的轴：

```
[ ] 这条结论的主语是单数还是复数？
[ ] 出现"所有 / 各 / 均 / 都 / 全部" → 逐个列出被验证的实例
[ ] 未被验证的实例标 ❓，并把结论降级为"<具体实例> 上成立"
```

反例（Reddish，代价：唯一正确的路径被自我封印两小时）:
```
[ ] redis 容器 CapEff=a80425fb       → 依据: 实测 → 🟢 强
[ ] www 容器 mknod 成功但 dd EPERM    → 依据: 实测 → 🟢 强
    ❌ 两条都 🟢，却被外推成"所有容器都无特权 / 都读不了块设备"
    ✅ 正确写法: "redis 容器无特权"、"www 容器读不了块设备"
    真相: backup 容器 CapEff=0000003fffffffff，可直读块设备拿到 root flag
```
🔴 **强证据 + 过量词 = 最危险的组合**。弱证据让人存疑；强证据让人停止检查。

### ⑤ 二分验证
```
取因果链中间一步，实验验证：
→ 先跑不含 modprobe 的命令序列 (echo hello)
→ BUILD 能 SUCCEEDED 吗？
→ 能 → 问题在后面
→ 不能 → 问题在容器生命周期本身
```

## 5 Whys 的批评与应对
| 5 Whys 弱点 | HTB 版应对 |
|-----------|----------|
| 停在症状不深挖 | Why 5 后强制继续，"为什么"直到能改代码 |
| 无法超越当前知识 | 假设审计步骤，强制重审"已排除"项 |
| 不同人会问出不同根因 | 用实验验证每一步，不依赖直觉 |
| 倾向单一根因 | 接受可能有多个阻断点，并行修复 |

## Nimbus 实战示例
```
失败点: BUILD:FAILED, OCI exec
Why 1-3 → 容器 init 失败
Why 4 → mkdir 权限
Why 5 → gosu floci 降权
Why 6-7 → BASH_FUNC_id%% 可绕过
结论: 脚本对，我删错了。修复: 保留 BASH_FUNC, 换新 project 名
```
