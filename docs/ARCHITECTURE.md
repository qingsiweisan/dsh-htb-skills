# 架构与变异点地图(ARCHITECTURE)

> 本文档回答一个问题:**想改框架时,该碰哪里、不该碰哪里。**
> 移植自 Anthropic defending-code-reference-harness 的 docs/customizing.md —— "Where the C/C++ specifics live, concretely":把系统切成**通用机制域**(换个领域不变)与**内容域**(随靶机/技术演进),并用契约文件把两域解耦。

## 1. 两域总览

```
┌────────────────────────── 通用机制域(plumbing,不随内容变) ──────────────────────────┐
│  dsh-htb-router/src/index.js     事件驱动注入引擎(匹配→加载卡正文→agent.inject)      │
│  scripts/audit_routing.py        引用/层级/白名单静态审计                              │
│  scripts/triage_skills.py        MAPPING→索引生成+结构校验                             │
│  scripts/verify_run.py           判定层:flag/cred 捕获的确定性复核                     │
│  state.jsonl 六事件型契约        key-state 产物规范(box-startup 卡定义)                │
│  capture-verdict 三步+否决项     捕获判定流程(可复用于任何"声称捕获了 X"的场景)       │
└─────────────────────────────────────────────────────────────────────────────────────┘
        ▲ 消费规则表/卡片正文                  ▲ 校验 MAPPING/卡片                     
┌────────┴──────────────────────── 内容域(domain content,随靶机/技术演进) ──────────────┐
│  skills/*/SKILL.md              114 张卡:知识本体(T1 目录可见/T2/T3 按名加载)          │
│  dsh-htb-router/cordis.patch.yml  rules 规则表(85 条:场景正则→卡名,是内容不是代码)    │
│  scripts/triage_skills.py MAPPING 卡名→(domain,tier) 映射                              │
│  scripts/audit_routing.py WHITELIST 正文合法 token 名单(随卡演进)                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

判定:"某件事该放哪"——凡是"换一台靶机/换一个领域就不需要改"的,是机制域;凡是"每台新靶机/每个新技术都要加一条"的,是内容域。**机制域修改必须走完整验证(改完跑一轮靶机),内容域修改跑 triage 即可。**

## 2. 变异点表(想做什么 → 改哪里)

| 想做什么 | 改哪里 | 不碰哪里 |
|---|---|---|
| 沉淀一台新靶机的知识/新 quirk | 新建/更新 `skills/<name>/SKILL.md` + MAPPING 一行 + triage 生成索引 | router 引擎、审计脚本逻辑 |
| 让某场景自动注入某卡 | `dsh-htb-router/cordis.patch.yml` 加一条 rule(pattern 用单引号字面量正则) | src/index.js |
| 新增"可判定捕获"的类型(如 证据文件 artifact 判定) | `capture-verdict` 卡步骤 + `verify_run.py` 加一个检查函数 | state.jsonl 事件型语义不变更时其它不动 |
| 改 key-state 事件型/schema | `box-startup`「key-state 规范」+ `capture-verdict` 引用的字段 + `verify_run.py` 解析逻辑,三处同步 | router 规则表(除非触发词变了) |
| 移植整个框架到新领域(如 取证/红队内网) | 换 `skills/` 卡片库 + 重写 `cordis.patch.yml` rules 表;机制域原样复用 | src/index.js、audit、triage、verify_run |
| 新增静态检查规则(引用/层级/格式) | `audit_routing.py` 加检查函数 + 更新 WHITELIST 必要时 | 卡片正文 |

## 3. 两域之间的契约文件(接口即契约)

| 契约 | 定义位置 | 消费方 | 关键约定 |
|---|---|---|---|
| state.jsonl | box-startup 卡 | verify_run.py / capture-verdict / 收尾汇总 | 一行一事件;evidence 可重放;六事件型枚举 |
| router rule | cordis.patch.yml | src/index.js | `{id,label,pattern,cards}`;YAML 单引号=正则字面量;cards 必须是卡名 |
| MAPPING | triage_skills.py | audit_routing.py / 索引生成 | 卡名→(domain,tier);T2/T3 必须 disable-model-invocation |
| 卡片 frontmatter | 每张卡 | DSH skill 注册表 | name 唯一;description 含触发短语 |
| 卡内引用 | 卡片正文 | audit_routing.py | 反引号卡名=引用;非卡名 token 进 WHITELIST |

## 4. 与 Anthropic 架构的对应(学习锚点)

| 他们 | 我们 | 性质 |
|---|---|---|
| harness/cli.py+agent.py(编排/运行时) | DSH 宿主(会话/事件/注入)——不在本仓库 | 平台 |
| 变异点清单(customizing.md 五处 C/C++-specific) | 本表第 2 节 | 地图 |
| found_bugs.jsonl / report.json 等工件 schema | state.jsonl 六事件型 | 契约 |
| grade agent + 可执行 oracle | capture-verdict + verify_run.py | 验证层 |
| .claude/skills ↔ 自主管线镜像 | 我们的卡即"镜像"(DSH 会话里同一套卡交互与自主共用) | 形态 |

## 5. 已知欠账(诚实清单)

- 判定层语义复核(独立子会话对抗复核)仍是人工操作,未机械化——卡里写了流程,无脚本。
- 没有变异点级的"加卡→实测"回归流程(他们用 canary ~6min 冒烟;我们缺一个 5 分钟级冒烟靶)。
- CARD-NORMS 第 2 条(漏洞形状)是内容规范,audit 无法自动检查,靠 review。
