# dsh-htb-skills

HTB（Hack The Box）打靶框架，封装为 [DeepSeek Harness](https://github.com/deepseek-ai) 插件。

> 社区项目，**并非** DeepSeek 官方插件，也不代表 DeepSeek 的认可或背书。
> 仅用于**授权环境**（HTB 靶机、自建实验环境）的攻防练习。见 [SECURITY.md](SECURITY.md)。

## 是什么

一个"技能库 + 状态账本 + 路由 + 守卫"的组合，目标不是让模型知道更多，
而是让它在**正确的时刻**想起该想起的东西、**该停的时候**停得下来。

三个组件：

| 组件 | 目录 | 作用 |
|---|---|---|
| **技能库 + 守卫** | 根目录（`src/` `skills/` `scripts/`） | 164 张技术卡 + 5 个观测/守卫模块 + 9 个 `htb_*` 工具 + 30 道自检闸 |
| **路由** | `router/` | 93 条规则：从工具调用推断攻击阶段，按需注入对应卡片（不是全量灌） |
| **预设** | `preset/` | persona 与插件装配（把上面两者接到一个会话里） |

## 关于卡片里的 `RS`

部分卡片带一行 `📌 DSH 适配：本技能移植自 RS`，以及 `（⚠️ xxx 是 RS 时代工具名）` 的注记。

**RS = Reasonix Studio**，是这批卡片最初成形的环境（作者的上一代工作台）。两者工具名不同，
所以每张移植过的卡都在头部标了映射关系（例如 `read_skill` / `run_skill` → DSH 的 `skill` 工具）。
这些注记是**迁移痕迹**，不是外部依赖 —— 本仓库不依赖 RS，也不包含它的代码。

## 六层结构

按"离模型思维的距离"排，越靠后越可靠：

```
L1 输入   它看到什么   router 按阶段注入卡片 / htb_brief 传假设给子 agent
L2 动作   它能做什么   4 道守卫（红线 / 提问 / WP / 停止协议）+ dead 必须带对照证据
L3 反馈   做完看到什么 单次输出超标 + 上下文累积 + 失败归因 6 类 + 战线预算
L4 时间   什么时候停   stall 90 分钟 / budget 6 小时 → 注入提醒 + 上闸
L5 结构   什么离开脑子  state.jsonl（fact / intent / auto-probe）+ loot 台账
L6 采样   换起点       未实现（见 docs/ARCHITECTURE.md 的"未做"清单）
```

分层、装配、生效条件与已知欠账见 [`docs/FRAMEWORK.md`](docs/FRAMEWORK.md)；改代码前读 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)（变异点地图）；卡片写作规范见 [`docs/CARD-NORMS.md`](docs/CARD-NORMS.md)。

## 目录结构

```
dsh-htb-skills/
├── package.json              # dsh.bundle.patch → cordis.patch.yml
├── cordis.patch.yml          # 注入 host 插件行
├── src/
│   ├── index.js              # 插件入口（注册 provider / 工具 / 守卫）
│   ├── sherlock-tools.js     # 6 个 htb_sherlock_* 工具
│   ├── state-tools.js        # htb_fact / htb_frontier / htb_brief（状态账本）
│   ├── guard.js              # 红线守卫（18 条）
│   ├── ask-guard.js          # 提问守卫（不把解题责任推回用户）
│   ├── wp-guard.js           # WP 守卫（打靶会话不读官方 writeup）
│   ├── struggle.js           # 停滞/重复/预算的判定
│   ├── struggle-watch.js     # 判定接线 + 停止协议闸
│   ├── scope-observe.js      # 出站目标观测（只记录，永不拦截）
│   ├── context-hygiene.js    # 上下文卫生（单次 + 累积）
│   ├── error-classify.js     # 失败归因（6 类 + 同类合并）
│   └── auto-state.js         # 战线推断 + 切换摘要 + 战线预算
├── skills/                   # 164 张技能卡（T1 路由 / T2 深度 / T3 参考）
│   └── htb-skill-index/      #   领域 × 层级总索引
├── scripts/                  # 30 道自检闸（25 个 node 用例 + python 审计）
├── templates/                # 并行侦察 workflow / 通道适配器
├── docs/                     # 架构与卡片规范
├── router/                   # 路由插件（规则表 + 匹配逻辑）
└── preset/                   # persona 与装配
```

## 安装

```sh
git clone https://github.com/qingsiweisan/dsh-htb-skills.git
cd dsh-htb-skills
```

**1) 技能库 + 守卫**（link 安装，本地改代码即时生效）

```sh
dsh plugin --profile web add link:./dsh-htb-skills
```

**2) 路由**（可选，但强烈建议——没有它，卡片只在被想起时才生效）

```sh
dsh plugin --profile web add link:./dsh-htb-skills/router
```

**3) 预设**：把 `preset/cordis.patch.yml` 里的 persona 段落合并进你的 profile 配置。
其中 `C:\Users\<user>\...` 是占位符，按你的实际路径替换。

```sh
dsh web   # 重启后新建会话，看到 htb-skill-index 等 T1 卡即为生效
```

> 注意：插件挂载后，`~/.dsh/skills` 里的同名散装技能会与插件里的卡**重复**
> （同名时 preset 层遮蔽全局层）。迁移前先备份：
>
> ```sh
> mv ~/.dsh/skills ~/.dsh/skills.bak
> ```

## 自检

```sh
node scripts/framework-check.mjs          # 30 道闸，绿了才算没改坏
node scripts/router-rules-test.mjs        # 只跑路由规则表
python scripts/triage_skills.py           # 重生成索引卡（需 pyyaml）
python scripts/audit_routing.py           # 路由完整性审计（只读）
```

改完卡片或规则**必须**跑 `framework-check.mjs`。它覆盖：卡片元数据一致性、
路由引用可解析、守卫接线、状态账本、上下文卫生、失败归因、战线推断、
以及"文档数字与实际一致"（防止 README 说 164 张卡而实际 163 张）。

## 卡片的 frontmatter 约定

```yaml
---
name: web-attacks
description: 'Web 攻击综合手册：OWASP 映射 → …（检索词：…）'
whenToUse: '目标有 HTTP/HTTPS 攻击面时：…'
# T2/T3 卡额外带这一行；T1 卡不写：
disable-model-invocation: true
metadata: { domain: web, tier: T1 }
---
```

- `domain`：`meta / web / ad-win / linux / db / cloud / creds / forensics / network / tools`
- `tier`：`T1`（进会话目录）/ `T2`（深度，按名加载）/ `T3`（参考与题源，按名加载）

新增一张卡 = 建目录 + 写 `SKILL.md` + 在 `scripts/triage_skills.py` 的 `MAPPING` 登记
`domain/tier` + 重跑校验链。`slug` 的每个分词都必须出现在元数据里（否则路由搜不到）。

## 兼容范围

- DeepSeek Harness `0.1.0-rc.x`（对齐 `@deepseek-ai/dsh-skill-filesystem ^0.1.0-rc.6`）
- Node `^22.19.0 || >=24.0.0`
- Harness 仍在开发者预览期，升级后如有破坏性变更，请对照上游 `skill-filesystem` 的导出

## 许可证

MIT。技能卡内容整理自个人实战与公开资料；不含任何真实环境凭据（见 [SECURITY.md](SECURITY.md)）。

**关于第三方仓库**：卡片里出现的 `github.com/...` 链接是**工具来源**（告诉你这个工具去哪拿），
不是本仓库的依赖。本仓库**不包含**这些项目的代码，也没有 vendored 目录；
运行时只依赖 `@deepseek-ai/dsh-skill-filesystem` 与 `@deepseek-ai/dsh-llm`（Harness 一方组件）。
