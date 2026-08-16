# dsh-htb-skills

HTB（Hack The Box）打靶技能库，封装为 DeepSeek Harness 插件。

这是一个社区项目，并非 DeepSeek 官方插件，也不代表 DeepSeek 的认可或背书。

## 是什么

- **114 张技能卡**：从 Reasonix Studio 的 HTB 技能库移植，覆盖 Web / AD-Windows / Linux / 数据库 / 云 / 取证等 10 个领域；
- **插件形态**：包内自带 `skills/` 树，通过官方 `@deepseek-ai/dsh-skill-filesystem` 的 provider 机制注册为名为 `htb` 的技能提供者——技能随包版本化、git 管理，编辑即时热重载，不写任何文件进 `~/.dsh/skills`；
- **三层结构**：T1 路由卡进会话目录；T2 深度卡 / T3 参考卡带 `disable-model-invocation: true` 隐藏，按名精确加载；`htb-skill-index` 是全部卡名的领域×层级总索引。

## 安装

```powershell
# 1. 克隆本仓库
git clone https://github.com/qingsiweisan/dsh-htb-skills.git

# 2. 安装到 DSH profile（link 安装，本地改代码即时生效）
dsh plugin --profile web add link:./dsh-htb-skills
#   或从 npm 安装：
#   dsh plugin --profile web add dsh-htb-skills

# 3. 重启 dsh web，新建会话即可看到 htb-skill-index 等 T1 卡
```

Linux / Kali 同理，路径换成克隆目录即可。

> 注意：插件挂载后，`~/.dsh/skills` 里的同名散装技能会与插件里的卡**重复**（同名时 preset 层会遮蔽全局层）。迁移时先备份再清空散装目录：
>
> ```sh
> mv ~/.dsh/skills ~/.dsh/skills.bak   # 确认插件生效后再删除
> ```

## 目录结构

```
dsh-htb-skills/
├── package.json          # dsh.bundle.patch 指向 cordis.patch.yml
├── cordis.patch.yml      # 注入 host 插件行：- id: htb-skills
├── src/index.js          # 插件本体：注册 htb skill provider（无浏览器半区）
├── skills/               # 114 张技能卡（SKILL.md + frontmatter）
│   ├── htb-skill-index/  #   总索引（T1，进目录）
│   ├── box-startup/      #   T1 路由卡示例（含 key-state 产物规范）
│   └── ...               #   T2/T3 卡带 disable-model-invocation: true
├── docs/
│   ├── CARD-NORMS.md     # 卡片写作规范（可解析工件/漏洞形状/语义 rubric/子代理隔离）
│   └── ARCHITECTURE.md   # 架构与变异点地图（机制域 vs 内容域，改框架先读它）
└── scripts/
    ├── triage_skills.py  # 分层/修 whenToUse/修坏链/重生成索引卡（末尾自动跑路由审计）
    ├── fix_yaml.py       # 全量 YAML 引号规范 + PyYAML 校验（幂等：解码后重转义）
    ├── audit_routing.py  # 路由完整性审计（只读）：名字唯一性/MAPPING 双向一致/
    │                     #   tier 与 disable-model-invocation 一致/索引卡新鲜度/跨卡引用可解析
    └── verify_run.py     # 判定层：flag/cred 捕获事件的确定性复核（读磁盘 transcript）
```

### 卡片的 frontmatter 约定

```yaml
---
name: web-attacks
description: 'Web 攻击综合手册：OWASP 2025 映射→…'
whenToUse: '目标有 HTTP/HTTPS 攻击面时：…'
# T2/T3 卡额外带这一行；T1 卡不写：
disable-model-invocation: true
metadata: { domain: web, tier: T1 }
---
```

- `domain` 取值：`meta / web / ad-win / linux / db / cloud / creds / forensics / network / tools`
- `tier` 取值：`T1`（进目录）/ `T2`（深度，按名加载）/ `T3`（参考与题源，按名加载）

## 维护

改完技能后跑一遍校验链（需 `pip install pyyaml`；三个脚本都幂等，可重复跑）：

```sh
python scripts/fix_yaml.py        # 规范引号 + 校验全部 frontmatter
python scripts/triage_skills.py   # 分层元数据 + 重生成索引卡（末尾自动跑路由审计）
python scripts/audit_routing.py   # 路由审计：引用解析/索引一致性（任一错误退出码 1）
```

audit_routing.py 检查的路由面：卡名合法且唯一、目录名与卡名一致（警告）、`MAPPING` 与磁盘双向覆盖（索引不会挂空、不会漏卡）、`metadata.tier` 与 `disable-model-invocation` 一致、索引卡与 `MAPPING` 生成内容逐字节一致（STALE-INDEX）、卡内 backtick/[[wiki]]/中文路由关键词（加载/详见/见/查…）引用的名字全部可解析（DANGLING-REF），以及引号翻倍回归守卫（QUOTE-RUN-CORRUPTION）。

新增一张卡 = 在 `skills/` 下建目录 + 写 SKILL.md + 在 `scripts/triage_skills.py` 的 `MAPPING` 里登记 domain/tier，重跑校验链。插件 `watch` 默认开启，编辑后无需重启。

## 发布到 GitHub / npm

```sh
git init
git add .
git commit -m "dsh-htb-skills: initial HTB skill library plugin"
gh repo create dsh-htb-skills --public --source=. --push   # 或手动 git remote add + push
```

- 建议给仓库加 [dsh-plugin](https://github.com/topics/dsh-plugin) topic 方便被发现（官方生态指引）；
- 发布 npm：`npm publish`，之后两台机器都可以 `dsh plugin --profile <name> add dsh-htb-skills` 安装；
- 升级 = `git pull`（link 安装）或 `dsh plugin --profile <name> update dsh-htb-skills`（npm 安装）。

## 兼容范围

- DeepSeek Harness `0.1.0-rc.x`（与 `@deepseek-ai/dsh-skill-filesystem ^0.1.0-rc.6` 对齐）；
- Node `^22.19.0 || >=24.0.0`；
- Harness 仍处于开发者预览期，升级后如有破坏性变更请对照上游 `skill-filesystem` 的导出再使用。

## 许可证

MIT。技能卡内容移植自 Reasonix Studio 的个人技能库。
