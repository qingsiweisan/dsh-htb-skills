# 卡片写作规范(CARD-NORMS)

> 面向本仓库维护者与未来卡片作者。四条规范移植自 Anthropic defending-code-reference-harness 的 prompt 工程层(详见 docs/prompting.md 与 harness/prompts/*),已在实战中验证:规范写进卡片的点,模型执行率显著高于靠自觉的点。
> 核心原则:**机制 > 提醒**——凡是关键行为,卡里要给出可检查的契约,而不是"请务必……"。

## 1. 跨阶段消费的输出,必须有 schema(可解析工件,而非散文)

**来自**:file-as-contract + "让模型输出可验证工件,而非散文"。

- 凡是一个阶段的输出会被另一个阶段/工具消费的,卡里必须内嵌其 schema 与落盘时机。
- 现状参考实现:
  - `box-startup`「key-state 规范」:`<box>-state.jsonl`,六事件型(flag/cred/access/artifact/deadend/note),append-only,`evidence` 必须是可重放命令——被 `capture-verdict` 与 `scripts/verify_run.py` 消费。
  - `capture-verdict`:三步流程 + 五条否决项,每条否决项对应 verify_run.py 的一个确定性检查。
- 写作要求:新输出契约必须能回答三问:**谁消费它?怎么解析它?解析失败算什么?**(参考他们的 fail-open/fail-closed 分阶段决策。)

## 2. 描述漏洞形状,不要列清单

**来自**:docs/prompting.md "Describe Vulnerability Shapes, Not Checklists" —— 枚举漏洞类会**降低召回**(模型过度聚焦被点名的类,漏掉其余);正确做法是描述结构性属性。

- 好例子(他们的 vuln-scan):"攻击者输入改变了解释型语言的语法结构" —— 而不是 "找 SQLi、XSS、CSRF"。
- 对我们:CVE/技术卡的第一段应先写**触发该漏洞的结构性条件**(什么输入经过什么路径到达什么危险操作),再给具体命令;禁止把卡片写成"工具 A 命令 1、命令 2、命令 3"的清单(例外:quickref-cards 的定位就是速查清单,允许)。
- 新增漏洞类时:先问"这个 bug 的形状是什么",再写卡;两张卡描述同一形状 = 该合并。

## 3. 要求判定的地方,给证据锚定的 rubric

**来自**:report_grader 的 0/1/2 语义锚点 + "语义 rubric 而非关键词扫描"。

- 凡是卡里要求模型"判断/评级/确认"的,必须给出可判定的证据标准,而不是关键词列表:
  - 0 = 空/复述(无证据);
  - 1 = 有推理无证据(没有 file:line / 没有实际运行输出);
  - 2 = 证据挂引用(file:line、命令输出、复现观察)。
- 现状参考实现:`capture-verdict` 五条否决项(每条都指向 transcript 里可查的事实)。
- 写作要求:判定标准写成"可被 verify_run.py 这类工具复核的谓词",写不出谓词的判定 = 判不准的判定,删掉或降级为提示。

## 4. 子代理隔离靠机制,不靠提醒

**来自**:triage/patch 技能的"禁 fork + 单消息并发 + 最小信息"。

- 任何要求并行子代理的卡,必须写明三件套:
  1. **不 fork**:用独立上下文的子代理(subagent),禁止继承主对话(fork)——共享上下文传播盲区;
  2. **单消息并发**:所有并行任务在同一条消息里一次性发出;
  3. **最小信息**:每个子代理只喂它自己任务需要的最小输入,互不见推理。
- 现状参考实现:`parallel-recon` 模式 A 规则。
- 为什么写进卡而不是指望模型自觉:独立性是统计性质,只有机制保证它;一条"请独立判断"的提醒不产生独立性。

## 附:写作风格基线(继承既有约定)

- frontmatter:name/description(含触发短语)/whenToUse(T1)/metadata{domain,tier}/disable-model-invocation(T2/T3)。
- 卡内引用其它卡用反引号卡名(被 scripts/audit_routing.py 解析为引用);新出现的非卡名 token 记得进 WHITELIST。
- 写完跑 `python3 scripts/triage_skills.py`(0 errors 才算过)。
