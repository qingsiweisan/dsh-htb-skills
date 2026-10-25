# dsh-htb-router

Deterministic skill router for DeepSeek Harness HTB sessions.

## 它解决什么问题

三轮同靶机盲打验证证明:模型侧路由(让模型"自觉"加载技能卡)只在流程起点可靠;流程中途的阶段(云凭据到手、进入容器、CodeBuild 阶段)会系统性跳过相关卡——模型判定"这些知识我预训练里已有"。而卡里恰恰存着它没有的实战细节(IMDS 十进制绕过、CodeBuild 8 个 quirk)。

本插件把"选卡"这个动作从模型手里拿走:监听 harness 的 `tool/call` 事件(工具执行前记录),用**技术关键词正则**(协议/服务/命令,非靶机特定)判定当前攻击阶段,命中即把对应技能卡**正文直接注入**模型上下文。模型不需要选择、甚至不需要服从——知识已经在眼前。

## 原理

```
模型敲出 bash "aws sts get-caller-identity…"
        ↓ harness 在工具执行前发出 tool/call 事件
htb-router 规则表匹配(aws/sts/sqs → aws-attack-surface + cloud-attacks)
        ↓
agent.inject(卡正文) → 模型下一步决策时知识已在上下文中
```

- **确定性访问**:注入由框架事件驱动,不依赖模型自觉
- **通用性**:规则基于技术关键词(SSRF/IMDS/AWS/容器/AD/Linux 提权),适配黑箱目标
- **克制**:每张卡每会话只注入一次,默认最多 8 次注入、单卡正文截断 20KB,不撑爆上下文
- **可逆**:随插件生命周期自动卸载

## 安装(Kali DSH)

本插件**随主仓库一起发布**，位于 `dsh-htb-skills/router/`，不需要单独 clone：

```bash
git clone https://github.com/qingsiweisan/dsh-htb-skills.git
cd dsh-htb-skills
dsh plugin --profile web add link:./dsh-htb-skills          # 技能库 + 守卫
dsh plugin --profile web add link:./dsh-htb-skills/router   # 本插件
# 重启 dsh web 进程生效
```

> 早期版本把 router 作为独立仓库 `~/dsh-htb-router` 安装；`htb_brief` 读规则表时
> 会**先找包内 `router/`，再退回 `~/dsh-htb-router`**，两种布局都能用。

规则表与阈值在 `cordis.patch.yml` 的 row config 里,改完重启生效。

## 与 dsh-htb-skills 的分工

- `dsh-htb-skills`(根目录):164 张技术卡 + 5 个观测/守卫模块 + 9 个 `htb_*` 工具
- `dsh-htb-skills/router`(本目录):确定性路由 —— 在正确的时刻把正确的卡投递给模型
