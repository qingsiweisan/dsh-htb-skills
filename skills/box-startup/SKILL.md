---
name: 'box-startup'
description: 'HTB 靶机启动：5件必做→双轨查询→粘滞点匹配。核心骨架，战术细节按需加载。'
whenToUse: '开始打一台新 HTB 靶机时：5 件必做 + 双轨查询 + 粘滞点匹配，其余战术按需加载。'
metadata: { domain: meta, tier: T1 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

# HTB 靶机启动流程

> 🔴 **5 件必做 + 双轨查询 + 粘滞点。其余战术细节按需加载。**

## ⛔ 禁止行为

```text
❌ "我看到 X，可能是什么？" → 读工作区的 <box>-progress.md 进度文件（自己维护的进度笔记）！
❌ "接下来怎么办？" → 先查「阶段0 决策路由」，读工作区的 <box>-progress.md 进度文件再分流！
❌ "我好像卡住了" → debug-5whys！
❌ 同一路径失败 ≥3 次 → 强制 debug-5whys
❌ AES256 Kerberoast → 不爆破，换委派路径
❌ 工具第一次认证失败 → 先查「工具局限表」确认是否支持此认证方式
❌ 攻击链已写在文档里 → 不自行"探索"已排除的死路
🆕 ❌ 不看 --help 直接敲命令
🆕 ❌ 凭记忆编 CVE 编号
🆕 ❌ 手写反弹 shell（用进度文件模板）
🆕 ❌ Windows 命令用 - 代替 /
🆕 ❌ 模型说"X 有 Y 漏洞"不验证直接执行
```text

## 🔴 启动时必做 5 件事

```text
[1] 时钟同步: ntpdate -b <DC_IP>  (Kerberos 不工作的第一原因)

[2] 加载记忆: 本地笔记「<靶机名>」 → 复用上次攻击链
    记忆匹配≥2 → 直接读该靶机记录，不再从头枚举

[3] 隧道方案: 只建一种 (首选 chisel SOCKS)，不混用
    验证: ss -tlnp | grep <端口> && ps aux | grep chisel

[4] 凭据去交互: 拿到任何密码/TGT 立刻存文件，不每次手工输入

[5] 已知链复用: 记忆中有完整链 → 逐步骤原样执行 → 卡住才分析
    🔴 已知链重打 = 变更检测，不是重扫:
        a. 先验证原链入口（ssh/curl/原端口版本/认证状态）— 一条命令
        b. 入口未变 → 直接走原链，跳过 nmap -p- 全端口重扫
        c. 入口变了（版本/端点/认证/404）→ 才回到阶段1 全量扫描
        d. 每步验证配置是否变化（Browsed: marimo 从无认证→token 认证 = 变化信号）
```text

## 🆕 核心原则速查

```text
🔴 控制账户 ≠ 知道密码 → 委派模拟优先于找密码
🔴 AES256 Kerberoast → 不可爆破 → 换委派路径
🔴 MSSQL 连接必须用 FQDN 不能用 IP → SPN 匹配
🔴 groupType Global→Domain Local 不可直跳 → 经过 Universal
🔴 certipy template 不支持 Kerberos ccache → bloodyAD set object
```text

## 🆕 工具局限表

| 工具 | 不支持 | 替代方案 |
|------|--------|---------|
| `certipy template` | Kerberos ccache | `bloodyAD set object` 直改 LDAP |
| `bloodyAD msldap modify` | 整数属性 | `set object` 的 `-v=` 格式 |
| `impacket-mssqlclient` | IP (SPN 不匹配) | **必须用 FQDN** |
| `certipy shadow` | 无 CA 的 KDC | 换 RBCD 路径 |

## 🩹 粘滞点速查

> 🔴 **同一错误出现 2 次 → 查下表 → 匹配到 → 直接用已知方案。**

| 错误特征 | 根因 | 方案 |
|----------|------|------|
| `KDC_ERR_PREAUTH_FAILED` (AES) | PBKDF2 输出当 AES key | `aesKrbKeyGen.py -host`, RFC 3961 |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | IP 而非 FQDN | 改成 `@dc2.domain.htb` |
| `ERROR_NOT_SUPPORTED` (groupType) | Global→Domain Local 直跳 | 经过 Universal (-2147483640) |
| `KDC_ERR_PADATA_TYPE_NOSUPP` | KDC 无 CA | 换 RBCD 路径 |
| `KRB_AP_ERR_SKEW` | 时钟偏差 | `ntpdate -b <DC_IP>` |
| `KRB_AP_ERR_MODIFIED` (SOCKS) | SOCKS 破坏 Kerberos | 换直接端口转发或本地操作 |
| （完整粘滞点表见 blocking-points-detail 卡） | | |

## 🆕 困境分类 → 记忆映射表（卡住时先输出标签再动手）

> 🔴 **机制：自动 recall 扫描对话文本匹配记忆索引。卡住时先输出"困境分类标签"（类型+关键词），让相关记忆自动送进上下文——不靠自觉想起。**
> 🔴 **输出格式（不可跳过）: `🔴 困境类型: <...> | 🔴 关键词: <隧道 relay 445 SMB...>`**

| 困境类型 | 自动 recall 应命中的记忆 |
|----------|------------------------|
| 网络可达性/端口全封 | `tunneling-port-forwarding`（隧道）/ `unknown-service-probe` |
| 权限不足（提权） | `linux-privesc` / `windows-privesc` |
| 认证失败（AD） | `mssql-attack-chain` / `ntlm-relay-chain` / `kerberos-only-ad` / `adcs-attack-chain` |
| 信息缺失/方向未知 | `enumeration-command-layer` / `unknown-service-probe` / `attack-surface-meta` / `no-hint-solving` |
| 工具行为异常 | `blocking-points-detail`（三问表）/ `derive-command` / `netexec-escape` |
| SQL/MSSQL 相关 | `mssql-attack-chain`（含 SUSER_SID 取域SID + sys.server_role_members 完整查询） |

## 🆕 不直觉的触发规则（保留 5 条）

> 🔴 **这些是新手容易忽略的信号——不是常规的"Web→web-attacks"。**

| 信号 | 操作 |
|------|------|
| `ss -tlnp` 发现 `srw-rw----` (Unix socket) | 检查 socket GID → 当前用户在此组? → `python3 -c "import socket;s=socket.socket(socket.AF_UNIX);s.connect(...)"` |
| 发现 RODC / `krbtgt_XXXX` 账户 | 加载 `rodc-privesc-chain`，不尝试常规 DCSync |
| UAC=4128 / nxc -M pre2k 命中 | 加载 `pre2k-attack`，密码=小写主机名 |
| SMB 可写共享但无凭据 | 加载 `scf-ntlm-theft`，投放 .scf → Responder |
| 打印机 Web UI / 515/631/9100 | 加载 `printnightmare-printer-leaks` |

---

## 阶段流程（v6 — 阻断点嵌入）

```yaml
阶段0: 🔴 决策路由（先定模式，再分流）
        ├─ 用户指定纯自动化任务 → 走自动化主循环（阻断点1/2/3 仍适用）
        ├─ 默认手动模式 → 读工作区 <box>-progress.md 进度文件（自己维护的进度笔记）
        │   ├─ 命中≥2 → 复用已知链，逐步骤原样执行
        │   └─ <2 → 加载 no-hint-solving（A–E 与进度文件阻断点4 二选一，不重复执行）
        └─ 两条路径切换必须显式声明，禁止中间态
        🆕 🔴 todo_write 开局: 建 9 步阶段清单（映射 htb-workflow）→ 每步完成 todo_write 工具 签收
阶段1: nmap 两步扫描 (PTY 全端口 → bash 工具 版本识别，禁 masscan) → 🔴 阻断点2: 侦察字典 (每个端口跑固定探测，不靠LLM探索)
        🆕 🔴 并行子代理/parallel-recon 强制: 版本扫描后，端口探测+搜索全部丢 subagent（2-8 并行）
            → 主上下文只收结论摘要，细节 subagent 返回结果 按需取（Hercules: 串行灌爆上下文压缩3-4次）
        ├─ HTTP/S → whatweb + gobuster + ffuf vhost + curl headers
        ├─ SMB → nxc 匿名 + smbclient 枚举
        ├─ 其他端口 → 查侦察字典表逐项执行
        ├─ 🔴 阻断点4: 攻击面穷举框架 (仅未加载 no-hint-solving 时执行；已加载 → 跳至其 A–E，二选一不重复)
        │   ├─ A: Web 注入探测矩阵 (6种注入各1个请求)
        │   ├─ B: 服务CVE管道 (每个版本搜 searchsploit+GitHub)
        │   ├─ C: 文件泄露探测 (/.git /.env /robots.txt...)
        │   ├─ D: JS分析 (API路径+版本号)
        │   └─ E: 异常汇总 → 反推漏洞类型 → 按优先级排序
        └─ 🔴 全部端口探测跑完并收集结果 → 才进入阶段2
阶段1.4: 环境指纹 — 交互型漏洞先拿版本号
阶段1.5: 精简能力探测 — 指纹后只测不确定项
阶段2: 利用 → 凭据喷洒所有服务 → 动态失败聚类
阶段2.5: 🔴 阻断点1: SHELL_BOOTSTRAP (拿shell后硬性流程)
        ├─ Linux: 6组固定序列 → 产出本地状态报告 → 才允许提权
        └─ Windows: 5组固定序列 → 产出本地状态报告 → 才允许提权
        └─ 🆕 阻断点6: 无条件隧道判断 — ss -tlnp 看本机监听 → 外部端口全封?
            → ★立即 chisel SOCKS (R:socks) + proxychains ★（Signed 教训: 全封≠死路，隧道让受害者自己连自己）
        └─ 🆕 MSSQL 实例: 必查 sys.server_role_members 完整成员表（IS_SRVROLEMEMBER 只答"我是谁"）
阶段3: 提权 → linux-privesc / windows-privesc + ad-checklist
阶段4: 🔴 阻断点3: 方向对但操作不通 → 三问检查
        ├─ 第一问: 触发机制 — 读脚本加载逻辑了吗？
        ├─ 第二问: 工具行为 — curl/sudo/nc 有隐藏行为吗？
        └─ 第三问: 系统规则 — sudo精确匹配/cron PATH/AppArmor？
阶段5: 收尾 → flag → 攻击链 → quirk 入库
        🔴 收尾强制三步（每台打完）:
        [1] 记忆沉淀: 靶机名/完整攻击链/quirk 写入工作区笔记(<box>-complete.md)；
            有 memory MCP 的会话 → 实体+关系补建（先 search_nodes 查重，存在则 add_observations）
        [2] 技能反哺: 新 quirk/教训补进对应场景卡（场景命名优先）；改完跑 triage 校验
        [3] 变更复盘: 本次哪条规则"想到了没用/用了不对" → 记入下次收尾检查
```text

## 🔗 按需加载的专项 Skill

> 🔴 **不自动加载。agent 按需用 skill 工具加载 <name>。**

| 场景 | Skill | 关键内容 |
|------|-------|---------|
| Web 端口 | `web-attacks` | 先读顶部索引定位技术栈 |
| 非 Web 服务 | `service-attacks` | 先读顶部索引定位端口 |
| Linux shell | `linux-privesc` | 先读顶部索引匹配内核版本 |
| Windows shell | `windows-privesc` + `ad-checklist` | 先 SharpHound |
| 凭据到手 | `password-attacks` + `lateral-movement` | hashcat 模式选择 |
| 容器/Pod | `container-escape` | privileged/capabilities 检查 |
| AD 域 | `ad-checklist` | 攻击路径优先级 |
| 同一路径失败 ≥3 | `debug-5whys` | 假设审计→二分验证 |
| 记忆无匹配 | `no-hint-solving` | A→E 自主发现五阶段 |
