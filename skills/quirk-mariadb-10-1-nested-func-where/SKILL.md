---
name: 'quirk-mariadb-10-1-nested-func-where'
description: 'MariaDB 10.1.x 嵌套函数在 WHERE 子句失效的 quirk，替代方案为 HEX(LEFT()) 精确匹配'
disable-model-invocation: true
metadata: { domain: db, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## MariaDB 10.1.x — 嵌套函数在 WHERE 子句中失效

**Why:** Writeup HTB 盲注实战中发现: 所有嵌套函数调用 (RIGHT(LEFT(col,N),1) / LEFT(RIGHT(col,N),1) / RIGHT(HEX(LEFT(...)),2)) 在 WHERE 子句中全部返回 False，但单层函数 (LEFT/RIGHT/ASCII/HEX) 正常工作。排查 40 分钟才定位到是 MariaDB 10.1 版本 quirk 而非 WAF 过滤。

**How to apply:**
- `RIGHT(LEFT(col,N),1)` → 不可用，改用 `HEX(LEFT(col,N))=HEX(0x<prefix><byte>)` 精确匹配
- `LEFT(RIGHT(col,N),1)` → 不可用
- `RIGHT(HEX(LEFT(...)),2)` → 不可用
- `CONV(HEX(...),16,10)` → 不可用 (CONV 函数本身可能被禁)
- 替代方案 A: HEX(LEFT(col,N)) 精确匹配逐字符穷举 (这次用的)
- 替代方案 B: 如果有报错注入，用 extractvalue 一次性拿数据
- 替代方案 C: 如果 >=/<= 可用，直接二分 (但 MariaDB 10.1 上字符串 >=/<= 也不可用)

**Affected:** MariaDB 10.1.x, 可能含 10.0/10.2
**Verified:** 2026-07-14, Writeup HTB (10.129.33.6)
**Cost:** ~40 min to discover
