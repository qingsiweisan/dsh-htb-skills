---
name: 'no-hint-solving'
description: '无hint做题：知识图谱无匹配时切换到自主发现模式。系统化枚举→版本CVE→源码攻击面→行为实验。禁止问用户。'
whenToUse: '知识图谱无匹配、遇到新题型自主发现时：枚举→版本 CVE→源码攻击面→行为实验；禁止问用户。'
metadata: { domain: meta, tier: T1 }
---

# Skill: 无 hint 解题 — 自主发现协议

> 🔴 **这是当知识图谱查不到匹配时的逃生舱，不是参考文档。**
> 🔴 **禁止问用户"怎么办"。要么按本协议执行，要么报告"以下路径已穷尽"。**

## 触发条件

```
在挂有 memory MCP 的机器上（Windows 教练会话）search 返回空或不相关 → 进入本协议；Kali 打靶机无此 MCP，等价物为读进度文件 + htb-skill-index 查卡
类比机器 < 2 台 → 进入本协议
```

## ⛔ 禁止行为
```
❌ "这个没见过" → 废话，按本协议开始枚举
❌ "可能是什么？" → 实验验证，不猜
❌ "你见过这个吗？" → 禁止问用户
❌ 翻 WP → 禁止
例外：用户明确授权搜索某卡点的通用技术或 writeup 时，以用户最新指令为准
```

---

## 阶段 A：攻击面穷举（30 分钟内完成）

### A1. 端口 → 服务 → 版本（两步）
```
[1] 全端口发现 (PTY 方式): bash 工具 "nmap -p- -sS -T4 -v <IP> -oN /tmp/ports.txt"
    → job_output 工具(idle_ms=300000) 等待完成 → 读取端口列表
[2] 版本识别: nmap -sV -sC -p PORT1,PORT2,... <IP> (bash 工具，≤30s)
    → 🔴 禁止一步 nmap -sV -sC -p-（违反「发现/版本分开两步」规则，且 -sC -p- 极慢）
对每个开放端口：curl/banner抓取 → 精确版本号
```

### A2. Web 攻击面（如果有 HTTP）
```
[ ] gobuster/ffuf 目录爆破（common + big wordlists）
[ ] ffuf vhost 枚举（必须做，不跳过）
[ ] 每个子域名独立处理：curl -H "Host: X" 
[ ] JS chunks 下载 → grep version/Version/VERSION → CVE 匹配
[ ] HTML 源码 → grep -E '(version|Version|VER|build)'
[ ] HTTP 响应头 → Server/X-Powered-By/Cookie 中的框架线索
[ ] robots.txt / sitemap.xml / .git/config / .env / composer.json
[ ] 每个输入框/上传点：行为测试（允许什么格式？报什么错？）
```

### A3. 认证攻击面
```
[ ] 注册/登录/密码重置 → 每个都走一遍，观察响应差异
[ ] 默认凭据表：admin/admin, root/root, guest/guest, 软件名/软件名
[ ] 弱密码喷洒：用表单自己的错误信息判断用户名是否存在
```

### A4. API 攻击面
```
[ ] 浏览器 DevTools Network 标签 → 抓所有 XHR/fetch 请求
[ ] /api/ /graphql /rest/ /swagger /docs /openapi
[ ] 每个 API 端点的参数：少一个会怎样？多一个会怎样？类型错了会怎样？
```

---

## 阶段 B：版本 → CVE 管道（发现版本号后立即执行）

```
对每个精确版本号，按顺序搜：
[ ] searchsploit <software> <version>
[ ] GitHub: "CVE <software> <version>"
[ ] NVD: https://nvd.nist.gov → 搜软件名
[ ] Google: "<software> <version> exploit"
[ ] GitHub Code Search: "<software>" "exec(" 或 "popen" 或 "system("

🔴 不过滤！先拿全列表再筛选。CVE 描述不含版本号不代表不能用。
🔴 每个 CVE 搜 PoC："CVE-XXXX-XXXXX exploit github"
```

---

## 阶段 C：拿 shell 后的提权发现

### C1. 第一秒（Linux）
```
id; uname -a; cat /etc/os-release
sudo -l; getcap -r /; find / -perm -4000 -type f 2>/dev/null
env; cat /proc/1/environ | tr '\0' '\n'
ps aux; ss -ntlp          # 内网服务 = 新攻击面
cat /etc/crontab; ls -la /etc/cron.*; systemctl list-timers
```

### C2. 第一秒（Windows）
```
whoami /all; whoami /priv
systeminfo; net user; net localgroup
netstat -ano | findstr LISTEN
dir "C:\Program Files"; dir "C:\Program Files (x86)"
env  # 或 set
```

### C3. 版本 → 提权 CVE
```
Linux: uname -r → searchsploit linux kernel <version>
       sudo -V → searchsploit sudo <version>
       dpkg -l → 每个包的版本 → searchsploit
       内网服务版本 → searchsploit

Windows: systeminfo → Windows Exploit Suggester
         whoami /priv → 特权令牌提权（SeImpersonate etc）
         已安装程序 → searchsploit each
```

---

## 阶段 D：行为实验（当 CVE 搜索无结果时）

> 🔴 **不要猜。改一个变量，观察输出差异。这是最被低估的技能。**

```
D1. 输入变化 → 输出变化
    改一个参数 → 错误信息不同？→ 泄露了内部状态
    加一个字段 → 接受了？→ 未做输入校验
    改数据类型 → 报错了？→ 泄露了后端语言/框架

D2. 文件上传行为
    .php 阻止了？→ 试 .php5 .phtml .phar .shtml
    .jsp 阻止了？→ 试 .jspx .JSP
    内容检查？→ 试 GIF header + PHP code
    路径遍历？→ ../../../

D3. 认证行为
    不存在的用户 vs 存在的用户 → 错误信息不同？→ 用户枚举
    空密码 → 什么错误？
    超长密码 → 溢出？

D4. 数据库注入行为
    输入 ' → 报错？→ SQL 注入
    输入 {{7*7}} → 输出 49？→ SSTI
    输入 <script> → 原样返回？→ XSS
    输入 ../../etc/passwd → 文件包含
```

---

## 阶段 E：源码审计（如果有源码泄露）

```
E1. git clone / tar xf 所有能拿到的源码
E2. grep -rE "(exec|system|popen|eval|shell_exec|passthru|Runtime\.exec|ProcessBuilder)" .
E3. grep -rE "(password|secret|key|token|credential)" .
E4. grep -rE "(upload|write|save|store)" . | grep -v ".git"
E5. grep -rE "(admin|root|sudo|su)" . | grep -v ".git"
E6. 配置文件：每个 config.* settings.* .env application.* → 读全
E7. 路由文件：每个 endpoint 追到 controller → 找未授权的
```

---

## 穷尽报告模板

> **当以上 5 阶段全部执行完仍未突破时，才允许输出此报告。**

```
穷尽报告：
- 目标：<IP>
- 开放端口：<list>
- 已识别软件/版本：<list>
- 已测试 CVE：<list>
- 已测试行为实验：<summary>
- 当前状态：在 <步骤> 卡住
- 最可疑的未验证假设：<具体到一行代码或一个参数>
```

禁止在穷尽报告之前问用户任何问题。
