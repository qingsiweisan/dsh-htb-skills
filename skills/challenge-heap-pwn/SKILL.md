---
name: 'challenge-heap-pwn'
description: 'glibc 堆 pwn 全流程:UAF 漏洞定位→按 glibc 版本选技术(safe-linking/TSU+/House of IO)→FSOP/部分覆盖泄漏→hook 时代与无 hook 时代收尾→seccomp 绕过（检索词：challenge heap pwn）'
whenToUse: 'HTB challenges 或靶机遇到菜单式堆题/附带 libc 的 pwn 时:漏洞定位→版本决策→泄漏→任意分配→shell。'
metadata: { domain: pwn, tier: T1 }
---

# glibc 堆 pwn playbook(Dream Diary: Ch4 + Quantum Memory Manager 沉淀)

> 前置: challenge-insane-playbook §2 纪律。先加载本卡再动手。

## 0. glibc 版本 → 可用技术速查

| glibc | 关键差异 | 主流路线 |
|---|---|---|
| <2.26 | 无 tcache | fastbin/unsorted attack、House of Force |
| 2.29–2.31 | tcache double-free 检查(key 字段) | tcache poisoning(无 safe-linking,直接写地址) |
| 2.32–2.33 | **safe-linking** `(pos>>12)^ptr` + 对齐检查;**有 __free_hook/__malloc_hook** | tcache 污染(需堆泄漏)→ hook + gadget 迁栈 |
| 2.34+ | **hook 全删**;更严检查 | House of IO / House of Rust / FSOP / IO_→改返回地址 |

## 1. 标准流程(七步)

1. **逆向定位漏洞**:先看 free/edit/show 的校验缺口(计数与遍历分离判断→自环双 free;只查 perm 不查 count);再看**非分配函数**里"数学量往返转换后与 rand() 比较"的概率后门——浮点不幂等可使所有分支落空却解锁已 free 块(Quantum 的 measure())。
2. **泄漏**:calloc 不查 tcache、malloc 才触发装箱 → 用"malloc 清 tcache,calloc 取 unsorted"分离控制;unsorted→largebin 后 `fd_nextsize/bk_nextsize` 是免 free 泄堆源;写 1 字节污染 bk 残留泄 libc;无泄漏时对 tcache 头做末 1–2 字节部分覆盖(1/16)打 `_IO_2_1_stdout_` 等低熵目标。
3. **整形**:精确控制 tcache/unsorted/fastbin 布局,让"要重叠的块"相邻;free 顺序决定合并结果。
4. **任意分配**:
   - 直接 tcache 污染:data 起始偏移(+8)挡住或 House of Lore 已修补 → 用 **Tcache Stash Unlink+**:smallbin→tcache 搬运循环信任 `tc_victim->bk`,先堆喷保证伪地址处有合法 fd/bk,借 `scanf` 内部 malloc 触发排序(非法选项不退出菜单=免费 malloc),覆盖链尾 bk,抽走真块后第 4 次分配触发搬运。
   - 2.34 无 hook:超 arena 上限(`mallopt(M_ARENA_MAX)` 定死/多线程)让新线程的 0x290 tcache_perthread_struct 落进同堆(**House of IO - Heap Reuse**),伪 size 把小块填进大 bin(每次 free 后回写安全值绕检查)= 拿到全部 bin 表读写权。
5. **FSOP 泄漏四件套**:块头写 `p64(0xfbad1800)+p64(0)*3`,改 `_IO_write_base` → puts 回显内存;指向 `environ-8` 泄栈。每次部分覆盖必须保持同一 ASLR 变体字节。
6. **控制流收尾**:
   - 有 hook(glibc≤2.33):`__free_hook-0x10` 落块(safe-linking `((heap)>>12)^(target-0x10)`),hook 写 COP gadget `mov rdx,[rdi+8]; call [rdx+0x20]`,free 时 RDI=块址 → setcontext+61 `mov rsp,[rdx+0xa0]` 迁栈到堆 ROP。
   - 无 hook(2.34+):任意分配到返回地址 → `"\x00"*N + pop_rdx + one_gadget`。
7. **seccomp**:先 `seccomp-tools dump` 看黑名单;**不查 arch(eSCAS 未启)→ `push 0x23; push addr; retfq` 切 32 位 + `int 0x80` execve**;x32 技巧(syscall+0x40000000)也可能被封;白名单按 vmmap 硬编码时,常漏 libc 之后的匿名 rw 区(__free_hook 所在)。

## 2. 命令模板

```bash
# 版本指纹与偏移动态计算
./libc.so.6 2>/dev/null | head -1; one_gadget ./libc.so.6; ROPgadget --binary ./libc.so.6 --only "mov rdx"
# docker 内复现远端 + 调试
docker run --rm -it -v $PWD:/h ubuntu:22.04 /bin/bash  # 换上题目 libc/ld
gdbserver :1234 ./chall
```

```python
# safe-linking / safe-linking 解码
def mangle(pos, ptr): return ((pos >> 12) ^ ptr)
heapleak = u64(p.recv(6) + b'\0\0')   # 常规堆泄漏读法(截断 6 字节)
```

## 3. 🔴 坑

- **概率利用(1/16 部分覆盖/浮点 UAF)必须整链循环重试**,单次失败≠链错。
- 多次部分覆盖要用**同一 ASLR 变体**的字节(首次覆盖后固定,后续沿用)。
- calloc **清零**会毁掉堆喷数据:地址安排避开后续 calloc 落点。
- 预留 tcache 空位(搬运循环要抽 3 真块+1 伪造);填满 tcache(7 个)才进 fastbin。
- 伪块 free 后**回写安全值**绕 double-free/tcache 检查;free 顺序决定合并。
- data 段偏移(+8)可能挡住直接 tcache 污染——先算清块内偏移再选技术。
- IDA 对大常数指针运算反编译会错,**看汇编**核对。
- 远端无 ls/cat:shell 内建 `echo`+`read` 逐字节读 flag。
- 作者排除的路线也记下来(Quantum:House of Rust 需 stable largebin 排序、尺寸受限+无 scanf/fgets 时做不到)——排除法本身就是定位手段。

## 4. 同类型决策树

```
拿到堆题 →
├─ 逆向: alloc/free 本体有洞? ──→ 直接 UAF/double-free
├─ 非分配函数的数学/随机比较 ──→ 概率性解锁已 free 块
├─ 指针白名单/seccomp? → 先定绕过路线再设计利用
├─ glibc ≤2.33: 泄堆+libc → tcache 污染(safe-linking) → hook+COP+setcontext
├─ glibc ≥2.34: 无 hook →
│   ├─ 有泄漏 → tcache 污染 → 任意分配改返回地址/FSOP
│   ├─ 无泄漏 → 部分覆盖打 stdout(1/16) → FSOP 依次泄 libc→heap→stack
│   └─ arena 上限可破 → House of IO(tps 重叠 = bin 表读写权)
└─ 题面多余机制(entangle/manage/memcpy) → 现成 write-what-where,先审计
```
