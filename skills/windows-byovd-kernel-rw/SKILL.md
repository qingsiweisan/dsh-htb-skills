---
name: 'windows-byovd-kernel-rw'
description: '第三方/自带驱动 BYOVD 原语：服务枚举发现 `\??\C:\...\x.sys`（自定义路径 + 带 PDB 路径 = 自编译）→ 反汇编取设备名与 IOCTL，**重点找 METHOD_NEITHER 且不 Probe 的 IOCTL**（本例三段式：`0x80002003` init 从裸用户指针读 0x20 字节 {magic, tid, prio, src, dst} / `0x8000200b` = `*(u64*)dst = *(u64*)src` 任意内核读写 / `0x80002007` free）→ `\\.\Device` 的默认 SD 常对 Users 开放（先试能不能直接 CreateFile）→ 用 `NtQuerySystemInformation(11)` 取 ntoskrnl base → 解析导出表拿 `PsInitialSystemProcess` → 遍历 `ActiveProcessLinks`（EPROCESS 偏移 pid 0x440 / links 0x448 / Token 0x4b8 / ImageFileName 0x5a8，**偏移随版本，必须用 pid/ImageFileName 自校验**）→ 把 System 的 Token 写进本进程 → SYSTEM。含反直觉判据：**High 完整性级别 ≠ Administrators**（服务账户 `NT AUTHORITY\SERVICE` 即使 High IL 也读不了 `C:\Users\<user>\*`）。（检索词：BYOVD、bring your own vulnerable driver、内核提权、kernel privesc、第三方驱动、.sys、driver、服务枚举驱动、sc query type= driver、\??\C:\、\\.\Device、设备名、IOCTL、METHOD_NEITHER、METHOD_BUFFERED、不 Probe、ProbeForRead、任意内核读写、arbitrary kernel read write、token swap、token stealing、EPROCESS、ActiveProcessLinks、PsInitialSystemProcess、NtQuerySystemInformation、SystemModuleInformation、ntoskrnl base、EPROCESS 偏移、pid 0x440、Token 0x4b8、ImageFileName、SYSTEM token、SeLoadDriverPrivilege、kdmapper、RingReaper、capa、High integrity、高完整性、NT AUTHORITY\\SERVICE、服务账户不等于管理员、Administrators、Access denied、驱动签名、DSE、kernel read write primitive）'
whenToUse: '拿到 Windows 提权立足点（尤其服务账户/`NT AUTHORITY\SERVICE` 这类"High IL 但非管理员"的令牌）时；或服务枚举/驱动列表里出现非微软的 `.sys`（自定义路径、带 PDB 路径、Auto+Running）；或已知目标装了自带内核驱动（HTB 机器常见自己写的驱动）。'
metadata: { domain: ad-win, tier: T2 }
---

# BYOVD：第三方驱动的任意内核读写 → SYSTEM

> 适用场景：目标机上跑着一个**自己写的驱动**（HTB 作者常自编译），设备只做一件事——把用户给的
> dst/src 拷来拷去。这类驱动通常**只检查 magic，不 Probe 用户指针**，于是"内核任意读写"白送。
> 拿到 SYSTEM token 只是收尾，难点在**确认原语 + 精确定位 EPROCESS**。

## 4. 🔴 反直觉判据：High 完整性 ≠ Administrators

服务账户（`NT AUTHORITY\SERVICE` / `LOCAL SERVICE` / `NETWORK SERVICE`）的进程常显示
`Mandatory Label\High Mandatory Level (S-1-16-12288)`，**看起来像"已经是管理员"**，实际：

```
whoami /groups     → 成员只有 Everyone / Users / Remote Desktop Users（**不在 Administrators**）
dir C:\Users\<user>     → Access is denied（Test-Path 也 false）
```
⇒ **别把 High IL 当提权完成**；`Administrator` 用户目录读不到就说明还得真提权。
另一条对称的坑：有了 `SeImpersonate` 才有 Potato 系；**先看 `whoami /priv` 再选路线**。

## 1. 触发信号（先怀疑，再验证）

```cmd
sc query type= driver state= all | findstr /I "RUNNING"
sc qc <Name>                     # 看 BINARY_PATH_NAME 与 START_TYPE
```
看这三样：①`\??\C:\<非 System32\drivers 路径>` ②二进制很小（几 KB）+ **带 PDB 路径**（自编译痕迹）
③`SERVICE_AUTO_START` + `RUNNING`。

## 2. 三步进门：设备 → IOCTL → 是否 Probe

1. **设备名**：反汇编找 `IoCreateDevice`/`IoCreateSymbolicLink` 附近的宽字符串
   （`\Device\Foo` 与 `\??\Foo`）。
2. **能不能打开**：作者往往不设 SD ⇒ `CreateFile("\\.\Foo", GENERIC_READ|GENERIC_WRITE, ...)`
   **普通 Users/服务账户就能成功**。先用一行 PowerShell 试，不要假设需要管理员。
3. **枚举 IOCTL**：看 `IRP_MJ_DEVICE_CONTROL` 的 switch，记录
   `CTL_CODE(FILE_DEVICE_UNKNOWN, N, METHOD_*, FILE_ANY_ACCESS)` 的实际值。

| 判据 | 含义 |
|---|---|
| `METHOD_NEITHER` | **参数是裸用户指针**，驱动自己决定要不要 `ProbeForRead/Write` |
| 无 `ProbeForRead/Write` | ⇒ 用户态给的任意地址都会被直接解引用 ⇒ **任意内核读写** |
| `METHOD_BUFFERED` | 参数经 IO manager 拷贝，一般只影响 SystemBuffer，价值低 |

**三段式是最常见的形态**（本例）：init（从用户结构读参数存起来）/ act（按存好的 dst,src 做一次 qword 拷贝）/
free（释放 pool）。只要 act 是"`*(u64*)dst = *(u64*)src`"，你就有了 **8 字节任意读写**。

## 3. 从任意读写到 SYSTEM（token swap）

```
NtQuerySystemInformation(SystemModuleInformation=11, buf, len)   # 普通用户可用
   → buf[0].ImageBase = ntoskrnl 基址
解析 ntoskrnl 导出表 → PsInitialSystemProcess（一个 PEPROCESS 指针）
遍历 ActiveProcessLinks 双向链表，逐项校验：
   pid        @ EPROCESS+0x440   （System = 4）
   ImageFileName @ +0x5a8        （ASCII，用来确认"这是我自己的进程"）
   Token      @ +0x4b8           （EX_FAST_REF，低 3 位是引用计数）
把 System 进程的 Token 写进本进程的 EPROCESS.Token
```

要点：
- **偏移随 Windows 版本变**（本例 Win10 19045：pid 0x440 / links 0x448 / Token 0x4b8 / ImageFileName 0x5a8）。
  定位办法：先扫链，用 `pid==4` 找 System 项，再用 `ImageFileName` 反查自己那一项 —— **靠这两个自校验，
  不靠猜偏移**。
- 写 Token 前把原值存下来，失败要能回滚；`Token` 低 3 位保留，按 `old & 7 | new` 处理更稳。
- 拿到 SYSTEM 后**在同一个进程里**读目标文件即可（token 已换，句柄权限随之提升；
  若在换 token 前打开过文件句柄，权限不会回溯升级 —— 重新打开）。

## 5. 前置检查与备选

- 打开设备失败（`ERROR_ACCESS_DENIED`）：看 SD 或换 `SeLoadDriverPrivilege` 路线（需管理员/服务权限）。
- 驱动被 DSE（驱动签名强制）拦：HTB 场景一般不涉及（驱动已装好在跑）；真实环境看 `bcdedit /set testsigning` 是否可行。
- 只想读内核内存也可以用同原语读 `nt!` 结构与 KASLR base（不必写，先证明读通了再写）。
- 落地脚本建议：一次进程内完成"读 base → 找 EPROCESS → 换 token → 读文件"，
  **幂等 + 失败回滚 token**，避免把机器打挂后无法复位。

## 6. 坑清单

1. `NtQuerySystemInformation(11)` 返回的是"已加载模块数组"，**第 0 项通常是 ntoskrnl**，但要按
   `ImageBase` 最大值/名字 `nt` 校验，别硬编码下标。
2. EPROCESS 偏移**跨版本漂移**；用 `pid`/`ImageFileName` 双校验，找不到就换偏移假设，不要盲写。
3. `ActiveProcessLinks` 是**环形**双向链表：从 `PsInitialSystemProcess` 起遍历，回到起点即结束。
4. 设备名与**服务名不同**（服务 `reaper` / 设备 `\\.\Reaper`）；符号链接没建时只能 `\Device\...` 访问（需权限）。
5. 写内核前先把"读"验通（读 `nt!` 里的已知值 / 读自己的 EPROCESS 对照 `pid`），**先读后写**。

## 7. 与其他卡的关系

| 卡 | 分工 |
|---|---|
| `windows-privesc` | 总检查表；§3.7 是"服务/驱动枚举 → 本卡"的路由入口 |
| `edr-evasion` | BYOVD 用于关 EDR/回调时的对抗视角（本卡只管提权） |
| `htb-machine-reset-recovery` | 打挂服务/驱动后的复位流程 |
