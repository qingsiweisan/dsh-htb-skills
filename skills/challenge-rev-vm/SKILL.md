---
name: 'challenge-rev-vm'
description: '逆向 VM/exotic ISA(自修改代码/OISC)标准方法:提取字节码→自建模拟器→热点循环→相邻迭代 diff→OOB 内存快照→黑盒扰动实验,识别低效算法后离线重算（检索词：challenge rev vm）'
whenToUse: '遇到自定义 VM/Subleq 类 OISC/自修改代码/"程序运行极慢输出 flag"的 Rev 题。'
metadata: { domain: rev, tier: T1 }
---

# Rev-VM playbook(Substandard Optimization 沉淀)

## 1. 提取与语义还原(静态)

1. 从符号/段提取字节码:`_binary_prog_bin_start/end` 夹的数据;`struct.iter_unpack('<i', ...)` 按 ISA 字长拆;跳过文件头(n×int)。
2. 反编译 step/do_step 主循环还原指令语义(Subleq: `mem[b] -= mem[a]`,结果 ≤0 跳 c;I/O 扩展 `a==-1` 读、`b==-1` 写、`c==-1` halt)。
3. 🔴 扫描**有无输入指令**:无输入的确定程序不能用"按输入计数指令"侧信道,输出完全确定 → 想离线重算。

## 2. 动态分析三件套(自修改代码静态读不懂时)

```python
# 自建模拟器(内存自动扩容——程序会写到代码段外,不扩容必崩)
program = [x[0] for x in struct.iter_unpack("<i", f.read())]
def do_subleq(a, b, c):
    program[b] -= program[a]
    return program[b] <= 0
```

1. **热点定位**:只打印非常规跳转,反复出现的 `jmp X -> Y` 即热点循环。
2. **相邻迭代 diff 执行日志**:大量行相同、只有个别值递减/±1 toggle 在变 → 控制流不变,变的是数据 = 计数器。
3. **OOB 内存快照**:dump 越界内存,每轮计数器减 1 + 某 cell 在 ±1 间翻转 = `while (n>0) { n-=1; i=0-i; }`——**用 O(n) 循环次数实现本可 O(1) 的判断(奇偶/取模/比较)**。
4. **黑盒扰动实验**:单变量改内存初值(如 program[1203]=0/3)观察分支差异,控制变量法验证推断,比通读快。

## 3. 离线重算(识别出算法即停,不逆剩余代码)

```python
f.seek(3 * 4)                                  # 跳过文件头 3 个 int
chars  = struct.unpack("1200i", f.read(1200*4))  # 双等长数组按索引对应
values = struct.unpack("1200i", f.read(1200*4))
for c, v in zip(chars, values):
    if v % 2 == 1: print(chr(c), end='')       # 值域统计:大数=数据,单字节=ASCII/代码
```

## 4. 值域分割 code/data

- 值远超合法代码地址范围(32 位大数)= 数据;单字节小整数 = ASCII/小常量。
- 双等长数组按索引对应 + 1-bit 条件位(奇偶)= 逐位隐写信道;改初值可验证信道方向。

## 5. 🔴 坑

- 模拟器必须自动扩容内存(Subleq 天然自修改 + 写代码段外)。
- 头部 int 数要实测跳过(本题 3 个);`f.seek(3*4)`。
- WP 参考模拟器的 I/O 分支语义可能与原 VM 不一致(pc+3 vs addr+4)——照抄前对齐真实语义。
- 大数循环百万次:必须靠 diff+快照,不能真跑完。
- "运行极慢 prints the flag over a long time" 的题面描述 = 线性计数副作用的直接信号,直接找数据离线重算。

## 6. 变体:**程序自身即 VM 解释器,字节码走 stdin**(2026-10 实战,约 5 分钟)

**识别信号**:附件是**单个 stripped ELF**,没有独立字节码文件;`strings` 里出现
`Give me code to execute: ` / `Executing %d opcodes.` / `Bad instruction!` / `This is the right answer!`
⇒ **"special machine" 就是程序本身**,输入是它要解释的字节码。

**做法(不需要写模拟器)**:

1. **读 opcode 位域**:`opcode = 8 个 hex 字符 → strtol(…,16) → 32 位`;总长必须满足 `len/8 == N`(如 N=5)。
2. **逐字段还原**(实测一例):
   `sel = op>>24`(跳表 idx1..5 = MOV/ADD/SUB/CMP/EXIT)、**每个 handler 还强制 `bits20-23 == 1`**、
   `dest = (op>>16)&0xf`(0=a,1=b,2=c,3=d)、`mode = (op>>12)&0xf`(0=imm/1=reg)、`src = val>>8`、
   **执行门 `(op & 0xfff) <= 0x100` 才执行**(否则跳过)。
   ⚠️ 掩码别数错位:实测 `0x0f000000` 是 bit24–27 **不是** bit28–31。
3. **抓 `main` 里的 per-index 硬校验**(每个下标对 opcode 有独立约束,如 `i1:(op&0xfff)==0x100`、`i2: sel==3 && bits16-23==0x11` …)
   ⇒ 结合终局条件(寄存器取值 + `flags` + 长度)构成**多约束系统**,通常**可证唯一**。
4. 🔴 **自证最便宜**:把候选字节码喂给**原程序**,它会自己打印
   `This is the right answer! Validate the challenge with HTB{%s}` ⇒ 一次本地运行即确认。
5. 本地跑必须给超时或管道输入(`echo '<code>' | ./bin`),别裸跑交互式程序。
