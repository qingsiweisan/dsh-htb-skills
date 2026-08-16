---
name: 'debug-5whys'
description: '改编自丰田5 Whys：攻防卡住时的强制追问框架。定义失败点→5 Whys追问→假设审计→二分验证'
whenToUse: '攻击卡住时强制追问：定义失败点→5 Whys→假设审计→二分验证。'
metadata: { domain: meta, tier: T1 }
---

# Skill: 5-Whys HTB

改编自丰田 5 Whys 根因分析。攻防卡住时的强制追问框架。

## 来源
Taiichi Ohno, Toyota Production System, 1988.
https://en.wikipedia.org/wiki/Five_whys

## 触发
- 同一攻击路径失败 ≥ 3 次
- 换了 2 个以上替代方向仍不通

## 流程

### ① 定义失败点（精确到一步）
```text
❌ "提权失败"
✅ "SUID 二进制运行后仍返回普通用户 shell"
```text

### ② 5 Whys 追问链（示例：SUID 提权失败）
```text
Why 1: 为什么 SUID 二进制没给 root？
  → 它 setuid(0) 后立刻又 drop 回原 uid

Why 2: 为什么 drop 回原 uid？
  → 脚本先解析了环境变量再 setuid

Why 3: 为什么环境变量能影响 setuid 顺序？
  → 脚本用 system() 调外部命令，PATH 可控

Why 4: 为什么 PATH 可控却没生效？
  → 改了 PATH 但没 export，子进程继承不到

Why 5: 为什么没 export？
  → 复制的命令少了 export，子进程用了默认 PATH
```text

### ③ Why 5 改造 — 追问到"可操作的根因"
```text
标准 5 Whys 可能在 Why 5 停住（"PATH 没 export"）
HTB 版继续:

Why 6: 有没有其他 SUID 二进制有同样问题？
  → 逐个读 SUID 脚本的 system() 调用点

Why 7: 能不能改脚本读取的配置文件？
  → 配置文件可写 → 注入命令 → setuid 前执行
```text

### ④ 假设审计（5 Whys 的补充）
5 Whys 的已知弱点：无法超越当前知识边界。补一个步骤：
```text
列出所有"已被排除的假设"及其排除依据:
[ ] SUID 二进制本身 → 依据: "没输出" → 🔴 弱！重新验证
[ ] PATH 已 export → 依据: "我以为改了" → 🟡 需要确认
```text

### ⑤ 二分验证
```text
取因果链中间一步，实验验证：
→ 先手跑 SUID 二进制，观察 uid 是否变化
→ 变成 root 了？→ 问题在后面的命令注入
→ 没变？→ 问题在 setuid 顺序/脚本逻辑本身
```text

## 5 Whys 的批评与应对
| 5 Whys 弱点 | HTB 版应对 |
|-----------|----------|
| 停在症状不深挖 | Why 5 后强制继续，"为什么"直到能改代码 |
| 无法超越当前知识 | 假设审计步骤，强制重审"已排除"项 |
| 不同人会问出不同根因 | 用实验验证每一步，不依赖直觉 |
| 倾向单一根因 | 接受可能有多个阻断点，并行修复 |
