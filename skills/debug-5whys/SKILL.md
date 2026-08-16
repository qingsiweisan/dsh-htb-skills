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
```
❌ "容器逃逸失败"
✅ "CodeBuild BUILD phase: Exit code 128 OCI runtime exec failed"
```

### ② 5 Whys 追问链
```
Why 1: 为什么 BUILD 失败？
  → OCI runtime exec failed: 容器已停止

Why 2: 为什么容器停止了？
  → init 命令没有成功保持容器 alive

Why 3: 为什么 init 命令 (tail -f /dev/null) 没成功？
  → 前面的 mkdir -p /codebuild 失败了

Why 4: 为什么 mkdir 失败？
  → 没有权限在 / 下创建目录

Why 5: 为什么没有权限？容器不是 privileged mode 吗？
  → entrypoint.sh 用 gosu floci 降权了，privileged 只给 cap 不改 uid
```

### ③ Why 5 改造 — 追问到"可操作的根因"
```
标准 5 Whys 可能在 Why 5 停住（"entrypoint 降权了"）
HTB 版继续:

Why 6: 有没有东西能绕过 entrypoint 降权？
  → 检查 entrypoint.sh: 它用 id 命令检查当前用户

Why 7: 能不能控制 id 的返回值？
  → BASH_FUNC_id%% 可以注入 bash 函数劫持 id

Why 8: BASH_FUNC_id%% 在原始脚本里吗？
  → 在。但我把它删了，以为是 cosmetic。
```

### ④ 假设审计（5 Whys 的补充）
5 Whys 的已知弱点：无法超越当前知识边界。补一个步骤：
```
列出所有"已被排除的假设"及其排除依据:
[ ] BASH_FUNC_id%% → 依据: "看起来是cosmetic" → 🔴 弱！重新验证
[ ] 镜像问题 → 依据: "旧session能跑" → 🟡 需要确认版本
```

### ⑤ 二分验证
```
取因果链中间一步，实验验证：
→ 先跑不含 modprobe 的命令序列 (echo hello)
→ BUILD 能 SUCCEEDED 吗？
→ 能 → 问题在后面
→ 不能 → 问题在容器生命周期本身
```

## 5 Whys 的批评与应对
| 5 Whys 弱点 | HTB 版应对 |
|-----------|----------|
| 停在症状不深挖 | Why 5 后强制继续，"为什么"直到能改代码 |
| 无法超越当前知识 | 假设审计步骤，强制重审"已排除"项 |
| 不同人会问出不同根因 | 用实验验证每一步，不依赖直觉 |
| 倾向单一根因 | 接受可能有多个阻断点，并行修复 |

## Nimbus 实战示例
```
失败点: BUILD:FAILED, OCI exec
Why 1-3 → 容器 init 失败
Why 4 → mkdir 权限
Why 5 → gosu floci 降权
Why 6-7 → BASH_FUNC_id%% 可绕过
结论: 脚本对，我删错了。修复: 保留 BASH_FUNC, 换新 project 名
```
