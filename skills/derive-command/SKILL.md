---
name: 'derive-command'
description: '从工具--help/wiki/源码推导正确命令，而非猜测。记忆无匹配时自动切换到此流程。'
whenToUse: '工具命令不在任何技能/笔记里时：从 -help/wiki/源码推导正确参数，而不是猜。'
metadata: { domain: meta, tier: T1 }
---

# Derive Command — 当记忆没有精确命令时推导参数

> 🔴 这不是参考文档。当你需要用的命令不在任何技能卡/本机笔记 中时，强制走此流程。目的是让你能从工具文档/源码中自己推导出正确参数，而不是猜。

## 触发条件（任一满足即触发）
- 需要用某个工具，但技能卡/本机笔记（禁止搜 writeup）里没有精确命令
- 工具执行失败且失败原因不是网络/权限/认证
- 同一工具同一步骤猜了 2 个不同参数都失败

## 推导流程（逐条执行，禁止跳过）

### Step 1: 用一句话写出我要这个工具做什么
```
"我要用 <工具名> 实现 <具体效果>"
```
如果写不出这句 → 你还没理解问题，先回去读上下文。

### Step 2: 获取工具的"菜单"
```bash
<工具> --help 2>&1 | head -80
# 或者
<工具> -h
# 如果 --help 输出太长 → 用 grep 筛选相关参数
<工具> --help 2>&1 | grep -iE '<关键词1>|<关键词2>'
```
从输出中找出**和你目标相关的 3-5 个参数名**。

### Step 3: 对每个候选参数，查它的文档
```bash
# 优先: 工具的 GitHub wiki (README.md, docs/ 目录)
# 次选: <工具> --help 中该参数的解释
# 再次: 搜索 "<工具> <参数名> example"
```
🚫 **禁止在不知道参数含义的情况下直接试。**

### Step 4: 构造最小测试
```
用最少参数 + 一个可验证的预期结果
"如果我加了 <参数X>，预期输出应该包含 <Y>"
```
只加一个参数 → 执行 → 验证预期 → 再加下一个参数。

### Step 5: 失败时只改一个参数
```
如果失败 → 先读取错误信息 → 只改一个参数 → 重新最小测试
🚫 禁止: 同时改 3 个参数 / 换工具 / 问用户
```

## 实例：如果没有 RODC golden 记忆，如何推导

```
Step 1: "我要用 Rubeus 伪造一个 Administrator 的 TGT，用 krbtgt_8245 的 AES 密钥签名"
Step 2: Rubeus.exe --help → 找到 golden 子命令 → golden --help →
         /user: /id: /domain: /sid: /aes256: /rc4: /rodcNumber: /flags:
Step 3: 查 Rubeus wiki → /aes256: 用于 AES key → /rodcNumber: 用于 RODC →
         /flags: forwardable,renewable 是标准 TGT flags
Step 4: 只加 /aes256: + /user: + /domain: → 看是否生成 "Forged a TGT"
Step 5: KDC_ERR_TGT_REVOKED → 查 wiki "RODC golden requires special flags" →
         加 /rodcNumber:8245 /flags:forwardable,renewable,enc_pa_rep → 通
```

## ⛔ 禁止行为
```
❌ 不看 --help 直接试
❌ 同时改多个参数
❌ 第一次失败就换工具
❌ 猜参数含义（"这个 flag 应该是指..."）
❌ 用 Google 返回的 2015 年博客代替官方文档
```
