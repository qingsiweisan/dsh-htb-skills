---
name: 'capture-verdict'
description: '捕获判定：flag/cred 到手后的强制判定流程——state.jsonl 事件写入 + 双命令独立复核 + 证据链可重放。判定层据此对抗复核。'
whenToUse: '捕获 user/root flag 或关键凭据时：写 state.jsonl 事件、双命令独立复核、证据链可重放。'
disable-model-invocation: true
metadata: { domain: meta, tier: T2 }
---
> 📌 DSH 用法：router 在 flag 读取命令出现时自动注入本卡；也可用 skill 工具按名加载。

# 捕获判定流程（flag/cred 到手后强制执行）

> 🔴 一句话：**捕获不是"你说了算"，是"证据可重放才算"**。每个 flag/cred 事件都要经得起判定层的对抗复核。

## 三步（不可跳过）

```text
[1] 立即写 state.jsonl（type=flag|cred）
    - what = flag 值/凭据原文（先写后判，存疑注明「疑似」）
    - evidence = 刚才执行的确切命令（完整路径，如实记录）
    - 写命令见 box-startup「key-state 规范」

[2] 双命令独立复核（execution over claims）
    - 用与第一条不同的独立命令再读一次：
      cat /root/root.txt 之后 → md5sum /root/root.txt + ls -la /root/root.txt
    - 两条命令的输出必须一致（flag 值/hash 对应）
    - 复核命令追加进 evidence 字段（用逗号分隔），或补一条 note 事件

[3] 证据链自述（可追溯）
    - flag 事件 what 里注明「经：xxx 攻击链」，指回 access/cred 事件（按 ts 连成链）
    - 链断裂（flag 到手但说不清怎么到的）→ 判定层判「捕获未证实」，重打该段
```

## ⛔ 判定层否决项（以下任一即判捕获无效）

```text
❌ evidence 命令在会话 transcript 里找不到实际执行记录
❌ 输出与 what 里写的值对不上（flag 值/hash 不一致）
❌ 凭记忆写 flag 值，没有执行任何读取命令
❌ flag 值来自 writeup/搜索引擎（黑箱纪律：no-hint-solving）
❌ 双命令复核缺失（只有一条读取记录）
```

## 消费关系

- **确定性复核（机械层）**：`python3 scripts/verify_run.py --state <box>-state.jsonl [--cwd /root/htb]`——读磁盘原始 transcript（session.jsonl.zstd），逐事件检查：证据命令已执行 / 值在输出中 / 独立复核（第二读或 md5 对应）。exit 1 = 捕获未全部证实，复盘时以此为门。
- 复盘/判定层：确定性层通过后，独立子会话再做语义对抗复核（攻击链是否自洽、是否绕过 writeup、是否撞运气）——立场：默认捕获未证实，主动找证据推翻。
- 收尾：`<box>-complete.md` 只收录通过判定的 flag 事件。
