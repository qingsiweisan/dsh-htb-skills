---
name: 'challenge-crypto-prng'
description: 'Crypto 挑战双路线:自定义 PRNG 线性预测(GF(2) 符号执行+线性代数)与协议设计缺陷(秘密复用即泄漏/公开丢弃名单);含识别信号与求解模板（检索词：challenge crypto prng）'
whenToUse: '附件是自定义 PRNG/加密协议源码、要求预测输出或恢复共享密钥的题。'
metadata: { domain: crypto, tier: T1 }
---

# Crypto 挑战 playbook(Roulette + Clutch 沉淀)

## 路线 A:自定义 PRNG 预测(线性代数破译)

**判据**:更新函数只含 XOR/移位/循环旋转(无乘法)→ 每个输出比特是内部状态比特的 GF(2) 仿射函数 → 符号执行 + 解线性方程组完全破译。

### 标准六步(SageMath)

```python
# 1. 每个状态 bit 一个 GF(2) 变量
PR = PolynomialRing(GF(2), [f's{i}' for i in range(N*bits)])
# 2. 重写 PRNG:XOR = a+b(GF(2) 偶系数自动消去);rol = 切片重排 ml[r:]+ml[:r]
#    固定常数(如 MAGIC 0xb249b015)转比特向量 → 进常数项向量 B
# 3. 跑 symbolic_rand() 得每输出 bit 的线性式 C[i] = Σs_j + b_i
# 4. 实测 rank() 找最小请求数(部分输出 m-of-n bit 只增方程数;
#    秩会提前饱和,如 4096 态实测 768 次输出×5bit 后 rank 封顶 3840)
# 5. 收集真实输出拼向量 C(注意比特序:bin() 大端,输出低位在前要 [::-1] 与 zfill 补位)
# 6. 非方阵用 solve_right 取特解,不求逆:
state = A.solve_right(C + B)
# 然后构造真实 PRNG,先空跑同样次数同步流位置,再逐次预测
```

🔴 坑:MAGIC 常数每轮 twist 都参与,漏常数项 B 必错;恢复状态后**必须重放相同次数调用**对齐;比特序两端都要 `[::-1]`;服务器 `signal.alarm` 限制交互预算,先测单次交互耗时再定请求方式。

### PRNG 路线决策树

```
看更新函数:
├─ 纯线性(XOR/移位/旋转) → 符号执行 + solve_right
├─ 有乘法/取模 → LCG/截断 LCG 格攻击(lattice);布尔方程 → SAT
├─ 状态太大恢复不完 → 只恢复到"够预测"的部分(秩饱和是设计,凑不满是正常)
├─ 种子熵不足(时间戳/PID) → 直接爆破种子
└─ 输出经哈希 → 找可回推的还原轮(MT untwister 类)
```

## 路线 B:协议设计缺陷(量子/密钥交换/认证协议)

**判据**:"novel/新协议"+论文引用+全套源码+helpers 查找表 → 考协议**设计逻辑**,不考数学。

### 标准流程

1. **建模**:把协议拆成两张清单——公开信道传了什么(frames/sifting strings/reconciliation 结果/丢弃名单)vs 秘密状态是什么(态对选择/每帧测量结果)。目标常是"仅凭公开信息恢复秘密"。
2. **找复用**:秘密材料(态对索引)被多个公开结构共享时,**复用即泄漏**——两个公开标签 + 共享约束即可唯一化秘密(Clutch:帧 fj 与 fk 共享索引对 → fk 的公开 SS 约束 fj → 100% 确定度推出 MR)。
3. **"哪些被丢弃"本身是信息**:调和阶段公布歧义帧名单,恰好剔除原理上不可恢复的子集 → 可恢复部分覆盖全钥。先恢复高信息组,再以其为已知条件约束传播解锁剩余层,迭代闭合。
4. **实现**:直接复用题面 helpers 的 LUT(KEY_DERIVATION/BOB_MR_DERIVATION)做派生,勿重推表格;本地 `process(['python3','server.py'])` 全流程验证通过再打远程。
5. 行式 JSON 服务:`json.loads(r.recvline())` 循环读,含 error/info 行跳过;读到的字段转自有数据结构再计算。

### 🔴 坑

- 别试图恢复所有帧——位置不可区分的帧恢复不了,但它们恰被丢弃,钥仍完整。
- orientation/方向位取决于共享结构在拼接中的位置(`index[0]` 判定),判错整体取反。
- 帧列表转 tuple 才能进 set 去重;钥按帧序 join,顺序错则 AES 钥错。
- WP 参考脚本里的死代码(WP 自己也标注)不要照抄,按判据重写。
