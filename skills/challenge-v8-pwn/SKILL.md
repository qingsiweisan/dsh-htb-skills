---
name: 'challenge-v8-pwn'
description: 'V8/浏览器 pwn 全流程:patch.diff 定位新增 builtin→持指针期间调 JS 回调的 UAF→堆喷对齐升级 OOB→addrof+任意读写→指针压缩笼逃逸(ArrayBuffer/wasm RWX)（检索词：challenge v8 pwn）'
whenToUse: '附件是 d8 + patch.diff + js 脚本的 V8 题:diff 审计→UAF/OOB 构造→可复用任意读写→逃逸 cage→shellcode。'
metadata: { domain: pwn, tier: T1 }
---

# V8/浏览器 pwn playbook(Pyrrhus 沉淀)

> 前置: challenge-insane-playbook §2 纪律。d8 本地调试: `./d8 --allow-natives-syntax exp.js`(%DebugPrint 看对象布局)。

## 1. diff 审计定位漏洞(第一步,永远)

```bash
./d8 exp.js                      # 本地复现
git apply patch.diff 或直接读 diff
```
审计清单——patch 新增/修改的 builtin 里找:
1. **持裸指针/旧 length 期间调用用户可达 JS**:元素类型转换(ToNumber)、`Symbol.toPrimitive`/valueOf/toString、迭代器协议、getter——回调内 `a = undefined` 触发 GC 释放 backing store → 返回后仍写旧指针 = UAF 写(Pyrrhus 的 ArrayNumerify)。
2. 类型推断/边界检查缺失(经典 OOB)、map 未更新、length 未裁剪。
3. 回调返回值有 `Smi::cast` 之类断言 → 必须返回小整数,否则崩。

## 2. UAF → OOB 升级(写一个 Smi 也够)

1. 回调内完成"释放受害数组 → 堆喷 `new Array(500).fill(FILL)` 重占 → 返回特殊值":返回值被写回悬空位置,堆喷对齐后落点覆盖**存活数组的 capacity/length 字段** → OOB。
2. 喷数组长度要够大(<500 实测无法复用 freed 块);对齐每轮不同 → 多轮重试 + 逐数组探测(length 拉大读原界外,非 undefined 即命中,同时漏出 map/elements 指针)。

## 3. 建立可复用任意读写

- **改邻居的 elements 指针**(紧邻上方的数组),不是改被腐蚀数组自己的——改自己的会永久失去 OOB 锚点。
- addrof 通用构造:把目标对象放进能被 OOB 读到的指针槽(如 `setPrototypeOf` 后读 map+0x10 prototype 槽;或常见"double array/object array 邻接"法)。
- read/write 封装成函数后立刻固化测试,再往下走。

## 4. 指针压缩笼逃逸

- 压缩指针只覆盖 4GB cage 内;**ArrayBuffer 的 backing_store 是未压缩 64 位指针** → OOB 改它 = cage 外任意读写(标准跳板)。
- RWX + shellcode:wasm 实例地址+8 → trusted_data,+0x30 → RWX code 页地址 → 写 shellcode,调用导出的 wasm 函数跳入。
- 🔴 题目 bot 若带 `--jitless/--noexpose_wasm`(ApexSurvive 的 selenium flags),wasm 路线被封,别往这个方向想——信号在启动参数里。

## 5. 🔴 坑

- 喷射对齐靠运气 → 整个 exploit 包重试循环,命中检测写进脚本自动重跑。
- 回调内 GC 时机不稳定:多试几个触发组合(数组长度/元素类型/GC 压力)。
- `--allow-natives-syntax` 只在本地开;远端别依赖 `%DebugPrint`。
- d8 与 Chrome 的 flag 集不同;bot 题先读 selenium/js-flags 参数再定路线。
- 改 map/elements 前先 dump 内存确认字段偏移(不同 V8 版本差很多),用同版本 d8 动态核对。
