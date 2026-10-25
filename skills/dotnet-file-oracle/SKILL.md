---
name: 'dotnet-file-oracle'
description: '.NET 报错三态做盲枚举：无法列目录时，用 Could not find file / Could not find a part of the path / is denied 三种消息区分"文件不存在 / 中间目录不存在 / 存在但无权限"。（检索词：dotnet file oracle）'
whenToUse: '只有文件读取能力（XXE/LFI/模板注入）却需要找文件、确认路径或定位 flag 时使用。'
metadata: { domain: web, tier: T3 }
---

# .NET 报错三态 = 盲文件系统枚举预言

> 来源：Scaffold HTB (Hard)。XXE 只能"读内容"、不能"列目录"，靠这套三态语义把盲读变成可枚举。

## 漏洞形状

盲文件读取工具（XXE 外部实体、ASP.NET 的 LFI、模板引擎的文件包含）通常只回答"内容"或"失败"。
但 .NET 的 `File.OpenRead` 家族在**三种不同成因**下抛出的消息是**可区分**的，于是"失败"被拆成两条信息：

| 返回消息（片段） | 语义 | 可推断的事实 |
|---|---|---|
| `Could not find file 'X'` | 文件不存在 | **父目录存在**（否则会是第三种） |
| `Could not find a part of the path 'X'` | 中间目录不存在 | 该路径上至少一层目录缺失 |
| `Access to the path 'X' is denied` | 路径存在但 ACL 拒绝 | **对象存在**；目录恒报此错 |

关键点：第三种把"存在性"和"可读性"解耦了 —— 即使读不到内容，也能确认**目标存在**。

## ✅ 目录枚举（把预言变成列目录）

对候选目录 D 探测一个必然不存在的随机名：

```
探测 D/x9z  →  返回 "Could not find file"        ⇒ D 存在
          →  返回 "Could not find a part..."   ⇒ D 不存在
```

配合字典型（常见目录名 + 主题词）就能在**无列目录能力**下重建目录树；逐层下探即可。

## ✅ 敏感文件定位（不必先能读）

直接探测目标路径本身：

```
C:/Users/<user>/Desktop/user.txt      → "is denied"  ⇒ 文件存在（flag 就在这里）
C:/Users/Administrator/Desktop/root.txt → "is denied" ⇒ 同上
```

拿到"存在"结论后再想办法换身份/换通道去读，比盲目绕权限高效得多。

## ⚠️ 实现纪律（否则假阳性淹没有效信号）

1. **低并发（3–4）**。WCF/ASP.NET 在高并发下会超时，返回空消息 → 被误判为"命中"。
2. **失败重试**（同一路径重试 2–3 次），并把"空消息/异常"单独归类，**不计入命中**。
3. **每次探测使用唯一的外部 DTD/载荷名**（如按路径 hash 生成），避免解析器缓存导致读到上一次的结果。
4. **载荷服务端口先确认空闲**（`ss -tlnp`）；残留进程占用会让整轮扫描静默全败。
5. 二进制文件（.sdf/.dll/.exe）会返回编码类错误（Invalid character in the given encoding），**同样证明文件存在** —— 但别指望读出内容。
6. 单个探测通常要 1–3 秒；上千候选一律**放后台任务**跑，前台只轮询日志。

## 验证标准（可复算）

- 先对**已知存在**的路径（如 `C:/Windows/win.ini`）与**已知不存在**的路径各探一次，确认三态可复现 —— 校准通过才继续。
- 判定"目录存在"必须由 `D/随机名 → Could not find file` 这一条谓词支持；仅凭"读取该目录报 denied"不算（目录恒报 denied）。
- 判定"文件存在"必须由 `is denied` 支持；`Could not find file` 只能判定"不存在"。

## 参考实现（可直接抄的探测函数骨架）

```python
def classify(msg):
    if not msg:                                  return 'NOMSG'      # 超时/异常，丢弃
    if 'Could not find a part of the path' in msg: return 'NOPARENT'  # 目录不存在
    if 'Could not find file' in msg:               return 'NOFILE'    # 文件不存在（父目录在）
    if 'is denied' in msg:                         return 'EXISTS_DENIED'
    return 'CONTENT'                                                  # 读出内容
# 目录：probe(d + '/x9z') == 'NOFILE'  ⇒ d 存在
```

## 跨平台对照

| 平台 | "文件不存在" | "中间目录不存在" | "存在但拒绝" |
|---|---|---|---|
| .NET | Could not find file | Could not find a part of the path | Access to the path … is denied |
| PHP | failed to open stream: No such file | failed to open stream: No such file | Permission denied |
| Java | FileNotFoundException | FileNotFoundException | AccessDeniedException |

**只有 .NET 天然区分前两者**；PHP/Java 场景需换手段（时间差、长度差、报错栈差异）——见 `xml-attacks-beyond-xxe` 的无回显替代通道。

**Why:** 盲读场景下"读不到"往往被当成死路，实际上错误消息本身就是一条枚举信道，能把盲读升级为半盲枚举。
**How to apply:** 拿到任意文件读取原语后，第一件事是校准三态（`mdt-monitoring-xxe` 的读取通道同样适用），再用它枚举目标机的目录树与 flag 路径。
