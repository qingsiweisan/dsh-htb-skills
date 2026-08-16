---
name: 'netexec-escape'
description: '构建 netexec 远程命令时自动避免 cmd 转义和 Get-Item bug'
whenToUse: '用 netexec 在远程 Windows 上执行命令前：避免 cmd 转义和 Get-Item bug。'
disable-model-invocation: true
metadata: { domain: tools, tier: T3 }
---

# Netexec Command Builder

当需要用 netexec 在远程 Windows 目标上执行命令时，**自动应用以下规则**：

## 规则 1: 路径有空格 → PowerShell 原生

| 禁止 | 使用 |
|------|------|
| `cmd /c` 配合带空格的路径 | PowerShell 原生 cmdlet |
| `cmd /c "dir C:\X Y\Z"` | `Get-ChildItem "C:\X Y\Z"` |
| `cmd /c "if exist ..."` | `Test-Path "..."` |
| `cmd /c "type ..."` | `Get-Content "..."` |
| `cmd /c "icacls ..."` | `Get-Acl "..."` (或 icacls 只用于无空格路径) |

## 规则 2: 文件大小 → Get-ChildItem

```text
# ✅ 正确: (锁定文件也能读)
(Get-ChildItem "C:\path\file.exe").Length

# ❌ 错误: (锁定文件返回 0)
(Get-Item "C:\path\file.exe").Length
```text

## 规则 3: 复杂脚本 → 先写文件

```text
1. HTTP serve script → Invoke-WebRequest download to target
2. Start-Process powershell -File local.ps1
```text

## 规则 4: 必须内联 → Base64

```bash
CMD='while($true){...}'
B64=$(echo -n "$CMD" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)
netexec ... -X "powershell -NoP -EncodedCommand $B64"
```text

## 规则 5: 变量 → 单引号包裹

```bash
netexec ... -X '"$var"'   # 单引号内 $ 不被 bash 展开
```text

## 执行前检查

构建命令后，逐条检查：
1. 有 `cmd /c` 吗？→ 能替换吗？
2. 路径有空格吗？→ 确保无 cmd 层
3. 用 `Get-Item` 了吗？→ 换成 `Get-ChildItem`
4. 多层引号嵌套？→ Base64 或写文件
