---
name: 'evil-winrm-path-escaping'
description: 'evil-winrm/heredoc 路径转义：\b→退格 \r→回车，解决方案用正斜杠或双反斜杠'
disable-model-invocation: true
metadata: { domain: tools, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# evil-winrm 路径转义陷阱

## 问题
通过 heredoc 或管道传命令给 evil-winrm 时，反斜杠会被 shell 解释：
- `\b` → 退格符（Backspace），`C:\Program Files\UpdateMonitor\bin` → `UpdateMonitoin`
- `\r` → 回车符（CR），`C:\ProgramData\root.txt` → `ProgramData<CR>oot.txt`
- `\w` / `\n` / `\t` — 某些 shell 也会解释

## 解决方案
1. **用正斜杠**: `C:/Program Files/UpdateMonitor/bin` ✅
2. **用双反斜杠**: `C:\\Program Files\\UpdateMonitor\\bin` ✅ (在单引号字符串中)
3. **避免 heredoc <<<**: 用 `echo '...' | evil-winrm` 代替

## 其他 WinRM 问题
- `$null` 重定向: bash 会先解析 `2>$null` → 用 `-ErrorAction SilentlyContinue`
- `findstr` 管道: bash 可能截获 `|` → 用 PowerShell 的 `Select-String`
- `netexec winrm` 执行命令有 Python zip() bug → 用 evil-winrm 代替

**Why:** 多次因路径被 shell 截获导致命令失败，浪费大量时间
**How to apply:** 所有发往 evil-winrm 的 Windows 路径用正斜杠；避免使用 bash 特殊字符
