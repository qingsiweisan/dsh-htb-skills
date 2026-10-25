---
name: 'evil-winrm-path-escaping'
description: 'evil-winrm/heredoc 路径转义：\b→退格 \r→回车，解决方案用正斜杠或双反斜杠（检索词：evil winrm path escaping）'
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
- `nxc winrm … -x` 执行命令：某些 netexec 版本的 winrm `-x` 存在 Python `zip()` 相关问题（症状：远程执行报错 / 回显为空或异常），
  版本边界（**哪个版本引入、哪个版本修掉**）**待核实** —— 本卡与 `netexec-reference` 都无版本实测记录，本机也未安装 netexec（`nxc` 不在 PATH），
  **不写版本号**。✅ **不知道版本边界时用下面这条决策规则（一次实测定路，不要凭版本号猜）**：
  1. 先跑一次 `nxc winrm <target> -u '<u>' -p '<p>' -x whoami`；
  2. **正常回显目标机器 whoami 输出**（无 traceback、无 Python 异常、非空）⇒ 判定该版本已修，**直接用 netexec**；
  3. **报错 / 回显为空 / 出现 Python 异常** ⇒ 判定该版本未修，**改用 evil-winrm 兜底**（本卡上文的正斜杠写法）。
  👉 同一个问题的另一面见 `netexec-reference` 的「WinRM」节（同一决策规则）。

**Why:** 多次因路径被 shell 截获导致命令失败，浪费大量时间
**How to apply:** 所有发往 evil-winrm 的 Windows 路径用正斜杠；避免使用 bash 特殊字符
