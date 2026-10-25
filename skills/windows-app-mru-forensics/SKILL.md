---
name: 'windows-app-mru-forensics'
description: 'Windows 应用级 MRU/历史注册表取证：7-Zip(FolderHistory/ArcHistory/CopyHistory/PanelPath)、RecentDocs、OpenSavePidlMRU、TypedPaths、Jumplist Quick Access、Bags IconLayouts —— 回答"文件被谁打开过/压缩包里有什么目录/桌面曾存在什么"（检索词：7zip/7-Zip/FolderHistory/ArcHistory/CopyHistory/PanelPath/MRU/RecentDocs/OpenSavePidlMRU/TypedPaths/IconLayouts/jumplist/注册表取证/zip 内部/forensics/app）'
whenToUse: '题目所问的文件本体不在证据里（zip 不在采集里却问包内目录、问"谁打开过这个文件"、问"桌面曾有什么"）时：改读应用自己写的 MRU/历史注册表键。'
metadata: { domain: forensics, tier: T3 }
---

# Windows 应用 MRU / 历史注册表取证

> 来源：OpTinselTrace24-6 Sleigh Slayer (Hard, 24/24) T9 —— "用 7zip 枚举了 Santa 桌面上的 zip，包里与圣诞奖金相关的目录是？"
> 而 `finance_christmas.zip` **根本不在 KAPE 采集里**。

## §0 判断信号（何时换思路）

题目问的事件，**其文件本体不在证据里**：

| 题面形态 | 说明 |
|---|---|
| "用 7zip 枚举了某个 zip，包里某目录叫什么" | zip 已被移走/未采集 → 读 7-Zip 浏览历史 |
| "这个文件最后被谁/哪个程序打开过" | 读 RecentDocs / OpenSavePidlMRU / Jumplist |
| "桌面上曾经存在过哪些文件" | 读 `Shell\Bags\1\Desktop\IconLayouts` |
| "用户在资源管理器地址栏输过什么" | 读 TypedPaths |

> 🔑 **核心心法**：不要因为样本不在就放弃。先问"**谁会记录它**"——注册表 MRU 家族几乎总有一处留痕，且**比文件本体更耐删**（很多题故意把文件拿走，只留 MRU）。

## §1 7-Zip（Windows DFIR 最常考的 MRU 之一）

全部在 **`HKCU\Software\7-Zip\...`**（= 用户 NTUSER.DAT）。
⚠️ 7-Zip 会**同时写 `7-Zip` 与 `7-zip` 两个大小写键**（内容相同），遍历时两个都要看。

| 键 | 类型 | 回答什么问题 |
|---|---|---|
| `FM\FolderHistory` | REG_BINARY = **UTF-16LE MULTI_SZ** | ⭐ 面板浏览历史，**连"进入压缩包内部"的路径都记**：`<zip全路径>\<包内目录>\` → "包里有什么"的唯一答案源 |
| `FM\CopyHistory` | 同上 | 7z 复制/移动的**目标目录** |
| `Compression\ArcHistory` | 同上 | 最近创建/打开的归档（7z 打的包名） |
| `FM\PanelPath0` / `PanelPath1` | REG_SZ | 最后一次面板所在目录（"最后访问的路径"→ **去掉尾部 `\`**） |
| `Compression\Archiver`/`Level` | REG_SZ/DWORD | 默认压缩格式（zip/7z）与等级 |
| `FM\Columns\*`、`FM\Panels` | REG_BINARY | 列布局/面板数（做题基本用不到） |

**解码（MultiSZ 必须按 utf-16-le 解；直接 `strings` 一条都读不出）**：

```python
# pip 环境需 python-registry（本机 python 已装 Registry 模块）
from Registry import Registry
r = Registry.Registry(r'...\Users\santa\NTUSER.DAT')      # 脏 hive 需把 ntuser.dat.LOG1/LOG2 放同目录
def multisz(b):
    return [x for x in b.decode('utf-16-le', 'replace').split('\x00') if x.strip('\x00')]
k = r.open(r'Software\7-Zip\FM')
print(multisz(k.value('FolderHistory').value()))   # ['...\finance_christmas.zip\...\performance_bonus_24\\', ...]
print(multisz(k.value('CopyHistory').value()))
print(r.open(r'Software\7-Zip\Compression').value('ArcHistory').value())
print(k.value('PanelPath0').value())
```

**一次扫全 hive 找 zip 痕迹**（除 7-Zip 外还能捞出 OpenSavePidlMRU/RecentDocs/IconLayouts）：

```python
def rec(key, path):
    for v in key.values():
        try: val = v.value()
        except Exception: continue
        if isinstance(val, (bytes, bytearray)):
            s = val.decode('utf-16-le', 'ignore')            # 关键：别用 latin1/ascii
            for m in __import__('re').findall(r'[ -~]{4,}', s):
                if '.zip' in m.lower(): print(path, '\\', v.name(), '->', m)
        elif isinstance(val, str) and '.zip' in val.lower():
            print(path, '\\', v.name(), '->', val)
    for sk in key.subkeys(): rec(sk, path + '\\' + sk.name())
rec(r.root(), '')
```

**战例（Sleigh Slayer T9，答案就在第 1 行）**：

```
C:\Users\santa\Desktop\finance_christmas.zip\finance_christmas\Employees\performance_bonus_24\   ← 答案（"Christmas bonus" = performance_bonus_24）
C:\Users\santa\Desktop\finance_christmas.zip\finance_christmas\Employees\
C:\Users\santa\Desktop\finance_christmas.zip\finance_christmas\
C:\Users\santa\Desktop\finance_christmas.zip\finance_christmas\North-Workshop\
C:\Users\santa\Desktop\finance_christmas.zip\
```
同题组另外三问也全出自这四道键：`FM\CopyHistory`=`C:\Users\Public\scan\`、`Compression\ArcHistory`=`C:\Users\santa\Desktop\scan87x.zip`、`FM\PanelPath0`=`C:\Program Files (x86)\WindowsPowerShell\Configuration\Registration`。

## §2 Explorer / 系统 MRU 家族（文件本体不在时的备选）

| 键 | 给什么 |
|---|---|
| `...\Explorer\RecentDocs\.<ext>\N` + `RecentDocs\N` | 按扩展名分组的最近文档（值 = UTF-16 文件名，旁边带 PIDL） |
| `...\Explorer\ComDlg32\OpenSavePidlMRU\<ext>\N` | **打开/保存对话框**里选过的文件（比 RecentDocs 更接近"程序真的用了它"） |
| `...\Explorer\ComDlg32\LastVisitedPidlMRU` | 对话框最后停留目录 |
| `...\Explorer\TypedPaths\url1..N` | 地址栏**手输**的路径（攻击者手动跳目录的痕迹） |
| `...\Shell\Bags\1\Desktop\IconLayouts` | **桌面图标布局的 UTF-16 文件名**（"桌面曾存在哪些 zip"的旁证，Sleigh Slayer 里捞出 `finance_christmas.zip`/`transfer_scanned.zip`/`KAPE.zip`） |
| `Recent\*.lnk` | 每个被访问对象的 LNK（TargetPath/Arguments/时间） |
| `Recent\AutomaticDestinations\*.automaticDestinations-ms` | Jump List（Quick Access 等）→ 用 **JLECmd** 解，别手搓 OLE |

Jump List AppID（JLECmd `AppIdDescription` 原生给出，实测样本）：
`f01b4d95cf55d32a`=Windows Explorer · `5f7b5f1e01b83767`=Quick Access · `9b9cdc69c1c24e2b`=Notepad 64-bit · `ccba5a5986c77e43`=Microsoft Edge (Chromium)；
`2fc20fb544cbf2a9` JLECmd 无描述，其条目指向 `...\Documents\keepass\*.kdbx` → 疑似 KeePass（**未确证别当结论**）。

## §3 工具

| 目标 | 工具 | 命令 |
|---|---|---|
| 注册表 hive 任意键 | python-registry | `Registry.Registry(path)`（脏 hive 带上 LOG1/LOG2） |
| Shellbag | SBECmd | `SBECmd.exe -d <hive目录> --csv <out>` |
| Jump List | JLECmd | `JLECmd.exe -d <AutomaticDestinations> --csv <out>` |
| Prefetch | PECmd | `PECmd.exe -d <prefetch> --csv <out>`（注意：**prefetch 不记 GUI 里翻过哪些目录**） |

工具下载：`https://download.ericzimmermanstools.com/net9/<Tool>.zip`（.NET 9）。

## §4 坑

- 🔴 **MultiSZ/REG_BINARY 不能直接 `strings`**：UTF-16LE 且以 `\x00` 分隔，ASCII 扫描 0 命中 → 必须 `decode('utf-16-le')` 再 split。
- 🔴 **别拿 prefetch 找"浏览过哪个目录"**：7ZFM 的 prefetch 只列进程加载的 DLL 和少量文件；GUI 内导航只在注册表里。
- **大小写成对键**：`Software\7-Zip` 与 `Software\7-zip` 都写；只读一个会漏（顺带 `Software` 的 WOW64 重定向在离线 hive 里不生效，不必担心）。
- **时间戳**：7-Zip 这些值没有逐条时间；要时间线就配合键 LastWriteTime（regipy/python-registry 的 `key.timestamp()`）+ prefetch/SRU。
- **hive 是"活的"就要事务日志**，否则 python-registry 可能读到旧快照。
- 反取证意识：攻击者删文件容易，**清 MRU 难**——所以这类题常常"文件没了，答案还在"。

## §5 与相邻卡分工

- **Shellbag / 文件夹访问时间**（BagMRU、LastInteracted、UNC 共享、zip 内容 ShellType）→ `sherlock-investigation` §7（用 SBECmd，本卡不重复）。
- **Sherlock 题型路由 / 续做（API 拿每题 flag）/ KAPE triage 全流程** → `sherlock-investigation`（本卡是其 §6.1 的细节展开）。
- **没有 hive、只有内存/日志** → 走 `sherlock-investigation` §4/§5。
- **脚本样例**：`C:\Users\<user>\sherlock-work\sleigh\dump7z2.py`（7-Zip 四键 + 全 hive zip 扫描，可直接改路径复用）。
