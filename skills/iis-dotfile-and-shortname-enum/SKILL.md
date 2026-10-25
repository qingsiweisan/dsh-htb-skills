---
name: 'iis-dotfile-and-shortname-enum'
description: 'IIS/.NET 站点的"半截泄露"枚举链：桌面属性文件(.DS_Store/desktop.ini)还原目录树 + 8.3 短文件名(波浪号)枚举只给前 6 字符 → 字典裁剪补全。适用于目录爆破一片 404、站点只肯漏半个名字的情况。（检索词：iis/shortname/short name/8.3/tilde/波浪号/ds_store/dsstore/dotfile/desktop.ini/thumbs.db/iis_shortname_scanner/ds_walk/半泄露/短文件名/403 目录/目录枚举/兼容名/enum/enumeration）'
whenToUse: 'IIS/ASP.NET 站点目录爆破无果、nikto 报桌面元数据文件、或短名枚举拿到"某文件的前 6 个字符"时'
metadata: { domain: web, tier: T2 }
---

# IIS/.NET 站点：半截泄露枚举

> 适用：目录爆破返回一片 404/403，但站点因**部署遗留文件**或**文件系统兼容名**漏出半个名字。
> 两种泄露**互补**：一种给"有哪些目录/文件"（全名），一种给"那个文件叫什么"（只有前 6 字符）。

## 0. 触发信号

| 信号 | 含义 |
|---|---|
| nikto 报 `OSVDB-6694`、或 `/.DS_Store`、`/desktop.ini`、`/Thumbs.db` 可 200 | web 根是从开发机/共享盘**直接同步**来的（不是标准部署） |
| 全端口只有 web，目录爆破全 404，首页是 IIS 默认页或 ASP.NET 应用 | 常态，不代表没东西 |
| 某目录返回 **403**（目录存在但禁 listing） | 目录名已知、内容未知 → 下一步的短名枚举正好对症 |
| 基本认证弹窗的 realm 里出现**主机名/域名** | 顺手记下，后面主机名绑定/域枚举都要用 |

## 1. 桌面属性文件 → 目录树（成本最低，先做）

`.DS_Store`(macOS) / `desktop.ini`(Windows) / `Thumbs.db` 是"目录内容缓存"，会把**同级目录名与部分文件名**写进自身。

```bash
curl -sI http://<TARGET>/.DS_Store | head -1          # 200 = 存在
# 抓 + 解析（社区解析器任选；核心就是把文件里的名字抠出来）
python ds_walk.py -u http://<TARGET>                  # 例：Keramas/DS_Walk
# 手工兜底：.DS_Store 里的名字多为 UTF-16BE
curl -s http://<TARGET>/.DS_Store -o ds && strings -a -el ds | sort -u
```

🔴 产出往往几十条，**全部落进待验证清单**，别只看开头几条（有价值的目录常夹在中间）。
🔴 同一个 web 根下的**子目录也各自有 `.DS_Store`**（`/<dir>/.DS_Store`）——根目录读完再逐个深入。

## 2. 403 目录：不是终点

目录名已知但 403：**只能说明不许列举，不等于里面的文件不能直接请求**。
→ 直接上 §3 的短名枚举 + §4 的补全；同时对已知文件名试 `.bak/.old/.zip/.config/.txt` 等后缀。

## 3. 8.3 短名（波浪号）枚举 —— 只给前 6 个字符

NTFS 为兼容 16 位程序保留 8.3 兼容名；IIS 对 `~` 请求的差异响应构成侧信道，**只暴露名字前 6 字符 + 扩展名前 3 字符**。

```bash
msf > use auxiliary/scanner/http/iis_shortname_scanner
msf > set RHOSTS <TARGET>
msf > set PATH /                    # 拿到子目录后改成 set PATH /<subdir> 再跑
msf > run
# 形如： http://<TARGET>/<sub>/<pfx>~1.<ext>*      ← <pfx> 最多 6 字符
```

🔴 **读法**：这是"存在一个以 `<pfx>` 开头、扩展名 `<ext>` 的文件"，**前缀是截断的**。
🔴 **按目录生效**：根目录命中率最低（名字多是默认模板），**子目录才是重点**，每个子目录都要单独跑一遍。
🔴 扩展名也会被截断（`xxxx*~1.con*` → `.config` 一类），命中 `.con*` 时优先怀疑**配置文件**。

## 4. 关键一步：短名前缀 + 字典裁剪补全

短名给"半个名字"，剩下用字典接口 —— 把爆破空间从几万条压到几十条：

```bash
# 只留字典里以该前缀开头的词
grep '^<pfx>.*' /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt > fuzz.txt
# 把前缀之后的部分当参数位
wfuzz -z file,fuzz.txt -t 50 --sc 200 -u 'http://<TARGET>/<dir>/<pfx>FUZZ.txt'
ffuf  -w fuzz.txt -u 'http://<TARGET>/<dir>/<pfx>FUZZ.txt' -fc 404
```

判据：**HTTP 200 + 响应体长度与软 404 不同**。先跑一轮不限状态码观察 baseline，把同长度的错误页剔掉。

## 5. 相邻思路（同一"半截信息"家族）

| 拿到的东西 | 下一步 |
|---|---|
| 目录名 | 对该目录再跑短名枚举（§3） |
| 文件前缀 + 扩展名 | 字典裁剪补全（§4）；命中 `.txt/.config/.xml` 直接读 |
| 用户名格式（登录框/邮件/日志） | `username-generation` |
| 主机名/域（realm、证书 CN） | 主机名绑定、Kerberos、域枚举 |

## 6. 坑

| 坑 | 说明 |
|---|---|
| 只扫根目录 | 短名枚举必须按目录逐个跑 |
| 把短名当完整文件名 | 6 字符是上限，直接用必 404 |
| 忽略软 404 | wfuzz/ffuf 默认把"同样 200 的错误页"当命中，先标 baseline |
| 只认 200 | 部分站点命中返回 302/500，先做一轮不限状态码的观察 |
| 前缀过滤后仍喷全字典 | 过滤完只剩几十词，喷全量既慢又吵 |

## 7. 蓝队视角（顺手记）

- 删除 web 根下的 `.DS_Store`/`desktop.ini`/`.git`/`.svn` 等开发遗留；部署流水线加"禁止同步隐藏文件"。
- 兼容名无法只对单站点关闭：`fsutil 8dot3name set 1`（按卷）或部署期禁用；长名文件越少，泄露面越小。
- 检测：大量 `~1` 后缀请求、对 `/.DS_Store` 的访问 = 扫描/信息收集特征。

## 相关卡

- 目录/参数/子域发现总流程 → `enumeration-command-layer`、`htb-methodology`
- 命中配置文件后找凭据 → `credential-hunting-locations`
- 确认是 .NET 站后 → `dotnet-viewstate-machinekey-rce`、`dotnet-file-oracle`
