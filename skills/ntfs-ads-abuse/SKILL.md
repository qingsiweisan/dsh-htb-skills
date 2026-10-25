---
name: 'ntfs-ads-abuse'
description: 'NTFS 备用数据流(ADS)双向用法:发现别人藏在流里的凭据/库/flag(dir /r、Get-Item -Stream、streams.exe),以及自己往 ADS 里藏 payload 绕过目录列举。含 Zone.Identifier = MOTW 判读。（检索词：ADS/alternate data stream/备用数据流/数据流/NTFS stream/streams.exe/dir/r/Get-Item -Stream/Zone.Identifier/MOTW/keepass/藏文件/隐藏数据/取证/alternate-data-stream/NTFS-stream/abuse）'
whenToUse: '目录里文件大小与内容对不上、桌面/flag 目录看着是空的、或压缩包与文本文件疑似夹带了别的东西时加载。'
metadata: { domain: ad-win, tier: T3 }
---

# NTFS 备用数据流(ADS):藏文件与藏凭据

> 来自 Insane 官方 WP 逐台回核,**3 台命中**:Minion / BigHead / Hackback。

ADS 是 NTFS 原生特性:一个文件可有多个数据流,默认流是 `:$DATA`,其余流对 `dir` 常规列举**完全不可见**,也**不计入文件大小**。"文件看着正常、里面另有乾坤"就是它的标准形态。

🔴 **双向用法**:① **发现** —— 别人(出题人/攻击者)把凭据、数据库、flag 藏在流里,取证/夺旗视角;② **利用** —— 你自己往 ADS 里藏 payload,绕过按文件名/扩展名的目录列举与部分扫描。

## 触发信号

| 现象 | 含义 |
|------|------|
| `dir` 显示文件存在但"里面没东西" / 大小与用途明显不匹配 | 主内容可能只是幌子,真数据在别的流里 |
| 桌面、Administrator 目录、flag 目录列举后一无所获 | 先按模式 1 查流,别急着换思路 |
| 已知文件名却读不出预期内容(`root.txt` 读出来是乱码/二进制) | 该文件是 ADS 的**载体**,内容在 `root.txt:<流名>` |
| 文件名旁出现 `:Zone.Identifier` | MOTW 标记,文件来自网络(见模式 4) |
| `more`/`type` 输出二进制乱码而非文本 | 流里藏的是文件本体(库/压缩包/PE),走模式 2 导出 |
| 拿到压缩包、图片、日志等"看起来很日常"的文件 | Minion 的 `backup.zip` 就是这么藏的 |

## 前置验证

```powershell
Get-Item -Path *.* -Stream *        # ① 当前目录全部流(重点看 Stream 列非 :$DATA 的行)

# ② 递归扫(:$DATA 是主内容,不是藏的东西)
Get-ChildItem -Recurse -File | Get-Item -Stream * | Where-Object Stream -ne ':$Data'

Get-Item -Path C:\Users\<user>\Desktop\root.txt -Stream *   # ③ 单个文件确认
```

```cmd
dir /ah /r                                            :: ④ cmd 侧一次性列举(/r 显示流,/a 显示隐藏)
dir /r /s
streams.exe -s -accepteula C:\Users\<user>     :: ⑤ Sysinternals 递归(被 AppLocker 拦时见 applocker-clm-bypass)
```

🔴 `Get-Item -Stream *` 一定会列出 `:$DATA` —— 那是文件本体,不是藏的东西。过滤掉它再判断。

## 模式 1: 发现 —— 把流列出来

条件:目录列举看着正常但拿不到东西,或已知有可疑载体文件。**先列流,再决定读不读。**

```powershell
get-item -path *.* -stream *        # Minion 的原始命令:输出里出现名为 pass 的流 → 就是它
```

```cmd
dir /ah /r                          :: BigHead / Hackback 的原始命令(Administrator 桌面)
:: → root.txt:Zone.Identifier   (BigHead,实为 Keepass 库)
:: → root.txt:flag.txt           (Hackback,真 flag)
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Minion | decoder 桌面 `backup.zip` 看似普通压缩包;`get-item -path *.* -stream *` 发现一个名为 `pass` 的流 |
| BigHead | Administrator 桌面 `dir /ah` 只看到 troll flag;`dir /ah /r` 才暴露出 `root.txt:Zone.Identifier` |
| Hackback | Administrator 桌面 `dir /ah /r` 暴露 `root.txt:flag.txt` —— 文件名本身骗过了肉眼 |

## 模式 2: 读取与导出 —— 把流内容取出来

条件:已定位到流名。文本流直接读;二进制流必须先 base64 编码带出,否则 shell 会把字节吃掉。

```powershell
get-content backup.zip -stream 'pass'        # 文本流直接读
powershell get-content root.txt:flag.txt
```

```cmd
more < root.txt:Zone.Identifier              :: cmd 侧读法
type root.txt:flag.txt
certutil -encode root.txt:Zone.Identifier foo.txt    :: 二进制流:编码后带出
:: 攻击机侧: base64 -d foo.txt > foo && file foo
```

```bash
# BigHead:导出后认出是 Keepass 2 库;keyfile 路径从 %APPDATA% 的 Keepass 配置读
# <KeySources><Association><DatabasePath>..\..\Users\Administrator\Desktop\root.txt:Zone.Identifier
# <KeyFilePath>..\..\Users\Administrator\Pictures\admin.png
./keepass2john -k ~/Documents/HTB/Bighead/admin.png ~/Documents/HTB/Bighead/root.kdbx > hash
john -w=rockyou.txt hash      # → darkness
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Minion | `get-content backup.zip -stream 'pass'` 读出 NTLM hash → hashkiller 破出 `1234test` → `net use y: \\10.10.10.57\c$ /user:administrator 1234test` |
| BigHead | `more < root.txt:Zone.Identifier` 是二进制 → `certutil -encode` 带出 → `file` 认出 Keepass 2 库 → `keepass2john -k admin.png root.kdbx` 破出 `darkness` → 库中 Gilfoyle 条目含 root.txt |
| Hackback | `powershell get-content root.txt:flag.txt` 一步拿 flag(纯文本流) |

🔴 **二进制流不能直接 `type`/`get-content` 输出到终端** —— 会撞上编码/换行破坏,且大量不可打印字符。一律 `certutil -encode` 转 base64 再带出。

## 模式 3: 利用 —— 自己往 ADS 里藏 payload

条件:需要让文件在目录列举、按文件名/扩展名的检查、以及部分扫描里"看起来干净"。主文件名用完全正常的诱饵,内容写进额外流。

```powershell
Set-Content -Path C:\Users\Public\notes.txt -Stream hidden -Value '<payload>'   # 写
Get-Content -Path C:\Users\Public\notes.txt -Stream hidden                     # 读
Remove-Item -Path C:\Users\Public\notes.txt -Stream hidden                     # 清理,别留现场
```

```cmd
echo <payload> > C:\Users\Public\notes.txt:hidden
type C:\Users\Public\notes.txt:hidden
:: 读出来后落盘再执行(Win7+ 不支持直接执行 ADS 路径)
:: for /f "delims=" %i in ('type notes.txt:hidden') do echo %i > C:\ProgramData\p.bat
streams.exe -d -accepteula C:\Users\Public\notes.txt     :: 收尾删流
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| BigHead | 出题人把**整个 Keepass 数据库**塞进 `root.txt:Zone.Identifier` —— `dir`/`dir /ah` 两次列举都没暴露,只有加 `/r` 才现形,证明 ADS 对常规列举有效 |
| Hackback | 真 flag 放进 `root.txt:flag.txt`,载体 `root.txt` 本身是假 MD5;`dir /ah` 单用看不出来 |
| Minion | NTLM hash 放进 `backup.zip:pass`,不查流的人永远只看到 zip 本体 |

🔴 **三个必须记住的限制**
1. **ADS 只在 NTFS 上存在** —— 拷到 FAT32、U 盘、或经某些网络传输会**静默丢失**,藏了就取不回来。
2. **`copy` 保留流,`type`/重定向不保留** —— 想带走就整体 `copy`,别 `type file > newfile`。
3. **Windows 7 以后不能直接从 ADS 路径执行**(`file.txt:evil.exe` 会被拒) —— 正确用法是"读出→落盘→执行"。

## 模式 4: `Zone.Identifier` 是 MOTW 标记,不是藏东西的地方

条件:看到任何 `:Zone.Identifier` 流。**先判读语义,再决定要不要当"藏匿物"处理。**

```cmd
more < root.txt:Zone.Identifier
:: [ZoneTransfer]
:: ZoneId=3        ← 3 = Internet,即"从网上下载来的"
```

ZoneId 语义:`0`=本地机器、`1`=内网、`2`=可信站点、`3`=Internet、`4`=受限站点。带这个流就说明文件**来自网络**(浏览器/邮件/下载器写的),这是 Mark-of-the-Web,也是 SmartScreen/Office 受保护视图的触发依据。

### HTB 案例
| 机器 | 细节 |
|------|------|
| BigHead | 流名恰好叫 `Zone.Identifier`(伪装成普通 MOTW 标记,实际内容是 Keepass 库)—— 🔴 **名字像元数据不代表内容就是元数据**,必须实际读一遍 |

🔴 本卡最容易翻车的认知陷阱:看到 `Zone.Identifier` 的第一反应是"哦,就是个下载标记,没用"。BigHead 的整个 root flag 链就卡在这一念之间 —— **先 `more <` 看内容,再下结论**。

## 快速检查清单

```bash
[ ] Get-Item -Path *.* -Stream *                         # 当前目录全部流
[ ] dir /ah /r                                            # cmd 侧一次性列举(含隐藏+流)
[ ] Get-ChildItem -Recurse -File | Get-Item -Stream * | ? Stream -ne ':$Data'
[ ] streams.exe -s -accepteula <目录>                     # Sysinternals 递归
[ ] 过滤掉 :$DATA 后再看有没有别的流名
[ ] 有流 → 文本? get-content -stream '<名>' / more < file:stream
[ ] 有流 → 二进制? certutil -encode file:stream out.txt 带出
[ ] 压缩包/图片/日志等"日常文件"是否查过流?
[ ] 桌面与 flag 目录列举为空时,是否已查过 ADS?
[ ] 看到 Zone.Identifier → 先 more < 读内容,别当元数据跳过
[ ] 要藏东西:载体文件名正常、内容进额外流、事后 streams.exe -d 清理
[ ] 传输前确认目标盘是 NTFS(copy 保留流,type 重定向不保留)
```

## 教训

1. **"文件里没东西"不等于没有东西** —— NTFS 流对 `dir` 默认不可见且不计入大小。列举为空时第一个动作是查流。
2. **`dir /r` 是 Windows 上性价比最高的一条命令** —— BigHead 和 Hackback 的 root 段都是被这一条打开的。
3. **`Get-Item -Stream *` 会列出 `:$DATA`** —— 那是主内容,别把文件本身当成"隐藏流"而空欢喜。
4. **二进制流必须 base64 带出** —— 直接 `type` 出来是乱码,`certutil -encode` 是标准通道。
5. 🔴 **名字像元数据 ≠ 内容是元数据** —— BigHead 的 `Zone.Identifier` 里躺着整个 Keepass 库。先读,再判断。
6. **ADS 能藏整个数据库** —— 流长度异常大就按"完整文件"对待:导出 → `file` 识别 → 对应破解工具。
7. **藏是双向的** —— 出题人用它藏 flag/凭据,你也可以用它藏 payload;但非 NTFS 传输会静默丢流,且 Win7+ 不能原地执行 ADS。
8. **拿到流里的凭据后不要停** —— Minion 的 hash 破出 `1234test` 后立刻 `net use` 挂 c$;BigHead 的库打开后拿到的是 root.txt 条目。

## 相关卡

- `password-attacks` —— 流里导出的是 hash / Keepass 库(kdbx)/ 压缩包时,转过去做识别与破解(keepass2john、hashcat 模式选择)。
- `sherlock-investigation` —— 取证视角:要回答"这个文件被谁动过/来自哪里",与本卡配合读 MOTW 与端点痕迹。
- `windows-app-mru-forensics` —— 需要回答"哪个文件曾被打开过、压缩包里有什么目录"时(注册表 MRU 比文件本体更耐删)。
- `windows-privesc` —— 流里拿到的是本地管理员口令/hash,要找提权路径时。
- `living-off-the-land` —— 需要 `certutil`/`bitsadmin` 把流内容带出或落地时。
- `applocker-clm-bypass` —— `streams.exe` 等工具被执行策略拦下、或 PowerShell 落在 CLM 时。
- `scf-ntlm-theft` —— 场景从"读文件"变成"投文件偷 hash"时。
