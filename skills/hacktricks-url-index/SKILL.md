---
name: 'hacktricks-url-index'
description: 'HackTricks 直达 URL 索引：DLL劫持/ADCS/RBCD/AS-REP/NTLM Relay 等关键技术页面（hacktricks.wiki 已验证）。'
whenToUse: '遇到具体技术环节时按名查直达 URL，直接 web_fetch，不绕搜索引擎。'
metadata: { domain: meta, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# HackTricks 直达 URL 索引（已验证 2026-08，新域名 hacktricks.wiki）

> 🔴 遇到技术环节 → 先查本索引 → `web_fetch` 直接打开对应页面（内容完整可读），不需要搜索引擎绕路
> 基础 URL: `https://hacktricks.wiki/en/` （旧域名 book.hacktricks.xyz 已迁移）

## Windows 提权
| 技术 | URL |
|------|-----|
| **DLL Hijacking**（含 ProcMon 找缺失 DLL + 任意文件写链） | `windows-hardening/windows-local-privilege-escalation/dll-hijacking/index.html` |
| Windows LPE 总索引 | `windows-hardening/windows-local-privilege-escalation/index.html` |
| COM Hijacking | `windows-hardening/windows-local-privilege-escalation/com-hijacking.html` |
| Potato 系（JuicyPotato/RoguePotato/PrintSpoofer） | `windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html` |
| Token 滥用 | `windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html` |
| ACL/DACL | `windows-hardening/windows-local-privilege-escalation/acls-dacls-sacls-aces.html` |
| Named Pipe 提权 | `windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.html` |

## AD 攻击（active-directory-methodology/）
| 技术 | URL |
|------|-----|
| **AS-REP Roast** | `windows-hardening/active-directory-methodology/asreproast.html` |
| **Kerberoast** | `windows-hardening/active-directory-methodology/kerberoast.html` |
| **RBCD** | `windows-hardening/active-directory-methodology/resource-based-constrained-delegation.html` |
| 约束委派 | `windows-hardening/active-directory-methodology/constrained-delegation.html` |
| 无约束委派 | `windows-hardening/active-directory-methodology/unconstrained-delegation.html` |
| **ADCS 全系（ESC1-8）** | `windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html` |
| Shadow Credentials | `windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.html` |
| **NTLM Relay + Coercion** | `generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.html` |
| 密码喷洒 | `windows-hardening/active-directory-methodology/password-spraying.html` |
| Kerberos 原理 | `windows-hardening/active-directory-methodology/kerberos-authentication.html` |
| DCSync / Golden / Silver / Pass-the-* | 同在 `active-directory-methodology/`（dcsync.html / golden-ticket.html / silver-ticket.html / pass-the-ticket.html） |
| BadSuccessor (dMSA) | `windows-hardening/active-directory-methodology/badsuccessor-dmsa-migration-abuse.html` |
| Golden dMSA/gMSA | `windows-hardening/active-directory-methodology/golden-dmsa-gmsa.html` |

## Web / 通用
| 技术 | URL |
|------|-----|
| 文件上传攻击 | `pentesting-web/file-upload/index.html` |
| ZIP 技巧（zip slip 相关） | `generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.html` |

## 使用流程（嵌入规则0 两连查）
```
技术环节动手前:
  [1] memory search "<技术关键词>"        ← 查自己的资产
  [2] 查本索引 → web_fetch 对应 HackTricks 页面  ← 直达官方 wiki
  [3] 索引没有 → tavily search "<技术> <软件>"
```
**Why:** Bruno 教训——DLL 劫持目标猜了 3 轮（hostfxr/hostpolicy），HackTricks DLL Hijacking 页面早就有"任意文件写→缺失 DLL 劫持"章节；搜索引擎绕路不如直达 wiki。
**How to apply:** 每次会话自动加载；遇到上表技术先查索引再动手；新技术发现后补录本索引（URL 用 `curl -sI` 验证 200）。
