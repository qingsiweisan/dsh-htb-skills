---
name: 'kali-tools-augmented'
description: 'Kali 工具补全：pipx 安装 bloodyAD/coercer/pywhisker + GitHub 克隆 PetitPotam/PKINITtools/targetedKerberoast/krbrelayx/pre2k/DonPAPI'
disable-model-invocation: true
metadata: { domain: tools, tier: T2 }
---

# Kali 工具补全 — 2025-07-06

## pipx 安装（~/.local/bin/）
- **bloodyAD 2.5.4** — LDAP 操作 / dMSA / Shadow Credentials / 通用 AD 枚举
- **coercer 2.4.3** — 自动检测和利用所有强制认证方法（PetitPotam/PrinterBug/DFSCoerce等）
- **pywhisker 0.1.2** — Shadow Credentials 攻击（pyWhisker）

## GitHub 克隆（/opt/tools/）
- **PetitPotam** — topotam/PetitPotam → PetitPotam.py
- **PKINITtools** — dirkjanm/PKINITtools → gettgtpkinit.py / gets4uticket.py / getnthash.py
- **targetedKerberoast** — ShutdownRepo/targetedKerberoast → targetedKerberoast.py
- **krbrelayx** — dirkjanm/krbrelayx → krbrelayx.py / addspn.py / dnstool.py / printerbug.py
- **pre2k** — garrettfoster13/pre2k
- **DonPAPI** — login-securite/DonPAPI

## 系统包（已安装）
- certipy-ad 5.0.3
- netexec 1.4.0
- lsassy 3.1.11
- impacket 全套 (ntlmrelayx/dacledit/rbcd/secretsdump...)
- responder 3.1.7.0
- mitm6

## 运行方式
- pipx 工具: `~/.local/bin/bloodyAD`, `~/.local/bin/coercer`, `~/.local/bin/pywhisker`
- GitHub 工具: `python3 /opt/tools/<repo>/<script>.py`
- 系统工具: 直接命令（certipy-ad / netexec / impacket-* / responder）

**Why:** 之前 Kali 缺少 9 个关键 AD 攻击工具，ADCS/NTLM relay/强制认证链从未实战过。补全后可覆盖完整 AD 攻击面。
**How to apply:** 新靶机遇到 AD 环境时，检查这些工具是否适用。
