---
name: 'ad-type-recognition'
description: 'AD 域渗透题型识别：快速决策树，OS版本→KDS→权限→攻击路径，避免盲目爆破'
whenToUse: 'AD 域靶机拿到 shell 第一秒做题型识别：OS→KDS→权限→攻击路径决策树。'
metadata: { domain: ad-win, tier: T1 }
---

# AD 域渗透题型识别

> 🔴 **拿到 shell 第一秒执行 — 决定攻击路径，避免盲目爆破**

## 决策树

```text
[ ] OS 版本？
    ├─ Windows Server 2025 (Build 26100+) → dMSA, VBS, Credential Guard
    ├─ Windows Server 2016-2022 → Shadow Credentials, ADCS, RBCD
    └─ 更早 → 传统 AD 攻击

[ ] KDS Root Key 存在？
    └─ LDAP 搜 CN=Group Key Distribution Service → dMSA 攻击题型（BadSuccessor = 原始攻击名 / BetterSuccessor = 补丁后变体，本卡下文统一用 BetterSuccessor 指代）

[ ] 已控用户权限？
    ├─ CreateChild on OU + GenericWrite on 目标 → 🎯 BetterSuccessor
    ├─ GenericWrite on 目标 → Shadow Credentials (首选)
    ├─ WriteDacl / WriteOwner → RBCD
    └─ 仅 READ → 信息收集

[ ] 有 VM 文件？
    └─ .vmem/.vmdk/.vhd/.sav/.vmsn → VMkatz 直接提取

[ ] 有 ADCS？
    └─ certipy find -vulnerable → ESC1-13（与 ad-checklist 一致）

[ ] 都无？
    └─ 传统 Kerberoast / ASREP / 爆破
```text

## 攻击路径优先级

| 条件 | 攻击 | 工具 | 速度 |
|------|------|------|------|
| KDS + CreateChild + GenericWrite | BetterSuccessor | bloodyAD/badS4U2self（社区 PoC 名，与 ad-checklist 的 SharpSuccessor 同源，以实际工具为准） | 30秒 |
| GenericWrite | Shadow Credentials | certipy/bloodyAD | 1分钟 |
| .vmem/.vmdk 文件 | VM 取证 | VMkatz | 2分钟 |
| 用户有 SPN | Kerberoast | Rubeus/GetUserSPNs | 需爆破 |
| ADCS 存在 | ESC1-13（与 ad-checklist 一致） | certipy | 5分钟 |

> 详细命令见 ad-checklist 卡

## 核心原则
1. **爆破永远是最后选项**
2. **Server 2025 = 先想 dMSA**
3. **有 GenericWrite = 先试 Shadow Credentials/BetterSuccessor**
4. **VM 文件 = VMkatz 最快**
