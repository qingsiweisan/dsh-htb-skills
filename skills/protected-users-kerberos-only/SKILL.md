---
name: 'protected-users-kerberos-only'
description: 'Protected Users组：禁止NTLM、只允许Kerberos。遇到STATUS_ACCOUNT_RESTRICTION立即换Kerberos。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Protected Users 组特征与应对

## 特征
- 禁止 NTLM 认证：`STATUS_ACCOUNT_RESTRICTION` 而非 `STATUS_LOGON_FAILURE`
- 只允许 Kerberos：AES128/AES256 加密
- 禁止 RC4 Kerberos
- 禁止委派（约束/非约束）
- TGT 生存期限制为 4 小时
- 禁止 RPC 某些操作（certipy 部分功能失败）

## 检测方法
```bash
# NTLM 测试: STATUS_ACCOUNT_RESTRICTION = Protected Users
netexec smb DC -u user -p pass  # → STATUS_ACCOUNT_RESTRICTION
# Kerberos 测试: 成功则确认
impacket-getTGT domain/user:'pass' -dc-ip IP
```

## 应对
- **所有认证必须用 Kerberos**: `-k -no-pass` 或 `export KRB5CCNAME`
- `certipy shadow auto` 用 `-k -no-pass` 而非 `-p`
- `bloodyAD` 用 `-k` 而非 `-p`
- netexec 用 `-k` 标志
- **时钟同步是铁律**: `ntpdate -b <DC_IP>` 每次 Kerberos 操作前执行

## 来源
Logging 靶机：svc_recovery 在 Emergency Recovery + Protected Users 组

**Why:** Protected Users 导致 NTLM 工具静默失败，容易误判为密码错误
**How to apply:** STATUS_ACCOUNT_RESTRICTION → 立即换 Kerberos 认证，先同步时钟
