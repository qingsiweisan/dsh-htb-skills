---
name: 'snmp-enumeration'
description: 'SNMP枚举攻击：snmpwalk/snmp-check→用户/进程/网络信息泄露→凭据发现。HTB最古老的但仍在用的信息收集向量。'
disable-model-invocation: true
metadata: { domain: network, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## SNMP 枚举与攻击

### 识别
- 端口 161 (UDP)
- `snmpwalk -v 2c -c public target`
- `snmpwalk -v 1 -c public target`

### 信息收集
```bash
# 基本系统信息
snmpwalk -v2c -c public target 1.3.6.1.2.1.1
snmpwalk -v2c -c public target iso.3.6.1.2.1.1

# 运行进程 (带命令行参数！)
snmpwalk -v2c -c public target 1.3.6.1.2.1.25.4.2.1.2

# 用户列表
snmpwalk -v2c -c public target 1.3.6.1.4.1.77.1.2.25

# 网络信息
snmpwalk -v2c -c public target 1.3.6.1.2.1.4  # IP
snmpwalk -v2c -c public target 1.3.6.1.2.1.2  # Interfaces

# 获取所有 OID
snmpwalk -v2c -c public target .1

# snmp-check (自动化)
snmp-check -c public target
```

### Community String 爆破
```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt target
hydra -P /usr/share/seclists/Discovery/SNMP/snmp.txt target snmp
```

### 常见 Community Strings
- `public` (只读, 几乎总是存在)
- `private` (读写)
- `internal`, `manager`, `admin`, `cisco`
