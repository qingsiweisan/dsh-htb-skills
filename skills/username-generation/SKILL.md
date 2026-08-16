---
name: 'username-generation'
description: 'AD用户名生成规则+工具(username-anarchy/namemash)。枚举第一步必须。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 用法：按卡名用 skill 工具加载；长任务用 bash 后台任务、并行侦察用 subagent。

## 用户名生成 — AD 枚举第一步

### 姓名 → AD 用户名规则
拿到真名（LinkedIn、OSINT、内部文档）后，AD 用户名最常见的格式生成规则：

| 格式 | 示例 (John Smith) |
|------|-------------------|
| FirstLast | johnsmith |
| First.Last | john.smith |
| FLast | jsmith |
| FirstL | johns |
| First | john |
| LastF | smithj |
| Last.First | smith.john |
| Last | smith |
| 3 letter + 3 digits | abc123 |

### 工具
```bash
# username-anarchy (最全)
git clone https://github.com/urbanadventurer/username-anarchy
./username-anarchy John Smith > users.txt
./username-anarchy --input-file names.txt --select-format first.last > users.txt

# namemash.py (更轻量)
python3 namemash.py -n "John Smith" > users.txt
```text

### 集成到枚举流
```bash
# 1. 从各种源收集姓名
# 2. 生成用户名列表
# 3. 用 kerbrute 验证哪些用户存在
kerbrute userenum -d domain.local --dc DC_IP users.txt
# 4. 有效的用户名 → 密码喷洒 / ASREPRoast
```text
