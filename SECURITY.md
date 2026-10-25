# 安全与脱敏说明

## 使用范围

本项目面向 **HTB 靶机、自建实验环境**等**已获授权**的攻防练习场景。
卡片里的大量内容来自退役靶机的公开解题思路，**不适用于真实生产环境**，
也不构成任何形式的攻击授权。请自行确认目标在授权范围内。

## 仓库内不含真实凭据

发布前对整个仓库做过一次逐文件扫描与脱敏，规则如下。

### 已脱敏（替换为 `<REDACTED>` 或占位符）

| 类别 | 处理 |
|---|---|
| 靶机/挑战中取得的**明文口令** | `<REDACTED>` |
| **NT hash / SHA-512 crypt / PBKDF2 摘要** | `<REDACTED>` |
| **JWT secret / machineKey / ViewStateUserKey** | `<REDACTED>` |
| **服务 token**（Vault `hvs.` 等） | `<REDACTED>` |
| **SSH 私钥 passphrase** | `<REDACTED>` |
| **flag 样本**（`HTB{...}` 与裸 32 位 hex） | `<REDACTED>` / `<32-hex-flag>` |
| **本机用户名路径**（`C:\Users\Administrator` 等） | `C:\Users\<user>` |
| **git-credentials / restic 密码 / 配置文件备份里的口令** | `<REDACTED>` |

### 有意保留（不属于凭据）

| 类别 | 原因 |
|---|---|
| `md5("foo") = acbd18db…`、空 LM hash `aad3b435…`、MD5 魔数 `0e462097…` | 技术常量，是判断依据本身 |
| 合约地址、IPFS CID | 公开链上数据 |
| 密文（padding-oracle 样本等） | 无密钥不可用 |
| `$PASSWORD` / `$TOKEN` 等变量名 | 命令模板，不含值 |
| 靶机侧路径（`C:\Users\santa`、`/home/frank/`） | 目标机器的账户名，非凭据 |

### 扫描方法

两轮独立检测，避免单一正则清单漏项：

1. **模式匹配**：HTB token 原文（与本机 `~/.dsh/htb-token.txt` 逐字比对）、
   JWT、私钥块、云厂商密钥、GitHub/Slack/OpenAI token、`HTB{...}`、
   32/40 位 hex、`password/token/secret = ...`、绝对用户路径。
2. **高熵串检测**：长度 20–64、大小写+数字齐全、Shannon 熵 ≥ 3.9 的纯字母数字串，
   逐条人工判读。这一轮抓到了模式匹配漏掉的 4 处（Vault token、SHA-512 哈希、
   restic 密码、明文口令）——**只靠正则清单是不够的**。

## 提交前自查

如果你要往本仓库加内容，请先确认：

- [ ] 不含任何真实环境的 token / 口令 / 私钥 / 会话 cookie
- [ ] flag 已替换为 `<REDACTED>`
- [ ] 本地绝对路径已替换为 `C:\Users\<user>` 或 `~/`
- [ ] 跑过 `node scripts/framework-check.mjs`（含 `cards/no-flag` 闸）

## 报告问题

如果发现仓库里仍有凭据泄漏，请**不要**提 issue 公开细节，
直接通过 GitHub 的私密漏洞报告（Security → Report a vulnerability）联系维护者。
