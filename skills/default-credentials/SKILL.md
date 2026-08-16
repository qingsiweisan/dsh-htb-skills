---
name: 'default-credentials'
description: '默认凭据速查表：数据库/Web框架/远程访问/开发工具/CICD/硬件的常见默认用户名密码 + 快速喷洒命令'
disable-model-invocation: true
metadata: { domain: creds, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# 默认凭据速查表

> 每次遇到登录框/SSH/MSSQL/Web 管理面板 → CTRL+F 搜服务名 → 照抄试

## 数据库

| 服务 | 用户名 | 密码 |
|------|--------|------|
| **MSSQL** | `sa` | `<blank>`, `sa`, `password`, `P@ssw0rd`, `admin`, `sa123` |
| **MySQL** | `root` | `<blank>`, `root`, `password`, `admin`, `mysql` |
| **PostgreSQL** | `postgres` | `postgres`, `password`, `admin` |
| **Oracle** | `system`, `sys` | `manager`, `change_on_install`, `oracle` |
| **MongoDB** | `<none>` | (默认无认证) |
| **Redis** | `<none>` | (默认无认证，可能设 `requirepass`) |

## Web 应用/框架

| 服务 | 用户名 | 密码 |
|------|--------|------|
| **Tomcat** | `admin`, `tomcat`, `manager` | `admin`, `tomcat`, `s3cret`, `password` |
| **Jenkins** | `admin`, `jenkins` | `admin`, `jenkins`, `password` |
| **WordPress** | `admin`, `administrator` | `admin`, `password`, `wordpress` |
| **Joomla** | `admin` | `admin`, `joomla`, `password` |
| **Drupal** | `admin` | `admin`, `password` |
| **phpMyAdmin** | `root`, `pma` | `<blank>`, `root`, `password` |
| **Grafana** | `admin` | `admin`, `grafana` |
| **Kibana** | `elastic` | `changeme`, `elastic` |
| **CMS/Framework Admin** | `admin` | `admin`, `password`, `changeme` |

## 远程访问 / SSH / RDP

| 服务 | 用户名 | 密码 |
|------|--------|------|
| **Raspberry Pi** | `pi` | `raspberry` |
| **Kali Linux** | `kali` | `kali` |
| **Ubuntu (旧版 OVA)** | `ubuntu` | `ubuntu` |
| **Alpine Linux** | `root` | `<blank>` |
| **OpenWrt** | `root` | `<blank>`, `admin` |
| **NAS (Synology)** | `admin` | `synology`, `<blank>` |
| **vSphere/ESXi** | `root` | `<blank>` (装后设) |

## 开发工具/平台

| 服务 | 用户名 | 密码 |
|------|--------|------|
| **MLflow** | `admin` | `password`, `admin` |
| **Jupyter** | `<token in URL>` | (token 在启动日志或 `~/.jupyter/`) |
| **GitLab (初始 root)** | `root` | `5iveL!fe` |
| **SonarQube** | `admin` | `admin` |
| **Airflow** | `admin` | `admin` |
| **Hoverfly** | `admin` | (启动参数 `-add -password X` 或用 JWT `/api/token-auth`) |
| **NiFi** | `<none>` | (默认无认证，新版本初始用户名密码在 logs) |
| **Webmin** | `root` | (系统的 root 密码) |

## CI/CD

| 服务 | 用户名 | 密码 |
|------|--------|------|
| **Jenkins** | `admin` | `password` (首次启动随机，在 `~/.jenkins/secrets/initialAdminPassword`) |
| **TeamCity** | `admin` | `admin` |
| **Bamboo** | `admin` | `admin` |

## 硬件/嵌入式

| 设备 | 用户名 | 密码 |
|------|--------|------|
| **Cisco Router/Switch** | `admin`, `cisco` | `cisco`, `admin`, `password` |
| **IP Camera (常见)** | `admin` | `admin`, `123456`, `<blank>` |
| **Printer (HP Jetdirect)** | `admin` | `admin`, `<blank>` |
| **UPS (APC)** | `apc` | `apc` |

## 快速测试命令

```bash
# SSH 快速测试
for pass in '' 'admin' 'password' 'root' '123456'; do
  sshpass -p "$pass" ssh -o ConnectTimeout=3 user@TARGET 'id' && echo "FOUND: $pass"
done

# 常见用户名列表
echo -e 'admin\nroot\nsa\npostgres\nadministrator\npi\nkali\nubuntu\nuser\nmanager' > users.txt

# 常见密码列表
echo -e '\nadmin\npassword\nroot\n123456\nchangeme\nAdmin123\nP@ssw0rd\ntomcat\njenkins' > pass.txt

# nxc 喷洒
nxc smb TARGET -u users.txt -p pass.txt --no-bruteforce --continue-on-success
nxc ssh TARGET -u users.txt -p pass.txt --no-bruteforce
nxc mssql TARGET -u users.txt -p pass.txt --no-bruteforce
nxc winrm TARGET -u users.txt -p pass.txt --no-bruteforce
```

## 注意事项

1. **先试空密码** — 无数服务默认无密码
2. **密码派生** — `服务名` + `123` / `admin` / `password` 是常见模式
3. **版本相关** — 某些默认密码随版本变化 (如 Jenkins)
4. **账户锁定** — 生产环境试 3-5 次就停，否则可能触发锁定
5. **从其他源收集用户名** — 网页源码、邮箱地址、RID 枚举、rpcclient
