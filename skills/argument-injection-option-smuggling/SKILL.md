---
name: 'argument-injection-option-smuggling'
description: '用户可控字符串进入某个命令的 argv 时（文件名经 shell 通配符展开、sudoers 允许的命令带 * 通配符、参数原样透传给 CLI），攻击面不是"命令注入"而是 argument injection / option smuggling：伪造选项让程序自己去做危险动作。含判据、无害探针、以及两个实战锚——web 上传文件名 → zip -TT 执行任意命令；sudo tcpdump 的 * 可跨 / ⇒ -Zroot 提权。**（检索词：argument injection、argument-injection、option smuggling、option-smuggling、参数注入、选项注入、选项走私、argv 注入、通配符注入、wildcard、filename to argv、文件名当选项、zip -TT、-TT、gzexe、sudoers 通配符、sudo -l 带星号、tcpdump -Z、tcpdump -z、tcpdump -V、AppArmor tcpdump、system exec shell_exec 拼接）**'
whenToUse: '看到 system()/shell_exec/exec 把文件名或用户输入拼进命令行且带通配符 *；或 sudo -l 里允许的命令带 * 通配符——先怀疑选项注入而不是命令注入'
metadata: { domain: web, tier: T2 }
---

# 参数注入 / 选项走私（argument injection & option smuggling）

> 🔷 一手实测来源：Dump（HTB Medium，Linux，2025-10-30 发布）—— 两个独立的参数注入面串成一条链。

🔑 核心认知：**shell 元字符被过滤 ≠ 参数安全**。只要用户可控的字符串以「一个 argv 元素」的身份进入某个命令，
它就可能被当成**选项**而不是数据；而很多 CLI 都有"选项一出手就执行命令/写文件/读文件"的能力。
这与命令注入是**两套不同的判据**，`escapeshellarg`/`basename` 治不了它。

## 0. 触发信号

| 信号 | 说明 |
|---|---|
| `system("cmd ... *")` / `shell_exec` 里带**通配符**，而该目录里的文件名来自用户 | 文件名成为 argv 元素 |
| 上传/解包后的文件名**只被 `basename()` 处理**（前导 `-` 保留） | 攻击面常在"看似已修"的地方 |
| `sudo -l` 允许的命令带 `*`（**参数**里的通配符） | 见 §2，这条最容易被误判为"没法用" |
| 程序把 `$1/$2` 原样透传给另一个 CLI（curl/wget/tar/zip/rsync/ssh） | 选项注入的第二跳 |

## 1. 无害探针（先确认能不能伪造选项，再想干什么）

```bash
# 文件名探针：上传一个叫 -h / --help 的文件，看目标命令的输出是否变成帮助信息
#   → 变成帮助信息 = 该位置被解析为选项（100% 确认）
# sudo 侧探针：塞一个绝对路径的已知无害可执行文件，看 sudo 是否放行
sudo -n <allowed-cmd> <合法参数...> -z/bin/true <填满模式的部分>
```
🔴 **先探针再构造 payload**：探针失败时你损失 5 秒；拿真 payload 去试失败时，你会以为"思路错了"而换方向。

## 2. 锚点 A：sudoers 的 `*` 在**参数**里可以匹配 `/`

这是本题最关键的一条、也是最反直觉的一条：

- sudoers 匹配**命令路径**时用 `FNM_PATHNAME` ⇒ `*` **不能**跨 `/`；
- 匹配**参数**（args 串）时不是这样 ⇒ **`*` 可以匹配 `/`**。
- sudo 把用户的 argv 用空格拼成一个字符串，再用 fnmatch 去比 sudoers 里那串参数
  ⇒ **只要模式里有一个 `*`，你就能在它覆盖的区间里插入任意多个额外参数**（用空格切分）。

Dump 的实例：
```
sudo -l 给出：
  (ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10
      -w/var/cache/captures/*/<uuid8-4-4-4-12>
      -F/var/cache/captures/filter.<uuid>

探针（被接受即证明 * 可跨 /）：
  sudo -n tcpdump -c10 -w/var/cache/captures/x -Zroot -z/bin/true \
       -G1 -W1 -w /<uuid> -F/var/cache/captures/filter.<uuid>
      ↑ 这一段全部落在 * 的覆盖区间里，拼接后仍匹配模式

形成的能力（tcpdump 三件套）：
  -Z<user>  改运行身份 / 决定 savefile 属主（-Zroot ⇒ root 属主，cron 才不会 WRONG FILE OWNER）
  -w<path>  改 savefile 目标（最后一个 -w 生效）⇒ "以 root 写任意路径"
  -c1       覆盖原本固定的 -c10，只抓 1 个包（让内容可控、体积最小）
  -r<pcap>  配合 -w 做**逐字节一致的复制**：先在可读路径产出一份、验证内容，再复制到目标
  -z<cmd>   注意：是 execlp(cmd, savefile) **不是 system()** ⇒ cmd 必须是单个可执行文件 token
  -V<file>  把文件当"文件名列表"读 ⇒ 第一个打不开的名字会出现在错误信息里 = **一次泄漏一行**
```
⚠️ `-z` 的实际可用性由 AppArmor 决定，不是由 sudo 决定（见 §4）。

## 3. 锚点 B：web 上传文件名 → zip 的选项（Dump 的初始 RCE）

```php
// download.php：用户可控的是**目录里的文件名**，而 * 由 shell 展开
chdir($_SESSION['userdir']);
system("zip /var/www/html/downloads/$r.zip * 2>&1");
```
```bash
# upload.php 只做了 basename()（剥掉 /），前导 - 原样保留
# 于是两个文件名就是两个选项：
#   -T        : 让 zip 测试归档
#   -TT<cmd>  : 指定测试用的命令 —— zip 会执行 system("<cmd> <临时文件>")
```
**四个必要条件（缺一即失败）**：
1. `-T` 与 `-TT<cmd>` **两个都要**（只有 `-TT` 不会触发测试阶段）；
2. 目录里**至少有一个普通文件**，否则 `zip error: Nothing to do!`，测试阶段根本不会到；
3. **字典序相邻**：`-TT<cmd>` 的下一个 argv 才是命令串 ⇒ 先把目录清空（本题用应用自带的 `delete.php`），
   只留 `-T`、`-TT<cmd>`、一个真文件；
4. 命令要经 shell ⇒ 在命令文件名里写 `... | base64 -d | sh #` 这类多段管道时，
   **末尾必须 `#`**，否则 zip 追加的临时文件路径会被当成 `sh` 的脚本参数。

🔴 **顺带一条高价值信号**：本题 `download.php` 把 `system(... 2>&1)` 的输出**回显在响应的 HTML 注释里**
（开发者调试残留）。这等于给了你一个**自带 oracle 的命令执行通道**：即使反弹 shell 还没建好，
也能用"投文件名 → 读响应"把任意命令的输出读回来。

## 4. 被沙箱/配置框架截断时：AppArmor 中介的是**解析后**路径

同一条命令上往往叠着两层限制，两层用的判据**不一样**，这个不对称本身就是利用点：

| 层 | 匹配对象 | 结果 |
|---|---|---|
| sudoers | 用户敲的**字面**参数串 | 决定"能不能跑"；`*` 可跨 `/` ⇒ 参数可注入 |
| AppArmor | 打开文件的**解析后**真实路径 | 决定"能读写哪里"；symlink 会被跟随 |

Debian 的 tcpdump profile 里与提权相关的几条（stock，非作者添加）：
```
owner @{HOME}/** rw,          # 配 -Zroot ⇒ 以 root 读写 /root/** 与 /home/*/ 的**非点**文件
/**.[pP][cC][aA][pP] rw,      # 任何 .pcap 结尾的路径
/{usr/,}bin/gzip ixr,         # 只给 -z 放行 gzip/bzip2（=> -z 拿不到任意命令执行）
audit deny @{HOME}/.* mrwkl,  # 显式 deny 优先于一切 allow：/root/.ssh/authorized_keys 写不进去（实测 EACCES）
```
站点覆盖文件 `/etc/apparmor.d/local/usr.bin.tcpdump` 常被作者改（Dump 里加了 `/**<uuid> rw`
让 web 应用能存 uuid 命名的抓包）——**这正是"读一张卡的权限表就能反推作者意图"的地方**，比盲试快得多。

## 5. 🔴 决策顺序（本题踩过的坑，按这个顺序走能省半小时）

```
[1] 先问：目标文件**能不能直接读**？  ← 本题的 root.txt 是单行文件，-V 一次就读全，
                                        而我先去造"写入 + 执行"链，还顺手覆盖了靶机的 root 脚本
[2] 再问：能不能用现成的**读取/复制**能力（-V / -r + -w）拿到目标，而不是造代码执行
[3] 再问：写入原语能不能覆盖"已经被 root 周期性执行"的文件？——**先验证执行机制，再投放**
        · cron 逐行解析 ⇒ 首行必须是合法行（pcap 首行是二进制 ⇒ bad minute，整个文件被忽略）
        · shell 执行无 shebang 的文件时会回退解释执行，但**前 80 字节含 NUL 就拒绝**（Exec format error）
          ⇒ 任何"写 pcap 当脚本"的思路都死在 NUL 上。`sh -n` 能过 ≠ 能执行
[4] 最后才造 RCE
```

## 6. 同类家族（同判据，可直接迁移）

- 归档器：`zip -TT<cmd>`、`7z @listfile`（读任意文件列表）、`tar` 的 `--checkpoint-action`、`-snl`
- 传输器：`rsync -e`、`scp -o`、`curl -o`/`-K`、`wget -O`/`--use-askpass`
- 解释器/工具：`ssh -o ProxyCommand`、`git --upload-pack`、`find -exec`、`awk` 的 `@load`
- 通用判据：**该 CLI 有没有"选项一出手就执行命令/写文件/读文件"的能力** —— 有就是选项注入，
  没有就退化成信息泄露（能改输出格式/写坏文件）。

## 速查清单

```bash
[ ] system/shell_exec/exec 的字符串里有没有 * ？→ 目录里我能造文件名吗？
[ ] 文件名只做了 basename()？→ 试 -h / --help 探针
[ ] sudo -l 里有 * ？→ 🔴 先测 * 能不能跨 /（塞一个绝对路径无害可执行文件）
[ ] 目标命令的 CLI 手册里，哪些选项会 exec()/写文件/读文件？（-z -Z -TT -o -K -@）
[ ] 上位限制是 sudoers 还是 AppArmor/SELinux？—— 前者匹配字面串、后者匹配真实路径，别混用判据
[ ] 🔴 先试"直接读目标文件"，再考虑造 RCE
```
