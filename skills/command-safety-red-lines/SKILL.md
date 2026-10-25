---
name: 'command-safety-red-lines'
description: '操作安全红线（开局必读）：会杀死自己会话/卡死 PTY/超时/传输超限的命令，会用畸形输入把服务永久卡死（单例后端连接 + 无重连），以及破坏性操作前的可逆性检查。🆕 含共享 lab 的公共安全（磁盘写满 / VPN 实例数 / WinRM 遗留进程 / zsh 分词）与「跑闸前核对工具链」（冻结快照假绿灯）。（检索词：pkill/self-kill/heredoc/timeout/too-long/red-lines/safety/自杀/卡死/可逆性/self kill/too long/red lines/command/畸形输入/永久卡死/服务不可用/single client/singleton/无响应/挂起/hang/malformed input/DoS/自伤/共享 lab/shared lab/磁盘写满/disk full/openvpn/tun/wsmprovhost/MaxStartups/zsh/分词/word splitting/工具链核对/冻结快照/假绿灯/false green/闸/卡数核对)'
whenToUse: '任何攻防任务开局、以及即将执行 pkill / heredoc / 长任务 / 大文件传输 / 破坏性操作之前。'
metadata: { domain: meta, tier: T1 }
---

# 操作安全红线（开局必读）

> 🔴 这些坑的共同特征：**一次就能造成事故，且损失在"你自己的会话/工具链/靶机"上**，
> 事后无法从目标侧补救。因此**不能等"操作不通"时才查** —— 必须在开局就加载。

## 1. 会杀死自己会话的命令

```
❌ pkill -f '<模式>'   ← 模式会匹配到「执行这条 pkill 的 shell 自己的命令行」
   实例: pkill -f 'http.server 8000'
        → 把承载它的 SSH/bash 会话一起杀掉，任务当场中断
✅ 锚定 + 取 PID 再 kill:
   pgrep -f '^完整命令$' | xargs -r kill -9
✅ 只杀占用端口的进程（最稳）:
   lsof -ti tcp:8000 | xargs -r kill -9
✅ 或者干脆不杀，换端口重开
```
同族风险：`killall python3`、`pkill -f python` —— 会连带杀掉自己和其他辅助脚本。

❌ **变体（2026-09 实测又中一次）：手写 `/proc` 扫描 + case 匹配**
```bash
# ❌ 看起来比 pkill 安全，其实一样自杀
for p in /proc/[0-9]*; do
  c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue
  case "$c" in *"chisel_linux server -p 9001"*) OLD="${p#/proc/}";; esac   # ← 也会匹配到自己！
done
kill "$OLD"
```
两个致命点：
1. **自己这条 bash 的命令行里就含有该字符串字面量** ⇒ `case` 必然匹配到 `$$`；
   同族还有 `ssh` 进程、`grep`/`pgrep` 本身。
2. **循环变量被覆盖**：每个匹配都赋给 `$OLD`，**最后一个**胜出 ——
   而自己的 bash 通常排最后 ⇒ 杀掉的是自己。症状就是 `ssh: connection lost mid-flight`。

❌ **变体 B（2026-09-30 JobTwo 实测再次中招，本次一天内 3 次）：模式字面量出现在同一条命名的「别的角色」里**
```bash
# ❌ 三种写法都会自杀，因为模式字符串就在自己这条命令行里 —— 哪怕它只是被 grep/awk/sed 的参数
pkill -f 'dropsmb[.]sh'                     # ← 自己命令行里就有 dropsmb[.]sh
ps -eo pid,args | grep 'responder -I'       # 无害；但下一行 kill $(...) 就把自己算进去了
awk '/ntlmrelayx\.py/ {print $1}' | xargs kill   # ← awk 的脚本串 = 自己的 argv
bash -c 'pkill -f "crack\.sh"; echo done'    # ← 字符类转义挡不住，因为匹配的是自己的 argv
```
🔴 **规律：只要模式字符串以任何形式出现在「你自己这条命令」里，`-f` 全命令行匹配就必然命中你。**
`grep 'x[.]y'` 这类"转义防自匹配"技巧**只对 `grep` 自己的进程列表有效**，对 `pkill -f` 无效 ——
因为它匹配的是 `/proc/self/cmdline`，而你的 cmdline 里躺着原样的 `x[.]y`。
症状固定是 `ssh: connection lost mid-flight` / 会话当场消失，**不会有任何报错**。

✅ **本次验证可用的两个配方（都用「排除自己 PID」而不是「让模式更精确」）**
```bash
# 配方1：ps + awk 显式排除 $$（最通用，可带多个模式）
mine=$$; ps -eo pid,args --no-headers | \
  awk -v m=$mine '$1!=m && (/dropsmb\.sh/ || /Responder\.py/) {print $1}' | xargs -r kill
# 注意：awk 的 pattern 里出现斜杠要转义；'$1!=m' 放在最前，短路掉自己

# 配方2：按端口反查 PID（最稳，完全不碰命令行）
ss -lntpH "sport = :445"     # → users:(("python3",pid=1234,fd=7))  取 pid 再 kill
lsof -ti tcp:445 | xargs -r kill
```
🔴 **纪律：`pkill`/`killall` 一律不用；`pgrep -f`/`ps|grep` 只在加 `$1!=$$` 排除后使用；
能用端口/文件句柄定位就别用命令行定位。**

✅ **正解：让内核告诉你谁占着端口，绝不匹配命令行**

```bash
PID=$(ss -lntpH "sport = :9001" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1)
[ -n "$PID" ] && kill "$PID"
# 变体: lsof -ti tcp:9001 ; fuser -k 9001/tcp
```
✅ 真要扫 `/proc` 就必须排除自身与祖先：
```bash
self=$$; for p in /proc/[0-9]*; do pid=${p#/proc/}; [ "$pid" = "$self" ] && continue; ...
```

## 2. 会卡死 PTY 的写法

```
❌ 多行 heredoc: cat >> f << 'EOF' ... EOF     → PTY 卡死
✅ 单行 printf:  printf 'a\nb\n' > f
✅ base64:      echo '<b64>' | base64 -d > f
✅ 本地文件直接落盘，不要绕 shell（本 harness: write 工具）
```

## 3. 会触发超时的写法

```
❌ 前台跑 >30s（find / nmap / 大文件传输）→ 工具超时 / Request failed
✅ nohup <cmd> > /tmp/out.txt 2>&1 &  → 轮询 cat
✅ 本 harness: pwsh / ssh_exec 的 run_in_background + job_output
🔴 python 必须加 -u，否则 stdout 块缓冲，重定向文件永远是 0 字节
```

## 4. 传输长度限制

```
❌ 单条命令塞超长内容 → Command too long
✅ 短文件(<2KB): echo '<base64>' | base64 -d > /tmp/x
✅ 大文件: 起 HTTP 让目标自己拉（目标无外网 → 经中转容器）
✅ 本地↔远程: ssh_upload / ssh_download / write，不要用 shell 拼
```

## 5. 同脚本并发

```
❌ 同一脚本起多实例 → 目标服务连接上限挂起 → 然后你去 pkill → 触发 §1
✅ 先确认无残留: pgrep -af <脚本名>
```

## 6. 🔴 破坏性操作前的可逆性检查

动手前问一句：**这一步出错，我能恢复吗？**

```
[ ] 破坏的是"目标"还是"我自己的会话/工具链"？（后者更常见，也更冤）
[ ] 涉及宿主 / 共享资源吗？（宿主 fs、挂载、容器运行时、共享目录）
[ ] 只读够用吗？→ 优先 debugfs -R / --dry-run / --list-only / -n
[ ] 需要写吗？→ 先备份 / 先写副本
[ ] 不可 undo 的操作 → 先确认靶机可以重置
```

🔴 **真实事故（Reddish, Insane）**：为读宿主 ext4 上的 `root.txt`，用
`losetup` + `mount /dev/loop0` 对**已 rw 挂载**的同一文件系统造出**第二个 superblock**
→ journal 错误 → 内核按 `errors=remount-ro` 把宿主根置为只读
→ 三个容器的 overlay 全部不可写、rsync 守护进程 lock file 创建失败
→ **整台靶机报废，只能重置**。

正确做法只有一条：`mknod` + `debugfs -R`（纯用户态只读，不建 superblock）。
→ 详见 `container-escape` §1.1 与 `htb-machine-reset-recovery`。

## 7. 🆕 会**永久卡死服务**的"畸形输入"（2026-10-01 Store 实测）

> 这一类不属于"命令行自杀"，但同样**一次就造成事故**，而且**不需要任何破坏性命令** ——
> 只是一条格式古怪的请求。后果是"靶机的一个服务节点永久不可用"，且**不会自愈**。

**机制**：目标应用把**后端客户端做成模块级单例、只 connect 一次、从不重连**，
每个请求都 `await` 这同一个连接（Store：`sftp.js` 把 `new Client()` + `connect()` 放在模块加载时执行；
`routes/index.js` 每个请求都 `await client.listFiles/get/put`）。
⇒ 只要**一次**后端操作半路失败/挂住，**后续所有 `await client.*` 永不 settle**。
表现为：**碰后端存储的路由永久无响应（TCP 连上、零字节），不碰后端存储的路由一切正常。**

**症状识别（很容易误判成"网络抖动"或"被 WAF 拦"）**
- `curl` 返回 `code=000` **且 `t=` 正好等于你的 `-m` 超时**（不是 5xx、不是 reset、连响应头都没有）
- **同一实例上"部分路由活、部分路由死"**，且死的都是同一类（都碰存储/DB/后端）
- 换副本（多端口/多实例）**立刻正常** ⇒ 是**实例级**状态损坏，不是网络或代码问题

**高危输入类型（在目标身上试这些之前，先问一句"它有共享后端吗"）**
- 路径类参数里塞 `..` / 不存在的父目录 / `%00` / 换行 —— 让后端的 open/stat 抛错
- 让后端"读一个不存在的东西"（Store：`/file/<不存在>` 触发的 `get()` 失败）
- 上传/下载中途失败（`ssh2-sftp-client.get()` **先创建/截断本地文件再流式写** ⇒ 留下 0 字节文件）

**纪律**
1. **多副本服务只拿一个副本做畸形输入实验**，并在台账里记下"我污染了哪个副本"（Store：5000 被打挂，后半程全程用 5001/5002）。
2. 发现"部分路由永久无响应"→ **别去修**，直接换副本/重启服务，把它当作"已消耗的环境"。
3. 单例连接这种结构在 `sftp.js`/`db.js`/`redis.js`/`client.js` 里一眼可见 —— **拿到 LFI/源码就先看它**，能提前知道哪些请求危险。
4. 与 §6 同类：动手前问"这一步出错我能恢复吗"；这里"出错"的形状是**静默的、延迟的、不可自愈的**。

## 8. 🆕 远端 shell 上的"目录递归命令"= 隐形自杀（2026-10-01 Reaper 实测）

反弹 shell / `cmd.exe` 一旦发出**递归或全盘**命令，就可能把**唯一通道**永久堵死：

```cmd
where /r C:\ root.txt      # ❌ 全盘扫描
dir /s C:\                 # ❌
dir /r C:\                 # ❌（还会把所有 ADS 打出来）
for /r C:\ %i in (*) do @echo %i
Get-ChildItem -Recurse C:\  # ❌（PowerShell 版同理）
```

**机制**：`C:\Users\All Users`、`C:\Documents and Settings` 这类 **junction/符号链接**会被递归遍历
无限套娃（老版本 cmd 不识别重解析点）⇒ `cmd.exe` 卡在循环里，**socket 仍 ESTAB 但永远不再回显**。

**判据**（别当"命令慢"）：
- 命令发出后 **10 分钟以上零输出**，而 `ss -tnp` 显示连接仍 `ESTAB`；
- 服务端（被打的机器）**其他端口/服务一切正常** ⇒ 是你这条通道死了，不是机器挂了。

**纪律**：
1. **白名单命令**：`type <已知路径>`、`dir /b <目录>`、`Test-Path`、`where <浅路径>`、`tasklist`。
2. 真要扫盘：**另开一条通道**再扫，或把候选路径**本地**列出来逐个试；不要把"唯一 shell"押在扫描上。
3. 与 §7 同源：单连接服务 + 超长/含 NUL 的输入也会把读循环搞坏（本次另一台机器上是 1 KB+ 的畸形 key）⇒
   **发现"连上却零字节"就当 wedge 处理，直接 reset，不要反复重连**（见 `htb-machine-reset-recovery` §7）。

## 9. 🆕 共享 lab 上的"自我安全 = 公共安全"（Pro Lab 实测，2026-10-03）

> 单机靶机打坏了只影响自己；**Pro Lab / 共享实验网上，你的自伤会变成别人的故障**，
> 而且有些伤害**在你断开之后还在继续**。

```
[ ] 🔴 【别往靶机写大文件 / 别让输出全盘落盘】—— 有实例因磁盘被写满而僵死。
    ✅ 大输出只经 stdout 并用 `head`/`tail` 截断；❌ 不要 `find / > /tmp/all.txt`、
       `nmap -oN` 全端口全段、`tcpdump -w` 长时抓包留在目标机上。
    判据：写下任何重定向之前先问一句"这盘上还剩多少空间、我这一条会占多少"。
    （`df -h` 先看一眼；已经伤了就清掉自己的产物再继续。）
[ ] 🔴 【切 VPN 前后各查一次实例数与接口数】——
      `pgrep -a openvpn | wc -l` 与 `ip -brief addr | grep -c tun` 两个数【必须相等】。
      实例事故：两个 openvpn 抢同一 IP ⇒ 实验网全断，且症状像"靶机挂了"。
      ⇒ 收尾时按 PID 精确停（`kill <pid>`），**绝不 `pkill -f openvpn`**（§1 同族自杀）。
[ ] 🔴 【`Invoke-Command` / WinRM 起的远端循环必须显式收尾】——
      Windows 上 `wsmprovhost.exe` 在**客户端断开后仍然存活**，会继续对目标建连。
      事故：把目标 sshd 打到 `Exceeded MaxStartups`（**160 条遗留连接**），
      ⇒ 之后**所有人**（包括你自己）连不上那台机器。
      ✅ 正确形态：远端命令必须【同步等待结束 + 收结果】，或明确 `Stop-Process` 掉远端进程；
         循环一律带"总条数上限 + 结束条件"，不要"跑到天荒地老"的那种。
[ ] 🔴 【Kali 侧交互 shell 是 zsh：未加引号的 `$VAR` **不做分词**】——
      `K="-i a -o b"; cmd $K` 在 zsh 里会把整串当成【一个词】⇒ 命令静默变形、白跑一轮。
      本场真实代价：一条扫描/喷洒命令因此空跑。
      ✅ 复杂命令一律【写到 `/tmp/x.sh` 再 `bash /tmp/x.sh`】（最稳，也便于复查），
         或显式 `eval`、或 zsh 的 `$=VAR` 分词。
[ ] 🔴 【共享 lab 礼节】—— 不动别的玩家的进程 / 文件 / 会话；
      若某服务被自己（或你发现是别人）打死，**修好它并留下痕迹**（别留一个"半死"的共享入口）。
```

### 9bis 🔴🆕 跑「技能库闸」之前先核对工具链版本（会致错的坑，2026-10-03 实测）

```
[ ] 🔴 某些主机上存在**冻结快照**的工具链 —— 例：Kali 的 /root/dsh-htb-skills 里，
      scripts 是**修复前版本**、skills/ 只有 **114 张**（活库在 ~/.dsh/skills，已 162 张）。
      ⇒ 拿快照跑闸会得到 **"0 errors" 假绿灯**：你以为"库是干净的"，而活库可能满身错误。
[ ] ✅ 核对两步（**跑任何闸之前**）：
      ① **看它打印的目标目录** —— 修复后的 triage/audit 会打印 `目标: <path> (<来源>)`，
         来源应是活库（`~/.dsh/skills (live)`），**不是包内镜像**；
      ② **看扫描到的卡数**是否等于你认知的卡数（`114 ≠ 162` 就是拿错工具链了）。
[ ] 🔴 **`triage_skills.py` 会写卡**（规整 frontmatter + 重建索引）⇒
      **跑完必须重读文件再编辑**：不要凭"跑闸前的内存印象"改卡 ——
      否则轻则 edit 报 `file changed since you read`，重则你按旧内容做替换而匹配不到（或改错位置）。
```


## 与其他卡的关系

| 卡 | 分工 |
|---|---|
| `prolab-engagement-playbook` §8.3 | **越界红线**：别的实验室实例网段（VPN 推来的 `10.13.37/38`、`10.129.0.0/16`、其它 `10.10.x`）绝对不碰 |
| `blocking-points-detail` §3.5 | 传输/执行的**细节**（HTTP 服务、PTY 驱动交互程序） |
| `htb-machine-reset-recovery` | 已经打挂了怎么办 + 重置 API + 重置后果 |
| `container-escape` §1.1 | 读宿主 fs 的正确姿势（debugfs）与 mount 禁令 |

**Why:** 这几条原本埋在 `blocking-points-detail`（T2，按需加载）里，
结果是"**事故先于卡到达**" —— 本次 `pkill -f` 自杀就是这么发生的。
**How to apply:** 开局随 `box-startup` 一起加载；执行 §1–§9 涉及的命令前扫一眼对应小节。
**🆕 2026-10-03 扩容：** 原卡只覆盖"单机打靶的自伤"；Pro Lab/共享实验网上还要管 §9 那一类
——**你的自伤会变成别人的故障，且有些伤害在你断开之后仍在继续**（磁盘写满、遗留 VPN 实例、
WinRM 远端进程堵死共享入口）。
