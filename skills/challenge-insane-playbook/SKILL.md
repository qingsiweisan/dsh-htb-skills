---
name: 'challenge-insane-playbook'
description: 'HTB Challenges 解题总路由:附件形态→领域识别→六类专项 playbook 路由;含官方 WP 获取方法与 exploit 开发纪律（检索词：challenge/insane/playbook/rev/pwn/crypto/forensics/web）'
whenToUse: '做 HTB challenges(非靶机/非 Sherlock)时先加载:识别题型→路由到 heap/kernel/v8/web/crypto/rev 专项卡。'
metadata: { domain: challenges, tier: T1 }
---

# HTB Challenges 解题总路由

> 用法: 用 skill 工具按名加载 challenge-insane-playbook。先识别题型,再加载对应专项卡。

## 0. 官方 WP 获取(卡死 2 小时以上才对答案;对完必须把新原语沉淀进对应专项卡)

```text
1. 挑战列表 (浏览器上下文 fetch, app.hackthebox.com 已登录页):
   GET https://labs.hackthebox.com/api/v4/challenges?difficulty[]=insane&state=retired&per_page=100
   🔴 参数是 difficulty[] 和 state=retired;retired=true 会被忽略;per_page ≤ 100,>page 翻页
2. 官方 WP: GET https://labs.hackthebox.com/api/v4/challenge/{id}/writeup/official
   → {"url": "https://htb-content-prod-private-storage.s3...pdf?X-Amz-..."} (预签名,1h 有效,无需认证)
3. S3 直链本地 PowerShell Invoke-WebRequest 下载即可(不过 Cloudflare);labs API 限流 15 次/窗口,间隔 ≥4s
4. 提取文本: 传 Kali `pdftotext -layout x.pdf x.txt`
5. 存档位置: C:\Users\<user>\deepseek-harness\htb-challenge-wps\<难度>-<状态>\
```

## 1. 题型识别决策表(第一眼附件/环境)

| 信号 | 领域 | 加载专项卡 |
|---|---|---|
| 菜单式交互 + 附带 libc/ld.so(或 Dockerfile 指定 glibc) | glibc 堆 | challenge-heap-pwn |
| initramfs.cpio(.gz) + 无源码 .ko + /dev 自定义设备 | Linux 内核 pwn | challenge-kernel-pwn |
| d8 二进制 + patch.diff + .js 脚本 | V8/浏览器 | challenge-v8-pwn |
| 网站源码(Dockerfile/bot/admin 定时访问) | Web 多级链 | challenge-web-chain |
| 自定义 PRNG / 加密协议 / 密钥交换源码 | Crypto | challenge-crypto-prng |
| 自定义 VM / OISC / 自修改代码 / "运行极慢"描述 | Rev-VM | challenge-rev-vm |

复合信号(常见):Dockerfile 含反代版本号(如 Traefik 2.10.4)= 已知 CVE + 自写后端内存洞双入口;网站 + C 后端 = Web 链 + 内存溢出组合(NovaCore 模式)。

## 2. Exploit 开发纪律(全领域通用)

1. **本地完整复现远端**:同 glibc/内核/d8 版本(docker);pwn 用 `gdbserver :1234` attach 进容器调;调通才打远端。
2. **原语升级链**:bug → (信息泄露) → 任意读写 → 控制流 → 绕缓解 → shell/flag。每一步先固化成函数再走下一步,不要串起来盲调。
3. **概率性 exploit 必须包死循环重试**(部分覆盖 1/16 类、竞态类);重试粒度=整条链重来。
4. **版本偏移动态算**:symbol 偏移、gadget、结构体字段全部用本地同版本文件算,绝不抄 WP 的硬编码常量(换版本必崩)。
5. **逆向找漏洞先看非分配函数**:比较函数误用(strncmp 对二进制)、失败路径提前 return 跳过清理/逆变换、计数与遍历分离判断——UAF 常不在 alloc/free 本体。
6. **锁定义了却没用 = 竞态题**;能找到 copy_to/from_user 挂起点就优先 userfaultfd/FUSE 确定化。
7. 交互题先写**自动重连+异常重置**的 pwntools 骨架,再写利用逻辑;服务器 `alarm(N)` 决定交互预算。

## 3. 通用坑

- 🔴 WP 偏移/常量绑定该题内核与 libc 版本,只学步骤,不抄数字。
- 🔴 概率分支(浮点误差/ASLR 变体/1-of-16)必须循环重试,单次失败不要怀疑利用链。
- 🔴 题面"多余机制"(entangle/manage/附加 memcpy)几乎总是官方给的载荷投递通道,先审计它。
- 🔴 远端容器环境与本地差异(无 ls/cat、PATH、alarm)是最后一公里的坑,shell 里用内建命令兜底。

## 4. flag 载体总表与提交纪律（50 道挑战实战沉淀,2026-10）

**先问"它凭什么判对"。** 带 container 的题,**本地跑通 ≠ 拿到旗** —— 本地二进制常打印**假旗**(实测见过 `HTB{F4k3_...}` 与 `HTB{LOCAL_TEST_FLAG}`) ⇒ **必须再用同一凭据/输入打一次容器**。反向也成立:容器没线索时,附件常能逆出"要送什么"。

**载体清单(按"先便宜后昂贵"顺序试)**

| 载体 | 识别信号 | 动作 |
|---|---|---|
| **贴图里的像素** | 文本层全空、资源里有图 | 导 `Texture2D`/`Sprite`/照片成 PNG **看图**;裁剪+放大+旋转(实测有一题要转 −56° 才可读) |
| **ROM 自绘位图** | `.gba` 等老游戏 ROM | 自定义 RLE(高 2 位==11 ⇒ `count=b&0x3F` + 填充字节);**像素流后紧跟 768B 调色板** |
| **机器码里的坐标表** | 贴图全是诱饵/纯色/噪声 | 反汇编找 `rep movs` + 大块 `.rodata` ⇒ **路点表**(相邻点连线即字形);诱饵函数常按模运算批量生成 |
| **metadata 里的密文** | Unity IL2CPP | **静态字段名 = 数据 blob 的 SHA-256** ⇒ `dump.cs` 直给偏移;key/IV/CT 三块凑 AES |
| **Flutter JIT 明文源码** | APK 里有 `flutter_assets/kernel_blob.bin` | `grep -a "file:///" kernel_blob.bin` **直接读 Dart 源码**,不必反编译 `libapp.so` |
| **结构性信道** | 页面/文件看着像噪声 | **HTML 标签类型序列 / 属性 / 嵌套深度**都可能是编码(见 `malware-static-analysis` §10.5),勿只在"词"上找 |
| **分段** | 明文扫 `HTB{` 零命中 | 旗可能拆在**注释位 / 被改的字段值 / 加密回显 / 文件名**里 |

**判据纪律**

- 🔴 **扫 `HTB{` 零命中 ≠ 没有旗**:旗可能**全小写 `htb{}`**、可能**字面含 `...`**(三个 0x2e,别当截断标记)、可能**很长**(80+ 字符,**原样抄写别截断**)。
- 🔴 **判定语义可当 oracle**:`wrong_answer` = 绝对不是答案;而 `correct:true` **或任何 `*_error` 闸**(如 `methodology_error` / `analysis_error`)= **这个串就是答案**,只差前置条件(登记工具/用对地址)。**看到 error 别以为答案错了。**
- 🔴 **提交纪律**:只提交**有出处证据**的候选;**盲试 ≤2~3 次**(本会话有一道 Insane 连交 12 次错误值 = 反面样本)。拿到候选**先在本地落地留痕**(哪个文件哪一行 / 哪次响应),再提交。
- 🔴 **"结果对了 ≠ 流程对了"**:只把旗写进提交载荷、本机无产物承载出处 ⇒ 复核者无法独立验证来源,等于把正确性建立在运气上。
- 🔴 **有界重试而非放弃**:当"全都没命中"时,先怀疑**否证工具本身**(实测:某个已知明文 oracle 把「内存镜像自身的字节」当成密文,而真密文在容器文件里 ⇒ 生产出一个看起来极严谨的**假否证**,差点让正确的路被永久排除)。**否证脚本要能被他人独立复核到那一行。**

**环境硬坑(会直接毁掉一次解题)**

- 🔴 **磁盘满时会静默损坏产出**:`/` 只剩 2G 时 `7z x -o/root/...` 产出**0 字节**文件却仍返回 `Everything is OK`(`file` 显示 `empty`)⇒ **一律解包到 `/tmp`(tmpfs)**。
- 🔴 **只有 Windows 侧能连 HTB 容器**(`154.57.x.x:port`;Linux 直连 TCP 挂死)⇒ **静态分析在 Linux、与容器交互在 Windows**。
- 🔴 **容器槽位全局只有 1 个**:起第二个会把第一个挤下线 ⇒ **同一时刻只允许一条容器题在跑**,由调度侧显式排队,不能靠子代理自觉。
