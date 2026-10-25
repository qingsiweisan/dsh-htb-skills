---
name: 'htb-machine-reset-recovery'
description: 'HTB 靶机自助重置与自伤恢复：API 端点(/vm/reset、v5 machine/own)、token 位置、重置三连后果(靶机IP/flag/容器IP)、以及"靶机被自己打挂"的处置流程。（检索词：reset/重置/打挂/恢复/flag轮换/api/404/406/recovery）'
whenToUse: '需要重置 HTB 靶机、靶机被自己打挂、或 flag 提交报 404/406 时。'
metadata: { domain: meta, tier: T1 }
---

# HTB 靶机重置 & 自伤恢复

> 🔴 碰宿主块设备 / 挂载等破坏性操作**之前**，先读 §4 的预防清单。

## 1. 什么时候用

- 靶机被自己打成不可用状态（文件系统只读、容器挂了、服务不响应）
- flag 提交报 404 / 406，不知道用哪个端点
- 重置后"所有脚本都连不上了"（靶机 IP 变了）

## 2. API 端点（实测可用）

**token 位置**：`~/.dsh/htb-token.txt`（JWT，单行）

**🔴 base 必须是 `https://labs.hackthebox.com/api/v4`**
`https://www.hackthebox.com/api/v4/...` 会被 Cloudflare 挡成 **406 + HTML**，
看起来像鉴权失败，其实是站点不对 —— 换 base 立刻 200。

```bash
T=$(cat ~/.dsh/htb-token.txt)
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
H=(-H "Authorization: Bearer $T" -H "accept: application/json, text/plain, */*"
   -H "origin: https://app.hackthebox.com" -H "referer: https://app.hackthebox.com/" -H "User-Agent: $UA")

# 查当前靶机（拿 id / ip / isSpawning）
curl -s "${H[@]}" https://labs.hackthebox.com/api/v4/machine/active

# 机器详情（含 authUserInUserOwns / authUserInRootOwns，用来验证是否真的 own 了）
curl -s "${H[@]}" https://labs.hackthebox.com/api/v4/machine/profile/<ID>

# 🔴 重置 —— 路径是 /vm/reset，不是 /machine/reset（后者 404）
curl -s "${H[@]}" -H "Content-Type: application/json" -X POST \
     -d '{"machine_id":<ID>}' https://labs.hackthebox.com/api/v4/vm/reset

# 🔴 提交 flag —— v4 /machine/own 已废弃，必须用 v5
curl -s "${H[@]}" -H "Content-Type: application/json" -X POST \
     -d '{"id":<ID>,"flag":"<FLAG>","difficulty":50}' \
     https://labs.hackthebox.com/api/v5/machine/own
```

提交成功的响应：
```json
{"message":"<Name> root is now owned.","own_type":"root","machine_pwned":true,"success":true}
```

### 🔴 2.1 token 过期时**不要**急着叫用户重新登录 —— 先 navigate 一次（JobTwo 实测）

症状：`localStorage.getItem('htb-token')` 返回 `null`，或它有值但对 `/api/v4/user/info` 返回 **401**。
磁盘上所有 `htb-token*.txt` 也全是过期 JWT（`exp` 已过）。**这时看起来只能让用户手动重登 —— 但通常不必。**

```js
// ✅ 第一步：先用浏览器导航到任意 app.hackthebox.com 页面
await page.goto('https://app.hackthebox.com/machines/<Name>');
//   ← SPA 初始化时会拿 refresh token 静默续期，把新的 htb-token 写回 localStorage
// ✅ 第二步：再读 localStorage，通常已经有值且可用
const tok = localStorage.getItem('htb-token');
await fetch('https://labs.hackthebox.com/api/v4/user/info', {headers:{Authorization:'Bearer '+tok}});
//   → 200 {info:{name:"..."}}  ⇒ 直接就能提交了
```
🔴 **教训**：JobTwo 的提权子代理因为"localStorage 里没有 token"就判定"需要用户重新登录"，
把整个提交环节挂起等人 —— 而实际只需 **navigate 一次**。**"读不到 token" ≠ "未登录"**；
SPA 的 token 生命周期与 localStorage 的可见性不同步。

### 🔴 2.2 机器旗是**裸 32 位十六进制**，不要套 `HTB{}`

| 题型 | flag 形态 |
|---|---|
| **Machines** | **裸 32 hex**，如 `<32-hex-flag>` |
| Challenges | `HTB{...}` |

JobTwo 实测：`user.txt` / `root.txt` 是 34 字节 = 32 ASCII hex + CRLF，`Format-Hex` 逐字节无花括号，
全盘 `findstr /s /i /m "HTB{" C:\*.txt` 零命中。**直接提交裸值即通过。**
（⚠️ 不要因为"没有 HTB{} 外壳"就怀疑自己读错了文件、或去盘上继续找"真正的 flag" —— 见 `windows-privesc` 的
"flag 形态判据"一节。平台注入器在部署期重写这两个文件，写进去的就是裸 hex。）


**踩过的 404 / 406 清单**

| 端点 | 结果 |
|------|------|
| `POST /api/v4/machine/reset` | ❌ 404 |
| `POST /api/v4/machine/own` | ❌ 404（已废弃 → 用 v5） |
| `POST /api/v4/vm/own` | ❌ 404 |
| `POST /api/v4/machine/submit` | ❌ 422（那是**投稿机器**用的，不是提交 flag） |
| `POST /api/v5/machine/own` | ✅ |
| `POST /api/v4/vm/reset` | ✅ |
| `GET www.hackthebox.com/api/v4/*` | ❌ 406（Cloudflare） |

参考实现：`htb-insane-10/htbcli.py`（内含上述端点，注释明确写了 v4→v5 迁移）。

## 3. 🔴 重置的三连后果（每次都要重新确认）

1. **靶机 IP 会变** —— 实测 `.161` → `.195`。所有硬编码 IP 的脚本必须 `sed` 一遍。
2. **flag 会轮换** —— 重置前的 user/root flag **全部作废**，必须重新读（别拿旧值去提交）。
3. **容器 IP 会重排** —— 同一台机器两次部署：nodered 从 `172.19.0.2` 变成 `172.19.0.3`，
   redis 从 `.3` 变成 `.2`。→ 重新定位用 Docker 内嵌 DNS：

   ```bash
   getent hosts redis www nodered     # 同网段服务名可解析
   # backup 等不在同网段的 → 解析失败，需从相邻容器扫 172.20.0.0/24
   ```

## 4. 自伤恢复：靶机被自己打挂了怎么办

**先分清是"服务挂"还是"文件系统挂"**：

```bash
touch /tmp/t1 && echo WRITE_OK || echo WRITE_FAIL     # 任意容器内
grep -E " / | /var/www" /proc/mounts                  # 出现 ro,errors=remount-ro = 宿主 fs 已只读
```

**宿主 fs 变只读的典型症状**：
- 三个容器的 `/tmp` 都写不了，只有 `/dev/shm`(tmpfs) 可写
- rsync 守护进程报 `@ERROR: failed to open lock file`（`/run` 在 ro 的 overlay 上，lock file 建不出来），
  但 `rsync rsync://host/` 列模块名仍正常 → 极具迷惑性

**处置**：
- ❌ 容器内**无法自救**：`mount -o remount,rw` 需要 CAP_SYS_ADMIN，只有特权容器有；
  而那时它的 cron 脚本多半已因重定向到 ro 路径而整体空转 → 没有注入通道
- ✅ **直接重置靶机**（§2）。不要在废墟上继续推理。

## 5. 🔴 预防（比恢复重要）

- 读宿主块设备**只用 `debugfs -R`（纯用户态只读，不加 `-w`）**，绝不 mount
- 绝不 `losetup` + mount 一个已挂载的 ext4 —— 会造出**第二个独立 superblock** →
  journal 错误 → `errors=remount-ro` → 宿主根全局只读、靶机报废
- `mount -o ro` 对已 rw 挂载的 fs 会 **EBUSY**：这不是"失败"，是内核在保护你，
  **不要用 loop 设备绕它**

## 6. 未通关但已破坏时的止损顺序

```
1. 先确认还有没有别的通道能拿 flag（别的容器 / 别的服务）
2. 没有 → 立刻重置，别在废墟上继续推理
3. 重置后：重新 nmap 拿新 IP → sed 脚本 → 重新定位容器 IP → 重做链
4. 已提交过的 flag 不受重置影响（own 记录在 HTB 侧，machine/profile 里可验证）
```

## 7. 🆕 服务「wedge」≠ 进程崩溃（2026-10-01 Reaper 实测）

**分清三态，处置完全不同**：

| 现象 | 判定 | 处置 |
|---|---|---|
| `connect` 被拒 / `RST` / 进程消失 | **崩溃**（payload 打到了不该打的地方） | 可继续试其它变体，不必急着 reset |
| **`connect` 成功（内核 backlog 应答）但 0 字节返回**，其它端口正常 | **wedge**（进程还在，处理线程卡死/持锁） | 🔴 **直接 reset，别反复重连**（重连只会再占一个卡死的线程槽） |
| 服务正常但业务接口 5xx/超时 | 应用层错误 | 换参数重试 |

**本次两个真实成因**（都会造成 `connect` 成功 + 零字节）：
1. **超长/含 NUL 的输入把服务的读循环搞坏**（给单连接菜单服务送 1 KB+ 的 key）；
2. **payload 的 DllMain 持有 loader lock**（`LoadLibraryExW` 加载远程 DLL，DllMain 里起 shell ⇒
   `LoadLibraryExW` 永不返回，服务线程永久占住锁）。

**纪律**：取旗优先 —— **每次打死服务前先确认旗是否已拿到**；wedge 之后不要试图"修复"，按 `§2` 直接 reset。
另：`machine/profile` 的 `machinePwnedDate` 是 UTC 硬时间戳，写台账以它为准（本地钟常有偏差）。
