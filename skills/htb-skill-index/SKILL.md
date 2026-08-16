---
name: 'htb-skill-index'
description: 'HTB 技能库总索引：按领域×层级列出全部技能名，供目录外卡名反查与按需加载。卡壳或需要具体技术时先查本表。'
metadata: { domain: meta, tier: T1 }
---

# HTB 技能库索引

用法：目录（system prompt）里只列出 T1 卡。T2/T3 卡设置了 disable-model-invocation，
不在目录中，但都可以用 skill 工具按名加载。命中具体技术时，直接用下面的名字加载；
不要根据名字猜测内容，加载后再按其指引执行。

## 元方法论 / 总路由

- **T1（14）**：attack-surface-meta、box-startup、chain-primitives、debug-5whys、derive-command、enumeration-command-layer、hacktricks-url-index、htb-master-checklist、htb-methodology、htb-workflow、no-hint-solving、parallel-recon、quickref-cards、tool-scenario-reference
- **T2（1）**：blocking-points-detail

## Web 应用

- **T1（4）**：cms-framework-rce、ssrf-protocol-matrix、web-attacks、web-chained-attacks
- **T2（7）**：flask-session-forgery、http-request-smuggling、log-poisoning-lfi-rce、prototype-pollution、python-sandbox-escape、xml-attacks-beyond-xxe、xslt-injection
- **T3（15）**：apache-struts-rce、bash-array-subscript-injection、chrome-cdp-discovery、cmd-injection-exit-code-precheck、command-injection-regex-bypass、cve-2025-69212-openstamanager-rce、cve-2026-27626-olivetin-rce、krayin-crm-attacks、log4shell-cve-2021-44228、ocr-file-write-rce、shellshock-cve-2014-6271、soap-wcf-injection、string-replace-dollar-sequence-xss、voice-symbol-xss、webauthn-xss

## AD / Windows

- **T1（4）**：ad-checklist、ad-type-recognition、lateral-movement、windows-privesc
- **T2（18）**：adcs-attack-chain、adminsdholder-abuse、dcshadow、dll-hijacking-practical、dnsadmins-privesc、dsrm-credentials、edr-evasion、exchange-owa-attacks、kerberos-only-ad、laps-password-extraction、ntlm-relay-chain、pre2k-attack、rbcd-spnless、rodc-privesc-chain、sccm-attacks、scf-ntlm-theft、sid-history-injection、username-generation
- **T3（5）**：dotnet-pipe-yaml-deserialization、kerberos-double-hop、printnightmare-printer-leaks、protected-users-kerberos-only、rdp-inception

## Linux / 提权

- **T1（3）**：container-escape、linux-privesc、persistence
- **T2（5）**：cron-privesc-patterns、living-off-the-land、nfs-privesc、shared-object-hijacking、sudo-escape-techniques
- **T3（6）**：cve-2024-47533-cobbler-rce、cve-2026-53359-januscape-kvm-escape、git-object-path-traversal、noncontainer-sandbox-escape、overlayfs-privesc、rbash-escape

## 数据库 / 消息中间件

- **T2（5）**：h2-java-alias-rce、kafka-pentesting、mssql-attack-chain、mysql-udf-privesc、postgresql-rce
- **T3（4）**：cypher-injection、mongodb-aggregation-injection、pgadmin-cve-2025-2945-rce、quirk-mariadb-10-1-nested-func-where

## 云 / IdP

- **T2（3）**：aws-attack-surface、cloud-attacks、minio-s3-pentesting
- **T3（2）**：aws-kms-decrypt-localstack、freeipa-pentesting

## 凭据与密码

- **T1（2）**：credential-spraying-password-reuse、password-attacks
- **T2（2）**：default-credentials、hash-shucking
- **T3（1）**：mirth-connect-hash-crack

## 取证 / Sherlocks

- **T1（1）**：sherlock-investigation
- **T2（1）**：malware-static-analysis

## 网络服务 / 隧道

- **T1（3）**：service-attacks、tunneling-port-forwarding、unknown-service-probe
- **T2（1）**：snmp-enumeration

## 工具链

- **T2（2）**：kali-tools-augmented、netexec-reference
- **T3（2）**：evil-winrm-path-escaping、netexec-escape

## 备注

- 移出技能库（个人状态/非 HTB）：ai-reverse-engineering-toolchain、checkpoint-toolchain、ctgoodjobs-scraper、logforge-sherlock-kape-triage、malware-analysis-external-tools
- 本索引由 triage_skills.py 生成，修改技能库后重新生成以保持同步。
