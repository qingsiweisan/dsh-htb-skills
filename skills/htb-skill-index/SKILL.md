---
name: 'htb-skill-index'
description: 'HTB 技能库总索引：按领域×层级列出全部技能名，供目录外卡名反查与按需加载。卡壳或需要具体技术时先查本表。'
whenToUse: '目录里没有所需技能、卡壳、或需要按领域×层级反查全部卡名时'
metadata: { domain: meta, tier: T1 }
---

# HTB 技能库索引

用法：T1/T2/T3 的卡都可以用 `skill` 工具按名加载（2026-09-01 起不再有
`disable-model-invocation` 区分；分层只表示粒度与沉淀时间）。命中具体技术时，
直接用下面的名字加载；不要根据名字猜测内容，加载后再按其指引执行。

## 元方法论 / 总路由

- **T1（19）**：attack-surface-meta、box-startup、chain-primitives、command-safety-red-lines、debug-5whys、derive-command、engagement-inventory-and-triage、enumeration-command-layer、frontier-and-evidence-anchors、hacktricks-url-index、htb-machine-reset-recovery、htb-master-checklist、htb-methodology、htb-workflow、no-hint-solving、parallel-recon、prolab-engagement-playbook、quickref-cards、tool-scenario-reference
- **T2（1）**：blocking-points-detail

## Web 应用

- **T1（6）**：challenge-web-chain、cms-framework-rce、sql-injection-primitive、ssrf-protocol-matrix、web-attacks、web-chained-attacks
- **T2（16）**：apache-htaccess-abuse、argument-injection-option-smuggling、broken-access-control-idor、dotnet-viewstate-machinekey-rce、flask-session-forgery、http-request-smuggling、iis-dotfile-and-shortname-enum、java-native-deserialization、log-poisoning-lfi-rce、office-document-phishing-payloads、orchestration-platform-rce、prototype-pollution、python-sandbox-escape、waf-filter-bypass-patterns、xml-attacks-beyond-xxe、xslt-injection
- **T3（19）**：apache-struts-rce、bash-array-subscript-injection、chrome-cdp-discovery、cmd-injection-exit-code-precheck、command-injection-regex-bypass、cve-2025-69212-openstamanager-rce、cve-2026-27626-olivetin-rce、cve-2026-wp2shell-wordpress、dotnet-file-oracle、electron-desktop-app-attacks、krayin-crm-attacks、log4shell-cve-2021-44228、ocr-file-write-rce、papercut-ng-attacks、shellshock-cve-2014-6271、soap-wcf-injection、string-replace-dollar-sequence-xss、voice-symbol-xss、webauthn-xss

## AD / Windows

- **T1（4）**：ad-checklist、ad-type-recognition、lateral-movement、windows-privesc
- **T2（25）**：ad-trust-and-forest-pivot、adcs-attack-chain、adminsdholder-abuse、applocker-clm-bypass、dcshadow、dll-hijacking-practical、dnsadmins-privesc、dsrm-credentials、edr-evasion、exchange-owa-attacks、federation-identity-abuse、kerberos-only-ad、laps-password-extraction、mdt-monitoring-xxe、ntlm-relay-chain、pre2k-attack、rbcd-spnless、rodc-privesc-chain、sccm-attacks、scf-ntlm-theft、sid-history-injection、username-generation、veeam-backup-attacks、windows-byovd-kernel-rw、windows-rop-deep-call
- **T3（7）**：dotnet-pipe-yaml-deserialization、group-type-abuse、kerberos-double-hop、ntfs-ads-abuse、printnightmare-printer-leaks、protected-users-kerberos-only、rdp-inception

## Linux / 提权

- **T1（3）**：container-escape、linux-privesc、persistence
- **T2（8）**：authorized-keys-landing、cron-privesc-patterns、linux-sandbox-boundary-escape、living-off-the-land、nfs-privesc、shared-object-hijacking、sudo-escape-techniques、symlink-attack-patterns
- **T3（6）**：cve-2024-47533-cobbler-rce、cve-2026-53359-januscape-kvm-escape、git-object-path-traversal、noncontainer-sandbox-escape、overlayfs-privesc、rbash-escape

## 数据库 / 消息中间件

- **T2（5）**：h2-java-alias-rce、kafka-pentesting、mssql-attack-chain、mysql-udf-privesc、postgresql-rce
- **T3（5）**：cypher-injection、mongodb-aggregation-injection、mssql-guardrail-bypass、pgadmin-cve-2025-2945-rce、quirk-mariadb-10-1-nested-func-where

## 云 / IdP

- **T2（4）**：aws-attack-surface、cloud-attacks、minio-s3-pentesting、supply-chain-artifact-attacks
- **T3（2）**：aws-kms-decrypt-localstack、freeipa-pentesting

## 凭据与密码

- **T1（3）**：credential-hunting-locations、credential-spraying-password-reuse、password-attacks
- **T2（2）**：default-credentials、hash-shucking
- **T3（1）**：mirth-connect-hash-crack

## 取证 / Sherlocks

- **T1（1）**：sherlock-investigation
- **T2（1）**：malware-static-analysis
- **T3（1）**：windows-app-mru-forensics

## 网络服务 / 隧道

- **T1（3）**：service-attacks、tunneling-port-forwarding、unknown-service-probe
- **T2（3）**：internal-rpc-broker-attacks、multi-hop-pivot-planning、snmp-enumeration
- **T3（2）**：hmailserver-attacks、tls-cert-san-enumeration

## 工具链

- **T2（2）**：kali-tools-augmented、netexec-reference
- **T3（2）**：evil-winrm-path-escaping、netexec-escape

## 二进制 / Pwn

- **T1（3）**：challenge-heap-pwn、challenge-kernel-pwn、challenge-v8-pwn
- **T2（1）**：linux-binary-stack-rop

## 密码学

- **T1（1）**：challenge-crypto-prng
- **T2（2）**：crypto-classic-attack-patterns、weak-prng-predictable-seed
- **T3（1）**：weak-rsa-key-recovery

## 区块链 / Web3

- **T2（1）**：challenge-blockchain-web3

## AI / Agentic

- **T2（1）**：mcp-ai-agent-attacks

## 逆向工程

- **T1（1）**：challenge-rev-vm

## 挑战赛 / Playbook

- **T1（1）**：challenge-insane-playbook

## 备注

- 移出技能库（个人状态/非 HTB）：ai-reverse-engineering-toolchain、checkpoint-toolchain、ctgoodjobs-scraper、logforge-sherlock-kape-triage、malware-analysis-external-tools
- 本索引由 scripts/triage_skills.py 生成，修改技能库后重新生成以保持同步。
