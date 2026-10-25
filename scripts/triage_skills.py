#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Re-run the triage pass over a skills tree.

Usage:
    python scripts/triage_skills.py [skills-dir]

Target resolution (first hit wins) —— 2026-09-30 新增，见下方 🔴：
    1. 命令行参数 [skills-dir]
    2. 环境变量 $HTB_SKILLS_DIR
    3. ~/.dsh/skills          （本机真正在用的库；DSH 会话读的就是它）
    4. <repo>/skills          （包内镜像，**历史快照**，不再是编辑源）

🔴 为什么要有这个优先级：包内 `skills/` 自 2026-09-13 起就没有再更新过，
   而活库 `~/.dsh/skills` 一直在改。默认指向包内会**静默审计一份冻结的旧快照**
   并报"全绿"，同时若对活库跑本脚本又会因 MAPPING/DOMAIN_LABEL 过期而**截断索引**。

- fixes whenToUse text glued inside description (legacy porting artifact)
- writes metadata: { domain: X, tier: T1|T2|T3 } on every card
- ⚠️ **不再**写 disable-model-invocation —— 该标志 2026-09-01 已全量移除（见 AGENTS.md），
  本脚本原先会把它重新加回 T2/T3，属于静默回退，已废止。
- fixes the [[mongodb-nosql-injection]] broken reference
- moves non-HTB / personal-state cards to <skills-dir>/.archive (not scanned)
- regenerates htb-skill-index from the MAPPING table below

🔴 索引只在**全部校验通过之后**才落盘：原先先写索引再报 UNMAPPED 错误，
   等于"报错退出 ≠ 什么都没改"，索引已经被截断了。
"""
import os
import re
import shutil
import sys
from collections import Counter, defaultdict

def resolve_skills_dir():
    """按 Usage 里的优先级解析目标技能目录。"""
    if len(sys.argv) > 1 and sys.argv[1].strip():
        return os.path.abspath(sys.argv[1]), 'argv'
    env = os.environ.get('HTB_SKILLS_DIR', '').strip()
    if env:
        return os.path.abspath(env), '$HTB_SKILLS_DIR'
    home_live = os.path.join(os.path.expanduser('~'), '.dsh', 'skills')
    if os.path.isdir(home_live):
        return os.path.abspath(home_live), '~/.dsh/skills (live)'
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'skills')), 'package mirror'

SKILLS, SKILLS_SOURCE = resolve_skills_dir()
# Archive must live OUTSIDE the skills root: any dir inside it would be scanned.
ARCHIVE = os.path.join(os.path.dirname(SKILLS), '.skills-archive')
INDEX_NAME = 'htb-skill-index'

DOMAIN_LABEL = {
    'meta': '元方法论 / 总路由',
    'web': 'Web 应用',
    'ad-win': 'AD / Windows',
    'linux': 'Linux / 提权',
    'db': '数据库 / 消息中间件',
    'cloud': '云 / IdP',
    'creds': '凭据与密码',
    'forensics': '取证 / Sherlocks',
    'network': '网络服务 / 隧道',
    'tools': '工具链',
    # 🆕 2026-09-30 补齐：活库里已有这些 domain 的卡，但 DOMAIN_LABEL 没有，
    #    而 generate_index_text 只遍历本表 ⇒ 这些卡会被**静默丢出索引**。
    'pwn': '二进制 / Pwn',
    'crypto': '密码学',
    'web3': '区块链 / Web3',
    'ai': 'AI / Agentic',
    'rev': '逆向工程',
    'challenges': '挑战赛 / Playbook',
    'win': 'Windows（独立域）',
    'other': '其他',
}

MAPPING = {
    # meta T1
    'attack-surface-meta': ('meta', 'T1'),
    'box-startup': ('meta', 'T1'),
    'chain-primitives': ('meta', 'T1'),
    'debug-5whys': ('meta', 'T1'),
    'derive-command': ('meta', 'T1'),
    'enumeration-command-layer': ('meta', 'T1'),
    # ========================================================================
    # 🆕 2026-10-10 ARTEX 双图概念迁移（架构推导，非实战回灌）新增 1 张卡。
    #    frontier-and-evidence-anchors = 持久化探索层：跨子代理/跨会话共享待办
    #      + 资产覆盖矩阵 + 证据角色(baseline/proof/...) + 全否型结论 retester 复核。
    #    缺此条 ⇒ 索引少 1 张卡（静默丢卡），且 audit 报 card-missing-from-MAPPING。
    # ========================================================================
    'frontier-and-evidence-anchors': ('meta', 'T1'),
    'hacktricks-url-index': ('meta', 'T1'),
    'htb-master-checklist': ('meta', 'T1'),
    'htb-methodology': ('meta', 'T1'),
    'htb-workflow': ('meta', 'T1'),
    'no-hint-solving': ('meta', 'T1'),
    'parallel-recon': ('meta', 'T1'),
    'quickref-cards': ('meta', 'T1'),
    'tool-scenario-reference': ('meta', 'T1'),
    # 索引卡本身也走 MAPPING，保证 loop 会刷新它的 metadata；
    # generate_index_text() 会把它从表格里排除，避免自引用。
    'htb-skill-index': ('meta', 'T1'),
    'blocking-points-detail': ('meta', 'T2'),
    # web
    'cms-framework-rce': ('web', 'T1'),
    'sql-injection-primitive': ('web', 'T1'),
    'ssrf-protocol-matrix': ('web', 'T1'),
    'web-attacks': ('web', 'T1'),
    'web-chained-attacks': ('web', 'T1'),
    'flask-session-forgery': ('web', 'T2'),
    'http-request-smuggling': ('web', 'T2'),
    'log-poisoning-lfi-rce': ('web', 'T2'),
    'prototype-pollution': ('web', 'T2'),
    'python-sandbox-escape': ('web', 'T2'),
    'xml-attacks-beyond-xxe': ('web', 'T2'),
    'xslt-injection': ('web', 'T2'),
    'argument-injection-option-smuggling': ('web', 'T2'),
    'apache-struts-rce': ('web', 'T3'),
    'bash-array-subscript-injection': ('web', 'T3'),
    'chrome-cdp-discovery': ('web', 'T3'),
    'cmd-injection-exit-code-precheck': ('web', 'T3'),
    'command-injection-regex-bypass': ('web', 'T3'),
    'cve-2025-69212-openstamanager-rce': ('web', 'T3'),
    'cve-2026-27626-olivetin-rce': ('web', 'T3'),
    'dotnet-file-oracle': ('web', 'T3'),
    'krayin-crm-attacks': ('web', 'T3'),
    'log4shell-cve-2021-44228': ('web', 'T3'),
    'ocr-file-write-rce': ('web', 'T3'),
    'shellshock-cve-2014-6271': ('web', 'T3'),
    'soap-wcf-injection': ('web', 'T3'),
    'string-replace-dollar-sequence-xss': ('web', 'T3'),
    'voice-symbol-xss': ('web', 'T3'),
    'webauthn-xss': ('web', 'T3'),
    # ad-win
    'ad-checklist': ('ad-win', 'T1'),
    'ad-type-recognition': ('ad-win', 'T1'),
    'lateral-movement': ('ad-win', 'T1'),
    'windows-privesc': ('ad-win', 'T1'),
    'adcs-attack-chain': ('ad-win', 'T2'),
    'adminsdholder-abuse': ('ad-win', 'T2'),
    'dcshadow': ('ad-win', 'T2'),
    'dll-hijacking-practical': ('ad-win', 'T2'),
    'dnsadmins-privesc': ('ad-win', 'T2'),
    'dsrm-credentials': ('ad-win', 'T2'),
    'edr-evasion': ('ad-win', 'T2'),
    'exchange-owa-attacks': ('ad-win', 'T2'),
    'kerberos-only-ad': ('ad-win', 'T2'),
    'laps-password-extraction': ('ad-win', 'T2'),
    'mdt-monitoring-xxe': ('ad-win', 'T2'),
    'ntlm-relay-chain': ('ad-win', 'T2'),
    'pre2k-attack': ('ad-win', 'T2'),
    'rbcd-spnless': ('ad-win', 'T2'),
    'rodc-privesc-chain': ('ad-win', 'T2'),
    'sccm-attacks': ('ad-win', 'T2'),
    'scf-ntlm-theft': ('ad-win', 'T2'),
    'sid-history-injection': ('ad-win', 'T2'),
    'username-generation': ('ad-win', 'T2'),
    'dotnet-pipe-yaml-deserialization': ('ad-win', 'T3'),
    'group-type-abuse': ('ad-win', 'T3'),
    'kerberos-double-hop': ('ad-win', 'T3'),
    'printnightmare-printer-leaks': ('ad-win', 'T3'),
    'protected-users-kerberos-only': ('ad-win', 'T3'),
    'rdp-inception': ('ad-win', 'T3'),
    # linux
    'container-escape': ('linux', 'T1'),
    'linux-privesc': ('linux', 'T1'),
    'persistence': ('linux', 'T1'),
    'cron-privesc-patterns': ('linux', 'T2'),
    'living-off-the-land': ('linux', 'T2'),
    'nfs-privesc': ('linux', 'T2'),
    'shared-object-hijacking': ('linux', 'T2'),
    'sudo-escape-techniques': ('linux', 'T2'),
    'cve-2024-47533-cobbler-rce': ('linux', 'T3'),
    'cve-2026-53359-januscape-kvm-escape': ('linux', 'T3'),
    'git-object-path-traversal': ('linux', 'T3'),
    'noncontainer-sandbox-escape': ('linux', 'T3'),
    'overlayfs-privesc': ('linux', 'T3'),
    'rbash-escape': ('linux', 'T3'),
    # db
    'h2-java-alias-rce': ('db', 'T2'),
    'kafka-pentesting': ('db', 'T2'),
    'mssql-attack-chain': ('db', 'T2'),
    'mysql-udf-privesc': ('db', 'T2'),
    'postgresql-rce': ('db', 'T2'),
    'cypher-injection': ('db', 'T3'),
    'mongodb-aggregation-injection': ('db', 'T3'),
    'pgadmin-cve-2025-2945-rce': ('db', 'T3'),
    'quirk-mariadb-10-1-nested-func-where': ('db', 'T3'),
    # cloud
    'aws-attack-surface': ('cloud', 'T2'),
    'cloud-attacks': ('cloud', 'T2'),
    'minio-s3-pentesting': ('cloud', 'T2'),
    'aws-kms-decrypt-localstack': ('cloud', 'T3'),
    'freeipa-pentesting': ('cloud', 'T3'),
    # creds
    'credential-spraying-password-reuse': ('creds', 'T1'),
    'password-attacks': ('creds', 'T1'),
    'default-credentials': ('creds', 'T2'),
    'hash-shucking': ('creds', 'T2'),
    'mirth-connect-hash-crack': ('creds', 'T3'),
    # forensics
    'sherlock-investigation': ('forensics', 'T1'),
    'malware-static-analysis': ('forensics', 'T2'),
    # network
    'service-attacks': ('network', 'T1'),
    'tunneling-port-forwarding': ('network', 'T1'),
    'unknown-service-probe': ('network', 'T1'),
    'snmp-enumeration': ('network', 'T2'),
    # tools
    'kali-tools-augmented': ('tools', 'T2'),
    'netexec-reference': ('tools', 'T2'),
    'evil-winrm-path-escaping': ('tools', 'T3'),
    'netexec-escape': ('tools', 'T3'),
    # ========================================================================
    # 🆕 2026-09-30 补齐：以下 38 条是「活库有卡、MAPPING 没有」的差集（09-24 之后
    #    新增的全部卡）。缺它们时跑本脚本会生成一份**少 38 张卡的索引**，其中包含
    #    `command-safety-red-lines`（开局必载）与 `htb-machine-reset-recovery` ——
    #    与 AGENTS.md 记录过两次的"方法论随卡被移出技能库而丢失"是同一类事故。
    #    domain/tier 一律取自各卡 frontmatter，不是手填。
    # ========================================================================
    # ad-win
    'ad-trust-and-forest-pivot': ('ad-win', 'T2'),
    'applocker-clm-bypass': ('ad-win', 'T2'),
    'federation-identity-abuse': ('ad-win', 'T2'),
    'ntfs-ads-abuse': ('ad-win', 'T3'),
    # ai
    'mcp-ai-agent-attacks': ('ai', 'T2'),
    # challenges
    'challenge-insane-playbook': ('challenges', 'T1'),
    # cloud
    'supply-chain-artifact-attacks': ('cloud', 'T2'),
    # creds
    'credential-hunting-locations': ('creds', 'T1'),
    # crypto
    'challenge-crypto-prng': ('crypto', 'T1'),
    'crypto-classic-attack-patterns': ('crypto', 'T2'),
    'weak-prng-predictable-seed': ('crypto', 'T2'),
    'weak-rsa-key-recovery': ('crypto', 'T3'),
    # forensics
    'windows-app-mru-forensics': ('forensics', 'T3'),
    # linux
    'authorized-keys-landing': ('linux', 'T2'),
    'linux-sandbox-boundary-escape': ('linux', 'T2'),
    'symlink-attack-patterns': ('linux', 'T2'),
    # meta
    'command-safety-red-lines': ('meta', 'T1'),
    'engagement-inventory-and-triage': ('meta', 'T1'),
    'htb-machine-reset-recovery': ('meta', 'T1'),
    'prolab-engagement-playbook': ('meta', 'T1'),
    # network
    'internal-rpc-broker-attacks': ('network', 'T2'),
    'multi-hop-pivot-planning': ('network', 'T2'),
    'tls-cert-san-enumeration': ('network', 'T3'),
    # pwn
    'challenge-heap-pwn': ('pwn', 'T1'),
    'challenge-kernel-pwn': ('pwn', 'T1'),
    'challenge-v8-pwn': ('pwn', 'T1'),
    'linux-binary-stack-rop': ('pwn', 'T2'),
    # rev
    'challenge-rev-vm': ('rev', 'T1'),
    # web
    'challenge-web-chain': ('web', 'T1'),
    'apache-htaccess-abuse': ('web', 'T2'),
    'broken-access-control-idor': ('web', 'T2'),
    'dotnet-viewstate-machinekey-rce': ('web', 'T2'),
    'java-native-deserialization': ('web', 'T2'),
    'orchestration-platform-rce': ('web', 'T2'),
    'waf-filter-bypass-patterns': ('web', 'T2'),
    'papercut-ng-attacks': ('web', 'T3'),
    'cve-2026-wp2shell-wordpress': ('web', 'T3'),
    'electron-desktop-app-attacks': ('web', 'T3'),
    # web3
    'challenge-blockchain-web3': ('web3', 'T2'),
    # ========================================================================
    # 🆕 2026-09-30 JobTwo（HTB Hard, Windows）实战回灌新增的 3 张卡。
    #    缺它们时跑本脚本会生成**少 3 张卡**的索引（静默丢卡，症状是
    #    "新写的卡 skill_search 搜不到 / 索引里没有"）。
    # ========================================================================
    'office-document-phishing-payloads': ('web', 'T2'),
    'veeam-backup-attacks': ('ad-win', 'T2'),
    'hmailserver-attacks': ('network', 'T3'),
    # ========================================================================
    # 🆕 2026-10-01 Reaper（HTB Insane, Windows）实战回灌新增的 2 张卡。
    #    windows-rop-deep-call  = 从 ROP 调深调用（shadow space / 16 字节对齐 / 崩点 RVA→导出名）
    #    windows-byovd-kernel-rw = 第三方驱动 METHOD_NEITHER 不 Probe ⇒ 内核任意读写 → token swap
    # ========================================================================
    'windows-rop-deep-call': ('ad-win', 'T2'),
    'windows-byovd-kernel-rw': ('ad-win', 'T2'),
    # ========================================================================
    # 🆕 2026-10-01 官方题解知识沉淀（来源脱敏，非实战回灌）新增 2 张卡。
    #    iis-dotfile-and-shortname-enum = 桌面属性文件 + 8.3 短名"半截泄露"枚举与补全
    #    mssql-guardrail-bypass         = 服务器级 DDL 触发器绕过 + 换机制换 token
    # ========================================================================
    'iis-dotfile-and-shortname-enum': ('web', 'T2'),
    'mssql-guardrail-bypass': ('db', 'T3'),
}

REMOVE = {
    'ctgoodjobs-scraper',
    'logforge-sherlock-kape-triage',
    'ai-reverse-engineering-toolchain',
    'checkpoint-toolchain',
    'malware-analysis-external-tools',
}

FIELD_RE = re.compile(r'^([A-Za-z][\w-]*)\s*:(.*)$')

try:
    import yaml as _yaml
except ImportError:
    _yaml = None


def yaml_unquote(v):
    """YAML 解码一个已加引号的标量值，得到真实字符串。

    直接 strip 外层引号会把上一轮已转义的 '' 留在值里，再次转义时引号翻倍；
    解码保证幂等。解码失败时退回纯外层引号剥离。
    """
    v = v.strip()
    if _yaml is not None and v:
        try:
            return _yaml.safe_load('x: ' + v)['x']
        except Exception:
            pass
    return unquote(v)


def parse_frontmatter(raw):
    if not raw.startswith('---'):
        return None, raw
    lines = raw.split('\n')
    fields = []
    closing = None
    for i in range(1, len(lines)):
        line = lines[i].rstrip('\r')
        if line.strip() == '---':
            closing = i
            break
        m = FIELD_RE.match(line)
        if m:
            val = m.group(2).strip()
            if val.endswith('---'):
                fields.append((m.group(1), val[:-3].rstrip()))
                closing = i
                break
            fields.append((m.group(1), val))
        elif fields:
            k, v = fields[-1]
            fields[-1] = (k, v + '\n' + line)
    if closing is None:
        return None, raw
    return fields, '\n'.join(lines[closing + 1:])


def unquote(v):
    """Strip the surrounding YAML quotes AND undo the escaping.

    🔴 2026-09-30 修：原实现只剥外层引号、不反转义，而 yq() 每次写都会把
    内层 `'` 加倍 —— 于是 `'...''...'` 读回来仍是 `...''...`，再写就成
    `...''''...`。**每跑一次本脚本，含 ASCII 引号的卡就再退化一层**（实测
    attack-surface-meta / scf-ntlm-theft / string-replace-dollar-sequence-xss /
    voice-symbol-xss 四张卡中招，审计只能报 QUOTE-RUN-CORRUPTION 却没有 recover
    工具）。修成幂等：读过什么、写回去还是什么。
    """
    v = v.strip()
    if len(v) >= 2 and v[0] in '\'"' and v[-1] == v[0]:
        q, inner = v[0], v[1:-1]
        if q == "'":
            # YAML 单引号标量：内层单引号写成两个单引号
            inner = inner.replace("''", "'")
        else:
            # 双引号标量：反转义反斜杠转义
            inner = inner.replace('\\"', '"').replace('\\\\', '\\')
        return inner
    return v


def yq(v):
    return "'" + v.replace("'", "''") + "'"


def generate_index_text(mapping, on_disk=None):
    """Render the htb-skill-index SKILL.md from a MAPPING table.

    mapping:  {name: (domain, tier)}   on_disk: optional set of card dirs
    currently present; dead MAPPING entries are excluded so a stale run
    cannot advertise cards that cannot load.
    """
    by_domain = defaultdict(lambda: defaultdict(list))
    for n, (d, t) in sorted(mapping.items()):
        if n == INDEX_NAME:
            continue
        if on_disk is not None and n not in on_disk:
            continue
        by_domain[d][t].append(n)
    lines = ['---',
             "name: 'htb-skill-index'",
             "description: 'HTB 技能库总索引：按领域×层级列出全部技能名，供目录外卡名反查与按需加载。卡壳或需要具体技术时先查本表。'",
             "whenToUse: '目录里没有所需技能、卡壳、或需要按领域×层级反查全部卡名时'",
             'metadata: { domain: meta, tier: T1 }',
             '---', '',
             '# HTB 技能库索引', '',
             '用法：T1/T2/T3 的卡都可以用 `skill` 工具按名加载（2026-09-01 起不再有',
             '`disable-model-invocation` 区分；分层只表示粒度与沉淀时间）。命中具体技术时，',
             '直接用下面的名字加载；不要根据名字猜测内容，加载后再按其指引执行。', '']
    # 🔴 不再 `for dom in DOMAIN_LABEL` 单遍历 —— 那样任何没登记的 domain 都会被
    #    **静默丢出索引**（2026-09-30 实测：pwn / crypto / web3 / ai / rev / challenges
    #    六个域的 12 张卡就是这么消失的）。改成"登记顺序在前 + 未登记的原样渲染在后"，
    #    并显式告警，保证**任何卡都不会因为域没登记而消失**。
    ordered = [d for d in DOMAIN_LABEL if d in by_domain]
    extra = sorted(d for d in by_domain if d not in DOMAIN_LABEL)
    if extra:
        print('WARN: domain 未登记进 DOMAIN_LABEL（已原样渲染，建议补标签）: %s' % ', '.join(extra))
    for dom in ordered + extra:
        tiers = by_domain.get(dom, {})
        lines.append('## %s' % DOMAIN_LABEL.get(dom, dom))
        lines.append('')
        for tier in ('T1', 'T2', 'T3'):
            names = sorted(tiers.get(tier, []))
            if names:
                lines.append('- **%s（%d）**：%s' % (tier, len(names), '、'.join(names)))
        lines.append('')
    lines.append('## 备注')
    lines.append('')
    lines.append('- 移出技能库（个人状态/非 HTB）：%s' % '、'.join(sorted(REMOVE)))
    lines.append('- 本索引由 scripts/triage_skills.py 生成，修改技能库后重新生成以保持同步。')
    return '\n'.join(lines) + '\n'


def main():
    os.makedirs(ARCHIVE, exist_ok=True)
    processed = []
    moved = []
    # 🔴 真正被写回的文件数 —— 与 processed（处理过的卡数）**不是一回事**。
    #    本脚本 2026-10-10 之前是"每跑一次就无条件重写 163 个文件"：实测重写 163 个而
    #    **SHA256 变化数 = 0**。后果不是改坏内容，而是**抹平 mtime** —— 而 mtime 是
    #    "谁写过卡库"的唯一证据（我们对子线程下的硬约束正是"技能库只读"）。
    changed = 0
    report = []

    for entry in sorted(os.listdir(SKILLS)):
        # 跳过隐藏项：.git 等不是技能卡（2026-10-22 卡库纳入 git 后误报 NO-SKILLMD）
        if entry.startswith('.'):
            continue
        dirpath = os.path.join(SKILLS, entry)
        skill_md = os.path.join(dirpath, 'SKILL.md')
        if not os.path.isfile(skill_md):
            report.append(('NO-SKILLMD', entry))
            continue
        raw = open(skill_md, encoding='utf-8').read()
        fields, body = parse_frontmatter(raw)
        if fields is None:
            report.append(('NO-FRONTMATTER', entry))
            continue
        fdict = {}
        for k, v in fields:
            fdict[k] = v

        name = yaml_unquote(fdict.get('name', ''))
        desc_raw = fdict.get('description', '')
        when = fdict.get('whenToUse', '')
        if 'whenToUse' not in fdict and ' whenToUse: ' in desc_raw:
            idx = desc_raw.index(' whenToUse: ')
            when = desc_raw[idx + len(' whenToUse: '):].strip()
            desc_raw = desc_raw[:idx].strip()
            report.append(('FIXED-WHENTOUSE', entry))
        desc = yaml_unquote(desc_raw)
        when = yaml_unquote(when)
        if '[[mongodb-nosql-injection]]' in desc or '[[mongodb-nosql-injection]]' in body:
            desc = desc.replace('[[mongodb-nosql-injection]]', 'web-attacks')
            body = body.replace('[[mongodb-nosql-injection]]', 'web-attacks')
            report.append(('FIXED-LINK', entry))

        if entry in REMOVE:
            dest = os.path.join(ARCHIVE, entry)
            if os.path.exists(dest):
                shutil.rmtree(dest)
            shutil.move(dirpath, dest)
            moved.append(entry)
            continue
        if entry not in MAPPING:
            report.append(('UNMAPPED', entry))
            continue

        domain, tier = MAPPING[entry]
        lines = ['---', 'name: %s' % yq(name)]
        if desc:
            lines.append('description: %s' % yq(desc))
        if when:
            lines.append('whenToUse: %s' % yq(when))
        # 🔴 不写 disable-model-invocation：该标志 2026-09-01 已全量移除（T1/T2/T3 都可被模型加载，
        #    分层只表示粒度与沉淀时间）。原实现 `if tier != 'T1'` 会把它**重新加回** 83 张卡，
        #    等于每次跑 triage 都把那次解禁静默回退掉。
        lines.append('metadata: { domain: %s, tier: %s }' % (domain, tier))
        lines.append('---')
        new_raw = '\n'.join(lines) + '\n' + body
        if not new_raw.endswith('\n'):
            new_raw += '\n'
        # 🔴 只在内容真的不同时才写（与 fix_yaml.py:107 同一判据）。
        #    本脚本既是"归一化"工具，又被 framework-check 当**闸**跑 —— 无条件写回会让
        #    "跑一次验收闸"= "重写 163 张卡"，把只读不变式与 mtime 证据一起毁掉。
        if new_raw != raw:
            with open(skill_md, 'w', encoding='utf-8', newline='') as f:
                f.write(new_raw)
            changed += 1
        processed.append((entry, domain, tier))

    tier_count = Counter(t for _, _, t in processed)
    domain_count = Counter(d for _, d, _ in processed)

    # ---------------------------------------------------------------
    # 🔴 校验必须先于索引落盘。
    #    原实现的顺序是「先写索引 → 再报 UNMAPPED 错误 → exit 1」，
    #    于是"报错退出"给人一种"什么都没改"的错觉，而索引**已经**被写成
    #    少 38 张卡的截断版（on_disk 只含 MAPPING∩磁盘，未映射的卡在
    #    line 425 就被 continue 掉了）。现在任何硬错误都在落盘前中止。
    # ---------------------------------------------------------------
    hard = [r for r in report if r[0] in ('NO-SKILLMD', 'NO-FRONTMATTER', 'UNMAPPED')]
    if hard:
        print('目标: %s  (%s)' % (SKILLS, SKILLS_SOURCE))
        print('processed: %d  moved: %d' % (len(processed), len(moved)))
        for r in report:
            print('report:', r)
        for r in hard:
            print('ERROR:', r)
        print('')
        print('🔴 上面有未映射/坏的卡 —— 已中止，**索引没有被改写**。')
        print('   修法：把 UNMAPPED 的卡名补进 scripts/triage_skills.py 的 MAPPING 表。')
        sys.exit(1)

    idx_dir = os.path.join(SKILLS, INDEX_NAME)
    os.makedirs(idx_dir, exist_ok=True)
    on_disk = {n for n, _, _ in processed}
    idx_path = os.path.join(idx_dir, 'SKILL.md')
    new_index = generate_index_text(MAPPING, on_disk=on_disk)
    old_index = open(idx_path, encoding='utf-8').read() if os.path.isfile(idx_path) else None
    # 同上：内容相同就别碰 mtime（索引卡也参与 framework-check 的只读不变式）。
    if old_index != new_index:
        with open(idx_path, 'w', encoding='utf-8', newline='') as f:
            f.write(new_index)
        changed += 1

    print('目标: %s  (%s)' % (SKILLS, SKILLS_SOURCE))
    print('processed: %d  moved: %d  changed: %d  tiers: %s  domains: %s' % (
        len(processed), len(moved), changed, dict(tier_count), dict(domain_count)))
    for r in report:
        print('report:', r)

    # 最后跑一遍路由审计（引用解析/索引一致性），任何错误都会以退出码 1 冒泡。
    try:
        import audit_routing
        sys.exit(audit_routing.main())
    except ImportError:
        print('hint: scripts/audit_routing.py not found; routing audit skipped')


if __name__ == '__main__':
    main()
