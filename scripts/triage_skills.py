#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Re-run the triage pass over the package skills tree.

Usage:
    python scripts/triage_skills.py [skills-dir]

- fixes whenToUse text glued inside description (legacy porting artifact)
- writes metadata: { domain: X, tier: T1|T2|T3 } on every card
- adds disable-model-invocation: true on T2/T3
- fixes the [[mongodb-nosql-injection]] broken reference
- moves non-HTB / personal-state cards to <skills-dir>/.archive (not scanned)
- regenerates htb-skill-index from the MAPPING table below
"""
import os
import re
import shutil
import sys
from collections import Counter, defaultdict

SKILLS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'skills')
SKILLS = os.path.abspath(SKILLS)
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
}

MAPPING = {
    # meta T1
    'attack-surface-meta': ('meta', 'T1'),
    'box-startup': ('meta', 'T1'),
    'chain-primitives': ('meta', 'T1'),
    'debug-5whys': ('meta', 'T1'),
    'derive-command': ('meta', 'T1'),
    'enumeration-command-layer': ('meta', 'T1'),
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
    'apache-struts-rce': ('web', 'T3'),
    'bash-array-subscript-injection': ('web', 'T3'),
    'chrome-cdp-discovery': ('web', 'T3'),
    'cmd-injection-exit-code-precheck': ('web', 'T3'),
    'command-injection-regex-bypass': ('web', 'T3'),
    'cve-2025-69212-openstamanager-rce': ('web', 'T3'),
    'cve-2026-27626-olivetin-rce': ('web', 'T3'),
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
    'ntlm-relay-chain': ('ad-win', 'T2'),
    'pre2k-attack': ('ad-win', 'T2'),
    'rbcd-spnless': ('ad-win', 'T2'),
    'rodc-privesc-chain': ('ad-win', 'T2'),
    'sccm-attacks': ('ad-win', 'T2'),
    'scf-ntlm-theft': ('ad-win', 'T2'),
    'sid-history-injection': ('ad-win', 'T2'),
    'username-generation': ('ad-win', 'T2'),
    'dotnet-pipe-yaml-deserialization': ('ad-win', 'T3'),
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
    'codebuild-floci-escape': ('linux', 'T3'),
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
    v = v.strip()
    if len(v) >= 2 and v[0] in '\'"' and v[-1] == v[0]:
        return v[1:-1]
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
             '用法：目录（system prompt）里只列出 T1 卡。T2/T3 卡设置了 disable-model-invocation，',
             '不在目录中，但都可以用 skill 工具按名加载。命中具体技术时，直接用下面的名字加载；',
             '不要根据名字猜测内容，加载后再按其指引执行。', '']
    for dom in DOMAIN_LABEL:
        tiers = by_domain.get(dom, {})
        lines.append('## %s' % DOMAIN_LABEL[dom])
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
    report = []

    for entry in sorted(os.listdir(SKILLS)):
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
        if tier != 'T1':
            lines.append('disable-model-invocation: true')
        lines.append('metadata: { domain: %s, tier: %s }' % (domain, tier))
        lines.append('---')
        new_raw = '\n'.join(lines) + '\n' + body
        if not new_raw.endswith('\n'):
            new_raw += '\n'
        with open(skill_md, 'w', encoding='utf-8', newline='') as f:
            f.write(new_raw)
        processed.append((entry, domain, tier))

    tier_count = Counter(t for _, _, t in processed)
    domain_count = Counter(d for _, d, _ in processed)

    idx_dir = os.path.join(SKILLS, INDEX_NAME)
    os.makedirs(idx_dir, exist_ok=True)
    on_disk = {n for n, _, _ in processed}
    with open(os.path.join(idx_dir, 'SKILL.md'), 'w', encoding='utf-8', newline='') as f:
        f.write(generate_index_text(MAPPING, on_disk=on_disk))

    print('processed: %d  moved: %d  tiers: %s  domains: %s' % (
        len(processed), len(moved), dict(tier_count), dict(domain_count)))
    for r in report:
        print('report:', r)

    # 硬错误（缺 frontmatter / 未映射）必须让整条校验链失败。
    hard = [r for r in report if r[0] in ('NO-SKILLMD', 'NO-FRONTMATTER', 'UNMAPPED')]
    if hard:
        for r in hard:
            print('ERROR:', r)
        sys.exit(1)

    # 最后跑一遍路由审计（引用解析/索引一致性），任何错误都会以退出码 1 冒泡。
    try:
        import audit_routing
        sys.exit(audit_routing.main())
    except ImportError:
        print('hint: scripts/audit_routing.py not found; routing audit skipped')


if __name__ == '__main__':
    main()
