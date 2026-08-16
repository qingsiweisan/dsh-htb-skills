#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Label unlabeled ``` code fences with a language tag (cosmetic).

Usage:
    python label_fences.py <skills-dir> [--apply]

Without --apply: dry-run, prints per-card counts of what would change.
Rules classify by the block's first non-empty line; ambiguous blocks get
`text`. Only lines that are exactly ``` are touched.

NOTE: run this only when no other process is editing the tree (it rewrites
every card that has unlabeled fences).
"""
import os
import re
import sys

SKILLS = sys.argv[1]
APPLY = '--apply' in sys.argv

PY_RE = re.compile(r'^(import\s+\w|from\s+\w|def\s+\w|class\s+\w|print\()|^#!(.*python|.*/usr/bin/env\s+python)')
PS_RE = re.compile(r'^(PS\s?[>]|powershell|Import-Module|Get-|Set-|Invoke-|New-Object|Add-Type|IEX|iex\s|\[System\.)')
SQL_RE = re.compile(r'^(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|USE\s|SHOW\s|DESC\s|EXEC\s|exec\s|mssql|mysql|psql|sqlcmd|sqsh)', re.I)
XML_RE = re.compile(r'^<\?xml|^<soap|^<project|^<configuration|^<beans|^<web-app')
HTTP_RE = re.compile(r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/')
YAML_RE = re.compile(r'^(\w+:\s|-\s+name:|apiVersion:|kind:)')
BASH_RE = re.compile(
    r'^(#!/(bin|usr/bin)|sudo\s|chmod\s|chown\s|nc\s|ncat\s|nmap\s|curl\s|wget\s|ssh\s|scp\s|git\s|cat\s|echo\s|grep\s|sed\s|awk\s|find\s|which\s|whoami\b|hostname\b|ifconfig\b|ip\s+a\b|netstat\b|ss\s+-|id\b|env\b|export\s|unset\s|source\s|cd\s|ls\b|mkdir\s|touch\s|rm\s|cp\s|mv\s|ln\s|tar\s|zip\s|gzip\s|dd\s|strings\s|strace\s|ltrace\s|ldd\s|objdump\s|gdb\s|file\s|ps\s|top\s|kill\s|systemctl\s|service\s|crontab\s|su\s|useradd\s|passwd\s|python[0-9]?\s|pip\s|npm\s|pnpm\s|node\s|go\s|rustc\s|cargo\s|make\s|gcc\s|docker\s|kubectl\s|minikube\s|helm\s|aws\s|az\s|gcloud\s|terraform\s|ansible\s|hashcat\s|john\s|hydra\s|netexec\s|nxc\s|crackmapexec\s|impacket\s|evil-winrm\s|mimikatz\s|rubeus\s|certipy\s|bloodyAD\s|responder\s|kerbrute\s|smbclient\s|smbmap\s|enum4linux\s|ldapsearch\s|chisel\s|ligolo\s|socat\s|ssh-keygen\s|openssl\s|msfconsole\s|msfvenom\s|searchsploit\s|sqlmap\s|ffuf\s|gobuster\s|feroxbuster\s|wfuzz\s|dirsearch\s|nikto\s|nuclei\s|whatweb\s|wpscan\s|burp\s|zap\s|proxychains\s|tcpdump\s|tshark\s|snmpwalk\s|snmpget\s|rpcclient\s|dnsrecon\s|dig\s|nslookup\s|host\s|ftp\s|telnet\s|redis-cli\s|mongosh\s|mongo\s|kafka-console\s|kubectl\s|docker-compose\s|\./\w|/usr/bin|/bin/|/opt/|/tmp/)'
)


def classify(first_line):
    s = first_line.strip()
    if not s:
        return 'text'
    if PY_RE.match(s):
        return 'python'
    if PS_RE.match(s):
        return 'powershell'
    if SQL_RE.match(s):
        return 'sql'
    if XML_RE.match(s):
        return 'xml'
    if HTTP_RE.match(s):
        return 'http'
    if YAML_RE.match(s):
        return 'yaml'
    if BASH_RE.match(s):
        return 'bash'
    return 'text'


def process(path):
    raw = open(path, encoding='utf-8').read()
    lines = raw.split('\n')
    changed = 0
    i = 0
    n = len(lines)
    while i < n:
        s = lines[i].strip()
        if s != '```':
            i += 1
            continue
        # 找块内第一行非空内容
        j = i + 1
        first = ''
        while j < n:
            sj = lines[j].strip()
            if sj.startswith('```'):
                first = ''
                break
            if sj:
                first = sj
                break
            j += 1
        lang = classify(first)
        if lang:
            lines[i] = '```' + lang
            changed += 1
        i += 1
    return lines, changed


total = 0
per_card = []
for d in sorted(os.listdir(SKILLS)):
    p = os.path.join(SKILLS, d, 'SKILL.md')
    if not os.path.isfile(p):
        continue
    lines, changed = process(p)
    if changed:
        total += changed
        per_card.append((d, changed))
        if APPLY:
            # split/join 往返本身保留原文件的结尾换行，直接写回即可
            with open(p, 'w', encoding='utf-8', newline='') as f:
                f.write('\n'.join(lines))
print('mode: %s  fences to label: %d  cards: %d' % ('APPLY' if APPLY else 'DRY-RUN', total, len(per_card)))
for d, c in per_card:
    print('  %-42s %d' % (d, c))
