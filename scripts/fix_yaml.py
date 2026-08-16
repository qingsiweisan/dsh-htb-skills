#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YAML-safety pass: single-quote name/description/whenToUse (escaping ' as ''),
then validate every frontmatter with PyYAML.

Usage:
    python scripts/fix_yaml.py [skills-dir]

Requires PyYAML: pip install pyyaml
"""
import os
import re
import sys

SKILLS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'skills')
SKILLS = os.path.abspath(SKILLS)

try:
    import yaml
except ImportError:
    print('NO_PYYAML: pip install pyyaml')
    sys.exit(2)

FIELD_RE = re.compile(r'^([A-Za-z][\w-]*)\s*:(.*)$')


def parse_block(raw):
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


def strip_quotes(v):
    v = v.strip()
    if len(v) >= 2 and v[0] in '\'"' and v[-1] == v[0]:
        return v[1:-1]
    return v


def yq(v):
    return "'" + v.replace("'", "''") + "'"


def main():
    checked = 0
    written = 0
    bad = []
    for entry in sorted(os.listdir(SKILLS)):
        p = os.path.join(SKILLS, entry, 'SKILL.md')
        if not os.path.isfile(p):
            continue
        raw = open(p, encoding='utf-8').read()
        fields, body = parse_block(raw)
        if fields is None:
            bad.append((entry, 'no-frontmatter'))
            continue
        checked += 1
        out = []
        for k, v in fields:
            if k in ('name', 'description', 'whenToUse'):
                out.append('%s: %s' % (k, yq(strip_quotes(v))))
            else:
                for seg in v.split('\n'):
                    out.append('%s: %s' % (k, seg))
        inner = '\n'.join(out)
        try:
            data = yaml.safe_load(inner)
            ok = isinstance(data, dict) and data.get('name') and data.get('description')
        except Exception as e:
            bad.append((entry, 'yaml-error: %s' % str(e).split('\n')[0]))
            continue
        if not ok:
            bad.append((entry, 'yaml-not-mapping'))
            continue
        new_raw = '---\n' + inner + '\n---\n' + body
        if not new_raw.endswith('\n'):
            new_raw += '\n'
        if new_raw != raw:
            with open(p, 'w', encoding='utf-8', newline='') as f:
                f.write(new_raw)
            written += 1
    print('checked: %d  rewritten: %d  bad: %d' % (checked, written, len(bad)))
    for b in bad:
        print('BAD:', b)
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
