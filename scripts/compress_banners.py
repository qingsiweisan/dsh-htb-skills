#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compress the full RS-port banner to the one-line DSH usage note.

Usage:
    python compress_banners.py <skills-dir> [--apply]

The banner is the exact line:
    > 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。
replaced by:
    > 📌 DSH 用法：用 skill 工具按名加载本卡。

Dry-run by default. Only this exact line is touched.
"""
import os
import sys

SKILLS = sys.argv[1]
APPLY = '--apply' in sys.argv

OLD = ('> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具'
       '按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。')
NEW = '> 📌 DSH 用法：用 skill 工具按名加载本卡。'

total = 0
per_card = []
for d in sorted(os.listdir(SKILLS)):
    p = os.path.join(SKILLS, d, 'SKILL.md')
    if not os.path.isfile(p):
        continue
    raw = open(p, encoding='utf-8').read()
    n = raw.count(OLD)
    if n:
        total += n
        per_card.append((d, n))
        if APPLY:
            with open(p, 'w', encoding='utf-8', newline='') as f:
                f.write(raw.replace(OLD, NEW))
print('mode: %s  banners to compress: %d  cards: %d' % ('APPLY' if APPLY else 'DRY-RUN', total, len(per_card)))
for d, c in per_card:
    print('  %-42s %d' % (d, c))
