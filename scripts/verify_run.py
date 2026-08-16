#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_run.py — 判定层:对抗复核 flag/cred 捕获事件(确定性第一层)。

立场:默认捕获未证实,主动找证据推翻(Anthropic grade-agent 同款)。

用法:
  python3 verify_run.py --state /root/htb/nimbus-state.jsonl \
      [--sessions /root/.dsh/sessions] [--cwd /root/htb]

机制(读磁盘原始 transcript,session.jsonl.zstd,零第三方依赖,需 zstd CLI):

  对 state.jsonl 的每个 type=flag 事件:
    A. 证据命令已执行   : 某 tool/call 的 arguments 规范化后包含 evidence 规范化文本
    B. 值在输出中       : 该调用的 tool/result 输出包含 what 中的 flag 值(32-hex)
    C. 独立复核         : 除 A 的调用外,存在第二个调用其输出包含该值;
                          或某调用输出包含 32-hex == md5(值)(md5sum 复核路径)
    flag : A+B+C 全过 = PASS
    cred : A+B = PASS,C 缺失仅 WARN(凭据双读不现实;md5 复核仍计入)

  exit 0 = 无 FAIL;exit 1 = 存在 FAIL(供 CI/复盘脚本 gating)。

事件行 schema 见 box-startup「key-state 规范」:
  {"ts","type","who","what","evidence"}
  what 里可含「经:xxx 攻击链」自述行,值用 32-hex 自动提取。
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

HEX32 = re.compile(r'\b([0-9a-f]{32})\b')
MD5HEX = re.compile(r'\b([0-9a-f]{32})\b')


def norm(s):
    s = str(s).lower()
    s = s.replace("'", '').replace('"', '')
    return re.sub(r'\s+', ' ', s).strip()


def walk_text(node):
    """从 tool/result 的 message 树里收齐所有 text 节点。"""
    out = []
    if isinstance(node, dict):
        if node.get('type') == 'text' and isinstance(node.get('text'), str):
            out.append(node['text'])
        for v in node.values():
            out.extend(walk_text(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(walk_text(v))
    return out


def load_state(path):
    events = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                print('state line not json, skipped: %r' % line[:80])
                continue
            if ev.get('type') in ('flag', 'cred'):
                events.append(ev)
    return events


def find_sessions(sessions_root, cwd):
    """找所有 cwd 匹配的 session 转录(session.jsonl.zstd)。"""
    hits = []
    if not os.path.isdir(sessions_root):
        return hits
    for ws in os.listdir(sessions_root):
        wsd = os.path.join(sessions_root, ws)
        if not os.path.isdir(wsd):
            continue
        for sd in os.listdir(wsd):
            p = os.path.join(wsd, sd, 'session.jsonl.zstd')
            if not os.path.isfile(p):
                continue
            head = subprocess.run(['zstd', '-d', '-c', p], capture_output=True,
                                  timeout=60).stdout.decode('utf-8', 'replace')[:2000]
            m = re.search(r'"cwd"\s*:\s*"([^"]*)"', head)
            if m and m.group(1) == cwd:
                hits.append(p)
    return hits


def load_calls(session_paths):
    """每个 tool/call 一条: (session, callId, name, args, result_text)。"""
    calls = []
    for sp in session_paths:
        try:
            raw = subprocess.run(['zstd', '-d', '-c', sp], capture_output=True,
                                 timeout=120).stdout.decode('utf-8', 'replace')
        except Exception as e:
            print('WARN decompress failed %s: %s' % (sp, e))
            continue
        by_call = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            t = ev.get('type')
            data = ev.get('data') or {}
            if t == 'tool/call' and data.get('callId'):
                by_call[data['callId']] = {
                    'session': os.path.basename(os.path.dirname(sp)),
                    'callId': data['callId'],
                    'name': data.get('name', ''),
                    'args': data.get('arguments', '') or '',
                }
            elif t == 'tool/result':
                cid = (data.get('message') or {}).get('source', {}).get('callId')
                rec = by_call.get(cid)
                if rec is not None:
                    rec['result'] = '\n'.join(walk_text(data.get('message')))
        calls.extend(v for v in by_call.values() if v.get('result') is not None)
    return calls


def verdict_for(ev, calls):
    etype = ev.get('type')
    evidence = norm(ev.get('evidence', ''))
    what = ev.get('what', '')
    values = [v.lower() for v in HEX32.findall(str(what).lower())]
    fails = []

    # A. 证据命令执行:所有 args 含 evidence 的调用都是候选;
    #    优先选输出里真含该事件值的候选(同一条命令可能被多个调用复现)。
    candidates = [c for c in calls if evidence and evidence in norm(c['args'])]
    if evidence and not candidates:
        fails.append('EVIDENCE-NOT-EXECUTED')
    elif not evidence:
        fails.append('NO-EVIDENCE-FIELD')

    if etype == 'flag' and not values:
        fails.append('NO-32HEX-VALUE-IN-WHAT')

    ev_call = None
    for c in candidates:
        res = norm(c.get('result', ''))
        if any(v in res for v in values):
            ev_call = c
            break
    if ev_call is None and candidates:
        ev_call = candidates[0]  # 都无值 → 取第一个用于 FAIL 诊断

    # B. 值在证据调用输出中
    val_in_ev = set()
    if ev_call is not None:
        res = norm(ev_call.get('result', ''))
        for v in values:
            if v in res:
                val_in_ev.add(v)
    missing_b = sorted(set(values) - val_in_ev)
    if missing_b:
        fails.append('VALUE-NOT-IN-OUTPUT:' + ','.join(missing_b[:2]))

    # C. 独立复核(flag 必需,cred 可选)
    second = {}
    md5_of = {}
    for c in calls:
        if ev_call is not None and c['callId'] == ev_call['callId']:
            continue
        res = norm(c.get('result', ''))
        for v in values:
            if v in res:
                second.setdefault(v, c['callId'])
        for h in MD5HEX.findall(c.get('result', '') or ''):
            for v in values:
                if hashlib.md5(v.encode()).hexdigest() == h:
                    md5_of.setdefault(v, c['callId'])
    missing_c = [v for v in values if v not in second and v not in md5_of]
    if etype == 'flag' and missing_c:
        fails.append('DOUBLE-CHECK-MISSING:' + ','.join(missing_c[:2]))

    if etype == 'cred':
        ok = not fails
        if missing_c:
            note = ' (WARN: cred 无独立复核)'
        else:
            note = ''
        return ('PASS' if ok else 'FAIL'), fails, note

    return ('PASS' if not fails else 'FAIL'), fails, ''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--state', required=True)
    ap.add_argument('--sessions', default='/root/.dsh/sessions')
    ap.add_argument('--cwd', default=None, help='默认 = state 所在目录')
    args = ap.parse_args()

    cwd = args.cwd or os.path.dirname(os.path.abspath(args.state))
    events = load_state(args.state)
    if not events:
        print('state 里没有 flag/cred 事件:%s' % args.state)
        sys.exit(2)

    paths = find_sessions(args.sessions, cwd)
    print('sessions matched cwd=%s: %d' % (cwd, len(paths)))
    for p in paths:
        print('  -', p)
    calls = load_calls(paths)
    print('tool/call(含 result)共 %d 条\n' % len(calls))

    any_fail = False
    for ev in events:
        verdict, fails, note = verdict_for(ev, calls)
        if verdict == 'FAIL':
            any_fail = True
        what_line = str(ev.get('what', '')).splitlines()[0][:60]
        print('%s %-5s %s' % (verdict, ev.get('type'), what_line))
        if fails:
            print('     fails: %s' % '; '.join(fails))
        if note:
            print('     ' + note)

    print('\nSUMMARY: %d events, %s' % (len(events),
          'ALL PASS' if not any_fail else 'HAS FAIL — 捕获未全部证实'))
    sys.exit(1 if any_fail else 0)


if __name__ == '__main__':
    main()
