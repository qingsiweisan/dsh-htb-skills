#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Routing-integrity audit for an HTB skill tree.

The skill registry keys skills by the frontmatter `name`; T1 cards appear in
the model catalog, T2/T3 are hidden and loaded by name. A routing bug is any
of: duplicate/colliding names, a MAPPING entry with no card on disk (index
advertises a name that cannot load), a card missing from MAPPING (no tier
metadata), a leftover `disable-model-invocation` (2026-09-01 起该标志已废除，
残留会让卡对模型不可见), a stale htb-skill-index, or a cross-card reference
pointing at a name that does not exist.

Usage:
    python scripts/audit_routing.py [skills-dir]

Target resolution (first hit wins) —— 2026-09-30 新增：
    argv[1] > $HTB_SKILLS_DIR > ~/.dsh/skills (live) > <repo>/skills (mirror)

🔴 为什么：包内 `skills/` 自 2026-09-13 起冻结，活库一直在改。默认指向包内会
   **对一份旧快照报"0 errors"，给出"一切正常"的假信号**（实测：包内 0 errors
   vs 活库 458 errors，其中绝大多数是工具自身过期）。

Exit code 1 when any ERROR is found; warnings are advisory. Runs read-only
(never rewrites cards); run scripts/triage_skills.py to regenerate the index
when it is stale.

Recommended chain (idempotent, run after any edit):
    python scripts/fix_yaml.py <skills-dir>
    python scripts/triage_skills.py <skills-dir>
    python scripts/audit_routing.py <skills-dir>
"""
import os
import re
import sys

def _resolve_skills():
    if len(sys.argv) > 1 and sys.argv[1].strip():
        return os.path.abspath(sys.argv[1]), 'argv'
    env = os.environ.get('HTB_SKILLS_DIR', '').strip()
    if env:
        return os.path.abspath(env), '$HTB_SKILLS_DIR'
    live = os.path.join(os.path.expanduser('~'), '.dsh', 'skills')
    if os.path.isdir(live):
        return os.path.abspath(live), '~/.dsh/skills (live)'
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'skills')), 'package mirror'

SKILLS, SKILLS_SOURCE = _resolve_skills()

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

try:
    import triage_skills as triage
except ImportError:
    triage = None

INDEX_NAME = 'htb-skill-index'
MAPPING = {}
REMOVE = set()
DOMAIN_LABEL = {}

if triage is not None:
    MAPPING = dict(triage.MAPPING)
    REMOVE = set(triage.REMOVE)
    DOMAIN_LABEL = dict(triage.DOMAIN_LABEL)

FIELD_RE = re.compile(r'^([A-Za-z][\w-]*)\s*:(.*)$')
BACKTICK_RE = re.compile(r'`([^`\n]+)`')
WIKILINK_RE = re.compile(r'\[\[([^\]\n]+)\]\]')
# 中文路由关键词 + 紧随其后的（可带反引号/括号的）技能名 token
CJK_KW_RE = re.compile(
    r'(?:加载|详见|参见|参考|查询|切换|路由|调用|先读|先看|查看|见|查)'
    r'\s*[`『「（(]?\s*([a-z][a-z0-9-]{2,})')
# 英文路由关键词：必须是一个独立单词（前面不能贴着字母），且后面至少要有一个空格；
# 只认含连字符的 token（单英文词噪声太大，且技能名几乎都带连字符）。
LATIN_KW_RE = re.compile(
    r'(?<![a-z0-9])(?:load|see|check|use)\s+[`『「（(]?\s*'
    r'([a-z][a-z0-9-]*-[a-z0-9-]+)')
NAME_TOKEN_RE = re.compile(r'^[a-z0-9][a-z0-9-]*$')

# 合法出现在正文里的工具/技术/协议 token（非技能名）。命中名单即视为已解析；
# 名单外且形似技能名（小写连字符 token）的引用会被列为 DANGLING 候选逐一复核。
#
# 🔴 2026-10-10 复核（实测，非估算）：旧名单 2211 条（去重后；里面还混着"写在
#    三引号字面量内部的注释"被 `.split()` 当成词条的脏数据 —— `#` / `Scaffold` /
#    `Windows` / `2026-09-13` 等就是这么进去的，这也是它越长越乱的一半原因）。
#    但闸实际能看到的候选只有 37 条，全部是误报：把 WHITELIST 清空重跑，上报 38 处
#    （去重 36 个 token + 1 个索引卡降级 WARN），**没有一条指向"应该存在却不存在
#    的卡"**（对照法：清空 vs 保留逐条比对，见下）。由此：
#      · 2211 条里只有 31 条实测承重 —— 删任意一条，它就会立刻以 DANGLING-REF 出现；
#      · 其余 2164 条**从未起过作用**（删掉闸的报错集合不变）。
#    所以旧名单的危险不在"产生假绿"，而在**能力**：那些口子每一个都能在将来静默
#    吞掉一条真断链（例如某张卡真的开始引用 `linpeas` 当卡名）。本次把名单砍到
#    47 条 = 31 条实测承重的误报豁免 + 16 条 ESC 技术编号；2026-10-10 二次复核又把
#    那 16 条 ESC 挪出名单（它们在 DANGLING 侧 0 承重，是被 BC 闸当锚点才留在里面的）
#    ⇒ **本名单现在 31 条**，全部是 DANGLING 侧实测承重的误报豁免，并给每条写一句
#    "为什么它不是交叉引用"。ESC 上界锚点见下方 ESC_ALIASES / ESC_MAX。
#    （下面用 dict 存 token→理由，理由写在**字面量外**，避免重蹈注释变词条的覆辙。）
WHITELIST_WHY = {
    # —— 靶机上的服务/私有仓库/目录名（长得像卡名，实为被测资产）
    'personal-webapp': 'Toby 靶机上的私有 Flask 仓库名，凭据来源',
    'supportsystem-db': 'Toby 靶机上的私有仓库名（凭据来源）',
    'rest-server': 'credential-hunting-locations：restic 的 REST 备份服务，攻击者自建',
    'hosting-app': 'RegistryTwo 私有 registry 里的镜像/仓库名',
    'htb-challenge-wps': '本地工作区目录（challenge-insane-playbook 存档路径）',
    # —— 命令 / 工具 / 库 / 编译目标（会被当普通标识符写进命令示例）
    'get-content': 'PowerShell cmdlet（NTFS ADS 读流）',
    'redis-cli': 'Redis 客户端命令',
    'ssh-keygen': 'OpenSSH 密钥生成命令',
    'jd-gui': 'Java 反编译工具（GitHub 项目名）',
    'mysql-connector-java': 'JDBC 驱动依赖名（恶意 MySQL 打法）',
    'ipa-client-install': 'FreeIPA 客户端安装命令（凭据常在参数里）',
    'update-ca-certificates': 'Debian 系装自签 CA 的命令',
    'template-sync': '靶机上 Gitea 的 cron 脚本名（cron-privesc-patterns）',
    'struts-pwn': '公开的 Struts exploit 脚本名',
    'fav-up': 'favicon hash 反查工具',
    'eth-account': 'Python web3 依赖库名',
    'i686-w64-mingw32-gcc': 'MinGW 32 位交叉编译器三元组',
    'ssl-enum-ciphers': 'nmap NSE 脚本名',
    'ssl-cert': 'nmap NSE 脚本名（取 CN/SAN）',
    # —— 协议/HTTP 指纹与中间件服务名
    'amqp-com': 'Dyplesher 上被 root 拉起的 AMQP 消费者服务名',
    'grpc-message': 'gRPC 响应头名（协议指纹）',
    'frame-ancestors': 'CSP 指令名',
    'unsafe-eval': 'CSP 关键字',
    # —— 靶机上采集到的字面量：用户、权限位、主题名、符号、默认口令
    'www-data': 'Web 服务运行用户（非卡名）',
    'srw-rw----': 'ls -l 的 Unix socket 权限位写法',
    'internal-creds': 'Kafka 业务 topic 名',
    'environ-8': 'glibc 符号名（environ-8 泄栈，heap pwn）',
    'change-me': 'app.secret_key 的代码内默认值（flask-session-forgery）',
    # —— 平台/赛事标识与凭据存放键
    'cyber-apocalypse-2024': 'HTB 赛事官方仓库名',
    'htb-token': 'HTB SPA 的 localStorage 键名 / token 文件名',
    # —— 已废除的 frontmatter 标志名（2026-09-01 起废除，非卡名）
    'disable-model-invocation': 'frontmatter 标志名，讨论"该标志已废除"时会误报；'
                                '索引卡里的提及另有索引卡例外降级为 WARN',
    # —— ⚠️ 这里**没有** esc1…esc16：ADCS 技术编号**不是** DANGLING-REF 的豁免。
    #    实测（2026-10-10，逐条单独移除 ⇒ 0 报错）：这 16 条在 DANGLING 侧 **0 承重** ——
    #    本文件 DANGLING 只认带连字符的 token（见下方 `if '-' not in tok: continue`），
    #    `esc<N>` 连候选都进不了，删掉它们报错集合不变。
    #    它们此前待在这份名单里的唯一原因，是 content-gate-test.mjs 的 BC 断言用
    #    **全文正则** `\besc(\d+)\b` 从本文件抓最大编号当上界锚点 ⇒ 一份"豁免名单"
    #    里混进了为另一道闸服务的锚点，语义被污染，且谁清理白名单谁把 BC 弄红。
    #    ⇒ 已搬到下方显式常量 ESC_ALIASES / ESC_MAX；BC 现在精确读那两行。
}
WHITELIST = set(WHITELIST_WHY)

# 🔴 ESC_ALIASES / ESC_MAX —— **不是** DANGLING-REF 的豁免名单，而是
#    「ADCS 证书模板滥用技术编号」的**已知上界锚点**，唯一用途是给
#    content-gate-test.mjs 的 BOUNDARY-BC 断言（卡内最大 ESC 编号 ≤ 声明的上界）
#    提供第三方锚点。此前该锚点靠全文正则从 WHITELIST_WHY 里抓，与白名单隐式耦合。
#
#    解析契约（改格式前先看 content-gate-test.mjs 的 parseEscAnchor）：
#      · `ESC_ALIASES = frozenset((` 起、首个 `))` 止的**块内**，只允许出现带引号的
#        'esc<N>' 字面量与空白/逗号；读方会先剥掉 `#` 注释再取编号（与 Python 语义一致：
#        注释不是成员 —— 旧白名单正是栽在"注释被 .split() 当词条"上）。
#      · 块内不要出现比真实上界更高的编号（哪怕写在注释里）：那等于把上界放宽一格。
#      · 单一真源：编号只写在 ESC_ALIASES 里；ESC_MAX 是**声明式镜像**，读方每次都会
#        校验 `ESC_MAX == max(ESC_ALIASES)`，不一致即 FAIL（手改一处不会被静默吞掉）。
ESC_ALIASES = frozenset((
    'esc1', 'esc2', 'esc3', 'esc4', 'esc5', 'esc6', 'esc7', 'esc8',
    'esc9', 'esc10', 'esc11', 'esc12', 'esc13', 'esc14', 'esc15', 'esc16',
))
ESC_MAX = 16   # 由 ESC_ALIASES 派生（卡里现在最远写到 ESC16）；改集合必须同步这行

# 前缀白名单：`impacket-psExec` / `impacket-xxx`、CSS 类名 `htb-square-button--*` 之类
# 永远不可能是技能卡名（技能卡名不含 `--`，也不以 `impacket-` 开头，那张卡叫
# `netexec-reference`）。用前缀放行，省得每出现一个新命令就补一条。
WHITELIST_PREFIXES = ('impacket-', 'htb-square-button', 'skills-backup-')

# slug 分词自洽检查（§I）里不算「用户会敲的词」的分词：结构词/虚词，补了是噪音。
# ⚠️ 只放结构词。内容词（binary / sandbox / filter / chain / identity …）一律要求有锚点 ——
#    2026-09-30 实测正是这些内容词缺失导致 21 条常见查询 0 命中。
SLUG_STOP = {
    'and', 'or', 'the', 'for', 'with', 'from', 'into', 'via',
    'landing', 'locations', 'patterns', 'attacks', 'points', 'detail',
    'cards', 'recovery', 'tools', 'augmented', 'solving', 'theft', 'planning',
    'linux', 'windows', 'htb',
}

# 卡名集合：以 frontmatter name 为准（skill 注册表按 name 加载）。
NAME_PAT = re.compile(r'^[a-z0-9][a-z0-9-]{2,}$')


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


def norm(text):
    return text.strip().lower()


def card_text(fdict, body):
    """All prose where a cross-card reference may appear."""
    parts = [fdict.get('name', ''), fdict.get('description', ''),
             fdict.get('whenToUse', ''), body]
    return '\n'.join(parts)


def main():
    errors = []
    warnings = []
    infos = []

    # 跳过隐藏项：.git 等不是技能卡（2026-10-22）
    dirs = sorted(d for d in os.listdir(SKILLS) if not d.startswith('.'))
    cards = {}          # dir -> (fdict, body)
    by_name = {}        # name(lower) -> dir
    ref_tokens = []     # (dir, token, kind) extracted candidates
    seen_bad = set()

    # --- A/B: load every card, validate frontmatter ---
    for entry in dirs:
        p = os.path.join(SKILLS, entry, 'SKILL.md')
        if not os.path.isfile(p):
            errors.append('NO-SKILLMD: %s' % entry)
            continue
        raw = open(p, encoding='utf-8').read()
        fields, body = parse_frontmatter(raw)
        if fields is None:
            errors.append('NO-FRONTMATTER: %s' % entry)
            continue
        fdict = {}
        for k, v in fields:
            fdict[k] = v
        name = unquote(fdict.get('name', ''))
        desc = unquote(fdict.get('description', ''))
        if not name:
            errors.append('NO-NAME: %s' % entry)
            continue
        if not desc:
            errors.append('NO-DESCRIPTION: %s (%s)' % (entry, name))
        # 引号翻倍回归守卫：正确的 YAML 转义最多出现连续 2 个单引号（''），
        # 出现 3 个以上说明历史转义 bug 复发（scripts/fix_yaml.py 已幂等化）。
        for field in ('name', 'description', 'whenToUse'):
            raw_val = fdict.get(field, '')
            if raw_val and "'''" in raw_val:
                errors.append('QUOTE-RUN-CORRUPTION: %s field=%s '
                              '(引号内代码字面量被 YAML 归一化脚本改写，如 login("",-1) → login(\'\'\',-1)；'
                              '手工改回双引号即可，仓库里没有 recover_quotes.py)' % (entry, field))
        if not NAME_PAT.match(name):
            errors.append('BAD-NAME-FORMAT: %s (%r)' % (entry, name))
        nkey = norm(name)
        if nkey in by_name:
            errors.append('DUPLICATE-NAME: %s (%s) collides with %s' % (entry, name, by_name[nkey]))
        by_name[nkey] = entry
        if entry != name:
            warnings.append('DIR-NAME-MISMATCH: dir=%s name=%s' % (entry, name))
        cards[entry] = (fdict, body)

    names = set(by_name.keys())
    names_original = {norm(unquote(fdict.get('name', ''))): unquote(fdict.get('name', '')) for fdict, _ in cards.values()}

    # --- D: MAPPING <-> disk bidirectional coverage ---
    on_disk = set(cards.keys())
    mapped = set(MAPPING.keys())
    for d in sorted(on_disk - mapped):
        errors.append('UNMAPPED-DIR: %s (add to MAPPING in scripts/triage_skills.py)' % d)
    for m in sorted(mapped - on_disk):
        errors.append('DEAD-MAPPING: %s (in MAPPING but no skills/%s/ dir -> index would route to nothing)' % (m, m))
    for m in sorted(REMOVE & on_disk):
        errors.append('RESURRECTED: %s is in REMOVE but still on disk' % m)
    for m, (dom, tier) in sorted(MAPPING.items()):
        if dom not in DOMAIN_LABEL:
            errors.append('BAD-DOMAIN: %s -> %s' % (m, dom))
        if tier not in ('T1', 'T2', 'T3'):
            errors.append('BAD-TIER: %s -> %s' % (m, tier))

    # --- E: tier metadata & disable-model-invocation consistency ---
    for entry, (fdict, body) in sorted(cards.items()):
        name = norm(unquote(fdict.get('name', '')))
        meta = fdict.get('metadata', '')
        m = re.search(r'tier:\s*(T[123])', meta)
        meta_tier = m.group(1) if m else None
        mapped_tier = MAPPING.get(entry, (None, None))[1] if entry in MAPPING else None
        if entry in MAPPING:
            if meta_tier != mapped_tier:
                errors.append('TIER-MISMATCH: %s metadata.tier=%s MAPPING=%s' % (entry, meta_tier, mapped_tier))
        elif entry == INDEX_NAME:
            pass  # generator owns the index card
        elif meta_tier:
            warnings.append('METADATA-WITHOUT-MAPPING: %s tier=%s but not in MAPPING' % (entry, meta_tier))
        # 🔴 期望值已于 2026-09-30 **反转**。2026-09-01 起 T2/T3 的
        #    `disable-model-invocation` 被全量移除（见 AGENTS.md 标志位变更记录），
        #    分层只表示粒度与沉淀时间，不再表示"模型可否调用"。
        #    原实现仍要求 T2/T3 **必须带**该标志 ⇒ 对活库报 83 条假错误，
        #    同时把真正的问题盖住了：标志**残留**才会让那张卡对模型不可见。
        dis = fdict.get('disable-model-invocation', '')
        dis_true = norm(dis) == 'true'
        if mapped_tier is not None and entry != INDEX_NAME and dis_true:
            errors.append('INVOCATION-FLAG-PRESENT: %s tier=%s 仍带 disable-model-invocation=true'
                          ' (2026-09-01 已废除；残留会让这张卡对模型不可见)' % (entry, mapped_tier))

    # --- F: index freshness (compare against generated text) ---
    if INDEX_NAME in cards:
        idx_path = os.path.join(SKILLS, INDEX_NAME, 'SKILL.md')
        current = open(idx_path, encoding='utf-8').read()
        expected = None
        if triage is not None:
            expected = triage.generate_index_text(MAPPING)
        if expected is not None and current != expected:
            # 🔴 2026-10-10 注释按**实测**改正（旧注释与事实矛盾）。
            #    实测：活库索引与 `generate_index_text(MAPPING)` 的输出**逐字节相同**，
            #    现有章节只有 16 个域 + 备注 —— 并不存在什么"各域能力摘要 / Pro Lab
            #    说明节 / 变更记录"式的手工增补。
            #    ⚠️ 旧注释声称索引"刻意是生成 + 手工增补的混合体""与生成器输出长期
            #    不一致是预期状态"——这正是会误导下一个审计者的地方：**跑
            #    `triage_skills.py` 会重新生成整份索引，会静默丢掉任何手工增补**
            #    （生成器不知道它们存在，也不报错）。手工增补必须写进生成器，
            #    否则就当作不存在。
            #    降级为 WARN 的理由不变：作为 ERROR 会让审计永远 exit 1，从而没人再看
            #    这个出口；刚跑完 triage 之后若仍不一致，才值得追究。
            warnings.append('STALE-INDEX: %s 与 MAPPING 生成内容不同（手工增补过即为预期；'
                            '刚跑完 triage 仍如此才需追究）' % INDEX_NAME)

    # --- G: cross-reference resolution ---
    for entry, (fdict, body) in sorted(cards.items()):
        text = card_text(fdict, body)
        for m in WIKILINK_RE.finditer(text):
            tok = m.group(1).strip()
            if not tok or not all(ord(c) < 128 for c in tok):
                continue
            ref_tokens.append((entry, tok, 'wikilink'))
        for m in BACKTICK_RE.finditer(text):
            tok = m.group(1).strip()
            if ' ' in tok or '\n' in tok:
                continue
            if not all(ord(c) < 128 for c in tok):
                continue
            # 🔴 2026-09-30 收紧：只有**带连字符**的反引号 token 才算"形似卡名"的
            #    交叉引用 —— 这正是本文件 WHITELIST 上方注释写明的原意（"形似技能名
            #    （小写连字符 token）"），但实现从来没做这个过滤。
            #    不加这一条时，`b64`/`sleep`/`jmp`/`stop`/`dev`/`core` 这类普通标识符
            #    全被当成悬空引用：实测 333 条 DANGLING 里 320 条是这种噪声，结果是
            #    审计**永远 exit 1**，等于没有审计（没人会去看 458 条里哪几条是真的）。
            if '-' not in tok:
                continue
            # 纯十六进制长串（GUID / 哈希片段）也不是卡名。
            if re.fullmatch(r'[0-9a-f]{8,}', tok):
                continue
            ref_tokens.append((entry, tok, 'backtick'))
        for m in CJK_KW_RE.finditer(text):
            # 同 backtick 类：只有带连字符的 token 才算"形似卡名"。
            # 不加这条时 "见 count" / "查 free" / "见 silver ticket" 都会被抓成悬空引用。
            if '-' not in m.group(1):
                continue
            ref_tokens.append((entry, m.group(1), 'route-kw'))
        for m in LATIN_KW_RE.finditer(text):
            ref_tokens.append((entry, m.group(1), 'route-kw'))

    dangling = {}
    # 🔴 2026-10-10 新增：把**灵敏度**变成可见读数。
    #    起因：独立交验发现 WHITELIST 已长到约 2210 词，且混入明显不是"工具/协议"的
    #    token（一个 64 位十六进制 AES256 值、RS 时代的 rname-generation /
    #    rs-kerberos-only 等遗留名）。当时实测：45 个候选里 33 个被白名单吞、6 个被
    #    前缀吞 ⇒ **上报 0 条**；所以"锚点自洽绿"**不能**读作"引用都真实"。
    #    ✅ 同日清账（对照组实测）：名单 2211 → 47，删掉的 2164 条没有一条承重 ——
    #    清空 WHITELIST 重跑只多出 38 处误报（36 个 token + 1 个索引卡 WARN，全部是
    #    靶机上的服务名/命令/协议头/字面量，无一条指向不存在的卡）。留下的 47 条里
    #    31 条在 DANGLING 侧承重；另外 16 条是 ESC 编号（BC 闸的上界锚点，与 DANGLING
    #    **无关**），2026-10-10 已挪到 ESC_ALIASES / ESC_MAX ⇒ 名单现为 31 条，
    #    "白名单条数"从此就是 DANGLING 灵敏度的直接读数。
    #    现在这行读数若出现"白名单吞"数量上涨，就意味着名单又被人随手加长了，值得盯。
    candidates = set()
    swallowed_whitelist = set()
    swallowed_prefix = set()
    for entry, tok, kind in ref_tokens:
        if tok != tok.lower() or not NAME_TOKEN_RE.match(tok):
            continue  # 大小写混杂/非法字符：不可能是全小写卡名
        if tok[0].isdigit():
            continue  # 数字开头的值/哈希/IP，不是卡名
        if tok in names:
            continue
        if len(tok) < 3:
            continue
        candidates.add(tok)
        if tok in WHITELIST:
            swallowed_whitelist.add(tok)
            continue
        if tok.startswith(WHITELIST_PREFIXES):
            swallowed_prefix.add(tok)
            continue
        dangling.setdefault(entry, set()).add((tok, kind))

    infos.append(
        'DANGLING-REF 灵敏度：候选 %d · 白名单吞 %d · 前缀吞 %d · 上报 %d'
        ' —— 上报 0 不等于"引用都真实"，只等于这把闸当前没在喊（见 WHITELIST 上方注释）'
        % (len(candidates), len(swallowed_whitelist), len(swallowed_prefix),
           sum(len(v) for v in dangling.values()))
    )

    for entry in sorted(dangling):
        for tok, kind in sorted(dangling[entry]):
            msg = 'DANGLING-REF: %s -> %r (%s)' % (entry, tok, kind)
            # 🔴 索引卡例外：它是"关于卡的地图 + 变更记录"，天然会提到已退役/改名的旧名
            #    （`weak-prng` → `weak-prng-predictable-seed`、`box-type-recognition`
            #    → `ad-type-recognition`、`linux-privesc-checklist` → `linux-privesc` …）。
            #    那些**不是路由错误**，是历史。技术卡里出现悬空引用才是真错 —— 读者被
            #    要求去加载一张不存在的卡。
            (warnings if entry == INDEX_NAME else errors).append(msg)

    # --- I: slug 分词锚点自洽（2026-09-30 新增，**ERROR 级**，是闸不是提醒）-----
    #
    # 为什么是 ERROR：这条纪律 2026-09-24 就总结出来了（"用户会敲的形态必须能命中"），
    # 但当时是**一次性补 14 张卡**，没变成准入条件 ⇒ 同批新写的 9 张卡和之后所有新卡
    # 都没被量过。实测（2026-09-30）37/153 张卡不满足，`binary exploitation` 0 命中、
    # `sandbox escape` 命中的是**别的两张卡**（正确卡被藏）。修完 37→0 之后立此闸。
    #
    # 判据：skill_search 按 /[^a-z0-9_-]+/ 切词 ⇒ **连字符不是分隔符**，
    #   slug 只贡献一个 token。所以 slug 的每个分词都必须作为**独立 token**
    #   出现在元数据（name+description+whenToUse）里。缺了就把词补进
    #   description 的（检索词：…）锚点段。
    unanchored = []
    for entry, (fdict, _body) in sorted(cards.items()):
        if entry == INDEX_NAME:
            continue
        meta = ' '.join([
            norm(unquote(fdict.get('name', ''))),
            norm(unquote(fdict.get('description', ''))),
            norm(unquote(fdict.get('whenToUse', ''))),
        ]).lower()
        tset = set(p for p in re.split(r'[^a-z0-9_-]+', meta) if p)
        parts = [p for p in entry.split('-') if len(p) >= 3 and p not in SLUG_STOP]
        missing = [p for p in parts if p not in tset]
        if missing:
            unanchored.append('%s -> %s' % (entry, ','.join(missing)))
    if unanchored:
        errors.append('SLUG-COMPONENT-UNANCHORED (%d 张)：%s'
                      % (len(unanchored), ' | '.join(unanchored)))

    # --- J: RS 时代工具名残留（2026-09-30 新增，**ERROR 级**）-------------------
    #
    # 本库的卡多数移植自 RS(另一个 harness),工具名不同。每张卡头部都有一行
    # `📌 DSH 适配：…原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具…` 作为**映射声明**,
    # 那是修法不是残留 —— 所以按行豁免(含「DSH 适配」/「RS 时代」/「⚠️」的行)。
    # 真正要抓的是**正文里仍在指挥模型用旧工具名**的行:实测 2026-09-30 有 11 处
    # (complete_step / read_subagent_result / execute_command / orch_next / shell_send /
    #  shell_read),全部已改成 DSH 原生写法(todo_write / job_output / pwsh·bash /
    #  run_in_background + job_output)。
    LEGACY_TOOLS = ('read_skill', 'run_skill', 'complete_step', 'read_subagent_result',
                    'execute_command', 'orch_next', 'shell_send', 'shell_read')
    # 豁免：**在同一行说明了新旧对应关系**的行 —— 卡片头的「DSH 适配」映射声明、
    # 我写的 ⚠️ 说明、以及索引卡变更日志里"修了 7 处 RS 旧工具名"这类**元讨论**。
    # 判据：该行同时出现 legacy 名 与 下面任一限定词。真·指令（"用 execute_command 跑"）
    # 不含任何限定词，仍会被抓。
    LEGACY_EXEMPT = ('⚠️', 'RS 时代', 'RS 的', 'RS 旧', '旧工具名', 'DSH 适配',
                     'DSH 落地', '本 harness', '原 read_skill', '原 run_skill')
    legacy = []
    for entry in sorted(cards):
        path = os.path.join(SKILLS, entry, 'SKILL.md')
        try:
            raw = open(path, encoding='utf-8').read()
        except OSError:
            continue
        # 🔴 报**文件行号**，不是正文内偏移 —— 不能直接用于定位的错误信息等于没报。
        fm_end = 0
        if raw.startswith('---'):
            close = raw.find('\n---', 3)
            fm_end = raw.count('\n', 0, close + 4) if close != -1 else 0
        for i, line in enumerate(raw.split('\n'), 1):
            if i <= fm_end:      # frontmatter 区间跳过
                continue
            if not any(t in line for t in LEGACY_TOOLS):
                continue
            if any(x in line for x in LEGACY_EXEMPT):
                continue
            hit = [t for t in LEGACY_TOOLS if t in line]
            legacy.append('%s:%d(%s) %s' % (entry, i, ','.join(hit), line.strip()[:58]))
    if legacy:
        errors.append('LEGACY-TOOLNAME (%d 处)：%s' % (len(legacy), ' ｜ '.join(legacy[:8])))

    # --- H: reachability (info): names never mentioned by any other card ---
    all_text = '\n'.join(card_text(fdict, body) for fdict, body in cards.values())
    unreferenced = []
    for n in sorted(names):
        if n == INDEX_NAME:
            continue
        if not re.search(r'(?<![a-z0-9-])%s(?![a-z0-9-])' % re.escape(n), all_text.replace(card_text(cards[by_name[n]][0], cards[by_name[n]][1]), '')):
            unreferenced.append(n)
    if unreferenced:
        infos.append('UNREFERENCED (reachable only via index; fine for T3): %s' % ', '.join(unreferenced))

    # --- T1 catalog quality: whenToUse present? (warning) ---
    no_when = []
    for entry, (fdict, _) in sorted(cards.items()):
        if entry not in MAPPING or entry == INDEX_NAME:
            continue
        if MAPPING[entry][1] == 'T1' and not fdict.get('whenToUse', '').strip():
            no_when.append(entry)
    if no_when:
        warnings.append('T1-WITHOUT-WHENTOUSE: %s' % ', '.join(no_when))

    print('目标: %s  (%s)' % (SKILLS, SKILLS_SOURCE))
    print('cards on disk: %d   MAPPING: %d   extracted refs: %d' % (len(cards), len(MAPPING), len(ref_tokens)))
    for w in warnings:
        print('WARN:', w)
    for i in infos:
        print('INFO:', i)
    for e in errors:
        print('ERROR:', e)
    print('SUMMARY: %d errors, %d warnings, %d infos' % (len(errors), len(warnings), len(infos)))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
