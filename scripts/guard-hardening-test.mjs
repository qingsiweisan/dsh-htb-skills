// Acceptance check for the 2026-10-10 guard hardening.
// Every case below is one the independent auditor (828e5fe7) listed.
// Pure function calls only — nothing is executed.
const M = await import('file:///C:/Users/Administrator/dsh-htb-skills/src/guard.js')
const rules = M.activeRules('C:/Users/Administrator/.dsh/htb-guard-rules.json')

const MUST_BLOCK = [
  ['G1 rm 同义改写', 'rm -r -f /'],
  ['G1 rm 同义改写', 'rm -rf -- /'],
  ['G1 rm 同义改写', 'rm --recursive --force /'],
  ['G1 rm 同义改写', 'rm -rf --no-preserve-root /'],
  ['G1 动词带引号', '"rm" -rf /'],
  ['G1 动词带引号', "'rm' -rf --no-preserve-root /"],
  ['G1 动词带引号', '"dd" if=/dev/zero of=/dev/sda'],
  ['G1 动词带引号', '"pkill" -f x'],
  ['G1 带引号设备', 'dd if=/dev/zero of="/dev/sda"'],
  ['G1 带引号设备', 'mkfs.ext4 "/dev/sda"'],
  ['G1 设备白名单漏', 'dd if=/dev/zero of=/dev/hda bs=1M'],
  ['G1 设备白名单漏', 'dd if=/dev/zero of=/dev/dm-0 bs=1M'],
  ['G1 设备白名单漏', 'dd if=/dev/zero of=/dev/mapper/vg-lv bs=1M'],
  ['G1 pkill 变体', 'pkill -ef ffuf'],
  ['G1 pkill 变体', 'pkill --fu ffuf'],
  ['G1 mount 长选项', 'mount --options loop img /mnt'],
  ['G1 killall 变体', 'killall -r .'],
  ['G1 killall 变体', 'killall5 -9'],
  // ── J3 收窄后仍必须拦（killall5 的三种真执行形态 + 保留的 killall -r）──
  //    依据 loot/_audit/J3-getopt.md §2.3 / §4：`killall5 -signalnumber` 是裸信号号，
  //    man 8 的 NAME 就是 "send a signal to all processes"。
  ['J3 killall5 命令位', 'killall5'],
  ['J3 killall5 命令位', 'sudo killall5'],
  ['J3 killall5 命令位', 'flush_cache; killall5 -9'],
  ['J3 killall5 命令位', 'true && killall5 -9'],
  ['J3 killall5 命令位', 'sudo /usr/sbin/killall5 -9'],
  ['J3 killall5 解释器', 'bash -c "killall5 -9"'],
  ['J3 killall5 解释器', "sh -c 'killall5 -9'"],
  ['J3 killall5 管道执行', 'echo "killall5 -9" | sh'],
  ['J3 killall -r 锚定仍拦', "killall -r '^ffuf$'"],
  ['J3 killall -r 长选项', 'killall --regexp .'],
  ['G1 PowerShell', 'Remove-Item -Recurse -Force C:\\'],
  ['G1 PowerShell', 'Clear-Disk -Number 0 -RemoveData -Confirm:$false'],
  ['G1 PowerShell', 'Format-Volume -DriveLetter C -FileSystem NTFS'],
  ['G1 PowerShell', 'ri -Recurse -Force C:\\'],
  ['G1 cmd.exe', 'del /s /q C:\\*'],
  ['G2 解释器绕过', 'bash<<<"pkill -f x"'],
  ['G2 解释器绕过', "awk 'BEGIN{system(\"pkill -f x\")}'"],
  ['G2 解释器绕过', "php -r 'system(\"pkill -f x\");'"],
  ['G2 解释器绕过', "lua -e 'os.execute(\"pkill -f x\")'"],
  ['G2 解释器绕过', "$c='pkill -f x'; & $c"],
  ['G4 等号写法', 'curl --request=DELETE http://h/api/user/1'],
  ['G4 方法带引号', "curl -X 'DELETE' http://h/api/user/1"],
  ['G4 URL 编码', 'curl http://h/%64elete'],
  ['G4 扩展名截断', 'curl http://h/api/delete.json'],
  ['G4 HTTPie', 'http DELETE http://h/x'],
  ['G4 Invoke-WebRequest', 'Invoke-WebRequest http://h/api/delete'],
  ['G4 原始请求行', 'printf "DELETE /x HTTP/1.1\\r\\n\\r\\n" | nc h 80'],
  ['G5 逃生前缀无边界', 'HTB_GUARD_ALLOW=1evil; rm -rf /'],
  ['G5 逃生前缀无边界', 'HTB_GUARD_ALLOW=10 dd if=/dev/zero of=/dev/sda'],
  ['回归修复', 'fetch("http://h/x",{method:"DELETE"})'],
]

// The auditor's own false-positive control set: ALL of these must stay allowed.
const MUST_ALLOW = [
  ['FP layover 事故案', 'pkill -x ffuf; sleep 1; cp -f a b'],
  ['FP', 'pkill -x ffuf'],
  ['FP loopdata 路径', 'mount -o bind /var/loopdata /x'],
  ['FP remount', 'mount -o remount,rw /'],
  ['FP 普通挂载', 'mount /dev/sda1 /mnt'],
  ['FP 子目录 rm', 'rm -rf /tmp/x'],
  ['FP 引号内文本', 'echo "dd if=x of=/dev/sda"'],
  ['FP 引号内文本 2', 'grep -rn "mount /dev/loop" ./docs'],
  ['FP 本地文件含 purge', 'curl -o /tmp/purge_report.html http://h/'],
  ['FP OPTIONS', 'curl -X OPTIONS http://h/'],
  ['FP SQL 只读', 'psql -c "select 1"'],
  ['FP redis 只读', 'redis-cli -h h INFO'],
  ['FP losetup 列举', 'losetup -a'],
  ['FP 纯引号文本', 'echo "a" "mount /dev/loop0 /mnt"'],
  ['FP 纯引号文本 2', "printf '%s' \"mount /dev/loop0 /mnt\""],
  ['FP 逃生前缀(合法)', 'HTB_GUARD_ALLOW=1 dd if=/dev/zero of=/dev/sda'],
  ['FP 自己的 loot', 'Remove-Item -Recurse -Force .\\loot\\Touch'],
  ['FP 只读 dd null', 'dd if=/dev/zero of=/dev/null bs=1M count=1'],
  // ── J3 实测的误拦修复（loot/_audit/J3-getopt.md §3 / §4）──────────────
  //    `killall5` 是程序名锚点，裸提及=纯文本。J3 取证时被这条拦了 2 次。
  ['J3 纯文本提及', 'man killall5'],
  ['J3 纯文本提及', 'man 8 killall5'],
  ['J3 纯文本提及', 'grep -rn killall5 loot/'],
  ['J3 纯文本提及', 'echo "killall5"'],
  ['J3 纯文本提及', 'ls -la /usr/sbin/killall5'],
  ['J3 纯文本提及', 'strings /usr/sbin/killall5 | head'],
  ['J3 纯文本提及', 'dpkg -S killall5'],
  ['J3 纯文本提及', 'cat /usr/share/man/man8/killall5.8'],
  ['J3 mount 死分支', 'mount --opt loop img /mnt'],
  // ── 基线：这些 J3/前任审计实测过必须继续放行 ─────────────────────────
  ['基线 pkill -e', 'pkill -e ffuf'],
  ['基线 pkill -F', 'pkill -F /run/x.pid'],
  ['基线 mount -o ro', 'mount -o ro img /mnt'],
  ['基线 killall 精确名', 'killall -9 ffuf'],
]

let blocked = 0
let missed = []
console.log('=== 必须拦下（审计者的绕过清单）===')
for (const [tag, cmd] of MUST_BLOCK) {
  const hit = M.checkCommand(cmd, rules)
  if (hit) { blocked += 1; console.log(`  ✓ ${hit.id.padEnd(24)} [${tag}]`) }
  else { missed.push([tag, cmd]); console.log(`  ✗ 仍放行 ${''.padEnd(15)} [${tag}] ${cmd}`) }
}
console.log(`  → ${blocked}/${MUST_BLOCK.length} 已拦`)

let allowed = 0
let fps = []
console.log('\n=== 必须放行（误拦防线）===')
for (const [tag, cmd] of MUST_ALLOW) {
  const hit = M.checkCommand(cmd, rules)
  if (!hit) { allowed += 1; console.log(`  ✓ ALLOW ${''.padEnd(32)} [${tag}]`) }
  else { fps.push([tag, cmd, hit.id]); console.log(`  🔴 误拦 ${hit.id.padEnd(22)} [${tag}] ${cmd}`) }
}
console.log(`  → ${allowed}/${MUST_ALLOW.length} 放行`)

if (missed.length) {
  console.log('\n=== 仍放行（已知残余 / 需判断）===')
  for (const [tag, cmd] of missed) console.log(`  · [${tag}] ${cmd}`)
}
if (fps.length) {
  console.log('\n=== 误拦（必须修）===')
  for (const [tag, cmd, id] of fps) console.log(`  · [${tag}] ${cmd}  → ${id}`)
}
console.log(`\n===== 拦 ${blocked}/${MUST_BLOCK.length} · 放 ${allowed}/${MUST_ALLOW.length} · 误拦 ${fps.length} =====`)
process.exit(fps.length === 0 ? 0 : 1)
