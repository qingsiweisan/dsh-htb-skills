/**
 * guard 规则表回归测试：`node scripts/guard-test.mjs`
 *
 * 四组用例：
 *   DENY      —— 必须拦下的（卡片 §1/§6 的事故模式）
 *   ALLOW     —— 必须放行的（卡片自己给的 ✅ 写法 + 引号里的纯文本）
 *   QUOTED_EXEC —— 引号内文本**被交给解释器执行**时必须照拦
 *   OVERRIDE  —— 逃生口只认命令开头
 */

import { checkCommand } from '../src/guard.js'

const DENY = [
  ["pkill -f 'http.server 8000'", 'pkill-f'],
  ['pkill -9 -f python', 'pkill-f'],
  ["pkill -f '^python3 -m http.server$'", 'pkill-f'],
  ['killall python3', 'killall-generic'],
  ['killall node', 'killall-generic'],
  ['sudo mount /dev/loop0 /mnt/host', 'mount-loop'],
  ['mount -o ro /dev/loop3 /mnt', 'mount-loop'],
  ['mkfs.ext4 /dev/sda1', 'mkfs'],
  ['dd if=/root/flag of=/dev/sda', 'dd-raw-device'],
  ['dd if=/dev/zero of=/dev/nvme0n1', 'dd-raw-device'],
  ['rm -rf /', 'rm-rf-root'],
  ['rm -rf ~', 'rm-rf-root'],
  ['rm -rf $HOME', 'rm-rf-root'],
  ['sudo rm -fr /', 'rm-rf-root'],
  // 只有**路径**被引号包住不算文本：动词在引号外
  ['rm -rf "/"', 'rm-rf-root'],
  ['rm -rf "$HOME"', 'rm-rf-root'],
  // 引号内的假命中 + 引号外的真命中，同一条命令里共存
  ['echo "dd if=x of=/dev/sda" && dd if=y of=/dev/sdb', 'dd-raw-device'],
  // 🆕 2026-09-30 补漏。来源：对 18 条样例句跑覆盖探针，实测漏拦 6 条、误拦 0 条。
  //  (a) losetup —— **这正是 Reddish 事故的第一步**（卡 §6 记的是 losetup + mount，
  //      而原守卫只覆盖了 mount 那一半）。加了 losetup 才与卡片记载对齐。
  ['losetup /dev/loop0 /tmp/root.img', 'losetup'],
  ['losetup -f --show /tmp/root.img', 'losetup'],
  ['sudo losetup -r /dev/loop7 disk.img', 'losetup'],
  //  (b) 一行版 loop 挂载：写法上完全不出现 /dev/loop，mount-loop 那条抓不到。
  ['mount -o loop /tmp/root.img /mnt/x', 'mount-o-loop'],
  ['mount -o rw,loop img /mnt', 'mount-o-loop'],
  //  (c) 经典删根通配：原正则尾部要求 `\s|$`，被 `/` 和 `*` 绕过。
  ['rm -rf /*', 'rm-rf-root'],
  ['rm -rf ~/', 'rm-rf-root'],
  //  (d) pkill 长选项等价于 -f。
  ['pkill --full chisel', 'pkill-f'],
]

const ALLOW = [
  // 卡片 §1 给的 ✅ 写法 —— 拦了它们就等于把正确解法也堵死了
  ['lsof -ti tcp:8000 | xargs -r kill -9', '按端口取 PID'],
  ["pgrep -f '^python3 -m http.server 8000$' | xargs -r kill -9", '锚定 pgrep'],
  ['ss -lntpH "sport = :9001"', '内核告诉你谁占端口'],
  ['kill 12345', '精确 PID'],
  // 同前缀但不能误伤
  ['rm -rf /tmp/build', '限定路径的 rm'],
  ['rm -rf ~/tmp/build', '限定路径的 rm（家目录子目录）'],
  ['rm -rf ./dist', '相对路径'],
  ['dd if=/dev/zero of=/tmp/img bs=1M count=10', '写普通文件'],
  ['mount /tmp/img /mnt/x', '挂普通文件（无 /dev/loop）'],
  ['mount | grep loop', '只读查看'],
  ['cat /proc/mounts', '只读'],
  ['mkfs --help', '只看帮助'],
  ['mkfs.ext4 /tmp/img', '格式化自己造的镜像文件'],
  ['pkill --help', '只看帮助'],
  ['cat /etc/passwd', '普通命令'],
  ['nmap -sV 10.10.11.5', '普通侦察'],
  // 危险动词落在引号字面量里 ⇒ 是文本，不是执行。
  // 这组就是 2026-09-24 首次验收时误伤的那条命令。
  ['echo "dd if=x of=/dev/sda"', '引号内的 dd'],
  ['grep -rn "mount /dev/loop" ./writeups/', 'grep 引号内的 mount'],
  ['git commit -m "docs: 说明为什么不要用 pkill -f"', 'commit message'],
  ['grep -rn "pkill -f" .', '搜自己的文档'],
  ['echo "rm -rf /"', '引号内的 rm'],
  // 🔴 2026-09-27 Layover 会话（session-2bfe46ca）实测误拦：参数扫描跨过了 `;`，
  // 把后面那条 `cp -f` 当成了 `pkill -f`。而被拦的 `pkill -x` 正是本表推荐的写法。
  ['pkill -x ffuf; sleep 1; cp -f /usr/share/wordlists/dirb/common.txt /root/x.txt',
    '分隔符后无关命令的 -f（真实误拦原样）'],
  ['pkill -x ffuf && cp -f a b', '&& 后面的 -f'],
  ['pkill -x ffuf | tee log; tar -xf a.tar', '管道/分号后面的 -f'],
  ['killall -q ffuf; node server.js', 'killall 后跟无关的 node'],
  ['mount | grep /dev/loop', '先 mount 再查 /dev/loop'],
  ['mkfs --help; ls /dev/sda', 'mkfs 帮助后跟 /dev/'],
  ['dd --help; echo of=/dev/sda', 'dd 帮助后跟 of=/dev/'],
  ['rm file.txt; chmod -Rf /tmp/x', 'rm 之后无关的 -Rf'],
  // 🆕 2026-09-30：新增 losetup / mount-o-loop 两条规则后，必须确认没把
  //    **排查手段**和**正常挂载**一起拦掉。这四条是误拦防线。
  ['losetup -a', '列举现有 loop 关联（排查手段，放行）'],
  ['losetup --list', '同上'],
  ['mount -o remount,rw /', '重挂载，不带 loop'],
  ['mount -o bind /var/loopdata /x', '路径里恰好含 "loop" 字样，但不是 loop 选项'],
]

// 引号不是保护：整条命令把文本交给解释器执行时，照拦。
const QUOTED_EXEC = [
  ['bash -c "pkill -f x"', 'pkill-f'],
  ["sh -c 'rm -rf /'", 'rm-rf-root'],
  ['eval "pkill -f x"', 'pkill-f'],
  ['python3 -c "import os; os.system(\'mount /dev/loop0 /mnt\')"', 'mount-loop'],
  ['perl -e "dd if=x of=/dev/sda"', 'dd-raw-device'],
  ['echo "dd if=x of=/dev/sda" | sh', 'dd-raw-device'],
  ['powershell -Command "pkill -f x"', 'pkill-f'],
  ['Invoke-Expression "pkill -f x"', 'pkill-f'],
]

// 逃生口：必须刻意写出来才生效，且只影响以它开头的命令。
const OVERRIDE = [
  ['HTB_GUARD_ALLOW=1 mkfs.ext4 /dev/sda1', '确认过才放行'],
  ["HTB_GUARD_ALLOW=1 pkill -f 'x'", '确认过才放行'],
  ['  HTB_GUARD_ALLOW=1 rm -rf /', '前导空白也算'],
  ['echo HTB_GUARD_ALLOW=1 && pkill -f x', '前缀不在开头 → 仍拦'],
]

let failed = 0
const fail = (msg) => {
  failed += 1
  console.log(`  ✗ ${msg}`)
}

console.log('DENY — 必须拦下')
for (const [cmd, want] of DENY) {
  const hit = checkCommand(cmd)
  if (!hit) fail(`漏拦 [${want}] ${cmd}`)
  else if (hit.id !== want) fail(`拦错规则 期望 ${want} 实得 ${hit.id}: ${cmd}`)
}
console.log(`  ${DENY.length} 条`)

console.log('ALLOW — 必须放行')
for (const [cmd, note] of ALLOW) {
  const hit = checkCommand(cmd)
  if (hit) fail(`误拦 [${hit.id}] ${cmd}  (${note})`)
}
console.log(`  ${ALLOW.length} 条`)

console.log('QUOTED_EXEC — 引号内文本被解释器执行')
for (const [cmd, want] of QUOTED_EXEC) {
  const hit = checkCommand(cmd)
  if (!hit) fail(`漏拦 [${want}] ${cmd}`)
  else if (hit.id !== want) fail(`拦错规则 期望 ${want} 实得 ${hit.id}: ${cmd}`)
}
console.log(`  ${QUOTED_EXEC.length} 条`)

console.log('OVERRIDE — 逃生口')
for (const [cmd, note] of OVERRIDE) {
  const shouldBlock = note.includes('仍拦')
  const hit = checkCommand(cmd)
  if (shouldBlock && !hit) fail(`逃生口漏放行 → 应仍被拦: ${cmd}`)
  if (!shouldBlock && hit) fail(`逃生口失效 [${hit.id}]: ${cmd}`)
}
console.log(`  ${OVERRIDE.length} 条`)

console.log(failed === 0 ? '\n✅ 全部通过' : `\n❌ ${failed} 条失败`)
process.exit(failed === 0 ? 0 : 1)
