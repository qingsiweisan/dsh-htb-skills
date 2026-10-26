/**
 * log-sink.js — 观测日志的写入器（复用 fd，避免每次 open/close）
 *
 * 为什么单独抽出来（2026-10-26 实测）：
 *   四个观测模块都挂在 `tools/post-execute` 上，每次工具调用各写一行 JSONL。
 *   Windows 上 `appendFileSync` 单次 **0.397 ms**（open + write + close），
 *   而其中 open/close 占了绝大部分 —— struggle-watch 单次调用 1.94 ms 里
 *   有 0.43 ms 花在这里，且**每次调用都付**。
 *
 *   换成"首次 openSync 拿 fd，之后 writeSync"：**0.0019 ms**，快 209 倍。
 *   关键：语义完全不变 —— `writeSync` 是同步写进内核，同进程内立刻 `readFileSync`
 *   就能读到（已用探针验证）。所以"日志写完立即可读"这条契约没被打破，
 *   现有测试不需要改。
 *
 * 刻意**不做**的事：
 *   - 不做用户态缓冲（那会改变"写完即可读"的语义，测试和事后排障都依赖它）
 *   - 不挂进程退出钩子（fd 由 OS 回收；writeSync 已经落盘，不丢）
 *
 * 失效恢复：
 *   日志文件被外部删除 / 权限变化时 fd 会失效。此时**重开一次**再试，
 *   仍失败就静默放弃 —— 观测日志写不动，绝不能影响工具结果。
 */

import { closeSync, existsSync, mkdirSync, openSync, writeSync } from 'node:fs'
import { dirname } from 'node:path'

/**
 * 创建一个日志写入器。
 *
 * 返回的对象只有两个方法：
 *   - `write(text)`：写一段文本（调用方自己拼 JSON + 换行）
 *   - `writeRecord(obj)`：`JSON.stringify` + 换行，省掉调用方重复拼接
 *   - `close()`：主动关闭（测试里用；生产不调用也能正常退出）
 *
 * @param path - 日志文件绝对路径。
 * @returns 写入器。
 */
export function createLogSink(path) {
  let fd
  let dirEnsured = false

  const ensure = () => {
    if (fd !== undefined) return fd
    if (!dirEnsured) {
      // 目录只 stat 一次：这是原来每次写入都要付的另一个系统调用。
      const dir = dirname(path)
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
      dirEnsured = true
    }
    fd = openSync(path, 'a')
    return fd
  }

  const reset = () => {
    try { if (fd !== undefined) closeSync(fd) } catch { /* 已经坏了，忽略 */ }
    fd = undefined
  }

  const write = (text) => {
    try {
      writeSync(ensure(), text)
    } catch {
      // fd 失效（文件被删 / 目录被换 / 权限变化）：重开一次再试。
      reset()
      dirEnsured = false
      try {
        writeSync(ensure(), text)
      } catch { /* 写不动就放弃：观测日志不能影响会话 */ }
    }
  }

  return {
    write,
    writeRecord(record) {
      write(`${JSON.stringify(record)}\n`)
    },
    close() {
      reset()
    },
  }
}
