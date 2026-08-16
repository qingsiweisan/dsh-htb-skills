---
name: 'dll-hijacking-practical'
description: 'DLL劫持实战：32/64位架构匹配、DllMain限制、CreateThread绕过、投放方式、验证方法'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T2 }
---
> 📌 DSH 用法：按卡名用 skill 工具加载；长任务用 bash 后台任务、并行侦察用 subagent。

# DLL 劫持实战笔记（来源 Logging 靶机）

## 架构匹配 🔴 最重要
- **必须匹配目标进程架构！**
- 用 `file` 命令确认: `PE32 executable (Intel i386)` = 32位, `PE32+ executable (x86-64)` = 64位
- 64位 DLL 被 32位进程 LoadLibrary → Error 193 (ERROR_BAD_EXE_FORMAT)；126 (MOD_NOT_FOUND) 是依赖/路径解析失败，两种都说明架构或路径不对
- MinGW: `i686-w64-mingw32-gcc` = 32位, `x86_64-w64-mingw32-gcc` = 64位
- msfvenom 默认可能生成 64位 DLL，需明确指定架构

## DllMain 能做什么
```text
✅ CreateFileA / WriteFile / ReadFile / CopyFileA
✅ CreateThread (新线程中执行复杂操作)
❌ WinExec / CreateProcessA / system() — 可能死锁或失败
❌ ShellExecute — 同上有问题
```text

## 绕过 DllMain 限制
- `CreateThread` + `Sleep(1000)` 让 DllMain 先返回，线程再执行 WinExec
- 但即使 CreateThread 也可能在某些环境下失败

## DLL 劫持投放方式
- 计划任务 + ZIP 提取: `Compress-Archive` 创建 ZIP，任务提取到 bin 目录
- 目标进程调用 `LoadLibrary` 加载被提取的 DLL
- 需确保投放路径对任务运行用户可写

## 验证 DLL 执行
- 最简单: `CreateFileA("C:\\ProgramData\\test.txt", ...)` 写文件
- 文件创建成功 = DLL 执行成功

**Why:** DLL 劫持是常见 HTB 提权路径，架构错误是最容易犯的错误
**How to apply:** 每次 DLL 劫持前先用 `file` 确认架构；DllMain 中只用文件操作验证执行；反弹 shell 用 CreateThread+Sleep 延迟执行
