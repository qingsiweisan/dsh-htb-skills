---
name: 'codebuild-floci-escape'
description: 'LocalStack/Floci CodeBuild 容器逃逸：BASH_FUNC_id%% 绕过 entrypoint gosu 降权 + project 名污染 + modprobe_path 劫持拿宿主机 root。'
whenToUse: '遇到 LocalStack(floci)/CodeBuild/CI 容器靶机，Lambda 容器无逃逸点、需从 CodeBuild 特权容器逃到宿主机时。'
disable-model-invocation: true
metadata: { domain: linux, tier: T3 }
---

## 攻击链
floci:4566 直连（无签名）→ CodeBuild create-project + start-build → BASH_FUNC_id%% 函数注入绕过 entrypoint 的 gosu floci 降权 → 容器以 root 运行 → CAP_SYS_ADMIN + modprobe_path 劫持 → 触发非法 ELF → 宿主机 root 执行 payload → 回连读 root.txt

## 关键细节
1. BASH_FUNC_id%% 不是 cosmetic：Floci entrypoint.sh 有 `exec gosu floci "$0" "$@"`；注入环境变量 `BASH_FUNC_id%%='() { echo "uid=0(root)..."; }'` 使 entrypoint 里 `id` 检查返回 uid=0 → 跳过 gosu → 真 root 运行
2. 降权绕过成功后 root 执行 CMD（`mkdir -p /codebuild/... && tail -f /dev/null`）→ 容器保活 → docker exec 可用
3. project 名污染：boto3 create_project 缓存配置，同名重建复用坏配置 → 每次删旧 project + 换全新名字
4. CLI 格式：`aws --cli-input-json file://project.json` 在 Floci 1.5.17 正确处理；boto3 序列化可能微妙失配（buildspec 换行、环境变量格式）
5. modprobe_path：容器 CAP_SYS_ADMIN 时写 /proc/sys/kernel/modprobe 指向恶意脚本，触发非法 ELF 执行 → 宿主机 root

## 教训
- 删除 BASH_FUNC_id%% 会致容器以 floci 运行、mkdir 失败秒死（当年 51 次失败根因）
- 不要在 Lambda/ECS/pidMode 上浪费时间：LocalStack Lambda 容器无逃逸点
- 来源：Nimbus HTB（2026-06 完整链记忆）
