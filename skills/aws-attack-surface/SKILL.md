---
name: 'aws-attack-surface'
description: '用攻击者视角读 AWS API 文档/参数：每个字段转成\"能控制什么/能绕过什么/能劫持什么\"'
whenToUse: '拿到 AWS API 参数/字段时：逐个转成"能控制什么/绕过什么/劫持什么"的攻击问题。'
disable-model-invocation: true
metadata: { domain: cloud, tier: T2 }
---

# Skill: AWS 攻击面映射

拿到的每个 AWS 参数/字段都转成攻击问题。

## 触发
- 遇到 floci/localstack/aws 环境变量
- 创建/修改任何 AWS 资源 (CodeBuild project, ECS task def, Lambda function, EC2 instance)

## 准入控制参数 → 逃逸路径

```
每个 environment 参数问:
  privilegedMode/increment → 能给我 CAP_SYS_ADMIN 吗?
  environmentVariables → 能注入环境变量控制容器行为吗?
  entryPoint → 能覆盖镜像默认入口吗?
  command → 能执行任意命令吗?
  volumes / mountPoints / host → 能挂载宿主机文件系统吗?
  pidMode → 能共享宿主机 PID namespace 吗?
  networkMode → host 能让我直接出网吗?
```

## 环境变量 → 行为劫持

```
每个环境变量问:
  BASH_FUNC_*%% → 能不能劫持 bash 函数? (entrypoint 里的 id/whoami/curl)
  PATH → 能不能优先执行我的二进制?
  LD_PRELOAD → 能不能注入 .so?
  HOME / USER / SHELL → 能影响脚本的行为逻辑吗?
  AWS_* → 能用我的凭据横向移动吗?
```

## 镜像 → 沙箱边界

```
image 参数问:
  谁构建的? → 有 gosu/setuid 降权吗? → 能绕过吗?
  有 curl/python/bash 吗? → 能回连吗?
  entrypoint.sh 做了什么? → 读源码了吗?
  默认用户是什么? → root 还是被降权?
  /proc/sys 可写吗? → privileged 给了但 kernel 让写吗?
```

## 文件路径 → 宿主穿透

```
每个路径参数问:
  这个路径在容器内还是宿主机上?
  overlay upperdir 能提取吗? → awk /proc/mounts
  /proc/1/root 能访问吗? → pidMode=host
  /var/run/docker.sock 挂载了吗? → 搜 sockets
```

## 🔴 Nimbus 教的具体教训

| 参数 | 我的反应 | 应该的反应 |
|------|---------|-----------|
| `environmentVariables: [{name: "BASH_FUNC_id%%", ...}]` | 这是 cosmetic，删了 | 🚨 什么函数叫 id？entrypoint 用 id 做什么？ |
| `privilegedMode: True` | 好，有 CAP_SYS_ADMIN | 🚨 给了 cap，但 uid 是谁？看 entrypoint |
| `image: "floci/floci:latest"` | 唯一可用镜像 | 🚨 这镜像的 entrypoint.sh 源码在哪？ |
| `command: ["/bin/sh", "-c", "..."]` | 能执行命令 | 🚨 entryPoint 能覆盖吗？覆盖后 uid 对不对？ |

## 核心原则

读 AWS 参数时问三句话：
1. **这个参数让我控制什么？**（文件、命令、用户、网络）
2. **目标环境期望什么？**（读 entrypoint.sh 源码，不要猜）
3. **基准假设是什么？**（"容器以 root 运行"——真的吗？验证！）
