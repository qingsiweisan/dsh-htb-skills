---
name: 'ocr-file-write-rce'
description: 'OCR 文字识别→文件写入→代码执行的攻击链技术。来源 Makesense HTB。含 OCR 字符误差绕过表 + 适合 OCR 的 PHP payload。'
disable-model-invocation: true
metadata: { domain: web, tier: T3 }
---


## OCR → File Write → RCE 攻击链（来源 Makesense 靶机）

### 场景
- 内部 PHP 服务使用 Tesseract OCR 识别用户提交的图像文字
- 识别后的文字可保存到服务器文件系统
- PHP 进程以 root / 高权限运行

### 利用步骤

#### 1. 生成含 payload 文字的 PNG 图像
- 用 ImageMagick（Kali）生成清晰文字图像：
```bash
convert -size 2000x120 xc:white -fill black -font DejaVu-Sans-Bold \
  -pointsize 70 -kerning -3 -annotate +10+80 'PAYLOAD_TEXT' output.png
```text
- 关键参数：大字体（70pt+）、负 kerning（-3）防止字符间空格、宽画布防止换行

#### 2. 绕过 OCR 字符识别误差
常见 OCR 对代码字符的错误识别：
| 原字符 | OCR 可能识别为 | 解决方案 |
|--------|---------------|---------|
| `_` (下划线) | ` ` (空格) | 避免使用带下划线的函数名 |
| `;` (分号) | `:` (冒号) | PHP `?>` 前可省略分号 |
| `$` (美元) | `S` | 使用不依赖变量的 payload |
| `` ` `` (反引号) | `'` 或空白 | 避免反引号，用函数代替 |
| `<` `>` | 可能正确识别 | 确认后再保存 |

#### 3. 适合 OCR 的 PHP payload
- ✅ `<?=readfile('/path/to/file')?>` — 读文件，无下划线无分号
- ✅ `<?=scandir('/path')?>` — 列目录
- ✅ `<?=phpinfo()?>` — 测试 PHP 执行
- ✅ `<?=1?>` / `<?=HELLO?>` — 最简单的功能测试
- ❌ `system()`, `exec()`, `file_get_contents()` — 可能被禁用或 OCR 分割

#### 4. 文件写入路径穿越
- 如果 save 路径被 `basename()` 保护，尝试：
  - `....//` — 双写绕过
  - URL 编码: `%2e%2e%2f`
  - 绝对路径 `/tmp/x`
- 如果 PHP built-in server 下 `.php` 文件被直接执行 → 写入 PHP webshell
- 如果路径穿越成功 → 写入 `authorized_keys`, `/etc/cron.d/`, 或覆盖现有文件

### 适用场景识别
- 任何接受图像上传并返回识别文字的服务
- Tesseract, EasyOCR, PaddleOCR 等 OCR 引擎
- 带有"保存结果到文件"功能的页面
