---
name: 'cms-framework-rce'
description: 'CMS/Web框架RCE速查：WordPress/Joomla/Drupal/Magento/Django/Flask/Spring Boot/Laravel 等 25+ CMS。'
whenToUse: '目标为 CMS 或 Web 框架时按框架名定位 RCE 路径；Krayin CRM (CVE-2026-38526) 见正文。'
metadata: { domain: web, tier: T1 }
---
> 📌 DSH 适配：本技能移植自 RS。原 read_skill/run_skill 调用 = 用 DSH 的 skill 工具按名加载对应技能；fleet/kali-mcp = 用 bash 后台任务与 subagent 工具实现。

# CMS / Web 框架 RCE 速查

> HTB 统计: Easy 20台 + Medium 22台 + Hard/Insane 多台 = **最常用的初始立足点向量之一**

## 按 CMS/框架索引

### WordPress
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| 插件 LFI | Social Warfare 插件 RCE (CVE-2019-9978) | Backdoor |
| CVE-2022-0739 | BookingPress SQLi | MetaTwo |
| CVE-2023-41425 | WonderCMS XSS→RCE (实际上 WonderCMS 是独立 CMS) | Sea |
| 主题编辑 | admin → Theme Editor → 写 PHP | Curling, Blocky |
| 弱密码 + 插件上传 | admin:admin → 上传恶意插件 | — |
| GiveWP CVE | 捐赠插件 RCE | Giveback (Hard) |
| xmlrpc.php | 暴力破解 / SSRF | — |
| wp-config.php 泄露 | 备份文件 / LFI | — |

### Joomla
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| CVE-2023-23752 | API 信息泄露 (直接读配置) | Devvortex |
| 管理面板 | 源码中 base64 密码 | Curling |

### Drupal
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| CVE-2018-7600 | Drupalgeddon2 (RCE) | Armageddon |
| CVE-2014-3704 | Drupalgeddon (SQLi + RCE) | Bastard |

### Magento
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| CVE-2015-1397 | Froghopper RCE | SwagShop |
| SQLi → 创建 admin | — | SwagShop |

### CMS Made Simple
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| CVE-2019-9053 | SQLi → 密码 crack | Writeup |

### Dolibarr
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| CVE-2023-30253 | PHP 注入 RCE | BoardLight |

### Chamilo LMS
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| CVE-2023-4220 | 无认证文件上传 RCE | PermX |

### Pluck CMS
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| CVE-2023-50564 | ZIP 上传 RCE | GreenHorn |

### Gibbon LMS
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| 文件写入 CVE | webshell → Kerberos | TheFrizz |

### Ghost CMS
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| Symlink 漏洞 | 文件读取 | LinkVortex |

### 🆕 Krayin CRM (Laravel)
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| CVE-2026-38526 | TinyMCE 上传 → PHP RCE (认证后) | Nexus |
| CVE-2026-36340 | 邮件附件上传 → RCE (认证后, v2.1.5) | — |
| CVE-2026-38532 | BOLA 越权密码重置 (认证后) | — |
| Git 历史凭据 | admin/krayin-docker-setup → commit diff → DB_PASSWORD | Nexus |

详见 krayin-crm-attacks

### Camaleon CMS (Ruby/Rails)
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| IDOR 提权 + 路径穿越 | /admin/users/{id} → admin | Facts |
| download_private_file | Path traversal → SSH key | Facts |

### Backdrop CMS
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| 模块上传 RCE | 认证后 RCE | Dog |

### Concrete CMS
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| 反序列化 / 上传 | — | — |

### OpenSTAManager
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| CVE-2025-69212 | importFE_ZIP 插件 → 命令注入 | Enigma |

## 按框架/语言索引

### Spring Boot (Java)
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| Actuator 泄露 | /actuator/env, /actuator/sessions | CozyHosting |
| 命令注入 | SSH hostname 字段注入 | CozyHosting |

### Laravel (PHP)
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| CVE-2021-3129 | Ignition debug RCE | Horizontall |
| Laravel-admin 上传 | 认证后上传 | Usage |
| 🆕 CVE-2026-38526 | Krayin CRM TinyMCE 上传 RCE | Nexus |

### Django (Python)
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| Pickle 反序列化 | 认证后 Django pickle RCE | HackNet |

### Next.js (JavaScript/React)
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| CVE-2025-29927 | 中间件认证绕过 | Previous |

### Flask (Python)
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| SSTI (Jinja2) | 模板注入 | Doctor, RedPanda, Sandworm |
| Session 伪造 | Flask cookie 伪造 | Noter |
| Werkzeug 哈希 | pbkdf2:sha256 → hashcat | Eighteen |
| js2py 逃逸 | CVE-2024-28397 | CodePartTwo, CodeTwo |

### Apache NiFi
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| ExecuteSQL + H2 | CREATE ALIAS Java RCE | Helix |

### Mirth Connect
| CVE / 技术 | 描述 | 机器 |
|-----------|------|------|
| CVE-2023-43208 | XStream 反序列化 pre-auth RCE | Interpreter |

## 通用 CMS 攻击检查清单

```bash
[ ] 识别 CMS: WhatWeb / Wappalyzer / 页面底部版权
[ ] 搜索版本号: 源码/html meta/composer.json/package.json/CHANGELOG
[ ] searchsploit <CMS> <version>
[ ] 默认凭据: admin:admin, admin:password, admin:<CMS_NAME>
[ ] 管理面板位置: /admin, /administrator, /wp-admin, /manager
[ ] 暴露的配置文件: wp-config.php, .env, config.php, settings.py
[ ] Git 泄露: .git/ → git log -p
[ ] API 端点: /api, /wp-json, /rest, /graphql
[ ] 文件上传: 头像/插件/主题/模块上传 → .php/.phtml/.phar bypass
[ ] 插件版本: /wp-content/plugins/<name>/readme.txt
[ ] 备份文件: .bak, .old, .swp, ~, .save
[ ] 🆕 如果发现 Laravel: 检查 debug mode + /_ignition/ + Laravel Debugbar
```

## 教训

1. **CMS = 已知 CVE 的天堂** — WhatWeb + searchsploit 超过 50% 命中率
2. **版本号是关键** — 花时间确认版本，不要盲目测 payload
3. **管理面板 + 弱密码 = RCE** — 任何 CMS 都测试一次 admin:admin
4. **插件 ≠ 核心** — 最严重的 CVE 常在插件/主题中
5. **配置泄露是无声杀手** — .env / wp-config.php / settings.py 常可直接访问
6. 🆕 **认证后漏洞也是漏洞** — Krayin 需要认证，但 Git 历史泄露的密码直接解决了认证问题
7. 🆕 **登录后第一件事：搜 CVE** — 不要手工找上传点，先搜版本号对应的已知漏洞
