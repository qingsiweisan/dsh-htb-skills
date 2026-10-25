---
name: 'cms-framework-rce'
description: 'CMS/Web框架RCE速查：WordPress/Joomla/Drupal/Magento/Django/Flask/Spring Boot/Laravel 等 25+ CMS。（检索词：cms/wordpress/joomla/drupal/magento/laravel/django/spring/wp2shell/stylesmuggler/pagebuilder/jce/spip/coldfusion/sharepoint/ghost/maxsite/framework）'
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
| 🔴 **wp2shell** | **CVE-2026-63030 + CVE-2026-60137**：Core **预认证 RCE 链**（REST batch 路由混淆绕过认证 + `author__not_in` SQLi 投毒缓存）。影响 **6.9.0–6.9.4 / 7.0.0–7.0.1**，**默认安装即可打、无需插件** → 详见 `cve-2026-wp2shell-wordpress` | — |
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
| 🔴 CVE-2026-48907 | **JCE**（Joomla Content Editor）未认证编辑器 profile 上传 → 写任意文件（9.8）。在野投放流氓 profile + webshell 到 `tmp`/`media`/`images`/`libraries` | — |
| 🔴 CVE-2026-56290 | **PageBuilder CK** 未认证文件上传 → **上传处理器直接执行 POST 内容**（10.0）。修复上线**数小时内**即被利用，webshell 落 `/media/com_pagebuilderck/gfonts/` | — |
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
| 🔴 CVE-2026-75650 | **"StyleSmuggler"** CVSS **10.0**：未认证攻击者通过 **Magento 邮件模板引擎注入 PHP** → RCE。影响 **< 2.4.7-p1**，进 KEV 2026-09-08 | — |
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
| 源码泄漏（部分路径穿越） | `albums_getimage.php` → 读 `admin_backup.php` 拿 `$ww` | Mist |
| 模块上传 RCE | `admin.php?action=installmodule`，**字段名 `sendfile`** | Mist |

🔴 **实测细节（Mist / Pluck 4.7.18）—— 下面两条都是"不知道就卡死"的类型：**

**1) 先拿 admin 哈希（源码泄漏）**
```
GET /data/modules/albums/albums_getimage.php?image=admin_backup.php
```
`$image` 只做了弱正则过滤，内部 `readfile('../../settings/modules/albums/'.$image)`
→ 用 `../` 够到 `data/settings/admin.php` 的备份 `admin_backup.php`，回显里 `$ww` 即 admin 口令哈希。
★ 这不是"完整路径穿越"，但同样值钱（同 web-attacks 里那条思路）。
★ `$ww` 属 SHA-512 族：先 `hashcat --identify` 确认再选 `-m`（裸 SHA-512 = 1700）。

**2) 模块上传 RCE —— 表单字段名是 `sendfile`，不是 `modulefile`**
```bash
# zip 内保持 <模块名>/<文件> 结构；POST /admin.php?action=installmodule（需先登录 admin）
curl -b cookie.txt -F 'sendfile=@mistmod.zip' 'http://T/admin.php?action=installmodule'
```
★ 用 `modulefile` / `file` 等字段名 → 服务端**收不到文件且不报错**，
  表现为"上传后什么都没发生"，极易误判成模块白名单/权限问题而白查。
★ 解压落点 `data/modules/<模块名>/`；**zip 内层目录会改变最终嵌套层级**，
  落点不对就用 webshell 列目录确认实际路径，别按预期路径去访问。
★ `images/` 下的 php **不会被解析**（回源码），只有站点根 / `docs/` 这类真·web 目录能执行。

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

## 🆕 2026 未认证 RCE 群（跨产品共同形态）

> **原语：`未认证可达的端点` + `能把内容写进可执行位置` = RCE。**
> 2026 这批 CMS/Web 漏洞**几乎全是这个形态**，只是"端点"和"可执行位置"换了个名字。
> 认出形态比记住 CVE 号重要 —— 遇到任何 CMS 都先问这两句。

```
# 判断信号（套任何 CMS）
[ ] 有没有【未认证】就能 POST 的端点？（上传 / 导入 / 预览 / 渲染 / 模板 / 邮件）
[ ] 它把内容写到哪里？—— 扩展名白名单？还是 web 根下的 media/images/tmp？内容原样执行还是转义？
[ ] 版本落在"补丁发布后数小时就被打"的窗口里？（2026 的武器化速度快于打补丁）
```

| 产品 | CVE | 要点 |
|------|-----|------|
| **SPIP** | CVE-2026-77806 | < 4.4.21 未认证 RCE。**`X-Spip-Filtre` 请求头**被 `analyse_resultat_skel` 错误处理 → 代码注入。2026-08 在野 |
| **Adobe ColdFusion** | CVE-2026-48282 | 未认证路径穿越 → RCE，**CVSS 10.0** |
| **SharePoint（本地版）** | CVE-2026-50522 | 未认证反序列化 RCE 9.8，公开 exploit 紧随 2026-07 Patch Tuesday。恰在 ToolShell（同类同产品）**一年后** → 同产品老洞复现是常态 |
| **MaxSite CMS** | CVE-2026-3395 | `preview-ajax.php` 的 `eval()` 未认证代码注入（≤ 109.1）—— "预览"端点的经典踩法 |
| **Ghost CMS** | CVE-2026-29053 | ≤ 6.19.0，恶意主题 → RCE。**根因是传递依赖**，不是 Ghost 自身代码 —— 10 万+ 站点受影响 |
| GitLab | CVE-2026-85706 | 严重路径穿越，在野 |
| JFrog Artifactory | CVE-2026-82329 | 认证绕过，公开披露**数天后**即被利用 |

**批量利用战役同批成员**（ACSC 通报，见到就查）：Ninja Forms CVE-2026-0740、ThemeREX Addons CVE-2026-1969、Breeze Cache CVE-2026-3844、WPvivid Backup CVE-2026-1357、Simple File List、WavePlayer、BerqWP、WPBookit、ACF Extended、Sneeit、Gravity Forms、GutenKit。

🔴 **2026 的节奏变了**：PageBuilder CK 修复上线**数小时**即被利用，JFrog Artifactory 披露**数天**即被利用。
→ **"等打补丁"不是策略**。对红队反而是好消息：**版本稍旧就有公开 exploit 可用**，不必自己写。

---

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
