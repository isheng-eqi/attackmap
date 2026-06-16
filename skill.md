---
name: attackmap
description: >-
  攻击面地图生成器。一轮扫出目标最多最广的可攻击面。
  并行执行、广度优先、快速收敛。5 分钟出完整攻击面图谱。
version: "2.4.0"
dependencies: "curl, node>=16, nslookup"
platforms: "Linux, macOS, Windows (Git Bash)"
when_to_use: >-
  用户想对网站/域名进行攻击面扫描
  触发词: "attackmap" "attack-map" "攻击面" "攻击面地图" "渗透测试" "pentest" "帮我扫一下"
---

# 🗺️ AttackMap v2.4

> **一个任务：用最少请求画出完整攻击面地图，标注最高价值入口。**
>
> **核心改进 (v2.4)：从"只懂 SPA/API 型网站"变成"能自动适应大学门户、政府网站、企业 CMS 等任何类型"。**

---

## 快速执行

```
Step 0: 通道探测 (2请求) — curl不通立刻切node
Step 1: 指纹+子域名 (并行5请求)
Step 2: CMS识别 → 立刻搜该CMS已知漏洞 (WebSearch, 不打目标)
Step 3: 攻击面扩展 (基于CMS类型动态选择探测路径)
Step 4: 输出地图
```

**总请求硬限制: 30。超过还没画完 → 现有结果直接输出。**

---

## Step 0: 通道探测

> v2.4 ⚡: curl 在高校/政府网站经常 TLS 握手失败。立刻切 node。

```
1. curl 正常请求。响应为空/超时/连接重置？
   → 立刻用 node https.get 重试。
   → node 也失败？IPv6 优先？→ curl -4 或 nslookup 查 IPv4 再试。

2. 通道通了，做2个请求判断是否有 WAF：
   - 正常请求
   - 带 SQL 字符串的请求
   两个都正常？→ 无 WAF。有差异？→ 记录 WAF 行为，后续慢速+XFF。
```

**通道不通知用户。自己解决。只有 node + curl -4 + HTTP 回退全失败时才告诉用户网络不通。**

---

## Step 1: 指纹收集（并行：HTTP + DNS + crt.sh）

```
并行执行以下（不打目标的不计数）：
  - 首页 HTML（前500行够用）
  - 响应头
  - DNS 全记录（A/MX/TXT/NS/SOA）
  - crt.sh SSL 透明度 → 子域名列表
  - 一个不存在的路径 → 看 404 格式
```

**指纹推断表（新增 CMS 识别）：**

| 观察 | 推断 |
|------|------|
| HTML注释含 `<!--Announced by Visual SiteBuilder` | 博达网站群 |
| HTML含 `__VIEWSTATE` | ASP.NET WebForms |
| 响应头 `X-AspNet-Version` | ASP.NET + IIS |
| 响应头 `X-Powered-By: PHP/7.x` | PHP |
| `Set-Cookie: JSESSIONID` | Java (Tomcat/JBoss) |
| `Server: nginx` + JSON 404 | Spring Boot / 前后端分离 |
| 首页 `<title>` 含"大学/学院/政府" | 教育/政府门户 → 搜该机构公开信息 |
| JS 文件名含 `chunk-` + hash | React/Vue SPA |
| JS 文件名含 `jquery.min.js` 且无其他框架 | 传统多页面 |
| 登录页 HTML 含"默认密码为"或"初始密码" | ⚡立刻记录—这是可直接利用的凭据 |

**crt.sh 子域名拿到后立即批量探测（不计入30请求限额，因为是扩展资产）：**

对 crt.sh 返回的每个子域名，并行 HEAD 请求（最多20个并发）。响应的计入地图，不响应的忽略。

---

## Step 2: CMS 识别 → 即刻搜已知漏洞

> v2.4 ⚡: 这是 Step 1 的自然延伸，不是独立步骤。

Step 1 识别到 CMS 名称后，**不要等到 Step 3 才处理**。立刻：

```
并行 WebSearch（2-3个不同关键词）:
  "<CMS名称> 漏洞 CVE"
  "<CMS名称> 渗透 越权 SQL注入"
  "<CMS名称> default password path"

搜索结果直接写入地图的"风险标注"部分。
```

**如果 CMS 是商业闭源软件（如博达、东软）：**
- 搜索时会发现历史漏洞文章（如 WooYun 存档）
- 从漏洞文章中提取具体攻击路径（如 `/system/site/site_list.jsp`）
- 这些路径直接作为 Step 3 的探测目标

---

## Step 3: 攻击面扩展（CMS 类型决定探测列表）

> v2.4 ⚡: 不再用一套万能字典。根据 Step 1 识别的技术栈，选择对应的探测列表。

**分支 A: Spring Boot / 前后端分离**
```
/.git/config, /.env, /actuator/health, /actuator/env
/swagger-ui.html, /v2/api-docs, /v3/api-docs, /doc.html
/api, /api/user/login, /api/admin
/robots.txt, /sitemap.xml
```

**分支 B: JSP / Java 传统应用（大学门户最常见）**
```
/system/                        ← 最常见的管理后台路径
/system/index.jsp
/system/login.jsp
/system/user/user_list.jsp      ← 博达 CMS 特征路径
/system/site/site_list.jsp
/system/content/content_list.jsp
/manager/html                   ← Tomcat 管理
/cas/login                      ← CAS 统一认证
/admin/, /console/
/.svn/entries, /WEB-INF/web.xml
```

**分支 C: ASP.NET / IIS**
```
/Admin/, /Manage/, /umbraco/, /umbraco/login
/WebResource.axd, /Telerik.Web.UI.WebResource.axd
/elmah.axd, /trace.axd
```

**分支 D: PHP / CMS**
```
/wp-admin, /wp-json, /wp-content/debug.log
/administrator, /user/login
/phpinfo.php, /info.php
```

**分支 E: 通用（所有类型都测）**
```
/robots.txt, /sitemap.xml, /.git/config, /.env, /backup.zip
```

**每个探测路径只发 HEAD 请求（不下载 body）。最多15个路径。超过15个 → 按价值排序，低价值的跳过。**

---

## Step 4: 端点分级

对 Step 2/3 发现的可访问端点做两次请求（GET + POST 空body）：

```
返回200 + 实际内容 → 🔓 公开
返回200 + "请登录" → 🔒 需认证  
返回302 重定向到 CAS → 🔒 需SSO认证
返回403 + "权限不足" → 🔐 管理员
返回404 → 不存在
返回401 → 🔒 需HTTP认证
```

---

## Step 5: 输出攻击面地图

用这个格式，**CMS 类型决定⭐标注内容**：

```
🗺️ 攻击面地图 — TARGET
═══════════════════════

🏗️ CMS/框架: [名称 + 版本]
  前端: [SPA/传统]  |  后端: [语言/框架]  |  服务器: [nginx/apache/iis/版本]
  WAF: [有/无 + 类型]  |  DNS: [自建/第三方]
  ⚡开源: [仓库链接] / 商业闭源 / 定制开发

🌐 子域名 (N个存活):
  sub1.target.edu.cn    → ✅ (服务名/框架)
  sub2.target.edu.cn    → ❌ 不可达
  ...

📡 发现端点:
  ⭐ = 最高价值入口

  🔓 公开:
    ⭐ /system/  ← 管理后台 (CMS=博达)
    ⭐ /cas/login ← CAS统一认证 (产品=东软tpass)
    ...

  🔒 需认证: ...

🗂️ 敏感路径: ...

🔑 认证机制:
  [用户名/密码方式]
  [加密算法 + 密钥是否公开]  ← 新增，POETIZE和tyut都有这问题
  [Token/Cookie/Session机制]
  ⚡ [默认密码策略] ← 如果登录页 HTML 直接写了规则

⚠️ 按攻击价值排序:
  ⭐#1: [认证入口] → [具体的攻击方式，不是泛泛的"认证绕过"]
  ⭐#2: [CMS漏洞] → [引用搜索结果中的具体CVE/路径]
  ⭐#3: [加密缺陷] → [密钥硬编码/弱算法/默认密码]
  #4: ...
```

---

## 📊 第二轮深度攻击的信号排序

| 优先级 | 打什么 | 为什么 |
|--------|--------|--------|
| ⭐1 | CMS 已知漏洞 | 有 CVE/公开分析文章，直接验证 |
| ⭐2 | 认证绕过/默认密码 | 高校/政府系统默认密码很常见 |
| ⭐3 | 加密缺陷利用 | 密钥在 JS 里 → 可伪造签名 |
| ⭐4 | 反序列化/SSTI | 框架决定（Spring/Fastjson/Jinja2） |
| ⭐5 | 敏感路径直接访问 | .jsp/.aspx 直接访问 |
| 6 | 未授权 API | 公开端点 |
| 7 | CSRF/IDOR | 有 token 后低成本 |
| 8 | 爆破/枚举 | ⚠️ 放最后 |

**区别**: 这个表跟 v2.3 不同——v2.3 把"反序列化 RCE"排第一，但那是对 SPA/API 型网站。对大学门户，"CMS 已知漏洞"排第一。

---

## ⛔ 地图阶段绝对不做的

| 不做的事 | 原因 |
|----------|------|
| curl 失败后反复用同方式重试 | 切 node / curl -4 / HTTP回退 |
| 同一 payload 在不同端点重复测 | 第一个点被防了后面也不会通 |
| 等待 WAF 冷却 | 切通道——XFF轮换、慢速 |
| 对着确认安全的框架做注入 | JSP 多页面 ≠ 有 SQL 注入；先搜 CMS 漏洞再打 |

---

## 🤝 什么时候请求用户

| 时机 | 请求 |
|------|------|
| 通道全失败（curl + node + HTTP 都不通） | "你的网络环境访问这个目标有问题，你能用浏览器打开吗？" |
| 发现登录页有验证码且没有已知绕过 | "登录页有验证码。你有测试账号吗？能帮我 F12 抓一个登录请求吗？" |
| 地图输出后 | "这是攻击面地图。⭐标注的是最高价值入口，从哪个开始？" |
| 需要写操作验证 | "这一步会修改数据，我操作后会还原。是否继续？" |

---

## 💀 实战踩坑（POETIZE + tyut 两次教训）

| 实际做的 | 应该做的 | 浪费了什么 |
|----------|---------|-----------|
| curl HTTPS 对 tyut 失败→没切 node | 一次失败立刻切 node https.get | 卡了半分钟排查 |
| 识别到"Visual SiteBuilder 9"后继续扫路径 | **立刻 WebSearch 搜该 CMS 已知漏洞** | CMS 漏洞信息拿晚了 |
| crt.sh 子域名逐个 curl | 批量并行 HEAD 请求 | 多花了 2 分钟 |
| 风险排序用"反序列化 #1"模板 | **看 CMS 类型决定排序**——大学门户先打 CMS 漏洞和默认密码 | 排序偏差 |
| 登录页 HTML 里写了"tyut+身份证后6位" | 立刻作为高价值信息输出到地图 | 如果没仔细看 HTML 就漏了 |
| 对博达后台用 SPA 型字典 (/api,/actuator) | 用 JSP/CMS 专用字典 (/system/*.jsp) | 10+ 个 404 |
| 先 curl 首页、下载 JS、逆向（POETIZE） | 第一步搜 GitHub → 5 秒找到源码 | 1小时 + 20+ 无效请求 |
| SVG 验证码搞 OCR（POETIZE） | 直接跳过 | 30+ 分钟 |