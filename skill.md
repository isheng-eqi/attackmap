---
name: attackmap
description: >-
  攻击面地图生成器。一轮扫出目标最多最广的可攻击面。
  并行执行、广度优先、快速收敛。5 分钟出完整攻击面图谱。
version: "2.2.0"
dependencies: "curl, node>=16, nslookup"
platforms: "Linux, macOS, Windows (Git Bash)"
when_to_use: >-
  用户想对网站/域名进行攻击面扫描
  触发词: "attackmap" "attack-map" "攻击面" "攻击面地图" "渗透测试" "pentest" "帮我扫一下"
---

# 🗺️ AttackMap v2.2 — 攻击面地图生成器

> **核心理念：一轮扫出最多最广的攻击面。广度优先，快速收敛，不纠缠细节。**
>
> 目标 = 5 分钟内给你一张"这个网站所有可攻击入口的地图"。
> 深度漏洞验证是第二轮的事。第一轮只做一件事——**穷举攻击面**。

---

## 输出物：攻击面地图

```
                    ┌─────────────────────────────┐
                    │      🌐 互联网入口            │
                    │  example.com / IP / CDN / WAF │
                    └─────────────┬───────────────┘
                                  │
        ┌─────────────┬───────────┼───────────┬─────────────┐
        ▼             ▼           ▼           ▼             ▼
   🏷️ 子域名      🔌 开放端口   📡 API端点   🗂️ 目录/文件   🔧 技术栈
  (证书+爆破)   (top1000扫描)  (JS提取+字典) (敏感路径)  (Server/CMS/WAF)
        │             │           │           │             │
        ▼             ▼           ▼           ▼             ▼
  🔓 无认证端点   🛡️ WAF规则   🔑 认证机制   📦 第三方集成  💾 源码/GitHub
```

---

## 🚀 执行流程

### Phase 1: 并行快扫 (2 min)

> 以下全部在同一轮并行执行。不等待任何一个返回结果再做下一个。

**第一批（零依赖，全并行）：**

```bash
# 1. HTTP 响应头
curl -sI "https://TARGET/" -o /tmp/headers

# 2. 首页 HTML
curl -s "https://TARGET/" -o /tmp/index.html

# 3. DNS 全记录
nslookup -type=A TARGET
nslookup -type=MX TARGET  
nslookup -type=TXT TARGET
nslookup -type=NS TARGET
nslookup -type=CNAME TARGET
nslookup -type=CNAME www.TARGET

# 4. SSL 证书透明度
curl -s "https://crt.sh/?q=%.TARGET&output=json"

# 5. IP 地理位置
curl -s "http://ip-api.com/json/TARGET_IP?lang=zh-CN"

# 6. 快速端口扫描 (top 30)
for port in 21 22 25 53 80 88 110 143 443 465 587 993 995 1433 1521 2082 2083 2086 2087 3306 3389 5432 6379 8080 8443 8888 9000 9090 9200 27017; do
  timeout 1 bash -c "echo > /dev/tcp/TARGET_IP/$port" 2>/dev/null && echo "PORT $port OPEN" &
done; wait

# 7. GitHub 源码搜索（如果之前没搜过）
# 搜索词: "<网站标题>" "<特征字符串>" site:github.com
```

**输出 Phase 1：**
```
🖥️ 技术栈指纹:
  Server: nginx/1.25.3
  后端: Spring Boot (JSON错误格式) / Express / Django
  前端: Vue.js/React (JS文件名特征) / jQuery / 原生
  WAF: 1Panel / Cloudflare / 阿里云WAF / 无
  CDN: 七牛云 / CloudFront / 无
  SSL: Let's Encrypt / DigiCert / 自签名

🌐 网络:
  IP: x.x.x.x (腾讯云 上海)
  开放端口: 80,443,8080,8888
  CDN/WAF: 主站无CDN, 静态资源走七牛云

📋 子域名 (从证书透明度):
  www.example.com
  api.example.com
  admin.example.com
  ...

🔑 关键响应头:
  Set-Cookie: Authorization=xxx; Path=/
  HSTS: max-age=31536000
  CORS: Access-Control-Allow-Origin: https://example.com
```

### Phase 2: 攻击面扩展 (3 min)

> 基于 Phase 1 结果，并行执行以下：

**2.1 前端路由提取（从 HTML + JS）：**

```bash
# 从首页提取所有 JS 文件
grep -oP 'src="([^"]*\.js[^"]*)"' /tmp/index.html | sort -u

# 下载主要 JS 文件，提取路由字符串
for js in app.js chunk-vendors.js; do
  curl -s "https://TARGET/js/$js" | grep -oE "'/[a-zA-Z0-9_/-]{3,40}'" | sort -u
done

# 同时提取 API 路径
curl -s "https://TARGET/js/app.xxx.js" | grep -oE '"[a-z]+/[a-zA-Z]+"' | sort -u
```

**2.2 敏感路径快速探测（Top 30，并行）：**

```bash
PATHS=(
  "/robots.txt" "/sitemap.xml" "/.git/config" "/.env"
  "/actuator" "/actuator/health" "/actuator/env"
  "/swagger-ui.html" "/swagger-resources" "/v2/api-docs" "/v3/api-docs" "/doc.html"
  "/api" "/api/" "/api/v1" "/api/v2"
  "/admin" "/admin/login" "/login" "/register"
  "/.well-known/security.txt"
  "/backup.zip" "/backup.tar.gz" "/dump.sql"
  "/phpinfo.php" "/info.php" "/test.php"
  "/console" "/druid" "/nacos"
  "/.DS_Store" "/crossdomain.xml"
)
for p in "${PATHS[@]}"; do
  code=$(curl -sI -o /dev/null -w "%{http_code}" "https://TARGET$p" --max-time 3)
  size=$(curl -sI "https://TARGET$p" --max-time 3 | grep -i content-length | awk '{print $2}' | tr -d '\r')
  echo "$p → $code ($size bytes)"
done
```

**2.3 如果有源码（白盒摸式）：**

```bash
# 直接遍历 GitHub API 获取所有 Controller 文件
curl -s "https://api.github.com/repos/USER/REPO/contents/src/main/java/com/xx/controller"

# 批量提取所有端点
for ctrl in UserController AdminController ArticleController CommentController; do
  curl -s "https://raw.githubusercontent.com/USER/REPO/master/src/main/java/com/xx/controller/$ctrl.java" \
    | grep -E '@(GetMapping|PostMapping|RequestMapping)'
done
```

**2.4 API 端点批量验证：**

```bash
# 从源码或 JS 提取到的端点列表，批量验证
# 用 curl 并发，每个端点一个请求，判断认证要求

ENDPOINTS=(
  "/api/user/login" "/api/user/logout" "/api/user/regist" "/api/user/getCode"
  "/api/article/listArticle" "/api/article/getArticleById"
  "/api/comment/listComment" "/api/comment/saveComment"
  "/api/admin/user/list" "/api/admin/login"
  "/api/webInfo/getWebInfo" "/api/webInfo/updateWebInfo"
  "/api/resource/upload" "/api/resource/saveResource"
  "/api/qiniu/getUpToken" "/api/weiYan/saveWeiYan"
)

for ep in "${ENDPOINTS[@]}"; do
  echo "=== $ep ==="
  # GET 测试
  get_resp=$(curl -s --max-time 3 "https://TARGET$ep" | head -c 100)
  get_code=$(echo "$get_resp" | grep -o '"code":[0-9]*' | grep -o '[0-9]*')
  get_msg=$(echo "$get_resp" | grep -o '"message":"[^"]*"')
  # POST 测试 (空 body)
  post_resp=$(curl -s -X POST --max-time 3 "https://TARGET$ep" -H "Content-Type: application/json" -d '{}' | head -c 100)
  post_code=$(echo "$post_resp" | grep -o '"code":[0-9]*' | grep -o '[0-9]*')
  echo "  GET  → code=$get_code $get_msg"
  echo "  POST → code=$post_code"
done
```

### Phase 3: 输出完整攻击面地图

**这是最终交付物。用这个格式输出给用户：**

```
🗺️ 攻击面地图 — poetize.cn
═══════════════════════════════════

🏗️ 架构
  前端: Vue.js SPA (webpack, Element UI)
  后端: Spring Boot (Java)  → 版本未知
  反向代理: OpenResty (nginx 1.22.1)
  WAF: 1Panel (频率限制 ~50req/s + 内容规则)
  CDN: 七牛云 (静态资源 file.poetize.cn)
  数据库: MySQL (MyBatis-Plus ORM)
  云平台: 腾讯云 (上海, 111.231.74.239)
  DNS: 阿里云万网

🌐 子域名
  poetize.cn          ← 主站
  www.poetize.cn      ← 无响应
  file.poetize.cn     ← 七牛云CDN (防盗链)

🔌 开放端口
  80   (HTTP → 301跳转HTTPS)
  443  (HTTPS → OpenResty → Spring Boot)
  其他端口均关闭

📡 API 端点 (共 N 个)
  🔓 无需认证:
    POST /api/user/login       ← 登录入口
    POST /api/user/regist      ← 注册入口
    GET  /api/user/captcha     ← 图形验证码
    POST /api/article/listArticle  ← 文章列表
    GET  /api/article/getArticleById ← 文章详情
    GET  /api/article/listSortArticle ← 分类文章
    POST /api/comment/listComment ← 评论列表
    GET  /api/webInfo/getWebInfo ← 站点配置
    GET  /api/user/getCodeForForgetPassword ← 忘记密码
  
  🔒 需认证:
    GET  /api/user/logout       ← 登出
    POST /api/user/updateUserInfo ← 更新信息
    POST /api/comment/saveComment ← 发表评论
    GET  /api/user/subscribe    ← 订阅标签
    GET  /api/user/getCode      ← 获取验证码
    POST /api/user/updateSecretInfo ← 修改密码
  
  🔐 管理员:
    POST /api/admin/user/list        ← 用户列表
    GET  /api/admin/changeUserStatus ← 封禁用户
    POST /api/webInfo/updateWebInfo  ← 网站配置

🗂️ 敏感文件/路径
  ✅ /sitemap.xml           → 107篇文章URL
  ❌ /robots.txt            → 不存在
  ✅ /actuator/*            → SPA fallback (已防护)
  ✅ /swagger-ui.html       → SPA fallback (已防护)
  ✅ /.git/                 → 403 (已防护)
  ❌ 无 .env / backup.zip   → 未暴露

🔑 认证机制
  方式: 用户名/邮箱/手机号 + 密码 + AES加密
  Token: UUID格式, 存于 Authorization 头
  角色: user / admin
  加密: AES-128-ECB, 密钥硬编码在JS中

💾 开源代码
  ✅ GitHub: itsharex/poetize (开源版, MIT协议)
  ⚠️ 生产运行PRO付费版, 与开源版有差异

📦 第三方集成
  七牛云 (文件存储)
  腾讯企业邮箱 (mxbiz1.qq.com)
  阿里云/华为云/腾讯云短信 (可选)
  QQ/微信/Gitee/微博登录 (可选)
  支付宝/微信支付 (PRO版)

⚠️ 初步风险标注
  🔴 高风险入口: login接口(认证绕过)、反序列化测试点
  🟡 中风险入口: 忘记密码接口(枚举)、订阅接口(CSRF)
  🟢 低风险: sitemap暴露、Server头泄露
```

---

## 📊 信号/成本排序（第二轮深度测试时参考）

| 优先级 | 测试类别 | 基于什么 |
|--------|---------|---------|
| 1 | 源码搜 GitHub | 成本零、信号极高 |
| 2 | F12 Network 实际请求 | 成本零、直接看真实格式 |
| 3 | 框架反序列化 RCE | Spring/Fastjson/Jackson → 高回报 |
| 4 | 未授权 API 深度利用 | 第一轮发现的公开端点 |
| 5 | 认证绕过/IDOR | 有 token 后低成本验证 |
| 6 | SSTI/SSRF/注入 | 框架特征决定优先级 |
| 7 | CSRF/XSS | 顺手测 |
| 8 | 用户枚举/爆破 | ⚠️ 低信号，最后做 |

---

## 🛠️ 速查命令

```bash
# 并行快速端口扫描
for port in 21 22 25 53 80 88 110 143 443 465 587 993 995 1433 1521 2082 2083 2086 2087 3306 3389 5432 6379 8080 8443 8888 9000 9090 9200 27017; do
  timeout 1 bash -c "echo > /dev/tcp/TARGET_IP/$port" 2>/dev/null && echo "⚠️ PORT $port OPEN" &
done; wait

# 敏感路径批量扫描 (并行)
for p in "/.git/config" "/.env" "/actuator/health" "/swagger-ui.html" "/admin" "/api" "/robots.txt" "/sitemap.xml"; do
  echo "$p $(curl -sI -o /dev/null -w '%{http_code}' https://TARGET$p --max-time 3) $(curl -sI https://TARGET$p --max-time 3 | grep content-length | awk '{print $2}')" &
done; wait

# 从 JS 提取路由
curl -s "https://TARGET/js/app.xxx.js" | grep -oE "'/[a-zA-Z0-9_/-]{3,60}'" | sort -u | head -30

# 源码搜索
# GitHub: "网站标题" + github
# Gitee:  "网站中文名" + 源码

# API 端点快速分级
for ep in "/api/user/login" "/api/user/regist" "/api/article/listArticle" "/api/admin/user/list" "/api/webInfo/getWebInfo"; do
  resp=$(curl -s --max-time 3 "https://TARGET$ep")
  code=$(echo "$resp" | grep -o '"code":[0-9]*' | grep -o '[0-9]*')
  if [ "$code" = "200" ]; then echo "🔓 $ep"; elif [ "$code" = "300" ]; then echo "🔒 $ep"; else echo "❓ $ep → $code"; fi
done
```

---

## 💀 POETIZE 实战踩坑（为什么会有 v2.2）

| 坑 | 问题 | 教训 |
|----|------|------|
| 搜源码太晚 | 逆向了 1 小时 JS，GitHub 5 秒就能找到 | **Phase 1 第一件事就是搜 GitHub** |
| 在低信号测试上死磕 | SVG 验证码 OCR 搞了很久，毫无产出 | **深度验证是第二轮的事，第一轮只管画地图** |
| WAF 触发后干等 | 等 60s → 再试 → 又封 → 重复 | **第一轮用最少请求画出攻击面，避免触发 WAF** |
| 参数名爆破 20+ 种 | 全部 400，浪费 WAF 额度 | **超过 5 次找不到 → 请求用户 F12** |

---

## 🤝 什么时候请求用户

| 时机 | 请求什么 |
|------|---------|
| 开始 | "F12 Network 看下首页加载了什么？" |
| 源码找不到 | "你知道这个网站用的是什么框架/CMS 吗？" |
| 需要登录 | "能注册一个测试账号吗？登录后把 login 请求的 Payload 发我" |
