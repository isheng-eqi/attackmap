---
name: attackmap
description: >-
  攻击面地图生成器。一轮扫出目标最多最广的可攻击面。
  并行执行、广度优先、快速收敛。5 分钟出完整攻击面图谱。
version: "2.3.0"
dependencies: "curl, node>=16, nslookup"
platforms: "Linux, macOS, Windows (Git Bash)"
when_to_use: >-
  用户想对网站/域名进行攻击面扫描
  触发词: "attackmap" "attack-map" "攻击面" "攻击面地图" "渗透测试" "pentest" "帮我扫一下"
---

# 🗺️ AttackMap v2.3

> **你只有一个任务：用最少的请求画出最完整的攻击面地图，然后告诉用户"从哪开始打"。**

---

## 执行决策树（按这个顺序，不是按脚本）

```
Step 0: WAF 测绘 (3个请求)
  └─ 用 WAF 结果决定后续所有请求的节奏

Step 1: 指纹收集 (并行, 5个请求)
  └─ 响应头 + 首页HTML + DNS + 首页JS文件列表

Step 2: 源码搜索 (0-1个请求)
  └─ 在线搜索，不是本地 grep

Step 3: 攻击面扩展 (基于 Step 1/2 结果动态决定)
  ├─ 有源码 → 直接读 Controller (0请求)
  ├─ 无源码但前端 JS 可读 → 从 JS 提取路由 (1-2个请求)
  ├─ 有无认证入口 → 拿 token 测权限 (等用户配合)
  └─ 以上都没用 → 轻量字典探测 (最多15个路径)

Step 4: 端点分级 (请求已有端点, 不枚举新路径)
  └─ 区分 "公开/需认证/管理员" 三类

Step 5: 输出地图 + 标注最高价值入口
```

**核心约束**：整个流程总请求数控制在 30 以内。超过 30 还没画完 → 说明目标攻击面确实很小 → 直接输出现有结果。

---

## Step 0: WAF 测绘（必须先做）

> 不用前面的 bash 端口扫描。用最少的请求判断是否存在 WAF 以及它的行为。

```bash
# 测试1: 正常请求 → 获取基准
curl -sI "https://TARGET/" --max-time 5

# 测试2: 带明显的SQL注入字符串
curl -sI "https://TARGET/?test=1' OR '1'='1" --max-time 5

# 测试3: 快速连发5个请求看是否触发限频
for i in 1 2 3 4 5; do
  curl -sI -o /dev/null -w "%{http_code} " "https://TARGET/" --max-time 3
done
```

**判断逻辑：**
```
测试2返回403且有WAF品牌页面 → 内容型WAF
测试3出现429/503/连接重置 → 频率型WAF
测试3最后一个请求非200 → 频率型WAF, 阈值≤5
都没有异常 → 无WAF或阈值很高
```

**如果有 WAF → 立即调整节奏：**
- 后续所有请求加 X-Forwarded-For 头轮换
- 后续每个请求间隔至少 2 秒
- 不要并行发批量请求

## Step 1: 指纹收集（并行5个请求）

> 这5个请求不触发 WAF（间隔足够大）

```bash
# 并行，每个间隔2s
# 1. 响应头
curl -sI "https://TARGET/" -H "X-Forwarded-For: 10.1.1.1"

# 2. 首页 HTML  
curl -s "https://TARGET/" -H "X-Forwarded-For: 10.1.1.2" | head -200

# 3. DNS 全记录 (本地, 不打目标)
nslookup TARGET && nslookup -type=MX TARGET && nslookup -type=TXT TARGET

# 4. 首页 JS 文件清单
# 从 HTML 提取 → grep for src="*.js"

# 5. 随便一个不存在路径 → 看404格式
curl -sI "https://TARGET/nonexistent999" -H "X-Forwarded-For: 10.1.1.3"
```

**从这5个请求推断：**

| 观察 | 推断 |
|------|------|
| `Server: nginx` + JSON错误格式 | Spring Boot / Express 后端 |
| JS文件名含 `vendor.element-ui` | Vue.js + Element UI |
| JS文件名含 `chunk-` + hash | React / Vue 打包 |
| 404返回HTML | SPA |
| 404返回 `{"error":"Not Found"}` | API 服务器 |
| `Set-Cookie: Authorization=` | Token 认证 |
| 首页 `<title>` 含品牌名 | 去 GitHub 搜这个 |

## Step 2: 源码搜索

基于首页 `<title>` 或 `<meta>` 中提取的网站名称：

```
在线搜索: "<网站名> github" 或 "<网站名> 源码 gitee"
搜索结果指向开源仓库 → 直接从 GitHub 读 Controller
没有结果 → 跳过, 不纠结
```

**找到源码后的动作（最节省请求的方式）：**
```bash
# 直接用 GitHub API 遍历包结构, 不是下载文件
curl -s "https://api.github.com/repos/USER/REPO/contents/src/.../controller"
# 然后逐文件读取 @RequestMapping 注解
```

## Step 3: 攻击面扩展（动态决定，不是固定列表）

**分支 A：有源码 → 直接白盒**
- 读出所有 Controller → 完整的端点清单
- 同时读 VO/DTO → 参数名一览
- 读 Config → 拦截器/过滤器/cors/加密配置
- **0 个额外请求到目标**

**分支 B：无源码但前端可读 → 从 JS 提取**
- 下载 `app.js` 和 `chunk-vendors.js`
- 提取路由字符串：`grep -oE "'/[a-zA-Z0-9_/-]{3,60}'"`
- JS 混淆不可读 → 跳到分支 C

**分支 C：黑盒 → 轻量字典**
- 只测这 15 个路径（不是 30+ 个）：
```
/.git/config, /.env, /robots.txt, /sitemap.xml
/actuator/health, /swagger-ui.html, /api, /api/v1
/admin, /login, /console, /druid/index.html
/wp-admin, /wp-json, /administrator
```
- 任何一个返回非200/非SPA → 记录并继续

## Step 4: 端点分级

> 不是枚举新端点——而是**对已知端点做快速分级**。

对 Step 2/3 发现的每个端点做两次请求（GET + POST 空body）:

```
返回200 + data → 🔓 公开
返回300/303 + "请登录" → 🔒 需认证  
返回303/403 + "权限不足" → 🔐 管理员
返回404 → 不存在
返回500 → ❓ 格式不对，记录
```

## Step 5: 输出攻击面地图

用这个格式。星号标注的是**最高价值入口——从这里开始打**。

```
🗺️ 攻击面地图 — TARGET
═══════════════════════

🏗️ 技术栈
  前端: [框架]  |  后端: [语言/框架]  |  服务器: [nginx/apache/iis]
  WAF: [产品名/无]  |  CDN: [有/无]  |  DNS: [注册商]
  开源代码: ✅ [仓库链接] / ❌ 未找到

🔌 入口
  开放端口: [列表]
  子域名: [证书透明度结果]

📡 API端点在 或 🗂️ 敏感路径
  ⭐ = 建议优先攻击

  🔓 无需认证:
    ⭐ POST /api/xxx/login      ← 认证入口，格式=form/json, 加密=AES/无
    ⭐ POST /api/xxx/any         ← 接受JSON的入口，测试反序列化
    GET  /api/xxx/public         ← 公开数据API
    ...

  🔒 需认证:
    POST /api/xxx/updateInfo     ← IDOR测试点
    GET  /api/xxx/logout         ← CSRF测试点
    ...

  🔐 管理员:
    POST /api/admin/xxx          ← 提权目标
    ...

🗂️ 敏感路径
  ✅ /sitemap.xml      → [N]条记录
  ✅ /actuator/health  → 真实内容 / SPA fallback
  ❌ /.git/            → [403/200/不存在]

🔑 认证机制
  方式: [用户名/邮箱/手机] + 密码 + [加密方式]
  Token: [JWT/UUID/自定义], 存于 [Header名/Header格式/Cookie名]
  Session: [有/无]

⚠️ 风险标注（按攻击价值排序）
  ⭐#1: [login接口] → 认证绕过/弱密码/SQL注入可能性
  ⭐#2: [JSON入口] → Fastjson/Jackson反序列化测试
  ⭐#3: [管理端点] → 提权/越权目标
  #4: [公开API] → 数据泄露风险
  #5: [其他] → ...
```

---

## 📊 从地图到深层攻击的信号排序

地图画完之后，按顺序打：

| 优先级 | 打什么 | 为什么 | 需要什么 |
|--------|--------|--------|---------|
| ⭐1 | 反序列化 RCE | 一次成功=直接拿shell | JSON入口 + 确认解析器 |
| ⭐2 | SSTI | 框架决定 | Thymeleaf/Freemarker/Jinja2 |
| ⭐3 | 未授权API数据获取 | 零成本高收益 | 地图中标记的公开端点 |
| ⭐4 | 认证绕过/弱凭据 | 有默认密码线索 | 源码/文档中的初始账号 |
| 5 | IDOR | 低成本 | 用户token |
| 6 | CSRF | 顺手 | 写操作端点 |
| 7 | 用户枚举 | 低信号 | 忘记密码/注册接口 |
| 8 | 爆破 | ⚠️ 放最后 | 不确定时不做 |

---

## ⛔ 地图阶段绝对不做的

| 不做的事 | 原因 |
|----------|------|
| 用 `/logout` 验 token | 消耗 token。用只读端点验 |
| 参数名爆破 > 5 次 | 大概率猜不出来。找用户要 F12 |
| 同 payload 重复测不同端点 | 第一个端点被防了后面也一样 |
| 对图形验证码做 OCR | 成功概率低，绕不过校验逻辑 |
| 等 WAF 冷却后重新打 | 换通道——XFF轮换、慢速、80端口 |

---

## 🤝 何时请求用户

| 时机 | 请求 |
|------|------|
| Step 0 WAF 确认后 | "你的站有 WAF，我会用慢速+XFF轮换扫，可能有点慢" |
| Step 1 JS 全是混淆的 | "JS 混淆了，无法提取路由。你有这个站用什么框架开发的线索吗？" |
| Step 3 发现登录入口 | "能注册一个测试账号吗？登录后 F12 → Network → 把 login 请求的 Payload 给我" |
| Step 4 发现管理员端点 | "我看到有管理端点。你有管理员账号吗？"（不强制） |
| 地图输出后 | "这是攻击面地图。⭐标注的是最高价值入口，你想从哪个开始？" |

---

## 💀 POETIZE 实战复盘（教训就在反面）

| 实际做的 | 应该做的 | 浪费了什么 |
|----------|---------|-----------|
| 先 curl 首页、下载 JS、逆向 | 第一步搜 GitHub → 5 秒找到源码 | 1小时 + 20+ 无效请求 |
| 拿到 token 后用 `/logout` 验证 | 用 `getUserByUsername` 等只读端点验 | 3 次重新登录 |
| SVG 验证码搞 OCR | 直接跳过，这成功概率极低 | 30+ 分钟 |
| login 参数名爆了 20+ 种 | 5 次没找到就找用户要 F12 | WAF 额度 + 等待 |
| WAF 封了干等 60s-120s | 立马切 XFF 轮换 / 慢速 | 数次 60s+ 等待 |
| 对着确认没 SQL 注入的端点继续测 | 确认 MyBatis-Plus 参数化后跳过 | 15+ 请求 |
