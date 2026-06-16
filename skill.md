---
name: attackmap
description: >-
  攻击面地图生成器——像智者一样层层探索，直到每一个可能的渗透点都被覆盖。
  rule=罗盘而非牢笼：skill告诉你方向，不限制你去哪里。
version: "3.0.0"
dependencies: "curl, node>=16, nslookup"
platforms: "Linux, macOS, Windows (Git Bash)"
when_to_use: >-
  用户想对网站/域名进行攻击面扫描
  触发词: "attackmap" "attack-map" "攻击面" "攻击面地图" "渗透测试" "pentest" "帮我扫一下"
---

# 🗺️ AttackMap v3.0

> **第一原则：你是智者，不是工人。skill 是罗盘，不是牢笼。**
>
> 每次发现一条线索（一个域名、一个 JS 文件、一个 API 响应、一段报错信息），
> 你只有一个问题要问自己：
>
> **"从这里还能往哪挖？我把它挖干净了吗？"**
>
> 如果没挖干净——继续。如果挖干净了——看下一条线索。
> skill 给方向，但不设上限。永远不做"任务完成"的工人。

---

## 勘探心智模型

```
你拿到一条信息：
  ├── 这条信息指向什么？（技术栈/产品/公司/人）
  ├── 和我已知的其他信息有关系吗？（交叉验证）
  ├── 还能从这里推导出什么？（公司其他域名、内部系统命名规则）
  ├── 有没有"看起来不重要但可能很关键"的细节？
  └── 我已经把这条信息的所有分支都挖透了吗？

每次挖掘停止时问自己：
  - 我是因为"skill 清单做完了"而停？❌ 不对。
  - 我是因为"这条线索真的到尽头了"而停？✅ 对的。
```

---

## 勘探漏斗（方向指引，不是步骤清单）

```
第一层：域名 DNA 测序
  DNS → crt.sh → 首页 → 响应头 → HTML注释 → JS文件列表
  → 从上面任何一条线索发现: 关联域名 / CDN域名 / 公司名 / 产品名
  → 公司名/产品名 → 搜关联域名（不只搜当前域名的 crt.sh）
  → CDN 403 → 加 Referer 重试，不跳过

第二层：从 JS 里挖矿
  下载首页引用的每一个 JS → 不是随便 grep 一下就完事
  → 提取: 所有 URL、所有路径、所有子域名、所有第三方域名
  → 对每个 URL: 它指向什么服务？能不能访问？有没有 API？
  → JS 太大（>100KB）→ 用 node 解析，不是 grep
  → JS 混淆了 → 记录但不纠结，继续下一条线索

第三层：从页面内容里找线索
  每个页面（首页/登录/注册/忘记密码/关于我们/帮助）:
  → HTML 注释 (<!-- XXX -->) → 可能泄露 CMS/框架/内部信息
  → meta 标签 → 关键词/描述/作者
  → 表单字段名 → 参数名
  → "默认密码" / "初始密码" / "忘记密码" → 凭据策略
  → 第三方 SDK（百度统计/神策/友盟）→ 可能泄露额外域名

第四层：子域名字典不能只靠 crt.sh
  crt.sh 给的 ≠ 全部子域名
  → 基于公司名/业务线推测: gateway/log/monitor/bi/report/ops/adminer
  → 基于常见内部服务: jenkins/gitlab/grafana/kibana/elk/nacos
  → 基于业务: partner/agent/open/developer/merchant
  → 每个新发现的子域名 → 它的 JS/HTML 里可能引用更多子域名

第五层：跨公司关联
  如果首页/footer/招聘页面提到关联公司/集团:
  → 搜这家公司所有域名 → 递归挖掘
  → 关联公司的 crt.sh → 可能和当前域名共用基础设施
  → 从当前网站 JS 中提取的其他域名 → 关联

第六层：每个 API 响应都是一条线索
  {"code":1,"msg":"projectId 不能为空"} → 参数名泄露
  "Shuidi Gateway..." → 产品名确认
  CORS: * → 可以跨域调用
  404 格式 → 框架指纹
  任何错误消息 → 信息泄露

第七层：CMS/框架识别 → 搜已知漏洞（最后一层，因为信息够了）
  不是泛泛搜 "<CMS> 漏洞"
  → 搜: "<CMS> <具体版本号> CVE"
  → 搜: "<CMS> 未授权访问"
  → 搜: "<CMS> 默认密码"
  → 搜: "<CMS> 渗透 实战"
```

---

## 输出物：攻击面地图

地图不是任务清单的完成标记——它是**当前已知所有线索的汇总**。

```
🗺️ sdbao.com 攻击面地图
═══════════════════════════════

🏗️ 技术栈
  前端: Nuxt.js SSR + Element UI
  API网关: APISIX (Shuidi Gateway)
  云平台: 腾讯云 (北京, 8节点CLB)
  关联公司: shuidihuzhu.com, shuidi-inc.com, shuidi.cn

🌐 子域名 (当前已发现11个)
  www.sdbao.com          ✅ Nuxt SSR 主站
  api.sdbao.com          ✅ APISIX网关
  gateway.sdbao.com      ✅ APISIX网关
  log.sdbao.com          ✅ 日志网关
  static1.sdbao.com      🔒 CDN (Referer可绕过)
  store.sdbao.com        🔒 CDN
  ds.shuidihuzhu.com     🔓 内部实验API (CORS:*)
  api.shuidihuzhu.com    ✅ 互助API网关
  www.shuidi-inc.com     ✅ 母公司官网
  ... (继续枚举中)

📡 API 端点
  ⭐ ds.shuidihuzhu.com/api/hawkeye/experiment/query
    → CORS:* → 可跨域调用
    → 参数: projectId (必需)
    → 产品: Hawkeye (A/B实验平台)
  
  ⭐ api.sdbao.com/api/health → "OK"

🔑 认证: 未知 (登录页存在但无法提取加密逻辑)

⚠️ 攻击入口 (按价值):
  ⭐#1: APISIX CVE-2020-13945 默认token
  ⭐#2: ds.shuidihuzhu.com CORS:* + 参数注入
  ⭐#3: APISIX CVE-2025-46647 OIDC绕过
  #4: log/gateway 网关未授权
  #5: 供应链: npm恶意包 sdbao-content-*
```

---

## 停止条件

以下情况才算一条线索"挖完了"：
- 已经尝试了所有合理的方向，全部回"不存在"或"无响应"
- 需要用户提供凭据/账号才能继续

以下情况不算"挖完了"：
- "skill 的探测清单做完了" ❌
- "试了 5 种组合都返回 404" — 可能路径不在顶级域名 ❌
- "JS 太大了 grep 搜不到" — 用 node 解析 ❌
- "CDN 返回 403" — 加 Referer 重试 ❌

---

## 💀 三次实战的教训

| 教训 | 表现 | 正确做法 |
|------|------|---------|
| 不能因为 CDN 403 就跳过 JS 分析 | sdbao: 403 → 没下载 JS → 漏了 ds.shuidihuzhu.com | **CDN 403 ≠ 文件不可读，加 Referer** |
| 不能只靠 crt.sh 做子域名发现 | sdbao: crt.sh 只有 4 个域名 → 实际 11 个 | **业务推测 + 字典 + 关联公司枚举** |
| 不能只搜当前域名的 crt.sh | sdbao: 没搜 shuidihuzhu.com → 漏了整个互助域 | **公司名 → 搜所有关联域名** |
| 不能用 grep 处理 556KB 的 JS | sdbao: grep 从 556KB 里只搜出 1 个 URL | **大 JS 用 node 逐模式解析** |
| 识别到 CMS 后不能只搜中文关键词 | sdbao: "水滴保 渗透" → 无结果 | **产品名 + 英文 CVE 搜索** |
| 不能把 skill 当检查清单 | POETIZE: 在 login 参数上爆了 20 次 | **15 次无结果 → 不是参数名错了，是编码/传输方式错了** |
| 发现了一个公司名不能停 | sdbao: 看到"水滴"但没继续搜关联公司 | **公司名 = 整个集团的所有域名都是攻击面** |