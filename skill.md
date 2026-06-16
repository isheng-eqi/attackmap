---
name: attackmap
description: >-
  攻击面罗盘——给一个资产，自动层层展开全部可攻击面。
  探测层从 DNA→页面→JS→API→子域→关联公司→CMS漏洞，每层都内建了四轮实战积累的触发规则。
version: "3.1.0"
dependencies: "curl, node>=16, nslookup"
platforms: "Linux, macOS, Windows (Git Bash)"
when_to_use: >-
  用户想对网站/域名进行攻击面扫描
  触发词: "attackmap" "attack-map" "攻击面" "攻击面地图" "渗透测试" "pentest" "帮我扫一下"
---

# 🗺️ AttackMap v3.1

> **给一个资产。罗盘自动转。**
>
> 每一层探测都内建了触发规则——来自 POETIZE、tyut、sdbao、ksyun 四轮实战。
> 不再需要"记住教训"。教训已经是罗盘的一部分了。

---

## 探测层（按顺序，每层自驱动）

### 第 0 层：通道建立

```
curl 不通 → node https.get({rejectUnauthorized:false})
node 不通 → HTTP 回退(80端口)
HTTP 不通 → curl -4 强制IPv4
全不通 → 报告用户

WAF 判定(2请求):
  正常请求 vs 带SQL字符串请求 → 有差异=内容WAF
  连发5次 → 最后非200=频率WAF
  有WAF → 后续全走XFF轮换+X-Forwarded-For:随机IP
```

### 第 1 层：域名 DNA

```
并行获取:
  DNS A/MX/TXT/NS/SOA
  crt.sh → 全量子域名证书
  IP → 云厂商/ISP/AS归属

从DNS直接推导:
  NS=自建(kscdns.com) → 自有基础设施,可能有内部DNS区域
  NS=万网/DNSPod → 第三方托管,子域名管理可能有限
  MX=网易/腾讯企业邮 → 邮箱独立系统
  MX=自建 → 邮箱在自有服务器,Exchange/Zimbra?
  SPF="-all" → 不对外发邮件
  SOA responsible=人名 → 管理员线索

从 crt.sh 发现关联域名:
  通配符 *.xxx.com 的数量 → 基础设施规模
  跨公司域名(xingyuanlingxi.com.cn出现在ksyun证书中) → 集团关联
  grafana/prometheus/jenkins/wiki→ 运维工具暴露
```

### 第 2 层：页面指纹

```
首页($TARGET) → 并行:
  响应头 → Server/X-Powered-By/Set-Cookie/CORS
  首页HTML(至少2000字节) → title/meta/js/css列表
  一个不存在路径 → 看404格式

从标签直接判断:
  <title> 含"大学/学院" → .edu域名, 搜博达CAS
  <title> 含"政府" → .gov域名
  <title> 含"云/Cloud/控制台" → 云厂商
  <meta name="author"> → 开发商线索
  <meta name="keywords"> → 业务关键词(用于后续搜索)

从JS文件直接判断:
  vendor.element-ui → Vue2 + Element UI
  chunk-xxx.hash.js → React/Vue webpack
  nuxt → Nuxt.js SSR
  vite → Vite打包 → Vue3/React现代项目
  jquery.min.js + 无其他框架 → 传统多页面
  无JS文件 → 纯静态/SSR直出

从404格式判断:
  HTML "<title>404" → 传统Web服务器
  '{"error":"Not Found"}' → API服务器/Spring Boot
  SPA index.html → 前端路由

从Set-Cookie判断:
  Authorization=xxx → Token鉴权
  JSESSIONID → Java/Tomcat
  PHPSESSID → PHP
  .AspNetCore. → ASP.NET Core
```

### 第 3 层：前端 JS 深挖

```
操作:
  从首页提取所有 <script src="..."> 和 <link href="...">
  对每个JS/CSS: CDN返回403 → 加 Referer:$TARGET 重试
  下载所有成功获取的JS

对每个下载到的JS:
  JS > 100KB → node解析(不是grep)
  JS < 100KB → grep够用

提取目标:
  ① URL模式: https?://[a-z0-9.-]+\.[a-z]{2,}  → 所有引用的域名
  ② 路径模式: "/api/[a-z]+" → API端点
  ③ 子域模式: \b([a-z]+)\.(?:当前域名)\b → 业务子域名
  ④ 特定框架模式:
     "cryptojs_key" → 加密密钥(密文在附近数组)
     "encrypt"/"decrypt" + 硬编码字符串 → 加密实现
     "strEnc" + 三个参数 → 东软DES
     "Authorization" → token传递方式
  ⑤ 路由模式: "'/[a-zA-Z0-9_/-]{3,60}'" → 前端路由
  ⑥ 内网API: "internal"/"inner"/"intranet"开头的域名

对每个提取出的新域名 → 回到第1层递归。
```

### 第 4 层：子域名字典展开

```
crt.sh给了N个 → 但这不是全部。继续:
  ① 从JS提取的子域名
  ② 从页面HTML提取的子域名
  ③ 业务推测(基于首页内容):
     云厂商 → {product}.console, {product}.api, {region}.api, ks3.{region}
     大学 → cas, sso, vpn, jw, lib, mail, card, ids
     保险 → gateway, log, report, partner, agent, merchant
  ④ 运维推测(所有行业):
     grafana, prometheus, kibana, rancher, jenkins, gitlab, wiki, jira
     bastion, svpn, oa, mail, monitor, bi, elk, nacos, apisix
  ⑤ 环境推测:
     test, dev, pre, stage, qa, uat, demo, sandbox

对每个新发现的子域名 → HEAD探测(并行批量)
  响应 → 记录到地图
  无响应 → 可能内网可达
```

### 第 5 层：API/端点分类

```
对通网探测找到的所有端点 → 每个端点发 GET + POST空body:
  200 + 实际数据 → "公开"
  200 + "请登录"/"未登录" → "需认证"
  302 → CAS/sso → "需SSO"
  403 + "权限不足" → "需更高权限"  
  400 XML + "MissingAccesskey" → "需AK/SK"(云API)
  404 → 不存在
  405 → 方法不允许
  500 → 记录为异常

对云API(返回XML <ErrorResponse>):
  → 识别服务类型(S3兼容/AWS兼容)
  → 搜索 "<服务名> SDK" 确认认证方式
  → 搜索GitHub "AccessKey ksyun" 找泄露
```

### 第 6 层：认证面分析

```
如果发现登录页:
  下载登录页JS → 搜加密实现
    "encrypt"/"decrypt"/"strEnc"/"RSAKey"/"JSEncrypt"/"bcrypt"
    "cryptojs_key"→ 密钥在附近数组
    无加密函数 → HTTPS直传密码
  表单字段 → username/account/phone/email/密码字段名
  HTML中"默认密码"/"初始密码" → 凭据策略泄露
  Cookie/Session机制 → token格式

如果发现云API(AccessKey认证):
  搜GitHub: "<公司名> AccessKey"
  搜GitHub: "<公司名> SecretKey"  
  搜Gitee: "<公司名> AK SK"
```

### 第 7 层：CMS/框架已知漏洞

```
对每一层识别到的CMS/产品:
  并行WebSearch(双语):
    "<产品名> <版本号> CVE"
    "<产品名> 漏洞 未授权"
    "<产品名> 默认密码"
    "<CMS名> bypass security"

  结果直接标注在对应端点上
```

---

## 停止条件

一条线索挖完 = 以下之一为真:
- 所有合理探测方向已穷举,全返回不存在/无响应
- 需要凭据才能继续
- 产生了新的子域名/端点 → 回到第1层继续

以下不算挖完:
- "罗盘清单跑完了"
- CDN返回403(加Referer重试)
- JS太大grep不到(用node)
- 试了N种组合全404(可能在其他子域名)
- 公司名已知但没搜关联域名

---

## 输出地图格式

```
🗺️ 攻击面地图 — $TARGET

🏗️ 架构: [CMS/框架] | [前端] | [后端] | [服务器] | [WAF/CDN]
📍 位置: [IP] ([云厂商/ISP] [城市])

🌐 子域名(N个):
  xxx.${TARGET}  ✅ [服务/框架] (关键特征)
  yyy.${TARGET}  🔒 [需认证/SSO]
  zzz.${TARGET}  ❌ 不可达(可能内网)

📡 端点:
  ⭐ endpoint1 — 特征1, 特征2 (为什么高价值)
  ⭐ endpoint2 — ...

🔑 认证: [方式] + [加密算法/密钥情况]

⚠️ 入口排序: ⭐#1 → ⭐#2 → ... (按可操作性+危害排序)
```
