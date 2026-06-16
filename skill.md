---
name: attackmap
description: >-
  攻击面地图生成器。勘探直觉来自五轮实战: POETIZE/tyut/sdbao/ksyun/ztgame。
  rule=触发→反应: 看到什么→下一步做什么。不是清单，是肌肉记忆。
version: "5.0.0"
dependencies: "curl, node>=16, nslookup"
platforms: "Linux, macOS, Windows (Git Bash)"
when_to_use: >-
  用户想对网站/域名进行攻击面扫描
  触发词: "attackmap" "attack-map" "攻击面" "pentest" "渗透"
---

# 🗺️ AttackMap v5.0

> **这不是规则清单。这是肌肉记忆。**
>
> 下面的每一条都来自某次实战——看到触发器，手已经在执行下一步了。
> 新的 Agent 拿到这份直觉，几秒钟做出我磨了几十轮才学会的事。

---

## 触发→反应表

每行格式: **你看到什么 → 立刻做什么** (为什么)

### 域名层

| 触发 | 反应 | 来源 |
|------|------|------|
| `<title>` 不是"首页"而是品牌名 | 搜 GitHub: `"品牌名" 源码` | POETIZE |
| crt.sh 出现 `lyncsrv-`/`mailbe`/`o365-` | Exchange/Lync 基础设施模式，立刻打 mail/owa/autodiscover | ztgame |
| crt.sh 出现 `bastion`/`svpn`/`rancher` | 内部运维暴露 — 记录但公网大概率不可达 | ksyun |
| crt.sh 出现 `*.api.` 通配符 | 云API，搜 GitHub: `"target" AK_SK AccessKey` | ksyun |
| crt.sh 包含非当前域名的其他公司域名 | 集团关联，搜那家公司的 crt.sh | sdbao |
| NS记录=自建(非万网/DNSPod) | 自有基础设施，DNS可能有内部区域文件泄露 | ztgame |

### HTTP 响应层

| 触发 | 反应 | 来源 |
|------|------|------|
| Server: openresty | 搜: `openresty CVE`，`openresty WAF bypass` | POETIZE |
| Server: KS3 / `x-kss-request-id` | S3兼容对象存储，立刻试 `/?max-keys=5` 列目录 | ksyun |
| Server: Microsoft-IIS/10.0 | 检查是否存在 Exchange/Azure AD Connect | ztgame |
| WAF拦截页显示产品名(1Panel/Cloudflare/腾讯云) | 搜: `"产品名" bypass CVE 2025 2026` | POETIZE |
| 403 Forbidden (非WAF) | 不加 Origin 头重试 | ztgame |
| `Access-Control-Allow-Origin: *` | 立刻列该域所有路径，看哪些返回敏感数据 | ztgame/ksyun |
| `{"code":400,"message":"参数异常！"}` | 端点存在但格式不对。找源码/F12确认正确格式。不爆破 | POETIZE |
| `{"code":300,"message":"请登录"}` | 端点存在+需认证。CSRF测试点 | POETIZE |
| XML `<ErrorResponse><Code>MissingAccesskey</Code>` | S3/AWS兼容API。搜 GitHub AK泄露 | ksyun |
| PDF/Word文档直接在HTTP响应中返回 | 下载→提取文本→搜PII(手机/身份证/邮箱) | ksyun |
| Cookie `domain=.xxx.com` 且子域页面可写 | XSS cookie劫持入口 | ksyun |
| 响应含 `SameSite=None; Secure` 且 `CORS:*` | CSRF可攻击目标 | ztgame |
| `<Server> 空格` 或 Server: 空 | 刻意隐藏，安全团队有意识，该网站安全水平可能较高 | tyut |

### HTML/JS层

| 触发 | 反应 | 来源 |
|------|------|------|
| HTML注释 `<!--Announced by Visual SiteBuilder` | 博达网站群，搜: `博达 漏洞`，打 `/system/` | tyut |
| JS文件`chunk-`+hash 或 `_nuxt/` | Vue/React/Nuxt打包。搜GitHub: `"网站名" vue` | POETIZE/sdbao |
| JS文件名含 `login12.js`/`code.js`/`encrypt` | 客户端加密。提取加密函数找密钥 | tyut |
| JS中 `strEnc(data,'1','2','3')` | 东软DES三重密钥。密钥='1','2','3' | tyut |
| JS中 `cryptojs_key` 字符串 | AES/加密密钥在混淆数组的同位置 | POETIZE |
| JS中 `S.encode = function(p){Base64.encode...charCode±...}` | Base64+偏移。可逆编码≠加密。一行还原 | ksyun |
| CDN域名返回403 | 加 `Referer: https://主站/` 重试。CDN防盗链通常在文件级不生效 | sdbao |
| CDN域名可访问但JS >100KB | 用node解析提取URL。grep对大文件低效 | sdbao |
| HTML内 `<div>默认密码为tyut加身份证后六位</div>` | 直接记录为凭据。不要等到"收集完信息再说" | tyut |
| HTML内 `忘记密码` / `找回密码` 链接 | 立刻访问。看是否区分"用户不存在"vs"验证码错误" | POETIZE |
| 登录页form有 `captcha` 字段 | 注册/忘记密码接口可能没有captcha。分开测 | POETIZE |
| `<script src="//third-party-cdn.com/xxx">` | 第三方资源可能有自己的安全策略 | ztgame |

### API响应层

| 触发 | 反应 | 来源 |
|------|------|------|
| 不存在端点返回 `{"timestamp":"...","status":404,"error":"Not Found"}` | Spring Boot。真实端点返回不同错误格式→端点枚举 | POETIZE |
| `"该账号不存在，请联系作者！"` vs 其他错误 | 用户枚举确认。立刻列表测试已知用户 | POETIZE |
| `"操作过于频繁"` | 频控存在，换 XFF 或等5秒不纠结 | ztgame |
| `"参数异常"` 全返回400 | Content-Type问题或参数名问题。找F12确认 | POETIZE |
| API返回完整用户数据(含userId/email/phone) | 检查是否可越权。传`{"id":1}`试IDOR | POETIZE |
| XML目录列表返回 `<ListBucketResult>` | S3 bucket公开。立刻遍历所有已知bucket名 | ksyun |
| multipart upload返回 `<UploadId>` | **匿名写入确认**。立刻试: 上传HTML+public-read ACL | ksyun |
| `x-kss-copy-source` 头可用 | **跨桶提权**。从不可读桶复制文件到可读桶 | ksyun |
| "此Web浏览器不支持JavaScript" | Exchange OWA。正在使用 AD FS 预认证 | ztgame |
| OWA URL含 `/owa/auth/15.2.1748/` | 精确版本号。立刻搜CVE | ztgame |
| EWS/PowerShell/MAPI/RPC 全部返回401 | Exchange 全栈暴露。密码喷洒价值极高 | ztgame |

---

## 直觉是怎么来的

上面 40+ 条触发规则，每一条对应一次"如果当时就想到这个该多好"。

POETIZE 的第一条经验——"标题搜GitHub"——来自我对着混淆JS逆向了1小时之后才想起来搜源码。之后 tyut/sdbao/ksyun/ztgame 四个目标，我再没有超过5分钟才想到搜源码。

**提炼的方法**不是"把5次经验写成规则"——那样永远追不上新的目标类型。而是**每次发现"做晚了"的时候，立刻提炼一句话的触发规则**。

---

## 如何用在下个Agent上

把这个文件放到新Agent的 skill 里。

Agent加载后不需要"执行什么步骤"。它只是在每次看到HTTP响应、HTML内容、JS文件时，大脑里自动触发对应的反应。

就像你开车看到红灯——不需要想"第3条规则说红灯要停"，你的脚已经在刹车上了。
