---
name: attackmap
description: >-
  轻量攻击面罗盘。不约束探索过程，只在结束时对照检查遗漏。
version: "4.0.0"
dependencies: "curl, node>=16, nslookup"
platforms: "Linux, macOS, Windows (Git Bash)"
when_to_use: >-
  用户给了一个域名/资产让你分析攻击面
  触发词: "attackmap" "attack-map" "攻击面" "pentest" "渗透"
---

# 🗺️ AttackMap v4.0

> **这个 skill 不告诉你"怎么想"。只提醒你"别忘了什么"。**
>
> 探索过程你自己来。直觉优先。结束时用这张表查漏补缺。

---

## 探索方式（你自己的）

发现线索→顺着挖→挖到尽头→看下一条线索。
中间不要停下来问我"这是第几步"。

---

## 收尾检查表（我的事）

全部探索结束后，对照这个表问自己：

```
☐ crt.sh 子域名查了吗？（不只当前域名的，关联公司的也查）
☐ DNS 记录全了吗？（A/MX/TXT/NS/SOA）
☐ 首页 HTML 每一条注释、meta、script src 都看过了？
☐ 每个 JS 文件都下载分析了？（大文件用 node 不是 grep）
☐ CDN 返回 403 的，加 Referer 重试了吗？
☐ 提取到的每个新域名/子域名都探测了？
☐ 每个可访问端点都分了级（公开/需认证/管理员/云API）？
☐ 登录页面的 JS 加密逻辑分析了？（搜 encrypt/cryptojs_key/strEnc）
☐ HTML 里有"默认密码"或"初始密码"这样的文字吗？
☐ 识别到 CMS/框架后，搜了 CVE 和已知漏洞吗？
☐ 搜了 GitHub/Gitee 有没有这个项目的源码或 AccessKey 泄露？
☐ 公司名/产品名扩展搜了关联域名的 crt.sh 吗？
☐ 云 API（XML ErrorResponse）搜了 GitHub AK/SK 泄露吗？
☐ API 响应里的每一个错误消息都分析过了？
☐ 内部运维域名（grafana/jenkins/bastion/oa/wiki）探测过了吗？
```

**全部打勾 = 一轮探索完成。**

---

## 输出格式

```
🗺️ 攻击面地图 — $TARGET
═══════════════════════
🏗️ 架构: ...
🌐 子域名(N个): ...
📡 端点: ⭐ 标注最高价值
🔑 认证: ...
⚠️ 入口优先级: ⭐#1 → ⭐#2 → ...
```
