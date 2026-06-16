#!/usr/bin/env python3
"""
渗透测试报告生成器 — 聚合所有 Phase 的输出，生成结构化报告

输入: JSON 文件目录 (各阶段扫描结果)
输出: 格式化的 Markdown 报告 + HTML 报告
"""
import sys
import io
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import json
import os
from datetime import datetime
from collections import Counter

TEMPLATE_MD = """# 🛡️ 渗透测试报告

> **生成时间**: {datetime}
> **测试目标**: {target}
> **测试标准**: PTES + OWASP WSTG v4.2 + NIST SP 800-115
> **工具**: Auto-Pentest Agent v1.0

---

## 📋 执行摘要

{executive_summary}

---

## 🔍 1. 信息收集结果

### 1.1 目标基本信息
{target_info}

### 1.2 子域名发现
{subdomain_summary}

### 1.3 存活主机
{live_hosts_summary}

### 1.4 技术栈识别
{tech_stack}

---

## 🛡️ 2. 安全配置评估

### 2.1 安全响应头
{security_headers_summary}

### 2.2 SSL/TLS 配置
{ssl_summary}

### 2.3 WAF/CDN 状态
{waf_summary}

---

## 🔴 3. 漏洞发现

### 3.1 漏洞总览
{vuln_overview}

### 3.2 Critical 级别
{critical_vulns}

### 3.3 High 级别
{high_vulns}

### 3.4 Medium 级别
{medium_vulns}

### 3.5 Low 级别
{low_vulns}

---

## 🛠️ 4. 修复建议

### 4.1 紧急修复 (24小时内)
{urgent_fixes}

### 4.2 短期修复 (1周内)
{short_term_fixes}

### 4.3 中期修复 (1个月内)
{mid_term_fixes}

### 4.4 长期改进
{long_term_improvements}

---

## 📎 5. 附录

### 5.1 测试工具
{tools_used}

### 5.2 测试限制
{limitations}

### 5.3 参考链接
- [OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/stable/)
- [PTES](http://www.pentest-standard.org/)
- [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

*本报告由 Auto-Pentest Agent 自动生成 | {datetime}*
"""


def generate_report(target, data_dir=".", output="pentest_report.md"):
    """聚合所有扫描数据生成报告"""

    report_data = {
        'datetime': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'target': target,
        'executive_summary': '',
        'target_info': '',
        'subdomain_summary': '',
        'live_hosts_summary': '',
        'tech_stack': '',
        'security_headers_summary': '',
        'ssl_summary': '',
        'waf_summary': '',
        'vuln_overview': '',
        'critical_vulns': '',
        'high_vulns': '',
        'medium_vulns': '',
        'low_vulns': '',
        'urgent_fixes': '',
        'short_term_fixes': '',
        'mid_term_fixes': '',
        'long_term_improvements': '',
        'tools_used': '',
        'limitations': '',
    }

    # 尝试加载各阶段的数据文件
    all_vulns = []
    live_count = 0
    subdomain_count = 0

    # --- 子域名数据 ---
    try:
        with open(os.path.join(data_dir, 'all_subs.txt'), 'r') as f:
            subs = [l.strip() for l in f if l.strip()]
            subdomain_count = len(subs)
            report_data['subdomain_summary'] = f"发现 {subdomain_count} 个唯一子域名"
    except FileNotFoundError:
        report_data['subdomain_summary'] = "未执行子域名枚举"

    # --- 存活主机 ---
    try:
        with open(os.path.join(data_dir, 'live_domains.txt'), 'r') as f:
            live = [l.strip() for l in f if l.strip()]
            live_count = len(live)
            report_data['live_hosts_summary'] = f"检测到 {live_count} 个存活 Web 服务"
    except FileNotFoundError:
        report_data['live_hosts_summary'] = "未执行存活检测"

    # --- 漏洞数据 ---
    for fname in os.listdir(data_dir):
        if fname.endswith('.json'):
            try:
                with open(os.path.join(data_dir, fname), 'r') as f:
                    data = json.load(f)
                    # 尝试提取漏洞信息
                    if isinstance(data, dict):
                        vulns = data.get('vulnerabilities', data.get('findings', []))
                        if isinstance(vulns, list):
                            all_vulns.extend(vulns)
            except Exception:
                pass

    # --- 构建漏洞汇总 ---
    if all_vulns:
        severity_counts = Counter(v.get('severity', 'info').lower() for v in all_vulns)
        total = len(all_vulns)
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        medium = severity_counts.get('medium', 0)
        low = severity_counts.get('low', 0)

        report_data['vuln_overview'] = f"""
| 严重度 | 数量 | 占比 |
|--------|------|------|
| 🔴 Critical | {critical} | {critical/total*100:.0f}% |
| 🟠 High | {high} | {high/total*100:.0f}% |
| 🟡 Medium | {medium} | {medium/total*100:.0f}% |
| 🟢 Low | {low} | {low/total*100:.0f}% |
| **总计** | **{total}** | 100% |
"""

        # 按严重度分类
        for v in all_vulns:
            sev = v.get('severity', 'info').lower()
            entry = f"- **{v.get('title', '未命名漏洞')}**\n"
            entry += f"  - 位置: {v.get('location', v.get('url', 'N/A'))}\n"
            entry += f"  - 描述: {v.get('description', '无描述')}\n"
            entry += f"  - CVSS: {v.get('cvss', 'N/A')}\n"
            entry += f"  - 修复: {v.get('remediation', '无')}\n\n"

            if sev == 'critical':
                report_data['critical_vulns'] += entry
            elif sev == 'high':
                report_data['high_vulns'] += entry
            elif sev == 'medium':
                report_data['medium_vulns'] += entry
            else:
                report_data['low_vulns'] += entry

    # --- 构建执行摘要 ---
    risk_level = "🔴 高风险"
    risk_desc = "发现严重安全漏洞，建议立即处置"
    if not all_vulns or (critical == 0 and high == 0):
        risk_level = "🟡 中等风险"
        risk_desc = "未发现严重漏洞，但存在可改进的安全配置"
    if not all_vulns and live_count == 0:
        risk_level = "✅ 未发现明显风险"
        risk_desc = "初步扫描未发现严重问题 (扫描深度有限)"

    report_data['executive_summary'] = f"""
**整体风险评估: {risk_level}**

{risk_desc}

- 扫描范围: {target}
- 发现子域名: {subdomain_count} 个
- 存活 Web 服务: {live_count} 个
- 发现漏洞总数: {len(all_vulns)} 个
"""

    # --- 修复建议 ---
    report_data['urgent_fixes'] = "- 立即修复所有 Critical 级别漏洞\n- 关闭不必要的公网暴露端口\n- 更新过期证书"
    report_data['short_term_fixes'] = "- 部署缺失的安全响应头 (HSTS/CSP/X-Frame-Options)\n- 禁用弱 TLS 版本\n- 删除泄露的敏感文件"
    report_data['mid_term_fixes'] = "- 实施安全编码规范\n- 配置 WAF 规则\n- 定期进行安全扫描"
    report_data['long_term_improvements'] = "- 建立安全开发生命周期 (SDL)\n- 实施持续安全监控\n- 定期进行渗透测试和安全培训"

    # --- 工具与限制 ---
    report_data['tools_used'] = "- Auto-Pentest Agent v1.0\n- Python (urllib, ssl, socket)\n- curl + nslookup\n- Nuclei (如已安装)\n- OWASP ZAP / Burp Suite (手动验证建议)"
    report_data['limitations'] = "- 扫描深度受限于可用工具\n- 被动扫描未覆盖所有攻击向量\n- 建议进行专业人工渗透测试补充\n- 未进行漏洞利用验证 (需单独授权)"

    # --- 生成报告 ---
    report = TEMPLATE_MD.format(**report_data)

    with open(output, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"✅ 报告已生成: {output}")
    print(f"   总字数: {len(report)}")
    return report


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_report.py <target> [data_dir] [output.md]")
        print("Example: python3 generate_report.py example.com ./scan_output report.md")
        sys.exit(1)

    target = sys.argv[1]
    data_dir = sys.argv[2] if len(sys.argv) > 2 else "."
    output = sys.argv[3] if len(sys.argv) > 3 else f"pentest_report_{target.replace('.', '_')}.md"

    report = generate_report(target, data_dir, output)
    print(report[:500] + "..." if len(report) > 500 else report)


if __name__ == '__main__':
    main()
