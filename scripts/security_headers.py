#!/usr/bin/env python3
"""安全响应头检查 — 基于 OWASP 最佳实践"""
import sys
import io
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import urllib.request
import urllib.error
import ssl
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# 安全头检查规则
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HSTS — 强制HTTPS连接，防止SSL剥离攻击",
        "missing_risk": "可能遭受中间人攻击和SSL剥离",
        "recommendation": "max-age=31536000; includeSubDomains; preload",
        "category": "SSL/TLS"
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "CSP — 防止XSS和数据注入攻击",
        "missing_risk": "容易受到XSS和内容注入攻击",
        "recommendation": "设置合理的CSP策略限制资源加载来源",
        "category": "XSS防护"
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "防止Clickjacking攻击",
        "missing_risk": "网站可被嵌入恶意iframe进行点击劫持",
        "recommendation": "DENY 或 SAMEORIGIN",
        "category": "UI安全"
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "防止MIME类型嗅探",
        "missing_risk": "浏览器可能错误解析文件类型",
        "recommendation": "nosniff",
        "category": "浏览器安全"
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "控制Referer头信息泄露",
        "missing_risk": "敏感URL信息可能泄露给第三方",
        "recommendation": "strict-origin-when-cross-origin",
        "category": "隐私"
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "启用浏览器XSS过滤器 (已废弃，但仍建议设置)",
        "missing_risk": "旧版浏览器缺少XSS防护",
        "recommendation": "1; mode=block (或用CSP替代)",
        "category": "XSS防护"
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "控制浏览器功能权限 (原Feature-Policy)",
        "missing_risk": "无法限制浏览器API使用",
        "recommendation": "限制不必要的浏览器功能",
        "category": "功能控制"
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "low",
        "description": "控制跨域资源加载",
        "missing_risk": "其他网站可以嵌入你的资源",
        "recommendation": "same-origin",
        "category": "跨域"
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "low",
        "description": "防止跨域窗口交互攻击",
        "missing_risk": "可能遭受Spectre类侧信道攻击",
        "recommendation": "same-origin",
        "category": "隔离"
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "low",
        "description": "控制跨域资源嵌入",
        "missing_risk": "无法启用跨域隔离",
        "recommendation": "require-corp",
        "category": "隔离"
    },
    "Cache-Control": {
        "severity": "low",
        "description": "控制浏览器缓存行为",
        "missing_risk": "敏感页面可能被缓存",
        "recommendation": "no-store, max-age=0 (敏感页面)",
        "category": "缓存"
    },
    "X-Permitted-Cross-Domain-Policies": {
        "severity": "low",
        "description": "控制Flash/PDF跨域请求",
        "missing_risk": "遗留跨域策略可能被滥用",
        "recommendation": "none",
        "category": "跨域"
    }
}


def check_headers(url, timeout=10):
    """检查目标的安全头配置"""
    result = {
        'url': url,
        'present': {},
        'missing': [],
        'score': 0,
        'max_score': len(SECURITY_HEADERS),
        'grade': 'F'
    }

    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        resp = urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx)
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        result['status_code'] = resp.status
        result['final_url'] = resp.url
    except urllib.error.HTTPError as e:
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        result['status_code'] = e.code
        result['final_url'] = e.url
    except Exception as e:
        result['error'] = str(e)
        return result

    # 检查每个安全头
    for header_name, info in SECURITY_HEADERS.items():
        header_lower = header_name.lower()
        if header_lower in resp_headers:
            result['present'][header_name] = resp_headers[header_lower]
            result['score'] += 1
        else:
            result['missing'].append({
                'header': header_name,
                'severity': info['severity'],
                'description': info['description'],
                'risk': info['missing_risk'],
                'recommendation': info['recommendation'],
                'category': info['category']
            })

    # 评分
    ratio = result['score'] / result['max_score']
    if ratio >= 0.9: result['grade'] = 'A'
    elif ratio >= 0.7: result['grade'] = 'B'
    elif ratio >= 0.5: result['grade'] = 'C'
    elif ratio >= 0.3: result['grade'] = 'D'
    else: result['grade'] = 'F'

    # 额外检查
    result['checks'] = {
        'https_redirect': str(resp_headers.get('location', '')).startswith('https') if 'location' in resp_headers else False,
        'has_server_header': 'server' in resp_headers,
        'server_value': resp_headers.get('server', ''),
        'has_x_powered_by': 'x-powered-by' in resp_headers,
        'x_powered_by_value': resp_headers.get('x-powered-by', ''),
    }

    return result


def print_report(results):
    """打印格式化报告"""
    print(f"\n{'='*70}")
    print(f"  🛡️  安全响应头检查报告")
    print(f"{'='*70}")

    for r in results:
        print(f"\n🌐 {r['url']}")
        print(f"   状态码: {r.get('status_code', 'N/A')}")
        print(f"   安全评分: {r['score']}/{r['max_score']} — Grade: {r['grade']}")

        if r.get('present'):
            print(f"\n   ✅ 已设置的安全头 ({len(r['present'])}):")
            for header, value in r['present'].items():
                print(f"      {header}: {value}")

        if r.get('missing'):
            print(f"\n   ❌ 缺失的安全头 ({len(r['missing'])}):")
            for m in r['missing']:
                icon = "🔴" if m['severity'] == 'high' else "🟡" if m['severity'] == 'medium' else "🟢"
                print(f"      {icon} {m['header']}")
                print(f"         {m['description']}")
                print(f"         风险: {m['risk']}")
                print(f"         建议: {m['recommendation']}")

        # 信息泄露检查
        checks = r.get('checks', {})
        if checks.get('has_server_header'):
            print(f"\n   ⚠️  信息泄露: Server: {checks['server_value']}")
        if checks.get('has_x_powered_by'):
            print(f"   ⚠️  信息泄露: X-Powered-By: {checks['x_powered_by_value']}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 security_headers.py <url> [<url2> ...]")
        print("   or: python3 security_headers.py --file <hosts_file>")
        sys.exit(1)

    urls = []
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == '--file':
            with open(args[i+1]) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        url = f"https://{line}" if not line.startswith('http') else line
                        urls.append(url)
            i += 2
        else:
            url = f"https://{args[i]}" if not args[i].startswith('http') else args[i]
            urls.append(url)
            i += 1

    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_headers, url): url for url in urls}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    print_report(results)
    print(f"\n📄 JSON 输出:")
    print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
