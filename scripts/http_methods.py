#!/usr/bin/env python3
"""HTTP 方法检查 — 检测危险 HTTP 方法 (PUT, DELETE, TRACE, OPTIONS)"""
import sys
import io
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import urllib.request
import urllib.error
import ssl
import json

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
SAFE_METHODS = ['OPTIONS', 'GET', 'HEAD', 'POST']

def check_method(url, method, timeout=5):
    """测试单个 HTTP 方法"""
    try:
        req = urllib.request.Request(url, method=method, headers={
            'User-Agent': 'Mozilla/5.0'
        })
        resp = urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx)
        return {
            'method': method,
            'status': resp.status,
            'allowed': True,
            'headers': dict(resp.headers),
        }
    except urllib.error.HTTPError as e:
        # 某些方法返回 4xx/5xx 但仍被允许
        return {
            'method': method,
            'status': e.code,
            'allowed': e.code != 405,  # 405 Method Not Allowed
            'headers': dict(e.headers) if hasattr(e, 'headers') else {},
        }
    except Exception as e:
        return {
            'method': method,
            'status': 0,
            'allowed': False,
            'error': str(e),
        }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 http_methods.py <url> [<url2> ...]")
        sys.exit(1)

    for arg in sys.argv[1:]:
        url = f"https://{arg}" if not arg.startswith('http') else arg

        print(f"\n{'='*50}")
        print(f"🔍 HTTP 方法检查: {url}")

        all_methods = DANGEROUS_METHODS + SAFE_METHODS
        results = []
        allow_header = ""

        for method in all_methods:
            result = check_method(url, method)
            results.append(result)
            if result['status'] > 0:
                icon = "🔴" if method in DANGEROUS_METHODS and result['allowed'] else "🟢"
                warning = " ⚠️ 危险!" if method in DANGEROUS_METHODS and result['allowed'] else ""
                print(f"   {icon} {method:8s} → {result['status']}{warning}")

            # 从 OPTIONS 响应中提取 Allow 头
            if method == 'OPTIONS' and result['status'] > 0:
                allow_header = result['headers'].get('Allow', result['headers'].get('allow', ''))
                if allow_header:
                    print(f"      Allow 头: {allow_header}")

        # 汇总
        dangerous_allowed = [r for r in results if r['method'] in DANGEROUS_METHODS and r['allowed']]
        if dangerous_allowed:
            print(f"\n   ⚠️  危险方法已启用: {', '.join(r['method'] for r in dangerous_allowed)}")
            print(f"   风险: PUT/DELETE 可能导致数据篡改，TRACE 可能泄露认证信息")

            # 检查 TRACE 是否存在 XST 风险
            trace_result = [r for r in results if r['method'] == 'TRACE' and r['allowed']]
            if trace_result:
                print(f"   🚨 XST 风险: TRACE 方法启用，可能导致跨站追踪攻击!")
        else:
            print(f"\n   ✅ 无危险 HTTP 方法暴露")

        print(f"\n📄 JSON:\n{json.dumps({'url': url, 'methods': results, 'allow_header': allow_header}, indent=2, ensure_ascii=False)}")


if __name__ == '__main__':
    main()
