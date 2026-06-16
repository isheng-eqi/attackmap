#!/usr/bin/env python3
"""存活主机探测 — 多线程 HTTP/HTTPS 探测"""
import sys
import io
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import urllib.request
import urllib.error
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

# 忽略 SSL 证书错误
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

def check_host(host, timeout=5):
    """检测单个主机是否存活（尝试 HTTPS 和 HTTP）"""
    host = host.strip()
    if not host:
        return None

    results = []

    for proto in ['https', 'http']:
        url = f"{proto}://{host}"
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            resp = urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx)
            # 读取响应头
            server = resp.headers.get('Server', '')
            content_type = resp.headers.get('Content-Type', '')
            location = resp.headers.get('Location', '')
            results.append({
                'host': host,
                'url': url,
                'status': resp.status,
                'server': server,
                'content_type': content_type,
                'redirect': location if 300 <= resp.status < 400 else '',
                'proto': proto
            })
            break  # 成功就停止尝试另一个协议
        except urllib.error.HTTPError as e:
            # 4xx/5xx 也算存活
            results.append({
                'host': host,
                'url': url,
                'status': e.code,
                'server': e.headers.get('Server', ''),
                'content_type': e.headers.get('Content-Type', ''),
                'redirect': '',
                'proto': proto
            })
            break
        except Exception:
            continue

    return results[0] if results else None


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 live_check.py <hosts_file> [--threads 20] [--timeout 5]")
        print("   or: python3 live_check.py --host example.com,test.com")
        sys.exit(1)

    threads = 20
    timeout = 5
    hosts = []

    # 解析参数
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == '--threads':
            threads = int(args[i+1]); i += 2
        elif args[i] == '--timeout':
            timeout = int(args[i+1]); i += 2
        elif args[i] == '--host':
            hosts = args[i+1].split(','); i += 2
        else:
            # 读取文件
            try:
                with open(args[i], 'r') as f:
                    hosts = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                hosts = [args[i]]  # 当作单个 host
            i += 1

    if not hosts:
        print("❌ No hosts to scan")
        sys.exit(1)

    print(f"🔍 存活检测: {len(hosts)} 个目标 (线程:{threads}, 超时:{timeout}s)")
    print("=" * 60)

    live = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_host, h, timeout): h for h in hosts}
        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            if result:
                live.append(result)
                emoji = "🟢" if result['status'] < 400 else "🟡" if result['status'] < 500 else "🔴"
                redirect = f" → {result['redirect']}" if result['redirect'] else ""
                print(f"  [{i:3d}/{len(hosts)}] {emoji} {result['url']} [{result['status']}] {result['server']}{redirect}")

    # 汇总
    print(f"\n{'='*60}")
    print(f"📊 统计:")
    print(f"   总数: {len(hosts)}")
    print(f"   存活: {len(live)}")
    print(f"   离线: {len(hosts) - len(live)}")

    # 按状态码分类
    from collections import Counter
    status_counts = Counter(r['status'] for r in live)
    print(f"   状态码分布: {dict(status_counts)}")

    # 输出
    print(f"\n📄 存活主机 JSON:")
    print(json.dumps(live, indent=2, ensure_ascii=False))

    # 同时输出纯文本列表 (供后续工具使用)
    with open('live_domains.txt', 'w') as f:
        for r in live:
            f.write(r['host'] + '\n')
    print(f"\n💾 已保存: live_domains.txt")

if __name__ == '__main__':
    main()
