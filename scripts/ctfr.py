#!/usr/bin/env python3
"""证书透明度日志子域名发现 — 聚合多个 CT 源"""
import sys
import io
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import urllib.request
import urllib.error
import json
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# CT 数据源
CT_SOURCES = [
    {
        'name': 'crt.sh',
        'url': 'https://crt.sh/?q=%25.{domain}&output=json',
        'parser': 'json',
        'field': 'name_value',
    },
    {
        'name': 'CertSpotter',
        'url': 'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer',
        'parser': 'json',
        'field': 'dns_names',
    },
]


def fetch_ct_data(source, domain, timeout=30):
    """从 CT 数据源获取子域名"""
    subs = set()
    try:
        url = source['url'].format(domain=domain)
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; AutoPentest/1.0)'
        })
        resp = urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx)
        data = resp.read().decode('utf-8', errors='ignore')

        if source['parser'] == 'json':
            entries = json.loads(data)
            for entry in entries:
                if source['field'] in entry:
                    value = entry[source['field']]
                    if isinstance(value, list):
                        for name in value:
                            name = str(name).strip().lower().lstrip('*.')
                            if name:
                                subs.add(name)
                    elif isinstance(value, str):
                        # crt.sh 返回 \n 分隔的多行字符串
                        for name in value.split('\n'):
                            name = name.strip().lower().lstrip('*.')
                            if name and '*' not in name:
                                subs.add(name)

        return source['name'], subs
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print(f"   ⚠️  {source['name']}: 请求频率限制，跳过")
        return source['name'], set()
    except Exception as e:
        return source['name'], set()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ctfr.py -d <domain> [-o output.txt]")
        sys.exit(1)

    domain = None
    output_file = None
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == '-d':
            domain = args[i+1]; i += 2
        elif args[i] == '-o':
            output_file = args[i+1]; i += 2
        else:
            domain = args[i]; i += 1

    if not domain:
        print("❌ 请指定域名: python3 ctfr.py example.com")
        sys.exit(1)

    print(f"🔍 证书透明度子域名枚举: {domain}")
    print("=" * 50)

    all_subs = set()

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(fetch_ct_data, src, domain) for src in CT_SOURCES]
        for future in as_completed(futures):
            source_name, subs = future.result()
            new = subs - all_subs
            all_subs.update(subs)
            print(f"   ✅ {source_name}: 找到 {len(subs)} 个子域名 (新增 {len(new)})")

    # 过滤有效子域名
    valid_subs = {s for s in all_subs
                  if s.endswith(domain) or domain in s
                  if len(s) > len(domain)
                  if not s.startswith('xn--')  # 暂跳过 IDN
                  if '.' in s}

    # 排序输出
    sorted_subs = sorted(valid_subs)
    print(f"\n{'='*50}")
    print(f"📊 总计发现: {len(sorted_subs)} 个唯一子域名")
    print(f"\n子域名列表:")
    for sub in sorted_subs:
        print(f"   {sub}")

    # 保存文件
    if output_file:
        with open(output_file, 'w') as f:
            for sub in sorted_subs:
                f.write(sub + '\n')
        print(f"\n💾 已保存: {output_file}")

    # JSON 输出
    print(f"\n📄 JSON 统计:")
    print(json.dumps({
        'domain': domain,
        'total': len(sorted_subs),
        'sources': [s['name'] for s in CT_SOURCES],
        'subdomains': sorted_subs,
    }, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
