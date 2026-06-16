#!/usr/bin/env python3
"""DNS 枚举脚本 — 纯 Python 标准库，无外部依赖"""
import socket
import sys
import io
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

class DNSEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.results = {
            'domain': domain,
            'records': {}
        }

    def query(self, record_type, name=None):
        """查询指定类型的 DNS 记录"""
        target = name if name else self.domain
        results = []
        try:
            answers = socket.getaddrinfo(target, None)
            if record_type == 'A':
                ips = set()
                for ans in answers:
                    ip = ans[4][0]
                    if ':' not in ip:  # 仅 IPv4
                        ips.add(ip)
                results = list(ips)
        except Exception:
            pass
        return record_type, results

    def query_txt(self):
        """使用 nslookup 获取 TXT/MX/NS 记录 (通过系统调用)"""
        import subprocess
        record_types = {
            'A': f'nslookup -type=A {self.domain}',
            'MX': f'nslookup -type=MX {self.domain}',
            'NS': f'nslookup -type=NS {self.domain}',
            'TXT': f'nslookup -type=TXT {self.domain}',
            'SOA': f'nslookup -type=SOA {self.domain}',
            'CNAME': f'nslookup -type=CNAME www.{self.domain}',
        }
        for rtype, cmd in record_types.items():
            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10, text=True)
                self.results['records'][rtype] = self._parse_nslookup(output, rtype)
            except Exception as e:
                self.results['records'][rtype] = f"Error: {e}"

    def _parse_nslookup(self, output, rtype):
        """解析 nslookup 输出"""
        lines = []
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Server:') or line.startswith('Address:') or line.startswith('DNS') or line.startswith('Name:') or line.startswith('***'):
                continue
            lines.append(line)
        return lines

    def reverse_dns(self, ip):
        """反向 DNS 查询"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def run(self):
        """执行完整 DNS 枚举"""
        print(f"\n🔍 DNS 枚举: {self.domain}")
        print("=" * 50)

        # 基础查询
        self.query_txt()

        # 输出结果
        for rtype, data in self.results['records'].items():
            status = "✅" if data and not str(data).startswith('Error') else "⬜"
            print(f"\n{status} {rtype} 记录:")
            if isinstance(data, list):
                for line in data:
                    print(f"   {line}")
            else:
                print(f"   {data}")

        # 总结
        print(f"\n{'='*50}")
        ips = []
        if 'A' in self.results['records']:
            for line in self.results['records']['A']:
                import re
                found = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                ips.extend(found)
        if ips:
            print(f"📌 发现 IP: {', '.join(set(ips))}")
            for ip in set(ips):
                rev = self.reverse_dns(ip)
                if rev:
                    print(f"   {ip} → {rev}")

        return self.results

    def to_json(self):
        return json.dumps(self.results, indent=2, ensure_ascii=False)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 dns_enum.py <domain>")
        print("Example: python3 dns_enum.py example.com")
        sys.exit(1)

    domain = sys.argv[1]
    enumerator = DNSEnumerator(domain)
    results = enumerator.run()
    print(f"\n📄 JSON 输出:\n{enumerator.to_json()}")
