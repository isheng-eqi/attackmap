#!/usr/bin/env python3
"""轻量端口扫描器 — 纯 Python socket，扫描 Top 100 端口"""
import sys
import io
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from collections import OrderedDict

# Top 100 常见端口及对应服务
COMMON_PORTS = OrderedDict([
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (111, "RPC"),
    (135, "MSRPC"), (139, "NetBIOS"), (143, "IMAP"), (443, "HTTPS"),
    (445, "SMB"), (993, "IMAPS"), (995, "POP3S"), (1433, "MSSQL"),
    (1521, "Oracle"), (1723, "PPTP"), (2049, "NFS"), (3306, "MySQL"),
    (3389, "RDP"), (5432, "PostgreSQL"), (5900, "VNC"), (5985, "WinRM-HTTP"),
    (5986, "WinRM-HTTPS"), (6379, "Redis"), (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"), (9200, "Elasticsearch"), (11211, "Memcached"),
    (27017, "MongoDB"), (5000, "Docker-Registry"), (9090, "Web-UI"),
    (3000, "Node.js"), (8000, "HTTP-Dev"), (8888, "HTTP-Dev2"),
    (25, "SMTP"), (465, "SMTPS"), (587, "SMTP-Submission"),
    (110, "POP3"), (995, "POP3S"), (143, "IMAP"), (993, "IMAPS"),
    (161, "SNMP"), (389, "LDAP"), (636, "LDAPS"),
    (873, "Rsync"), (1080, "SOCKS"), (2375, "Docker"),
    (3128, "Squid"), (4444, "Metasploit"), (4567, "Web-Dev"),
    (5001, "Web-Dev2"), (5060, "SIP"), (5222, "XMPP"),
    (5555, "ADB"), (5672, "RabbitMQ"), (6379, "Redis"),
    (6443, "K8s-API"), (7001, "WebLogic"), (7002, "WebLogic-SSL"),
    (8009, "AJP"), (8081, "HTTP-Alt2"), (8089, "HTTP-Alt3"),
    (8180, "HTTP-Alt4"), (9000, "PHP-FPM"), (9090, "Prometheus"),
    (9418, "Git"), (10000, "Webmin"), (15672, "RabbitMQ-Mgmt"),
    (27017, "MongoDB"), (27018, "MongoDB-Shard"),
])

def scan_port(host, port, timeout=2):
    """扫描单个端口"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            # 尝试获取 banner
            banner = ""
            try:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(2)
                sock2.connect((host, port))
                if port in [80, 443, 8080, 8443, 8000, 3000, 5000, 9090]:
                    sock2.send(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
                    banner = sock2.recv(256).decode(errors='ignore').split('\n')[0].strip()
                else:
                    banner = sock2.recv(128).decode(errors='ignore').strip()
                sock2.close()
            except:
                pass
            return {'port': port, 'service': service, 'banner': banner}
        return None
    except:
        return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 port_scanner.py <host/ip> [--ports 20,21,80,443] [--top 100] [--threads 50]")
        sys.exit(1)

    host = sys.argv[1]

    # 解析参数
    ports = list(COMMON_PORTS.keys())  # 默认扫描全部常见端口
    threads = 50
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == '--ports':
            ports = [int(p) for p in args[i+1].split(',')]
            i += 2
        elif args[i] == '--top':
            ports = list(COMMON_PORTS.keys())[:int(args[i+1])]
            i += 2
        elif args[i] == '--threads':
            threads = int(args[i+1])
            i += 2
        else:
            i += 1

    print(f"🔍 端口扫描: {host}")
    print(f"   目标端口: {len(ports)} 个 (线程: {threads})")
    print("=" * 60)

    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                banner = f" — {result['banner']}" if result['banner'] else ""
                print(f"  🟢 {result['port']:5d}/tcp  {result['service']:15s}{banner}")

    print(f"\n{'='*60}")
    print(f"📊 扫描完成: 发现 {len(open_ports)} 个开放端口")

    # 按端口排序
    open_ports.sort(key=lambda x: x['port'])

    # 风险标记
    high_risk = [22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 6379, 27017]
    for p in open_ports:
        if p['port'] in high_risk:
            print(f"  ⚠️  端口 {p['port']}/tcp ({p['service']}) — 高风险! 不应暴露在公网")

    print(f"\n📄 JSON 输出:")
    print(json.dumps({'host': host, 'open_ports': open_ports, 'count': len(open_ports)}, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
