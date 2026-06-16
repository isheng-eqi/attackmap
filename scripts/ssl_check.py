#!/usr/bin/env python3
"""SSL/TLS 安全检查 — 证书信息、协议版本、密码套件"""
import sys
import io
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import ssl
import socket
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_certificate_info(hostname, port=443, timeout=5):
    """获取 SSL 证书详细信息"""
    result = {
        'host': hostname,
        'port': port,
        'certificate': {},
        'issues': [],
        'score': 100,
        'grade': 'A+'
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((hostname, port))

        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert(True)
            cipher = ssock.cipher()
            tls_version = ssock.version()

        sock.close()

        # 解析证书
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_obj = x509.load_der_x509_certificate(cert, default_backend())
        subject = cert_obj.subject
        issuer = cert_obj.issuer

        # 提取信息
        not_before = cert_obj.not_valid_before_utc if hasattr(cert_obj, 'not_valid_before_utc') else cert_obj.not_valid_before
        not_after = cert_obj.not_valid_after_utc if hasattr(cert_obj, 'not_valid_after_utc') else cert_obj.not_valid_after

        result['certificate'] = {
            'subject': {attr.oid._name: attr.value for attr in subject},
            'issuer': {attr.oid._name: attr.value for attr in issuer},
            'serial_number': str(cert_obj.serial_number),
            'not_before': str(not_before),
            'not_after': str(not_after),
            'version': cert_obj.version.name if hasattr(cert_obj.version, 'name') else str(cert_obj.version),
        }

        # 检查 SAN (Subject Alternative Names)
        try:
            san_ext = cert_obj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            result['certificate']['san'] = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            result['certificate']['san'] = []

        result['tls_info'] = {
            'version': tls_version,
            'cipher': cipher,
            'cipher_name': cipher[0] if cipher else '',
            'cipher_bits': cipher[1] if cipher else 0,
        }

        # 检查问题
        now = datetime.utcnow()
        days_left = (not_after.replace(tzinfo=None) - now).days if hasattr(not_after, 'replace') else 30
        if days_left < 0:
            result['issues'].append({'severity': 'critical', 'msg': f'证书已过期! 过期 {abs(days_left)} 天'})
            result['score'] -= 40
        elif days_left < 30:
            result['issues'].append({'severity': 'high', 'msg': f'证书即将过期 (剩余 {days_left} 天)'})
            result['score'] -= 15
        elif days_left < 90:
            result['issues'].append({'severity': 'low', 'msg': f'证书将在 {days_left} 天后过期'})

        # 弱 TLS 版本
        if tls_version and tls_version in ['TLSv1', 'TLSv1.1']:
            result['issues'].append({'severity': 'critical', 'msg': f'使用弱TLS版本: {tls_version}'})
            result['score'] -= 25
        elif tls_version and tls_version == 'TLSv1.2':
            result['issues'].append({'severity': 'low', 'msg': 'TLS 1.2 可用，建议升级到 TLS 1.3'})

        # 弱密码检查
        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon', 'CBC']
        cipher_name = result['tls_info']['cipher_name'].lower() if result['tls_info'].get('cipher_name') else ''
        for wc in weak_ciphers:
            if wc.lower() in cipher_name:
                result['issues'].append({'severity': 'high', 'msg': f'弱密码套件: {result["tls_info"]["cipher_name"]}'})
                result['score'] -= 20
                break

        # 评分转等级
        if result['score'] >= 95: result['grade'] = 'A+'
        elif result['score'] >= 90: result['grade'] = 'A'
        elif result['score'] >= 80: result['grade'] = 'B'
        elif result['score'] >= 70: result['grade'] = 'C'
        elif result['score'] >= 60: result['grade'] = 'D'
        else: result['grade'] = 'F'

    except ssl.SSLError as e:
        result['error'] = f"SSL 错误: {e}"
        result['score'] = 0
        result['grade'] = 'F'
    except socket.timeout:
        result['error'] = f"连接超时 ({timeout}s)"
        result['score'] = 0
        result['grade'] = 'F'
    except ConnectionRefusedError:
        result['error'] = f"端口 {port} 连接被拒绝"
        result['score'] = 0
        result['grade'] = 'N/A'
    except Exception as e:
        # 如果 cryptography 库不可用，回退到纯 ssl 库
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((hostname, port))

            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_dict = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

            sock.close()

            result['certificate'] = cert_dict
            result['tls_info'] = {
                'version': tls_version,
                'cipher': cipher,
                'cipher_name': cipher[0] if cipher else '',
                'cipher_bits': cipher[1] if cipher else 0,
            }

            # 简单检查
            not_after_str = cert_dict.get('notAfter', '')
            if tls_version and tls_version in ['TLSv1', 'TLSv1.1']:
                result['issues'].append({'severity': 'critical', 'msg': f'弱TLS版本: {tls_version}'})
                result['score'] -= 25
                result['grade'] = 'C'

            result['note'] = 'cryptography 库不可用，使用有限检查'

        except Exception as e2:
            result['error'] = str(e2)
            result['score'] = 0
            result['grade'] = 'F'

    return result


def test_tls_versions(hostname, port=443, timeout=3):
    """测试支持的 TLS 版本"""
    versions = {
        'TLSv1': ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
        'TLSv1.1': ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
        'TLSv1.2': ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
    }
    results = {}
    for vname, protocol in versions.items():
        if protocol is None:
            results[vname] = 'not_testable'
            continue
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            ctx = ssl.SSLContext(protocol)
            sock = ctx.wrap_socket(sock, server_hostname=hostname)
            sock.connect((hostname, port))
            results[vname] = 'enabled'
            sock.close()
        except Exception:
            results[vname] = 'disabled'

    return results


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ssl_check.py <host> [port]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    print(f"🔒 SSL/TLS 安全检查: {host}:{port}")
    print("=" * 60)

    # 测试 TLS 版本
    print("\n📋 支持的 TLS 版本:")
    versions = test_tls_versions(host, port)
    for vname, status in versions.items():
        icon = "🟢" if status == 'disabled' else "🔴" if status == 'enabled' else "⬜"
        risk = " (不安全!)" if status == 'enabled' and vname in ['TLSv1', 'TLSv1.1'] else ""
        print(f"   {icon} {vname}: {status}{risk}")

    # 获取证书信息
    print("\n📜 证书信息:")
    result = get_certificate_info(host, port)

    if 'error' in result:
        print(f"   ❌ {result['error']}")
    else:
        print(f"   安全评分: {result['score']}/100 — Grade: {result['grade']}")
        cert = result.get('certificate', {})
        if cert:
            print(f"   主题: {cert.get('subject', {})}")
            print(f"   颁发者: {cert.get('issuer', {})}")
            print(f"   有效期: {cert.get('not_before', '')} ~ {cert.get('not_after', '')}")

            san = cert.get('san', [])
            if san:
                print(f"   SAN (备用域名): {', '.join(san[:10])}")
                if len(san) > 10:
                    print(f"     ... 及其他 {len(san) - 10} 个域名")

        print(f"\n   TLS 版本: {result.get('tls_info', {}).get('version', 'N/A')}")
        print(f"   密码套件: {result.get('tls_info', {}).get('cipher_name', 'N/A')}")

        if result.get('issues'):
            print(f"\n   ⚠️  发现 {len(result['issues'])} 个问题:")
            for issue in result['issues']:
                icon = "🔴" if issue['severity'] == 'critical' else "🟠" if issue['severity'] == 'high' else "🟡"
                print(f"      {icon} {issue['msg']}")
        else:
            print(f"\n   ✅ 未发现明显问题")

    print(f"\n📄 JSON:\n{json.dumps(result, indent=2, ensure_ascii=False, default=str)}")


if __name__ == '__main__':
    main()
