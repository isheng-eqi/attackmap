#!/usr/bin/env python3
"""CMS / 框架指纹识别 — 基于路径特征和响应特征"""
import sys
import io
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import urllib.request
import urllib.error
import ssl
import json
import re

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# CMS / 框架指纹库
CMS_FINGERPRINTS = {
    "WordPress": {
        "paths": ["/wp-admin/", "/wp-content/", "/wp-includes/", "/wp-json/wp/v2/users",
                   "/wp-login.php", "/xmlrpc.php"],
        "headers": {"x-generator": "WordPress"},
        "body_patterns": [r'wp-content/', r'wordpress', r'wp-json'],
        "meta": ["<meta name=\"generator\" content=\"WordPress"],
        "version_paths": ["/wp-content/readme.html", "/feed/"],
    },
    "Drupal": {
        "paths": ["/sites/default/", "/misc/drupal.js", "/themes/",
                   "/modules/", "/user/login", "/node/1"],
        "headers": {"x-generator": "Drupal", "x-drupal-cache": "", "x-drupal-dynamic-cache": ""},
        "body_patterns": [r'drupal\.js', r'drupal\.org', r'Drupal\.settings'],
        "meta": ["<meta name=\"generator\" content=\"Drupal"],
    },
    "Joomla": {
        "paths": ["/administrator/", "/media/system/", "/components/",
                   "/templates/system/", "/language/"],
        "headers": {},
        "body_patterns": [r'joomla!', r'/media/jui/', r'Joomla\.', r'/media/system/js/'],
        "meta": ["<meta name=\"generator\" content=\"Joomla"],
    },
    "Laravel": {
        "paths": ["/vendor/", "/storage/", "/.env"],
        "headers": {},
        "body_patterns": [r'laravel_session'],
        "meta": [],
        "cookies": ["laravel_session"],
    },
    "Django": {
        "paths": ["/admin/", "/admin/login/", "/static/admin/"],
        "headers": {"x-python": "", "x-django": ""},
        "body_patterns": [r'csrfmiddlewaretoken', r'__debug_toolbar__', r'django\.'],
        "meta": [],
        "cookies": ["csrftoken", "sessionid"],
    },
    "Ruby on Rails": {
        "paths": ["/assets/application-", "/rails/info"],
        "headers": {"x-rails": "", "x-request-id": ""},
        "body_patterns": [r'rails-ujs', r'turbolinks', r'<%= '],
        "meta": [],
        "cookies": ["_session_id"],
    },
    "Spring Boot (Java)": {
        "paths": ["/actuator", "/actuator/health", "/actuator/info", "/error",
                   "/swagger-ui.html", "/v2/api-docs", "/h2-console"],
        "headers": {"x-application-context": ""},
        "body_patterns": [r'Whitelabel Error Page', r'This application has no explicit mapping'],
        "meta": [],
    },
    "ASP.NET": {
        "paths": ["/WebResource.axd", "/ScriptResource.axd", "/Telerik.Web.UI.WebResource.axd"],
        "headers": {"x-aspnet-version": "", "x-aspnetmvc-version": "", "x-powered-by": "ASP.NET"},
        "body_patterns": [r'__VIEWSTATE', r'__EVENTVALIDATION', r'__doPostBack'],
        "meta": [],
        "cookies": ["ASP.NET_SessionId", ".ASPXFORMSAUTH", "__RequestVerificationToken"],
    },
    "Express.js (Node)": {
        "paths": [],
        "headers": {"x-powered-by": "Express"},
        "body_patterns": [],
        "meta": [],
        "cookies": ["connect.sid"],
    },
    "Next.js (React)": {
        "paths": ["/_next/static/"],
        "headers": {"x-powered-by": "Next.js"},
        "body_patterns": [r'__NEXT_DATA__', r'/_next/static/', r'__next'],
        "meta": [],
    },
    "Nuxt.js (Vue)": {
        "paths": ["/_nuxt/"],
        "headers": {},
        "body_patterns": [r'__NUXT__', r'/_nuxt/'],
        "meta": [],
    },
    "ThinkPHP": {
        "paths": ["/thinkphp/", "/public/index.php", "/application/"],
        "headers": {"x-powered-by": "ThinkPHP"},
        "body_patterns": [r'ThinkPHP', r'thinkphp'],
        "meta": [],
    },
    "PHPMyAdmin": {
        "paths": ["/phpmyadmin/", "/pma/", "/myadmin/"],
        "headers": {},
        "body_patterns": [r'phpMyAdmin', r'pma_'],
        "meta": [],
    },
    "Jenkins": {
        "paths": ["/jenkins/", "/jenkins/login", "/jenkins/script"],
        "headers": {"x-jenkins": "", "x-hudson": ""},
        "body_patterns": [r'Jenkins\.', r'Dashboard \[Jenkins\]'],
        "meta": [],
    },
    "GitLab": {
        "paths": ["/users/sign_in", "/explore", "/help"],
        "headers": {},
        "body_patterns": [r'GitLab', r'gitlab'],
        "meta": ["<meta content=\"GitLab"],
    },
    "Nginx": {
        "paths": ["/nginx_status"],
        "headers": {"server": "nginx"},
        "body_patterns": [],
        "meta": [],
    },
    "Apache Tomcat": {
        "paths": ["/manager/html", "/host-manager/html", "/docs/", "/examples/"],
        "headers": {"server": "Apache-Coyote"},
        "body_patterns": [r'Apache Tomcat', r'tomcat'],
        "meta": [],
    },
    "Apache HTTP Server": {
        "paths": ["/server-status", "/server-info"],
        "headers": {"server": "Apache"},
        "body_patterns": [],
        "meta": [],
    },
    "IIS (Microsoft)": {
        "paths": ["/iisstart.htm", "/owa/"],
        "headers": {"server": "Microsoft-IIS", "x-powered-by": "ASP.NET"},
        "body_patterns": [r'IIS Windows Server'],
        "meta": [],
    },
    "WebLogic (Oracle)": {
        "paths": ["/console/login/LoginForm.jsp", "/wls-wsat/"],
        "headers": {},
        "body_patterns": [r'WebLogic', r'bea\.'],
        "meta": [],
    },
    "JBoss / WildFly": {
        "paths": ["/jmx-console/", "/web-console/", "/console/"],
        "headers": {},
        "body_patterns": [r'JBoss', r'WildFly', r'jboss\.'],
        "meta": [],
    },
}


def fetch_url(base_url, path="", timeout=8):
    """请求 URL 并返回状态码、响应头、响应体"""
    url = base_url.rstrip('/') + path
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        resp = urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx)
        body = resp.read(65536).decode('utf-8', errors='ignore')
        return {'url': url, 'status': resp.status,
                'headers': {k.lower(): v for k, v in resp.headers.items()},
                'body': body}
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        return {'url': url, 'status': e.code,
                'headers': {k.lower(): v for k, v in e.headers.items()},
                'body': body}
    except Exception:
        return None


def fingerprint_cms(base_url):
    """识别 CMS/框架"""
    results = []
    all_matches = {}

    # 先请求首页
    home = fetch_url(base_url)
    if not home:
        return {'error': f"无法连接到 {base_url}"}

    server_info = {
        'server': home['headers'].get('server', ''),
        'x_powered_by': home['headers'].get('x-powered-by', ''),
        'x_generator': home['headers'].get('x-generator', ''),
    }

    # 对每个 CMS 指纹进行匹配
    for cms_name, fingerprint in CMS_FINGERPRINTS.items():
        cms_matches = []
        confidence = 0

        # 1. 检查特征路径
        for check_path in fingerprint.get('paths', []):
            resp = fetch_url(base_url, check_path)
            if resp and resp['status'] in [200, 301, 302, 401, 403]:
                cms_matches.append(f"路径存在: {check_path} ({resp['status']})")
                confidence += 15
                if resp['headers'].get('server'):
                    server_info['server'] = server_info['server'] or resp['headers'].get('server', '')

        # 2. 检查响应头特征
        for header_key, header_val in fingerprint.get('headers', {}).items():
            actual_val = home['headers'].get(header_key.lower(), '')
            if header_val:
                if header_val.lower() in actual_val.lower():
                    cms_matches.append(f"响应头匹配: {header_key}={actual_val}")
                    confidence += 25
            else:
                if actual_val:
                    cms_matches.append(f"响应头存在: {header_key}={actual_val}")
                    confidence += 20

        # 3. 检查 body 中的特征
        for pattern in fingerprint.get('body_patterns', []):
            if re.search(pattern, home['body'], re.IGNORECASE):
                cms_matches.append(f"body 匹配: {pattern}")
                confidence += 10

        # 4. 检查 meta 标签
        for meta_pat in fingerprint.get('meta', []):
            if meta_pat.lower() in home['body'].lower():
                cms_matches.append(f"meta 匹配: {meta_pat}")
                confidence += 20

        # 5. 检查 Cookie
        set_cookie = home['headers'].get('set-cookie', '')
        for cookie_name in fingerprint.get('cookies', []):
            if cookie_name.lower() in set_cookie.lower():
                cms_matches.append(f"Cookie 匹配: {cookie_name}")
                confidence += 15

        if cms_matches:
            all_matches[cms_name] = {
                'matches': cms_matches,
                'confidence': min(confidence, 100),
                'status': 'confirmed' if confidence >= 50 else 'likely' if confidence >= 25 else 'possible'
            }

    # 按置信度排序
    sorted_matches = sorted(all_matches.items(), key=lambda x: x[1]['confidence'], reverse=True)

    return {
        'url': base_url,
        'server_info': server_info,
        'detected': [{'name': name, **info} for name, info in sorted_matches],
        'home_status': home['status'],
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cms_fingerprint.py <url> [<url2> ...]")
        sys.exit(1)

    for arg in sys.argv[1:]:
        url = f"https://{arg}" if not arg.startswith('http') else arg
        result = fingerprint_cms(url)

        print(f"\n{'='*60}")
        print(f"🏷️  CMS/框架指纹识别: {url}")
        print(f"{'='*60}")

        sinfo = result.get('server_info', {})
        if sinfo.get('server'):
            print(f"   Server:    {sinfo['server']}")
        if sinfo.get('x_powered_by'):
            print(f"   PoweredBy: {sinfo['x_powered_by']}")
        if sinfo.get('x_generator'):
            print(f"   Generator: {sinfo['x_generator']}")

        if result.get('detected'):
            print(f"\n   检测结果:")
            for d in result['detected']:
                icon = "🎯" if d['status'] == 'confirmed' else "🔍" if d['status'] == 'likely' else "❓"
                print(f"      {icon} {d['name']} — 置信度: {d['confidence']}% ({d['status']})")
                for m in d['matches'][:5]:  # 最多显示5条
                    print(f"         • {m}")
        else:
            print(f"\n   ⬜ 未识别到已知 CMS/框架")

        print(f"\n📄 JSON: {json.dumps(result, indent=2, ensure_ascii=False)}")


if __name__ == '__main__':
    main()
