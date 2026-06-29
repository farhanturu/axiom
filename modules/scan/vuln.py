import re
from typing import Dict, List, Optional
from core.client import AxiomClient

class VulnDetector:
    def __init__(self, client: AxiomClient):
        self.client = client

    def check_headers(self, url: str) -> Dict:
        result = {'url': url, 'missing_security_headers': [], 'present_headers': {}}
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'Clickjacking',
            'X-XSS-Protection': 'XSS filter',
            'Referrer-Policy': 'Referrer',
            'Permissions-Policy': 'Permissions',
            'Access-Control-Allow-Origin': 'CORS',
        }
        try:
            resp = self.client.get(url, timeout=15)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            for hdr, name in security_headers.items():
                lkey = hdr.lower()
                if lkey in headers:
                    result['present_headers'][hdr] = headers[lkey]
                else:
                    result['missing_security_headers'].append(name)

            if 'server' in headers:
                result['server'] = headers['server']
            if 'x-powered-by' in headers:
                result['powered_by'] = headers['x-powered-by']
        except:
            result['error'] = 'could not fetch headers'
        return result

    def check_open_redirect(self, url: str) -> Dict:
        result = {'vulnerable': False, 'redirects': []}
        test_paths = ['//evil.com', '//evil.com%2F@test', 'https://evil.com', '//google.com']
        for path in test_paths:
            try:
                target = url.rstrip('/') + '/' + path.lstrip('/')
                resp = self.client.get(target, allow_redirects=False, timeout=10)
                loc = resp.headers.get('location', '')
                if 'evil' in loc or 'google' in loc:
                    result['vulnerable'] = True
                    result['redirects'].append({'path': path, 'location': loc})
            except:
                continue
        return result

    def check_directory_listing(self, url: str) -> Dict:
        result = {'vulnerable': False, 'paths': []}
        test_paths = ['/assets/', '/images/', '/uploads/', '/css/', '/js/']
        for path in test_paths:
            try:
                target = url.rstrip('/') + path
                resp = self.client.get(target, timeout=10)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if 'index of' in body or 'directory listing' in body or '<table>' in body and 'parent directory' in body:
                        result['vulnerable'] = True
                        result['paths'].append(path)
            except:
                continue
        return result

    def check_sqli_error_based(self, url: str, param: str = 'id') -> Dict:
        result = {'vulnerable': False, 'tests': []}
        payloads = ["'", "\"", "')", "'))", "\"))", "1'", "1' OR '1'='1"]
        for payload in payloads:
            try:
                resp = self.client.get(url, params={param: payload}, timeout=10)
                body = resp.text.lower()
                errors = [
                    'sql', 'mysql', 'syntax error', 'unclosed quotation', 'odbc',
                    'sqlite', 'postgresql', 'driver', 'db2', 'ora-', 'microsoft ole db'
                ]
                found_errors = [e for e in errors if e in body]
                if found_errors:
                    result['vulnerable'] = True
                    result['tests'].append({
                        'payload': payload,
                        'errors_found': found_errors[:3],
                        'status': resp.status_code,
                    })
            except:
                continue
        return result

    def check_xss_reflected(self, url: str, param: str = 'q') -> Dict:
        result = {'vulnerable': False, 'tests': []}
        payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>']
        for payload in payloads:
            try:
                resp = self.client.get(url, params={param: payload}, timeout=10)
                if payload in resp.text and resp.status_code == 200:
                    result['vulnerable'] = True
                    result['tests'].append({
                        'payload': payload[:50],
                        'status': resp.status_code,
                    })
            except:
                continue
        return result

    def check_ssrf(self, url: str) -> Dict:
        result = {'vulnerable': False, 'tests': []}
        targets = ['http://169.254.169.254/latest/meta-data/', 'http://127.0.0.1:22', 'http://localhost:8080']
        ssrf_patterns = ['instance-id', 'ami-id', 'public-hostname', 'local-ipv4',
                         'security-credentials', 'iam/', 'meta-data',
                         'ssh-rsa', 'ssh-dss', 'protocol version']
        for target in targets:
            try:
                resp = self.client.get(url, params={'url': target, 'path': target}, timeout=10)
                body = resp.text.lower()
                if resp.status_code == 200:
                    matches = [p for p in ssrf_patterns if p in body]
                    if len(matches) >= 2:
                        result['vulnerable'] = True
                        result['tests'].append({'target': target, 'status': resp.status_code, 'matches': matches[:3]})
            except:
                continue
        return result

    def full_scan(self, url: str) -> Dict:
        return {
            'headers': self.check_headers(url),
            'open_redirect': self.check_open_redirect(url),
            'directory_listing': self.check_directory_listing(url),
            'sqli_error': self.check_sqli_error_based(url),
            'xss_reflected': self.check_xss_reflected(url),
            'ssrf': self.check_ssrf(url),
        }
