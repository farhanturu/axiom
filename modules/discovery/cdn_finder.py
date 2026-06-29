import json
import os
from typing import Dict, List, Optional, Tuple
from core.utils import cidr_contains, extract_domain, gather_ips
from core.client import AxiomClient

class CDNFinder:
    def __init__(self, client: AxiomClient):
        self.client = client
        self._signatures = self._load_signatures()
        self._cdn_ips = self._load_cdn_ips()

    def _load_signatures(self) -> Dict:
        path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'waf_signatures.json')
        try:
            with open(path) as f:
                return json.load(f)
        except:
            return {}

    def _load_cdn_ips(self) -> Dict:
        path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'cdn_ips.json')
        try:
            with open(path) as f:
                return json.load(f)
        except:
            return {}

    def detect_cdn_by_ip(self, ip: str) -> Optional[str]:
        for cdn, data in self._cdn_ips.items():
            for cidr in data.get('ipv4', []) + data.get('ipv6', []):
                if cidr_contains(ip, [cidr]):
                    return cdn
        return None

    def detect_waf(self, url: str) -> Dict:
        result = {'url': url, 'waf': None, 'confidence': 0, 'indicators': []}
        try:
            resp = self.client.get(url, timeout=15)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text
            status = resp.status_code

            for key, sig in self._signatures.items():
                score = 0
                indicators = []

                for h, val in sig.get('headers', {}).items():
                    if val and headers.get(h) == val:
                        score += 25
                        indicators.append(f'header {h}: {val}')
                    elif val is None and h in headers:
                        score += 20
                        indicators.append(f'header {h} present: {headers[h]}')

                for cookie in sig.get('cookies', []):
                    if cookie in headers.get('set-cookie', ''):
                        score += 15
                        indicators.append(f'cookie: {cookie}')

                if status in sig.get('response_code', []):
                    score += 10
                    indicators.append(f'status code: {status}')

                for pattern in sig.get('body_patterns', []):
                    import re
                    if re.search(pattern, body, re.IGNORECASE):
                        score += 20
                        indicators.append(f'body pattern: {pattern}')

                if score >= 30:
                    result['waf'] = sig['name']
                    result['confidence'] = min(score, 100)
                    result['indicators'] = indicators[:5]
                    return result

            if resp.headers.get('server', '').lower() == 'cloudflare':
                result['waf'] = 'Cloudflare'
                result['confidence'] = 90
                result['indicators'] = ['server: cloudflare']
                return result

            result['waf'] = None
            result['confidence'] = 0
            return result

        except Exception as e:
            result['waf'] = 'unknown'
            result['error'] = str(e)
            return result

    def detect_all(self, url: str) -> Dict:
        domain = extract_domain(url)
        result = {
            'domain': domain,
            'url': url,
            'cdn': None,
            'waf': None,
            'waf_detail': None,
            'origin_ips': []
        }

        ips = gather_ips(domain)
        for ip in ips:
            cdn = self.detect_cdn_by_ip(ip)
            if cdn:
                result['cdn'] = cdn
                break

        waf = self.detect_waf(url)
        if waf.get('waf'):
            result['waf'] = waf['waf']
            result['waf_detail'] = waf

        for ip in ips:
            if not any(self.detect_cdn_by_ip(ip) for _ in [1]):
                found = self.detect_cdn_by_ip(ip)
                if not found:
                    result['origin_ips'].append(ip)

        return result
