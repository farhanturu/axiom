import json
import os
import random
from typing import Dict, List, Optional
from core.client import AxiomClient
from core.utils import encode_payload

class WAFBypass:
    def __init__(self, client: AxiomClient):
        self.client = client
        self._payloads = self._load_payloads()

    def _load_payloads(self) -> Dict:
        path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'bypass_payloads.json')
        try:
            with open(path) as f:
                return json.load(f)
        except:
            return {}

    def test_payload(self, url: str, param: str, payload: str, method: str = 'GET') -> Dict:
        result = {'payload': payload, 'status': None, 'blocked': True, 'response_size': 0, 'response_time': 0}
        import time
        try:
            params = {param: payload}
            start = time.time()
            if method == 'GET':
                resp = self.client.get(url, params=params, timeout=15)
            else:
                resp = self.client.post(url, data=params, timeout=15)

            elapsed = time.time() - start
            result['status'] = resp.status_code
            result['response_size'] = len(resp.text)
            result['response_time'] = round(elapsed, 3)

            result['blocked'] = self._is_blocked(resp)
            return result
        except Exception as e:
            result['error'] = str(e)
            return result

    def _is_blocked(self, resp) -> bool:
        status = resp.status_code
        body = resp.text.lower()
        if status in [403, 503, 406]:
            return True
        indicators = ['blocked', 'denied', 'rejected', 'forbidden', 'waf', 'security',
                      'suspicious', 'malicious', 'attack detected', 'access denied',
                      'cloudflare', 'attention required', 'please wait']
        return any(ind in body for ind in indicators)

    def test_sqli(self, url: str, param: str, method: str = 'GET') -> List[Dict]:
        results = []
        payloads = self._payloads.get('sqli', {})
        all_payloads = []
        for category in ['simple', 'encoded', 'bypass', 'time_based']:
            all_payloads.extend(payloads.get(category, []))
        for payload in all_payloads[:20]:
            result = self.test_payload(url, param, payload, method)
            results.append(result)
        return results

    def test_xss(self, url: str, param: str, method: str = 'GET') -> List[Dict]:
        results = []
        payloads = self._payloads.get('xss', {})
        all_payloads = []
        for category in ['simple', 'encoded', 'bypass', 'polyglot']:
            all_payloads.extend(payloads.get(category, []))
        for payload in all_payloads[:20]:
            result = self.test_payload(url, param, payload, method)
            results.append(result)
        return results

    def test_lfi(self, url: str, param: str, method: str = 'GET') -> List[Dict]:
        results = []
        payloads = self._payloads.get('lfi', {})
        all_payloads = []
        for category in ['simple', 'encoded', 'bypass']:
            all_payloads.extend(payloads.get(category, []))
        for payload in all_payloads[:15]:
            result = self.test_payload(url, param, payload, method)
            results.append(result)
        return results

    def test_rce(self, url: str, param: str, method: str = 'GET') -> List[Dict]:
        results = []
        payloads = self._payloads.get('rce', {})
        all_payloads = []
        for category in ['simple', 'encoded', 'bypass']:
            all_payloads.extend(payloads.get(category, []))
        for payload in all_payloads[:15]:
            result = self.test_payload(url, param, payload, method)
            results.append(result)
        return results

    def header_injection(self, url: str) -> List[Dict]:
        results = []
        injections = self._payloads.get('header_injection', {})
        for category, headers in injections.items():
            for header in headers[:5]:
                try:
                    if ':' in header:
                        key, value = header.split(':', 1)
                        resp = self.client.get(url, headers={key.strip(): value.strip()}, timeout=10)
                        results.append({
                            'header': header,
                            'status': resp.status_code,
                            'size': len(resp.text),
                            'blocked': self._is_blocked(resp)
                        })
                except:
                    continue
        return results

    def all_tests(self, url: str, param: str = 'id', method: str = 'GET') -> Dict:
        return {
            'sqli': self.test_sqli(url, param, method),
            'xss': self.test_xss(url, param, method),
            'lfi': self.test_lfi(url, param, method),
            'rce': self.test_rce(url, param, method),
            'header_injection': self.header_injection(url),
        }

    def case_permutation(self, payload: str) -> List[str]:
        variants = []
        for i in range(min(5, len(payload))):
            for j in range(i + 1, min(i + 4, len(payload))):
                if payload[i].isalpha() and payload[j].isalpha():
                    chars = list(payload)
                    chars[i] = chars[i].swapcase()
                    chars[j] = chars[j].swapcase()
                    variants.append(''.join(chars))
        return variants[:10]
