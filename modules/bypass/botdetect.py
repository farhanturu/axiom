import random
from typing import Dict, List, Optional
from core.client import AxiomClient
from core.fingerprint import FingerprintGenerator

class BotDetectionBypass:
    def __init__(self, client: AxiomClient):
        self.client = client
        self.fingerprint = FingerprintGenerator()

    def _test_endpoint(self, url: str, headers: Dict, label: str) -> Dict:
        try:
            resp = self.client.get(url, headers=headers, timeout=15)
            return {
                'label': label,
                'status': resp.status_code,
                'size': len(resp.text),
                'blocked': self._is_blocked(resp),
                'headers_used': {k: v[:50] for k, v in headers.items()},
            }
        except Exception as e:
            return {'label': label, 'error': str(e), 'blocked': True}

    def _is_blocked(self, resp) -> bool:
        body = resp.text.lower()
        status = resp.status_code
        if status in [403, 503, 429, 406]:
            return True
        indicators = [
            'blocked', 'denied', 'automated', 'automated queries',
            'unusual traffic', 'your request looks automated',
            'please complete the security check', 'cf-challenge',
            'attention required', 'just a moment', 'detected',
            'automated access', 'suspicious behavior'
        ]
        return any(ind in body for ind in indicators)

    def test_user_agents(self, url: str) -> List[Dict]:
        results = []
        categories = ['chrome', 'firefox', 'safari', 'edge', 'mobile', 'bot']
        for category in categories:
            ua = self.fingerprint.user_agent(category)
            headers = {'User-Agent': ua}
            result = self._test_endpoint(url, headers, f'ua_{category}')
            results.append(result)
        return results

    def test_headless_detection(self, url: str) -> List[Dict]:
        results = []
        scenarios = [
            {
                'label': 'headless_chrome',
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/125.0.0.0 Safari/537.36',
                }
            },
            {
                'label': 'normal_chrome',
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                    'Sec-CH-UA': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
                    'Sec-CH-UA-Mobile': '?0',
                    'Sec-CH-UA-Platform': '"Windows"',
                }
            },
            {
                'label': 'no_sec_headers',
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                }
            }
        ]
        for scenario in scenarios:
            result = self._test_endpoint(url, scenario['headers'], scenario['label'])
            results.append(result)
        return results

    def test_tls_fingerprints(self, url: str) -> List[Dict]:
        results = []
        profiles = ['modern', 'chrome', 'firefox']
        for profile in profiles:
            try:
                old_fp = self.client.fingerprint
                self.client.rotate_fingerprint()
                resp = self.client.get(url, timeout=15)
                results.append({
                    'label': f'tls_{profile}',
                    'status': resp.status_code,
                    'size': len(resp.text),
                    'blocked': self._is_blocked(resp),
                })
                self.client.fingerprint = old_fp
            except:
                results.append({'label': f'tls_{profile}', 'status': 0, 'blocked': True})
        return results

    def test_referer_spoof(self, url: str) -> List[Dict]:
        results = []
        referers = [
            'https://www.google.com/search?q=test',
            'https://www.bing.com/',
            'https://www.facebook.com/',
            'https://twitter.com/',
            'https://www.reddit.com/',
            'https://l.facebook.com/l.php',
            None,
        ]
        for ref in referers:
            headers = {}
            if ref:
                headers['Referer'] = ref
            label = f'referer_{ref.split("/")[2] if ref else "none"}'
            result = self._test_endpoint(url, headers, label)
            results.append(result)
        return results

    def complete_test(self, url: str) -> Dict:
        return {
            'user_agents': self.test_user_agents(url),
            'headless_detection': self.test_headless_detection(url),
            'tls_fingerprints': self.test_tls_fingerprints(url),
            'referer_spoof': self.test_referer_spoof(url),
        }
