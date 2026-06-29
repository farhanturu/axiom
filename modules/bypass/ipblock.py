import random
from typing import Dict, List, Optional
from core.client import AxiomClient
from core.proxy import ProxyManager

class IPBlockBypass:
    def __init__(self, client: AxiomClient, proxy_manager: Optional[ProxyManager] = None):
        self.client = client
        self.proxy_manager = proxy_manager

    def test_proxy(self, proxy: str, test_url: str = 'http://httpbin.org/ip') -> bool:
        try:
            resp = self.client.get(test_url, proxies={'http': proxy, 'https': proxy}, timeout=10)
            return resp.status_code == 200
        except:
            return False

    def rotate_ips(self, url: str, proxy_list: List[str]) -> Dict:
        results = {'successful': 0, 'failed': 0, 'responses': []}
        for proxy in proxy_list[:10]:
            try:
                old_proxies = self.client.session.proxies.copy() if hasattr(self.client.session, 'proxies') else {}
                self.client.session.proxies = {'http': proxy, 'https': proxy}
                resp = self.client.get(url, timeout=15)
                results['responses'].append({
                    'proxy': proxy,
                    'status': resp.status_code,
                    'size': len(resp.text),
                    'success': resp.status_code == 200,
                })
                if resp.status_code == 200:
                    results['successful'] += 1
                else:
                    results['failed'] += 1
            except:
                results['failed'] += 1
        return results

    def geo_spoof(self, url: str, geo_proxies: Dict[str, List[str]]) -> Dict:
        results = {}
        for region, proxies in geo_proxies.items():
            results[region] = self.rotate_ips(url, proxies[:3])
        return results

    def tor_test(self, url: str, tor_port: int = 9050) -> Dict:
        result = {'tor_enabled': False, 'accessible': False, 'details': {}}
        try:
            proxy = f'socks5://127.0.0.1:{tor_port}'
            resp = self.client.get(url, proxies={'http': proxy, 'https': proxy}, timeout=30)
            result['tor_enabled'] = True
            result['accessible'] = resp.status_code == 200
            result['details'] = {
                'status': resp.status_code,
                'size': len(resp.text),
            }
        except:
            result['accessible'] = False
        return result

    def dns_proxy_bypass(self, url: str) -> Dict:
        result = {'methods_tested': [], 'successful': False}
        methods = [
            {'label': 'direct', 'proxies': {}},
            {'label': 'socks5', 'proxies': {'http': 'socks5://127.0.0.1:9050', 'https': 'socks5://127.0.0.1:9050'}},
            {'label': 'http_proxy', 'proxies': {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}},
        ]
        for method in methods:
            try:
                resp = self.client.get(url, proxies=method['proxies'], timeout=15)
                result['methods_tested'].append({
                    'method': method['label'],
                    'status': resp.status_code,
                    'success': resp.status_code == 200,
                })
                if resp.status_code == 200:
                    result['successful'] = True
            except:
                result['methods_tested'].append({
                    'method': method['label'],
                    'success': False,
                    'error': 'connection failed'
                })
        return result
