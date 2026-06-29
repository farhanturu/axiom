import time
import random
import json
import os
from typing import Dict, List, Optional
from core.client import AxiomClient

class RateLimitBypass:
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

    def _spoof_headers(self, ip: str) -> Dict:
        headers = {}
        for h in ['X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP', 'X-Remote-IP',
                   'X-Client-IP', 'X-Forwarded', 'Forwarded-For', 'X-ProxyUser-Ip',
                   'Client-IP', 'True-Client-IP']:
            headers[h] = ip
        return headers

    def header_spoof_test(self, url: str, num_requests: int = 50) -> Dict:
        result = {
            'url': url,
            'total_requests': num_requests,
            'successful': 0,
            'blocked': 0,
            'status_codes': {},
            'rate_limited_at': None,
        }
        for i in range(num_requests):
            ip = f'{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}'
            headers = self._spoof_headers(ip)
            try:
                resp = self.client.get(url, headers=headers, timeout=10)
                code = resp.status_code
                result['status_codes'][code] = result['status_codes'].get(code, 0) + 1
                if code == 200:
                    result['successful'] += 1
                else:
                    result['blocked'] += 1
                    if result['rate_limited_at'] is None:
                        result['rate_limited_at'] = i + 1
            except:
                result['blocked'] += 1
        return result

    def slowloris_pattern(self, url: str, delay_range: Tuple[float, float] = (1.0, 5.0)) -> Dict:
        result = {'total': 0, 'successful': 0, 'pattern': 'slowloris'}
        for i in range(10):
            delay = random.uniform(*delay_range)
            time.sleep(delay)
            try:
                resp = self.client.get(url, timeout=30)
                if resp.status_code == 200:
                    result['successful'] += 1
                result['total'] += 1
            except:
                continue
        return result

    def burst_pattern(self, url: str, burst_size: int = 5, cooldown: float = 2.0) -> Dict:
        result = {'total': 0, 'successful': 0, 'pattern': 'burst'}
        for burst_num in range(3):
            for _ in range(burst_size):
                try:
                    resp = self.client.get(url, timeout=10)
                    if resp.status_code == 200:
                        result['successful'] += 1
                    result['total'] += 1
                except:
                    continue
            time.sleep(cooldown)
        return result

    def distributed_pattern(self, url: str, proxy_list: Optional[List[str]] = None) -> Dict:
        result = {'total': 0, 'successful': 0, 'pattern': 'distributed'}
        if not proxy_list:
            return result
        for proxy in proxy_list[:20]:
            try:
                old_proxy = self.client.session.proxies.copy() if hasattr(self.client.session, 'proxies') else {}
                self.client.session.proxies = {'http': proxy, 'https': proxy}
                resp = self.client.get(url, timeout=15)
                if resp.status_code == 200:
                    result['successful'] += 1
                result['total'] += 1
            except:
                continue
        return result

    def timing_analysis(self, url: str, num_requests: int = 10) -> Dict:
        result = {'url': url, 'request_times': [], 'avg_time': 0, 'rate_limit_detected': False}
        for _ in range(num_requests):
            try:
                start = time.time()
                self.client.get(url, timeout=10)
                elapsed = time.time() - start
                result['request_times'].append(round(elapsed, 3))
            except:
                result['request_times'].append(-1)

        times = [t for t in result['request_times'] if t > 0]
        if times:
            result['avg_time'] = round(sum(times) / len(times), 3)
            if len(times) >= 3:
                increase = times[-1] - times[0]
                result['rate_limit_detected'] = increase > 2.0

        return result

    def all_bypass_patterns(self, url: str, proxy_list: Optional[List[str]] = None) -> Dict:
        return {
            'header_spoof': self.header_spoof_test(url),
            'timing_analysis': self.timing_analysis(url),
            'burst_pattern': self.burst_pattern(url),
            'slowloris_pattern': self.slowloris_pattern(url),
            'distributed_pattern': self.distributed_pattern(url, proxy_list),
        }

from typing import Tuple
