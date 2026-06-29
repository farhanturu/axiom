import random
import json
import os
from typing import Dict, List, Optional

class FingerprintGenerator:
    def __init__(self, data_path: Optional[str] = None):
        self.data_path = data_path or os.path.join(os.path.dirname(__file__), '..', 'data')
        self._user_agents = self._load_json('user_agents.json')
        self._platforms = ['Windows', 'macOS', 'Linux', 'Android', 'iOS']
        self._architectures = ['x86_64', 'x86', 'arm64', 'arm']

    def _load_json(self, filename: str) -> Dict:
        path = os.path.join(self.data_path, filename)
        try:
            with open(path) as f:
                return json.load(f)
        except:
            return {}

    def user_agent(self, category: str = 'random') -> str:
        agents = self._user_agents.get(category, [])
        if not agents:
            agents = self._user_agents.get('chrome', [])
        return random.choice(agents) if agents else 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'

    def accept_headers(self) -> Dict[str, str]:
        profiles = [
            {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
             'Accept-Language': 'en-US,en;q=0.5'},
            {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
             'Accept-Language': 'en-US,en;q=0.9'},
            {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
             'Accept-Language': 'en-GB,en;q=0.5'},
        ]
        return random.choice(profiles)

    def sec_headers(self) -> Dict[str, str]:
        headers = {}
        if random.random() > 0.3:
            headers.update({
                'Sec-Fetch-Dest': random.choice(['document', 'empty', 'iframe']),
                'Sec-Fetch-Mode': random.choice(['navigate', 'cors', 'no-cors']),
                'Sec-Fetch-Site': random.choice(['none', 'same-origin', 'cross-site']),
                'Sec-Fetch-User': '?1',
            })
        if random.random() > 0.5:
            headers['Sec-CH-UA'] = '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"'
            headers['Sec-CH-UA-Mobile'] = '?0'
            headers['Sec-CH-UA-Platform'] = random.choice(['"Windows"', '"macOS"', '"Linux"'])
        return headers

    def headers(self) -> Dict[str, str]:
        ua = self.user_agent()
        accept = self.accept_headers()
        sec = self.sec_headers()
        return {
            'User-Agent': ua,
            **accept,
            **sec,
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'DNT': str(random.randint(0, 1)),
        }

    def http2_settings(self) -> Dict[str, int]:
        return {
            'HEADER_TABLE_SIZE': 65536,
            'MAX_CONCURRENT_STREAMS': 1000,
            'INITIAL_WINDOW_SIZE': random.choice([6291456, 6291464, 65535]),
            'MAX_HEADER_LIST_SIZE': 262144,
        }

    @staticmethod
    def ja3_signature() -> str:
        chrome = '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0'
        firefox = '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0'
        safari = '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0'
        return random.choice([chrome, firefox, safari])

    @staticmethod
    def accept_encoding() -> str:
        encodings = ['gzip, deflate, br', 'gzip, deflate', 'gzip, deflate, br, zstd']
        return random.choice(encodings)
