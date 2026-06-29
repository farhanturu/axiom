import requests
import ssl
import socket
import random
import time
from typing import Optional, Dict, List
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor

class TlsFingerprintSession(requests.Session):
    def __init__(self, cipher_suite: str = 'modern'):
        super().__init__()
        suites = {
            'modern': [
                'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
            ],
            'chrome': [
                'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
                'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
            ],
            'firefox': [
                'TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256',
                'TLS_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
            ]
        }
        self.cipher_suite = suites.get(cipher_suite, suites['modern'])
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=100)
        self.mount('http://', adapter)
        self.mount('https://', adapter)

    def request(self, method, url, **kwargs):
        if 'timeout' not in kwargs:
            kwargs['timeout'] = 30
        return super().request(method, url, **kwargs)

class AxiomClient:
    def __init__(self, proxy_chain: Optional[List[str]] = None, fingerprint: str = 'modern', concurrent: int = 10):
        self.fingerprint = fingerprint
        self.concurrent = concurrent
        self.proxy_chain = proxy_chain
        self.session = self._create_session()

    def _create_session(self) -> TlsFingerprintSession:
        session = TlsFingerprintSession(self.fingerprint)
        session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        if self.proxy_chain:
            session.proxies = {'http': self.proxy_chain[0], 'https': self.proxy_chain[0]}
        return session

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.session.post(url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        return self.session.head(url, **kwargs)

    def batch_get(self, urls: List[str]) -> List[Optional[requests.Response]]:
        def fetch(url):
            try:
                return self.get(url, timeout=15)
            except:
                return None
        with ThreadPoolExecutor(max_workers=self.concurrent) as executor:
            return list(executor.map(fetch, urls))

    def rotate_fingerprint(self):
        profiles = ['modern', 'chrome', 'firefox']
        self.fingerprint = random.choice(profiles)
        self.session = self._create_session()

    def rotate_proxy(self):
        if self.proxy_chain and len(self.proxy_chain) > 1:
            self.proxy_chain = self.proxy_chain[1:] + [self.proxy_chain[0]]
            self.session.proxies = {'http': self.proxy_chain[0], 'https': self.proxy_chain[0]}

    def close(self):
        self.session.close()
