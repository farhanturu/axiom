import random
import requests
import threading
from typing import List, Optional, Dict
from queue import Queue, Empty

class ProxyManager:
    def __init__(self, proxies: Optional[List[str]] = None):
        self._lock = threading.Lock()
        self._queue = Queue()
        self._working = []
        self._dead = []
        if proxies:
            for p in proxies:
                self._queue.put(p)

    def add(self, proxy: str):
        with self._lock:
            self._queue.put(proxy)

    def add_list(self, proxies: List[str]):
        with self._lock:
            for p in proxies:
                self._queue.put(p)

    def get(self) -> Optional[str]:
        with self._lock:
            try:
                return self._queue.get_nowait()
            except Empty:
                self._rebuild()
                try:
                    return self._queue.get_nowait()
                except Empty:
                    return None

    def mark_dead(self, proxy: str):
        with self._lock:
            if proxy in self._working:
                self._working.remove(proxy)
                self._dead.append(proxy)

    def mark_alive(self, proxy: str):
        with self._lock:
            if proxy not in self._working:
                self._working.append(proxy)

    def _rebuild(self):
        random.shuffle(self._working)
        for p in self._working:
            self._queue.put(p)

    def validate(self, proxy: str, timeout: int = 5) -> bool:
        try:
            r = requests.get('http://httpbin.org/ip', proxies={'http': proxy, 'https': proxy}, timeout=timeout)
            return r.status_code == 200
        except:
            return False

    def validate_all(self, timeout: int = 5) -> Dict[str, bool]:
        results = {}
        all_proxies = list(self._queue.queue) + self._working + self._dead
        seen = set()
        for p in all_proxies:
            if p not in seen:
                seen.add(p)
                results[p] = self.validate(p, timeout)
        return results

    @property
    def count(self) -> int:
        return self._queue.qsize() + len(self._working)

    @property
    def alive_count(self) -> int:
        return len(self._working)


class TorProxy(ProxyManager):
    def __init__(self, port: int = 9050, control_port: int = 9051, password: Optional[str] = None):
        super().__init__([f'socks5://127.0.0.1:{port}'])
        self.control_port = control_port
        self.password = password
        self.port = port

    def new_identity(self):
        try:
            import socket as sk
            s = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
            s.connect(('127.0.0.1', self.control_port))
            s.send(b'AUTHENTICATE "' + (self.password or '').encode() + b'"\r\n')
            s.recv(1024)
            s.send(b'SIGNAL NEWNYM\r\n')
            s.recv(1024)
            s.close()
            return True
        except:
            return False
