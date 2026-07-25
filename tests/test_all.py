import unittest
import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.client import AxiomClient
from core.fingerprint import FingerprintGenerator
from core.proxy import ProxyManager
from modules.discovery.cdn_finder import CDNFinder
from modules.discovery.tech_stack import TechDetector
from modules.bypass.waf import WAFBypass
from modules.bypass.ratelimit import RateLimitBypass
from modules.bypass.botdetect import BotDetectionBypass
from modules.scan.port import PortScanner
from modules.scan.dirbuster import DirBuster
from modules.scan.vuln import VulnDetector


class TestCore(unittest.TestCase):
    def test_client_creation(self):
        client = AxiomClient()
        self.assertIsNotNone(client)
        self.assertEqual(client.fingerprint, 'modern')
        client.close()

    def test_client_fingerprint(self):
        for fp in ['modern', 'chrome', 'firefox']:
            client = AxiomClient(fingerprint=fp)
            self.assertEqual(client.fingerprint, fp)
            client.close()

    def test_client_concurrent(self):
        client = AxiomClient(concurrent=20)
        self.assertEqual(client.concurrent, 20)
        client.close()

    def test_fingerprint_generator(self):
        fg = FingerprintGenerator()
        ua = fg.user_agent('chrome')
        self.assertIn('Mozilla', ua)
        
        headers = fg.headers()
        self.assertIn('User-Agent', headers)
        self.assertIn('Accept', headers)

    def test_proxy_manager(self):
        pm = ProxyManager()
        self.assertEqual(pm._queue.qsize(), 0)
        pm.add('http://proxy:8080')
        self.assertEqual(pm._queue.qsize(), 1)


class TestDiscovery(unittest.TestCase):
    def test_cdn_finder_init(self):
        client = AxiomClient()
        cdn = CDNFinder(client)
        self.assertIsNotNone(cdn)
        client.close()

    def test_tech_detector_init(self):
        client = AxiomClient()
        tech = TechDetector(client)
        self.assertIsNotNone(tech)
        client.close()


class TestBypass(unittest.TestCase):
    def test_waf_bypass_init(self):
        client = AxiomClient()
        waf = WAFBypass(client)
        self.assertIsNotNone(waf)
        self.assertIn('sqli', waf._payloads)
        self.assertIn('xss', waf._payloads)
        client.close()

    def test_waf_payloads_loaded(self):
        client = AxiomClient()
        waf = WAFBypass(client)
        self.assertGreater(len(waf._payloads.get('sqli', [])), 0)
        self.assertGreater(len(waf._payloads.get('xss', [])), 0)
        client.close()

    def test_ratelimit_init(self):
        client = AxiomClient()
        rl = RateLimitBypass(client)
        self.assertIsNotNone(rl)
        client.close()

    def test_botdetect_init(self):
        client = AxiomClient()
        bd = BotDetectionBypass(client)
        self.assertIsNotNone(bd)
        client.close()


class TestScan(unittest.TestCase):
    def test_port_scanner_init(self):
        client = AxiomClient()
        ps = PortScanner(client)
        self.assertIsNotNone(ps)
        client.close()

    def test_dirbuster_init(self):
        client = AxiomClient()
        db = DirBuster(client)
        self.assertIsNotNone(db)
        client.close()

    def test_vuln_detector_init(self):
        client = AxiomClient()
        vd = VulnDetector(client)
        self.assertIsNotNone(vd)
        client.close()


class TestData(unittest.TestCase):
    def test_payloads_file(self):
        path = os.path.join(os.path.dirname(__file__), '..', 'data', 'bypass_payloads.json')
        with open(path) as f:
            data = json.load(f)
        self.assertIn('sqli', data)
        self.assertIn('xss', data)
        self.assertGreater(len(data['sqli']), 0)

    def test_waf_signatures_file(self):
        path = os.path.join(os.path.dirname(__file__), '..', 'data', 'waf_signatures.json')
        with open(path) as f:
            data = json.load(f)
        self.assertIn('cloudflare', data)
        self.assertGreater(len(data), 5)

    def test_user_agents_file(self):
        path = os.path.join(os.path.dirname(__file__), '..', 'data', 'user_agents.json')
        with open(path) as f:
            data = json.load(f)
        self.assertGreater(len(data), 0)

    def test_cdn_ips_file(self):
        path = os.path.join(os.path.dirname(__file__), '..', 'data', 'cdn_ips.json')
        with open(path) as f:
            data = json.load(f)
        self.assertIn('cloudflare', data)


if __name__ == '__main__':
    unittest.main()
