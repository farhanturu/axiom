import dns.resolver
import dns.exception
import requests
import json
import socket
import ssl
from typing import Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import extract_domain, resolve_domain, gather_ips, cidr_contains
from core.client import AxiomClient

class OriginDiscovery:
    def __init__(self, client: AxiomClient):
        self.client = client
        self._cdn_ips = {
            'cloudflare': ['103.21.244.0/22', '103.22.200.0/22', '104.16.0.0/13', '173.245.48.0/20', '172.64.0.0/13'],
            'cloudfront': ['13.32.0.0/15', '13.224.0.0/14'],
            'fastly': ['151.101.0.0/16', '23.235.32.0/20'],
            'akamai': ['23.0.0.0/12', '23.32.0.0/11', '104.101.0.0/16'],
        }

    def _is_cdn_ip(self, ip: str) -> bool:
        for provider, cidrs in self._cdn_ips.items():
            if cidr_contains(ip, cidrs):
                return True
        return False

    def crt_sh_search(self, domain: str) -> Set[str]:
        ips = set()
        try:
            resp = requests.get(f'https://crt.sh/?q=%.{domain}&output=json', timeout=20)
            if resp.status_code == 200:
                certs = resp.json()
                for cert in certs[:100]:
                    name = cert.get('name_value', '')
                    if name and domain in name:
                        try:
                            addrs = socket.getaddrinfo(name, None)
                            for addr in addrs:
                                ip = addr[4][0]
                                if not self._is_cdn_ip(ip):
                                    ips.add(ip)
                        except:
                            continue
        except:
            pass
        return ips

    def dns_history(self, domain: str) -> Set[str]:
        ips = set()
        records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        for rtype in records:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=10)
                for rdata in answers:
                    value = str(rdata)
                    if rtype == 'MX':
                        mx_domain = value.split()[-1]
                        try:
                            mx_ips = gather_ips(mx_domain)
                            for ip in mx_ips:
                                if not self._is_cdn_ip(ip):
                                    ips.add(f'{ip} (via MX: {mx_domain})')
                        except:
                            pass
                    elif rtype in ['A', 'AAAA']:
                        if not self._is_cdn_ip(value):
                            ips.add(value)
                    elif rtype == 'NS':
                        try:
                            ns_ips = gather_ips(value)
                            for ip in ns_ips:
                                if not self._is_cdn_ip(ip):
                                    ips.add(f'{ip} (via NS: {value})')
                        except:
                            pass
            except:
                continue
        return ips

    def securitytrails_lookup(self, domain: str, api_key: Optional[str] = None) -> Set[str]:
        ips = set()
        if not api_key:
            return ips
        try:
            headers = {'APIKEY': api_key, 'Content-Type': 'application/json'}
            resp = requests.get(
                f'https://api.securitytrails.com/v1/domain/{domain}/subdomains',
                headers=headers, timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                subs = [f'{s}.{domain}' for s in data.get('subdomains', [])[:50]]
                with ThreadPoolExecutor(max_workers=10) as ex:
                    futs = {ex.submit(gather_ips, sub): sub for sub in subs}
                    for fut in as_completed(futs):
                        try:
                            for ip in fut.result():
                                if not self._is_cdn_ip(ip):
                                    ips.add(f'{ip} (via sub: {futs[fut]})')
                        except:
                            pass
        except:
            pass
        return ips

    def subdomain_enum(self, domain: str, wordlist: Optional[List[str]] = None) -> Set[str]:
        ips = set()
        if wordlist is None:
            wordlist = ['www', 'mail', 'ftp', 'admin', 'blog', 'cdn', 'api', 'dev',
                        'staging', 'test', 'portal', 'vpn', 'remote', 'webmail',
                        'direct', 'origin', 'origin-www', 'static', 'assets',
                        'img', 'images', 'ns1', 'ns2', 'mx', 'pop', 'smtp',
                        'secure', 'login', 'app', 'beta', 'shop', 'store',
                        'm', 'mobile', 'dashboard', 'cpanel', 'whm', 'cp',
                        'cloud', 'backup', 'support', 'help', 'forum', 'status']

        def check_sub(sub):
            try:
                fqdn = f'{sub}.{domain}'
                addrs = gather_ips(fqdn)
                result = set()
                for ip in addrs:
                    if not self._is_cdn_ip(ip):
                        result.add(f'{ip} (via {fqdn})')
                return result
            except:
                return set()

        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = [ex.submit(check_sub, sub) for sub in wordlist]
            for fut in as_completed(futs):
                ips.update(fut.result())

        return ips

    def ssl_cert_check(self, domain: str) -> Set[str]:
        ips = set()
        try:
            addrs = socket.getaddrinfo(domain, 443)
            for addr in addrs[:5]:
                ip = addr[4][0]
                try:
                    ctx = ssl.create_default_context()
                    with socket.create_connection((ip, 443), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            for subj in cert.get('subjectAltName', []):
                                if subj[0] == 'IP Address':
                                    val = subj[1]
                                    if not self._is_cdn_ip(val):
                                        ips.add(f'{val} (via SSL SAN)')
                except:
                    continue
        except:
            pass
        return ips

    def full_discovery(self, domain: str, api_key: Optional[str] = None, wordlist: Optional[List[str]] = None) -> Dict:
        result = {
            'domain': domain,
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'crt_sh_ips': [],
            'subdomain_ips': [],
            'ssl_san_ips': [],
            'origin_candidates': [],
        }

        standard_ips = gather_ips(domain)
        result['a_records'] = [ip for ip in standard_ips]

        dns_ips = self.dns_history(domain)
        for item in dns_ips:
            if 'via MX' in item:
                result['mx_records'].append(item)
            elif 'via NS' in item:
                result['ns_records'].append(item)

        crt = self.crt_sh_search(domain)
        result['crt_sh_ips'] = list(crt)

        subs = self.subdomain_enum(domain, wordlist)
        result['subdomain_ips'] = list(subs)

        ssl_ips = self.ssl_cert_check(domain)
        result['ssl_san_ips'] = list(ssl_ips)

        if api_key:
            st_ips = self.securitytrails_lookup(domain, api_key)
            for ip in st_ips:
                result['subdomain_ips'].append(ip)

        candidates = set()
        for ip in result['a_records']:
            if not self._is_cdn_ip(ip):
                candidates.add(ip)
        for ip_list in [result['mx_records'], result['ns_records'],
                        result['crt_sh_ips'], result['subdomain_ips'], result['ssl_san_ips']]:
            for item in ip_list:
                ip = item.split()[0] if item else item
                if ip:
                    candidates.add(ip)

        result['origin_candidates'] = list(candidates)
        return result
