import socket
import ipaddress
from typing import Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.client import AxiomClient
from core.utils import resolve_domain, extract_domain

class PortScanner:
    def __init__(self, client: AxiomClient, max_workers: int = 50):
        self.client = client
        self.max_workers = max_workers

    COMMON_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
        587: 'SMTP submission', 593: 'HTTP RPC', 636: 'LDAPS', 993: 'IMAPS',
        995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle DB',
        2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel SSL', 2086: 'WHM',
        2087: 'WHM SSL', 2095: 'Webmail', 2096: 'Webmail SSL', 2222: 'DirectAdmin',
        2375: 'Docker', 2376: 'Docker TLS', 3128: 'Squid', 3306: 'MySQL',
        3389: 'RDP', 3690: 'SVN', 4333: 'mSQL', 4444: 'Metasploit', 4848: 'GlassFish',
        5000: 'Flask/HTTP', 5432: 'PostgreSQL', 5555: 'Android ADB', 5800: 'VNC HTTP',
        5900: 'VNC', 5984: 'CouchDB', 6000: 'X11', 6379: 'Redis', 6443: 'Kubernetes',
        6666: 'IRC', 6667: 'IRC', 6668: 'IRC', 6669: 'IRC', 7001: 'WebLogic',
        7077: 'Spark', 8000: 'HTTP-alt', 8001: 'HTTP-alt', 8008: 'HTTP-alt',
        8009: 'AJP', 8080: 'HTTP-proxy', 8081: 'HTTP-proxy', 8083: 'HTTP-proxy',
        8086: 'InfluxDB', 8088: 'HTTP-proxy', 8090: 'HTTP-alt', 8181: 'HTTP-alt',
        8332: 'Bitcoin', 8333: 'Bitcoin', 8443: 'HTTPS-alt', 8888: 'HTTP-alt',
        9000: 'SonarQube', 9001: 'Tor', 9042: 'Cassandra', 9090: 'HTTP-alt',
        9092: 'Kafka', 9100: 'SMB', 9200: 'Elasticsearch', 9300: 'Elasticsearch',
        9418: 'Git', 9999: 'HTTP-alt', 10000: 'Webmin', 11211: 'Memcached',
        11214: 'Memcached', 11215: 'Memcached', 27017: 'MongoDB', 27018: 'MongoDB',
        27019: 'MongoDB', 50000: 'DB2', 50001: 'DB2', 50002: 'DB2',
    }

    def _scan_port(self, host: str, port: int, timeout: float = 2.0) -> Optional[Dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                service = self.COMMON_PORTS.get(port, 'unknown')
                return {'port': port, 'state': 'open', 'service': service}
            return None
        except:
            return None

    def scan_host(self, host: str, ports: Optional[List[int]] = None, timeout: float = 2.0) -> Dict:
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())
        result = {'host': host, 'open_ports': [], 'closed_count': 0}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futs = {executor.submit(self._scan_port, host, port, timeout): port for port in ports}
            for fut in as_completed(futs):
                port_info = fut.result()
                if port_info:
                    result['open_ports'].append(port_info)
                else:
                    result['closed_count'] += 1
        result['open_ports'].sort(key=lambda x: x['port'])
        return result

    def scan_domain(self, domain: str, ports: Optional[List[int]] = None, timeout: float = 2.0) -> Dict:
        host = resolve_domain(domain)
        if not host:
            return {'domain': domain, 'error': 'could not resolve domain'}
        result = self.scan_host(host, ports, timeout)
        result['domain'] = domain
        result['resolved_ip'] = host
        return result

    def quick_scan(self, host: str) -> Dict:
        top_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                     993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
                     8080, 8443, 9200, 27017]
        return self.scan_host(host, top_ports, timeout=1.5)

    def service_detect(self, host: str, port: int) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            if banner:
                first_line = banner.split('\r\n')[0]
                return first_line[:100]
            return self.COMMON_PORTS.get(port, 'unknown')
        except:
            return self.COMMON_PORTS.get(port, 'unknown')
