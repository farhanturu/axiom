import re
import json
import socket
import ipaddress
import hashlib
import base64
from typing import Set, Optional, Tuple
from urllib.parse import urlparse, urljoin

def extract_domain(url: str) -> str:
    parsed = urlparse(url if '://' in url else f'http://{url}')
    return parsed.netloc.lower()

def extract_base_url(url: str) -> str:
    parsed = urlparse(url if '://' in url else f'http://{url}')
    return f"{parsed.scheme}://{parsed.netloc}"

def is_valid_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except:
        return False

def is_valid_domain(target: str) -> bool:
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, target))

def resolve_domain(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def gather_ips(domain: str) -> Set[str]:
    ips = set()
    try:
        for info in socket.getaddrinfo(domain, None):
            ip = info[4][0]
            if is_valid_ip(ip):
                ips.add(ip)
    except:
        pass
    return ips

def cidr_contains(ip: str, cidr_list: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in cidr_list:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
    except:
        pass
    return False

def fingerprint_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()[:16]

def encode_payload(payload: str, encoding: str = 'base64') -> str:
    if encoding == 'base64':
        return base64.b64encode(payload.encode()).decode()
    elif encoding == 'hex':
        return payload.encode().hex()
    elif encoding == 'url':
        from urllib.parse import quote
        return quote(payload)
    return payload

def decode_base64(data: str) -> str:
    try:
        return base64.b64decode(data).decode()
    except:
        return data

def extract_links(html: str, base_url: str) -> Set[str]:
    links = set()
    patterns = [
        r'href=[\'"]?([^\'" >]+)',
        r'src=[\'"]?([^\'" >]+)',
        r'action=[\'"]?([^\'" >]+)',
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, html, re.IGNORECASE):
            url = match.group(1)
            if url.startswith('http'):
                links.add(url)
            elif url.startswith('/') or url.startswith('./') or url.startswith('../') or url.startswith('?'):
                links.add(urljoin(base_url, url))
    return links

def parse_cookies(cookie_str: str) -> dict:
    cookies = {}
    for item in cookie_str.split(';'):
        if '=' in item:
            key, value = item.strip().split('=', 1)
            cookies[key] = value
    return cookies

def sanitize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    return url

def timedelta_str(seconds: float) -> str:
    if seconds < 1:
        return f'{int(seconds * 1000)}ms'
    elif seconds < 60:
        return f'{seconds:.2f}s'
    else:
        return f'{int(seconds // 60)}m {int(seconds % 60)}s'
