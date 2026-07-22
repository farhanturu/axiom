<div align="center">

<img src="logo.svg" width="120" height="120" alt="Axiom Logo"/>

# AXIOM

**Multi-Layer Security Bypass Framework**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-00ff00.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/Version-2.1.0-06b6d4.svg?style=flat-square)](https://github.com/farhanturu/axiom/releases)
[![Status](https://img.shields.io/badge/Status-Stable-brightgreen.svg?style=flat-square)](https://github.com/farhanturu/axiom)

---

Penetration testing toolkit for CDN, WAF, CAPTCHA, bot detection, and rate limit evaluation.

**Designed for authorized security testing and educational purposes only.**

</div>

---

## Features

```
  Discovery
  ├── CDN detection       Cloudflare, CloudFront, Fastly, Akamai, Imperva
  ├── WAF fingerprinting  20+ WAFs with confidence scoring
  ├── Origin IP hunting   crt.sh, DNS history, subdomain enumeration
  └── Tech stack          Server, language, framework, CMS detection

  Bypass
  ├── WAF evasion         200+ payloads (SQLi, XSS, LFI, RCE, SSRF)
  ├── CAPTCHA solving     OCR, audio STT, 2captcha, CapSolver
  ├── Rate limit bypass   Header spoof, burst, slowloris, chunked
  ├── Bot detection       UA rotation, TLS fingerprint, referer spoof
  ├── Honeypot detection  Hidden fields, CSS traps, timing analysis
  └── IP block bypass     Proxy rotation, geo-spoof, Tor network

  Scan
  ├── Port scanner        1000+ ports with async scanning
  ├── Directory busting   500+ paths, recursive depth control
  └── Vulnerability       Headers, redirects, SQLi, XSS, SSRF, XXE
```

## Installation

```bash
git clone https://github.com/farhanturu/axiom.git
cd axiom

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### Optional Dependencies

```bash
# Browser automation (for CAPTCHA/JS challenges)
pip install playwright
playwright install chromium

# CAPTCHA solving
pip install 2captcha-python

# Advanced TLS fingerprinting
pip install tls-client
```

## Quick Start

```bash
# Full security assessment
python3 main.py -t https://target.com --full

# Discovery only
python3 main.py -t https://target.com --discover

# WAF bypass testing
python3 main.py -t https://target.com --bypass waf --param id

# Port scanning
python3 main.py -t https://target.com --scan ports

# Generate report
python3 main.py -t https://target.com --full -o report.json
```

## Usage

### Discovery

```bash
# Full discovery (CDN, WAF, origin IPs)
python3 main.py -t https://target.com --discover

# With technology detection
python3 main.py -t https://target.com --discover --tech
```

### Bypass

```bash
# All bypass techniques
python3 main.py -t https://target.com --bypass all

# WAF bypass with custom parameter
python3 main.py -t https://target.com --bypass waf --param id

# CAPTCHA and rate limit testing
python3 main.py -t https://target.com --bypass captcha

# Bot detection evasion
python3 main.py -t https://target.com --bypass botdetect
```

### Scan

```bash
# Full scan
python3 main.py -t https://target.com --scan all

# Port scan only
python3 main.py -t https://target.com --scan ports

# Directory enumeration
python3 main.py -t https://target.com --scan dirs

# Quick scan (top 100 ports)
python3 main.py -t https://target.com --scan ports --quick
```

### Proxy

```bash
# Test proxy connectivity
python3 main.py --proxy-action check --proxies http://proxy1:8080

# Tor integration
python3 main.py --proxy-action tor --new-ip
```

## Architecture

```
axiom/
├── main.py                    Entry point
├── requirements.txt           Dependencies
├── CHANGELOG.md               Version history
│
├── core/
│   ├── client.py              HTTP client with async support
│   ├── proxy.py               Proxy rotation and Tor
│   ├── fingerprint.py         Browser fingerprint spoofing
│   ├── tls.py                 TLS fingerprint emulation
│   ├── reporter.py            Report generation (JSON/HTML)
│   └── utils.py               Utilities
│
├── modules/
│   ├── discovery/
│   │   ├── cdn_finder.py      CDN and WAF detection
│   │   ├── origin_ip.py       Origin IP discovery
│   │   └── tech_stack.py      Technology detection
│   │
│   ├── bypass/
│   │   ├── waf.py             WAF bypass (200+ payloads)
│   │   ├── captcha.py         CAPTCHA solving
│   │   ├── ratelimit.py       Rate limit bypass
│   │   ├── botdetect.py       Bot detection evasion
│   │   ├── honeypot.py        Honeypot detection
│   │   └── ipblock.py         IP block bypass
│   │
│   └── scan/
│       ├── port.py            Async port scanner
│       ├── dirbuster.py       Directory enumeration
│       └── vuln.py            Vulnerability detection
│
└── data/
    ├── payloads/              Payload database
    ├── waf_signatures.json    WAF detection rules
    ├── user_agents.json       Browser user agents
    └── cdn_ips.json           CDN IP ranges
```

## Supported

| Category | Items |
|----------|-------|
| CDNs | Cloudflare, CloudFront, Fastly, Akamai, Imperva, StackPath |
| WAFs | Cloudflare, AWS, Imperva, Akamai, F5, ModSecurity, Sucuri, Barracuda, Fortinet |
| Payloads | SQLi, XSS, LFI, RCE, SSRF, XXE, Header Injection |
| Protocols | HTTP/1.1, HTTP/2, TLS 1.2/1.3 |

## Ethical Use

Axiom is designed for:

- Authorized penetration testing
- Internal security assessments
- CTF competitions
- Security research and education

**Do not use against systems without explicit written authorization.**

## License

MIT License

## Contact

- Email: paongtech@gmail.com
- GitHub: https://github.com/farhanturu/axiom
