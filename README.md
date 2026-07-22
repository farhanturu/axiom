<div align="center">

<img src="logo.svg" width="120" height="120" alt="Axiom Logo"/>

# AXIOM

**Multi-Layer Security Bypass Framework**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-00ff00.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/Version-2.1.0-06b6d4.svg?style=flat-square)](https://github.com/farhanturu/axiom/releases)

[![Documentation](https://img.shields.io/badge/Docs-Read%20Now-06b6d4?style=for-the-badge)](https://farhanturu.github.io/axiom)
[![GitHub](https://img.shields.io/badge/GitHub-Star-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/farhanturu/axiom)

---

Penetration testing toolkit for CDN, WAF, CAPTCHA, bot detection, and rate limit evaluation.

**Designed for authorized security testing and educational purposes only.**

</div>

---

## Quick Start (2 Minutes)

```bash
# 1. Clone
git clone https://github.com/farhanturu/axiom.git && cd axiom

# 2. Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. Run
python3 main.py -t https://target.com --full
```

---

## What Can Axiom Do?

<table>
<tr><td>🔍</td><td><b>Discover</b> - Find CDN, WAF, origin IPs, and tech stack</td></tr>
<tr><td>⚡</td><td><b>Bypass</b> - Test WAF evasion, CAPTCHA, rate limits, bot detection</td></tr>
<tr><td>🛡️</td><td><b>Scan</b> - Port scan, directory busting, vulnerability detection</td></tr>
</table>

---

## Commands

### Discovery
```bash
python3 main.py -t https://target.com --discover        # Find CDN & WAF
python3 main.py -t https://target.com --discover --tech  # + Tech stack
```

### Bypass
```bash
python3 main.py -t https://target.com --bypass waf       # WAF bypass test
python3 main.py -t https://target.com --bypass captcha   # CAPTCHA test
python3 main.py -t https://target.com --bypass all       # All bypass tests
```

### Scan
```bash
python3 main.py -t https://target.com --scan ports       # Port scan
python3 main.py -t https://target.com --scan dirs        # Directory scan
python3 main.py -t https://target.com --scan all         # Full scan
```

### Full Assessment
```bash
python3 main.py -t https://target.com --full             # Everything at once
```

### Help
```bash
python3 main.py --help                                   # Show all commands
python3 main.py --docs                                   # Open documentation
```

---

## Features

| Feature | Description |
|---------|-------------|
| CDN Detection | Cloudflare, CloudFront, Fastly, Akamai, Imperva |
| WAF Fingerprinting | 20+ WAFs with confidence scoring |
| Origin IP Hunting | crt.sh, DNS history, subdomain enumeration |
| WAF Bypass | 200+ payloads (SQLi, XSS, LFI, RCE, SSRF) |
| CAPTCHA Testing | OCR, audio STT, rate limit detection |
| Bot Detection | UA rotation, TLS fingerprint, referer spoof |
| Port Scanner | 1000+ ports with async scanning |
| Directory Buster | 500+ paths, recursive depth control |
| Vulnerability Scan | Headers, redirects, SQLi, XSS, SSRF |

---

## Documentation

**Full documentation with examples and API reference:**

[📖 Read the Docs](https://farhanturu.github.io/axiom)

---

## Examples

### Discovery Output
```
[+] Starting discovery on https://example.com
[+] Detecting CDN and WAF...

       CDN & WAF Detection
╭──────────┬─────────────────────╮
│ Property │ Value               │
├──────────┼─────────────────────┤
│ Domain   │ example.com         │
│ CDN      │ Cloudflare          │
│ WAF      │ Cloudflare WAF      │
╰──────────┴─────────────────────╯
```

### Bypass Output
```
[+] Testing WAF bypass with payloads...

         WAF Bypass Results
╭──────────┬──────────┬──────────╮
│ Category │ Attempts │ Bypassed │
├──────────┼──────────┼──────────┤
│ SQLi     │ 20       │ 3        │
│ XSS      │ 20       │ 5        │
│ LFI      │ 15       │ 2        │
╰──────────┴──────────┴──────────╯
```

---

## Request a Feature

Have an idea for Axiom? We'd love to hear it!

**[📝 Request a Feature](https://github.com/farhanturu/axiom/issues/new?template=feature_request.md)**

---

## Contributing

We welcome contributions! Here's how:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support

- 📖 [Documentation](https://farhanturu.github.io/axiom)
- 🐛 [Report Bugs](https://github.com/farhanturu/axiom/issues/new?template=bug_report.md)
- 💡 [Request Features](https://github.com/farhanturu/axiom/issues/new?template=feature_request.md)
- 📧 [Email](mailto:paongtech@gmail.com)

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for the security community**

[Star on GitHub](https://github.com/farhanturu/axiom)

</div>
