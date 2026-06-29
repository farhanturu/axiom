#!/usr/bin/env python3
import argparse
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.client import AxiomClient
from core.proxy import ProxyManager
from core.fingerprint import FingerprintGenerator
from core.output import Output
from core.utils import extract_domain, sanitize_url

out = Output()


def cmd_discover(args):
    client = AxiomClient(concurrent=20)
    out.banner()
    out.divider()
    out.info(f'Starting discovery on {args.target}')

    from modules.discovery.cdn_finder import CDNFinder
    from modules.discovery.origin_ip import OriginDiscovery
    from modules.discovery.tech_stack import TechDetector

    url = sanitize_url(args.target)
    domain = extract_domain(url)

    out.info('Detecting CDN and WAF...')
    cdn = CDNFinder(client)
    cdn_result = cdn.detect_all(url)
    out.table('CDN & WAF Detection', ['Property', 'Value'], [
        ['Domain', domain],
        ['CDN', cdn_result.get('cdn', 'None') or 'None'],
        ['WAF', cdn_result.get('waf', 'None') or 'None'],
    ])
    if cdn_result.get('waf_detail') and cdn_result['waf_detail'].get('indicators'):
        for ind in cdn_result['waf_detail']['indicators']:
            out.info(f'  WAF indicator: {ind}')

    out.info('Enumerating subdomains and hunting for origin IPs...')
    origin = OriginDiscovery(client)
    origin_result = origin.full_discovery(domain, api_key=args.api_key)

    rows = []
    for ip in origin_result.get('a_records', []):
        rows.append(['A Records', ip, 'Direct'])
    for item in origin_result.get('mx_records', [])[:10]:
        rows.append(['MX Record', item, 'Mail server'])
    for item in origin_result.get('crt_sh_ips', [])[:15]:
        rows.append(['Certificate', item, 'crt.sh'])
    for item in origin_result.get('subdomain_ips', [])[:20]:
        rows.append(['Subdomain', item, 'Enumeration'])
    for item in origin_result.get('ssl_san_ips', [])[:10]:
        rows.append(['SSL SAN', item, 'Certificate SAN'])

    if rows:
        out.table('Origin IP Candidates', ['Source', 'IP / Record', 'Method'], rows)
    else:
        out.warn('No origin IP candidates found')

    total_ips = len(origin_result.get('origin_candidates', []))
    out.success(f'Discovery complete — found {total_ips} potential origin IPs')

    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump({'cdn': cdn_result, 'origin': origin_result}, f, indent=2)

    if args.tech:
        out.info('Detecting technology stack...')
        tech = TechDetector(client)
        tech_result = tech.detect(url)
        tech_rows = []
        for key in ['server', 'powered_by']:
            if tech_result.get(key):
                tech_rows.append([key.replace('_', ' ').title(), str(tech_result[key])])
        for key in ['programming_lang', 'frameworks', 'analytics']:
            if tech_result.get(key):
                tech_rows.append([key.replace('_', ' ').title(), ', '.join(tech_result[key])])
        if tech_result.get('cms'):
            tech_rows.append(['CMS', tech_result['cms']])
        if tech_rows:
            out.table('Technology Stack', ['Property', 'Value'], tech_rows)

    client.close()


def cmd_bypass(args):
    client = AxiomClient(concurrent=10)
    out.banner()
    out.divider()
    out.info(f'Starting bypass testing on {args.target}')

    url = sanitize_url(args.target)

    if args.bypass in ('all', 'waf'):
        from modules.bypass.waf import WAFBypass
        out.info(f'Testing WAF bypass with payloads (param: {args.param})...')
        waf = WAFBypass(client)
        waf_result = waf.all_tests(url, param=args.param, method=args.method)
        total_attempts = sum(len(v) for v in waf_result.values())
        successful = 0
        for category, tests in waf_result.items():
            for test in tests:
                if isinstance(test, dict) and not test.get('blocked', True):
                    successful += 1
        out.table('WAF Bypass Results', ['Category', 'Attempts', 'Bypassed'], [
            ['SQLi', len(waf_result.get('sqli', [])), sum(1 for t in waf_result['sqli'] if not t.get('blocked', True))],
            ['XSS', len(waf_result.get('xss', [])), sum(1 for t in waf_result['xss'] if not t.get('blocked', True))],
            ['LFI', len(waf_result.get('lfi', [])), sum(1 for t in waf_result['lfi'] if not t.get('blocked', True))],
            ['RCE', len(waf_result.get('rce', [])), sum(1 for t in waf_result['rce'] if not t.get('blocked', True))],
            ['Header Inj.', len(waf_result.get('header_injection', [])), sum(1 for t in waf_result['header_injection'] if not t.get('blocked', True))],
        ])
        out.info(f'WAF bypass: {successful}/{total_attempts} payloads bypassed')

    if args.bypass in ('all', 'captcha'):
        from modules.bypass.captcha import CaptchaSolver, CaptchaTester
        out.info('Analyzing CAPTCHA implementation...')
        solver = CaptchaSolver(client)
        tester = CaptchaTester(client, solver)
        try:
            resp = client.get(url, timeout=15)
            captcha_info = tester.detect_captcha_type(resp.text)
            if captcha_info['has_captcha']:
                out.table('CAPTCHA Detection', ['Type', 'Details'], [
                    [ctype, 'detected'] for ctype in captcha_info['types']
                ])
                if 'sitekey' in captcha_info.get('details', {}):
                    out.info(f'  Sitekey: {captcha_info["details"]["sitekey"]}')
            else:
                out.info('  No CAPTCHA detected on initial page')

            rate_test = tester.bypass_rate_limit(url)
            out.table('Rate Limit Test', ['Metric', 'Value'], [
                ['Total requests', str(rate_test['total'])],
                ['Successful', str(rate_test['successful'])],
                ['Blocked', str(rate_test['blocked'])],
                ['Blocked after', str(rate_test['blocked_after']) if rate_test['blocked_after'] else 'N/A'],
            ])
        except Exception as e:
            out.error(f'CAPTCHA test failed: {e}')

    if args.bypass in ('all', 'ratelimit'):
        from modules.bypass.ratelimit import RateLimitBypass
        out.info('Testing rate limit bypass techniques...')
        rl = RateLimitBypass(client)
        rl_result = rl.all_bypass_patterns(url)
        out.table('Rate Limit Bypass', ['Technique', 'Requests', 'Success'], [
            ['Header Spoof', rl_result['header_spoof']['total_requests'], rl_result['header_spoof']['successful']],
            ['Burst Pattern', rl_result['burst_pattern']['total'], rl_result['burst_pattern']['successful']],
            ['Slowloris Pattern', rl_result['slowloris_pattern']['total'], rl_result['slowloris_pattern']['successful']],
        ])
        if rl_result['timing_analysis'].get('rate_limit_detected'):
            out.warn('  Rate limiting detected (increasing response times)')

    if args.bypass in ('all', 'botdetect'):
        from modules.bypass.botdetect import BotDetectionBypass
        out.info('Testing bot detection bypass...')
        bd = BotDetectionBypass(client)
        bd_result = bd.complete_test(url)
        for category, tests in bd_result.items():
            blocked = sum(1 for t in tests if t.get('blocked'))
            total = len(tests)
            out.table(f'Bot Detection: {category.title()}', ['Scenario', 'Status', 'Blocked'], [
                [t.get('label', '?'), str(t.get('status', '?')), 'Yes' if t.get('blocked') else 'No']
                for t in tests
            ])

    client.close()


def cmd_scan(args):
    client = AxiomClient(concurrent=50)
    out.banner()
    out.divider()
    out.info(f'Starting scan on {args.target}')

    url = sanitize_url(args.target)
    domain = extract_domain(url)

    from modules.scan.port import PortScanner
    from modules.scan.dirbuster import DirBuster
    from modules.scan.vuln import VulnDetector

    if args.scan in ('all', 'ports'):
        out.info('Scanning ports...')
        ps = PortScanner(client)
        host = domain
        scan_result = ps.quick_scan(host) if args.quick else ps.scan_domain(domain)
        if 'error' in scan_result:
            out.error(f'Port scan failed: {scan_result["error"]}')
        elif scan_result.get('open_ports'):
            out.table('Open Ports', ['Port', 'Service', 'State'], [
                [str(p['port']), p.get('service', 'unknown'), p.get('state', 'open')]
                for p in scan_result['open_ports']
            ])
        else:
            out.info('  No open ports found on common ports')

    if args.scan in ('all', 'dirs'):
        out.info('Directory enumeration...')
        db = DirBuster(client)
        dir_result = db.scan(url)
        if dir_result.get('found'):
            out.table('Discovered Paths', ['URL', 'Status', 'Size'], [
                [d['url'], str(d['status']), str(d['size'])]
                for d in dir_result['found'][:20]
            ])
        else:
            out.info('  No directories discovered')

    if args.scan in ('all', 'vulns'):
        out.info('Checking for common vulnerabilities...')
        vd = VulnDetector(client)
        vuln_result = vd.full_scan(url)
        for check, data in vuln_result.items():
            vuln_name = check.replace('_', ' ').title()
            if isinstance(data, dict):
                if data.get('vulnerable'):
                    out.warn(f'  {vuln_name}: VULNERABLE')
                    for test in data.get('tests', [])[:3]:
                        out.info(f'    - Payload: {test.get("payload", test.get("target", ""))[:60]}')
                elif data.get('missing_security_headers'):
                    out.info(f'  {vuln_name}: Missing: {", ".join(data["missing_security_headers"][:5])}')
                else:
                    out.info(f'  {vuln_name}: OK')

    if args.output:
        import json
        result = {}
        if args.scan in ('all', 'ports'):
            result['ports'] = scan_result if 'scan_result' in dir() else {}
        if args.scan in ('all', 'dirs'):
            result['directories'] = dir_result if 'dir_result' in dir() else {}
        if args.scan in ('all', 'vulns'):
            result['vulnerabilities'] = vuln_result if 'vuln_result' in dir() else {}
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)

    client.close()


def cmd_full(args):
    args.tech = True
    import types
    args.scan = 'all'
    args.bypass = 'all'
    out.info('Running full Axiom assessment...')
    cmd_discover(args)
    print()
    cmd_scan(args)
    print()
    cmd_bypass(args)


def cmd_proxy(args):
    out.info('Proxy management tools')
    from core.proxy import TorProxy

    if args.action == 'check':
        pm = ProxyManager()
        if args.proxies:
            pm.add_list(args.proxies)
            out.info(f'Testing {len(args.proxies)} proxies...')
            results = pm.validate_all(timeout=args.timeout)
            alive = [p for p, r in results.items() if r]
            dead = [p for p, r in results.items() if not r]
            out.table('Proxy Check Results', ['Status', 'Count'], [
                ['Alive', str(len(alive))],
                ['Dead', str(len(dead))],
            ])
            for p in alive[:10]:
                out.success(f'  {p}')

    elif args.action == 'tor':
        tor = TorProxy(port=args.tor_port)
        if args.new_ip:
            if tor.new_identity():
                out.success('Tor identity rotated')
            else:
                out.error('Failed to rotate Tor identity (check control port & password)')
        out.info(f'Tor proxy status: {tor.alive_count} active')


def main():
    parser = argparse.ArgumentParser(
        prog='axiom',
        description='Multi-Layer Security Bypass Framework — CDN/WAF/CAPTCHA/Bot Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  axiom --target https://example.com --discover          # Discover CDN, WAF, origin IPs
  axiom --target https://example.com --bypass all         # Test all bypass techniques
  axiom --target https://example.com --scan all           # Full vulnerability scan
  axiom --target https://example.com --full               # Complete assessment
  axiom --target https://example.com --bypass waf --param id  # WAF bypass with custom param
        '''
    )

    parser.add_argument('--target', '-t', help='Target URL or domain')
    parser.add_argument('--output', '-o', help='Output results to JSON file')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress output')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--api-key', '-k', help='API key for SecurityTrails/hunter.io')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10s)')

    discover = parser.add_argument_group('Discovery')
    discover.add_argument('--discover', action='store_true', help='Run discovery (CDN, WAF, origin IP)')
    discover.add_argument('--tech', action='store_true', help='Detect technology stack')

    bypass = parser.add_argument_group('Bypass')
    bypass.add_argument('--bypass', choices=['all', 'waf', 'captcha', 'ratelimit', 'botdetect'], help='Bypass type')
    bypass.add_argument('--param', default='id', help='Parameter name for payload injection (default: id)')
    bypass.add_argument('--method', choices=['GET', 'POST'], default='GET', help='HTTP method for bypass tests')

    scan = parser.add_argument_group('Scan')
    scan.add_argument('--scan', choices=['all', 'ports', 'dirs', 'vulns'], help='Scan type')
    scan.add_argument('--quick', action='store_true', help='Quick scan (top ports only)')
    scan.add_argument('--recursive', type=int, default=0, help='Directory scan depth')

    full = parser.add_argument_group('Full')
    full.add_argument('--full', action='store_true', help='Run full assessment (discover + scan + bypass)')

    proxy = parser.add_argument_group('Proxy')
    proxy.add_argument('--proxy-action', choices=['check', 'tor'], help='Proxy management action')
    proxy.add_argument('--proxies', nargs='+', help='List of proxies to test')
    proxy.add_argument('--tor-port', type=int, default=9050, help='Tor SOCKS port')
    proxy.add_argument('--new-ip', action='store_true', help='Request new Tor identity')

    args = parser.parse_args()

    if not any([args.discover, args.bypass, args.scan, args.full, args.proxy_action]):
        parser.print_help()
        print('\n[!] Use --target and at least one action. Example: axiom -t https://example.com --full')
        sys.exit(1)

    os.makedirs(os.path.join(os.path.dirname(__file__), 'data'), exist_ok=True)

    if args.proxy_action:
        cmd_proxy(args)
        return

    if not args.target:
        parser.error('--target is required for discovery, bypass, or scan actions')

    if args.full:
        cmd_full(args)
    elif args.discover:
        cmd_discover(args)
    elif args.bypass:
        cmd_bypass(args)
    elif args.scan:
        cmd_scan(args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        out.warn('Interrupted by user')
        sys.exit(1)
    except Exception as e:
        out.error(f'Unexpected error: {e}')
        if '-v' in sys.argv or '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
