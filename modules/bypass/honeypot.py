import re
from typing import Dict, List, Optional, Set
from core.client import AxiomClient
from core.utils import extract_links, extract_base_url

class HoneypotDetector:
    def __init__(self, client: AxiomClient):
        self.client = client

    def _get_page(self, url: str) -> Optional[str]:
        try:
            resp = self.client.get(url, timeout=15)
            return resp.text if resp.status_code == 200 else None
        except:
            return None

    def detect_hidden_fields(self, html: str) -> List[Dict]:
        fields = []
        patterns = [
            r'<input[^>]*type=["\']hidden["\'][^>]*>',
            r'<input[^>]*style=["\'][^"\']*display:\s*none[^"\']*["\'][^>]*>',
            r'<input[^>]*class=["\'][^"\']*hidden[^"\']*["\'][^>]*>',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                field = match.group(0)
                name = re.search(r'name=["\']([^"\']+)', field)
                value = re.search(r'value=["\']([^"\']*)', field)
                fields.append({
                    'name': name.group(1) if name else 'unknown',
                    'value': value.group(1) if value else '',
                    'html': field[:100],
                })
        return fields

    def detect_trap_links(self, html: str, base_url: str) -> List[Dict]:
        traps = []
        links = extract_links(html, base_url)
        patterns = {
            'display_none': r'display\s*:\s*none',
            'visibility_hidden': r'visibility\s*:\s*hidden',
            'opacity_zero': r'opacity\s*:\s*0',
            'position_absolute_off': r'position\s*:\s*absolute.*(?:left|top)\s*:\s*-\d+',
            'zero_size': r'width\s*:\s*0.*height\s*:\s*0|height\s*:\s*0.*width\s*:\s*0',
        }
        for link in list(links)[:50]:
            try:
                resp = self.client.head(link, timeout=5)
                for label, pattern in patterns.items():
                    if re.search(pattern, str(resp.headers), re.IGNORECASE):
                        traps.append({'url': link, 'method': label})
                        break
            except:
                continue
        return traps

    def detect_css_traps(self, html: str) -> List[Dict]:
        traps = []
        css_patterns = {
            'hover_trap': r'a\[href[^\]]*\]:hover\s*\{[^}]*display[^}]*block|visibility[^}]*visible',
            'invisible_link': r'\.\w+\s*\{[^}]*opacity:\s*0[^}]*\}',
            'off_screen': r'\.\w+\s*\{[^}]*position:\s*absolute[^}]*(?:left|text-indent):\s*-\d+',
        }
        for label, pattern in css_patterns.items():
            if re.search(pattern, html, re.IGNORECASE):
                traps.append({'type': 'css', 'pattern': label})
        return traps

    def detect_timing_traps(self, url: str) -> Dict:
        result = {'timing_anomalies': []}
        delays = [0, 2, 5]
        for delay in delays:
            try:
                start = __import__('time').time()
                self.client.get(f'{url}?__delay={delay}', timeout=30)
                elapsed = __import__('time').time() - start
                if elapsed - delay > 3:
                    result['timing_anomalies'].append({
                        'delay': delay,
                        'actual': round(elapsed, 2),
                        'suspicious': True
                    })
            except:
                continue
        return result

    def detect_honeypot_forms(self, html: str, base_url: str) -> Dict:
        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
        results = []
        for form_html in forms:
            action = re.search(r'action=["\']([^"\']+)', form_html)
            suspicious = False
            indicators = []
            hidden = self.detect_hidden_fields(form_html)
            if hidden:
                suspicious = True
                indicators.append(f'{len(hidden)} hidden fields')
            if re.search(r'password|cc_number|ssn|cvv|credit', form_html, re.IGNORECASE):
                indicators.append('sensitive fields')
            results.append({
                'action': action.group(1) if action else 'unknown',
                'suspicious': suspicious,
                'indicators': indicators,
                'field_count': len(re.findall(r'<input', form_html)),
            })
        return {'forms': results}

    def full_scan(self, url: str) -> Dict:
        html = self._get_page(url)
        if not html:
            return {'error': 'could not fetch page'}

        base = extract_base_url(url)
        return {
            'hidden_fields': self.detect_hidden_fields(html),
            'trap_links': self.detect_trap_links(html, base),
            'css_traps': self.detect_css_traps(html),
            'timing_traps': self.detect_timing_traps(url),
            'forms_analysis': self.detect_honeypot_forms(html, base),
        }
