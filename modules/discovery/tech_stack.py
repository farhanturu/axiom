import re
from typing import Dict, Optional, List
from core.client import AxiomClient
from core.utils import extract_base_url

class TechDetector:
    def __init__(self, client: AxiomClient):
        self.client = client

    def detect(self, url: str) -> Dict:
        result = {
            'url': url,
            'server': None,
            'programming_lang': [],
            'frameworks': [],
            'cms': None,
            'analytics': [],
            'other': []
        }
        try:
            resp = self.client.get(url, timeout=15)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text[:50000]

            result['server'] = headers.get('server')
            result['powered_by'] = headers.get('x-powered-by')

            self._detect_lang(headers, body, result)
            self._detect_frameworks(headers, body, result)
            self._detect_cms(body, result)
            self._detect_analytics(body, result)

            return result
        except Exception as e:
            result['error'] = str(e)
            return result

    def _detect_lang(self, headers: Dict, body: str, result: Dict):
        server = headers.get('server', '').lower()
        powered = headers.get('x-powered-by', '').lower()

        if 'nginx' in server or 'apache' in server or 'iis' in server or 'caddy' in server:
            result['other'].append(f'web_server: {headers.get("server")}')

        if 'php' in powered or 'php' in body[:2000].lower():
            result['programming_lang'].append('PHP')
        if 'asp.net' in powered or 'asp.net' in headers.get('x-aspnet-version', '').lower():
            result['programming_lang'].append('ASP.NET')
        if 'express' in body[:3000].lower():
            result['programming_lang'].append('Node.js/Express')
        if 'django' in body.lower() or 'csrftoken' in body.lower():
            result['programming_lang'].append('Python/Django')
        if 'rails' in body.lower() or 'ruby' in body.lower():
            result['programming_lang'].append('Ruby on Rails')
        if 'laravel' in body.lower() or 'livewire' in body.lower():
            result['programming_lang'].append('PHP/Laravel')

    def _detect_frameworks(self, headers: Dict, body: str, result: Dict):
        patterns = {
            'React': r'react(\.min)?\.js|__NEXT_DATA__|_next/static',
            'Vue.js': r'vue(\.min)?\.js|__VUE__|data-v-',
            'Angular': r'angular(\.min)?\.js|ng-app|ng-controller',
            'jQuery': r'jquery(\.min)?\.js|\$\(document\)\.ready',
            'Bootstrap': r'bootstrap(\.min)?\.(css|js)|col-md-|col-xs-',
            'Tailwind': r'tailwindcss|class="[^"]*[mp][trblxy]?-\d+',
            'FontAwesome': r'font-awesome|fontawesome|fa-',
            'Sass': r'\.scss|sass',
        }
        for name, pattern in patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                result['frameworks'].append(name)

    def _detect_cms(self, body: str, result: Dict):
        patterns = {
            'WordPress': r'wp-content|wp-includes|wp-json|wordpress',
            'Drupal': r'drupal|Drupal\.settings|Drupal\.ajax',
            'Joomla': r'joomla|com_content|com_contact',
            'Magento': r'magento|Mage\.|skin/frontend',
            'Shopify': r'shopify|myshopify\.com|cart\.js',
            'Wix': r'wix\.com|Wix\.js|static\.wixstatic',
            'Squarespace': r'squarespace\.com|static1\.squarespace',
        }
        for name, pattern in patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                result['cms'] = name
                break

    def _detect_analytics(self, body: str, result: Dict):
        patterns = {
            'Google Analytics': r'google-analytics\.com|ga\(|gtag\(|GA_',
            'Facebook Pixel': r'facebook\.com/tr|fbq\(|fb_pixel',
            'Hotjar': r'hotjar\.com|hj\(',
            'Cloudflare': r'cloudflare|cf-ray|cdn-cgi',
            'New Relic': r'newrelic\.com|NREUM',
            'Intercom': r'intercom\.io|intercomSettings',
        }
        for name, pattern in patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                result['analytics'].append(name)
