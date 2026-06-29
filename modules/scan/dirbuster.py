import os
from typing import Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.client import AxiomClient
from core.utils import extract_base_url

class DirBuster:
    def __init__(self, client: AxiomClient, wordlist_path: Optional[str] = None, max_workers: int = 20):
        self.client = client
        self.max_workers = max_workers
        self._common_dirs = [
            'admin', 'login', 'wp-admin', 'wp-content', 'wp-includes', 'administrator',
            'backup', 'backups', 'bak', 'config', 'css', 'js', 'images', 'img',
            'assets', 'static', 'uploads', 'upload', 'download', 'downloads',
            'api', 'v1', 'v2', 'rest', 'graphql', 'api/v1', 'api/v2',
            '.git', '.svn', '.env', 'db', 'database', 'sql', 'dump',
            'test', 'tests', 'testing', 'dev', 'development', 'staging',
            'phpmyadmin', 'pma', 'mysql', 'phpPgAdmin',
            'server-status', 'server-info', 'cgi-bin', 'cgi',
            'xmlrpc.php', 'wp-login.php', 'index.php', 'index.html',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'favicon.ico',
            'README.md', 'CHANGELOG.md', 'LICENSE', 'package.json',
            'composer.json', 'Dockerfile', 'docker-compose.yml',
            '.htaccess', '.htpasswd', 'web.config',
            'panel', 'cpanel', 'whm', 'webmail', 'mail',
            'forum', 'chat', 'support', 'help', 'docs', 'documentation',
            'sdk', 'client', 'mobile', 'app', 'webapp',
            'status', 'health', 'healthcheck', 'ping', 'metrics',
            'swagger', 'swagger-ui', 'api-docs', 'openapi',
            'proxy', 'cdn', 'cache', 'storage',
            'tmp', 'temp', 'log', 'logs', 'error', 'errors',
        ]

    def _check_url(self, base_url: str, path: str) -> Optional[Dict]:
        url = f'{base_url.rstrip("/")}/{path.lstrip("/")}'
        try:
            resp = self.client.get(url, timeout=10)
            if resp.status_code != 404:
                return {
                    'url': url,
                    'status': resp.status_code,
                    'size': len(resp.text),
                    'content_type': resp.headers.get('content-type', 'unknown')[:50],
                }
            return None
        except:
            return None

    def scan(self, url: str, extensions: Optional[List[str]] = None) -> Dict:
        base = extract_base_url(url)
        result = {'base_url': base, 'found': [], 'scanned': 0}

        targets = [d for d in self._common_dirs]
        if extensions:
            targets.extend([f'{d}.{ext}' for d in self._common_dirs[:30] for ext in extensions])

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futs = {executor.submit(self._check_url, base, path): path for path in targets}
            for fut in as_completed(futs):
                result['scanned'] += 1
                found = fut.result()
                if found:
                    result['found'].append(found)

        result['found'].sort(key=lambda x: x['status'])
        return result

    def recursive_scan(self, url: str, depth: int = 1) -> Dict:
        results = self.scan(url)
        if depth > 1:
            for item in results['found'][:5]:
                if item['status'] == 200 and not item['url'].endswith(('.php', '.html', '.js', '.css', '.png', '.jpg')):
                    sub = self.recursive_scan(item['url'], depth - 1)
                    results['found'].extend(sub.get('found', []))
        return results

    def custom_wordlist(self, url: str, wordlist: List[str]) -> Dict:
        base = extract_base_url(url)
        result = {'base_url': base, 'found': [], 'scanned': 0}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futs = {executor.submit(self._check_url, base, w): w for w in wordlist}
            for fut in as_completed(futs):
                result['scanned'] += 1
                found = fut.result()
                if found:
                    result['found'].append(found)
        return result

    def common_files(self, url: str) -> Dict:
        target = extract_base_url(url)
        files = [
            'robots.txt', 'sitemap.xml', 'sitemap_index.xml', 'crossdomain.xml',
            '.env', '.git/config', '.svn/entries', 'Dockerfile', 'docker-compose.yml',
            'composer.json', 'package.json', 'yarn.lock', 'package-lock.json',
            'webpack.config.js', 'tsconfig.json', 'Procfile', 'Makefile',
            'README.md', 'CHANGELOG.md', 'SECURITY.md', 'CONTRIBUTING.md',
            'LICENSE', 'LICENSE.txt', 'LICENSE.md',
            'phpinfo.php', 'info.php', 'test.php', 'admin.php',
            'wp-config.php', 'wp-config.php.bak', 'wp-config.old',
            'config.php', 'config.php.bak', 'config.inc.php',
            '.htaccess', '.htpasswd', 'web.config',
            'error_log', 'error.log', 'access.log', 'debug.log',
            'dump.sql', 'backup.sql', 'db.sql', 'database.sql',
            'index.php', 'index.html', 'index.htm', 'default.aspx',
            'favicon.ico', 'apple-touch-icon.png',
            'security.txt', '.well-known/security.txt',
        ]
        return self.custom_wordlist(target, files)
