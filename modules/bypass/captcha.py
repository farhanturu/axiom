import io
import os
import re
import time
import requests
from typing import Optional, Dict, List, Tuple
from PIL import Image, ImageFilter, ImageEnhance
from core.client import AxiomClient

try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

class CaptchaSolver:
    def __init__(self, client: AxiomClient, tesseract_cmd: Optional[str] = None):
        self.client = client
        if tesseract_cmd and TESSERACT_AVAILABLE:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

    def preprocess_image(self, image: Image.Image) -> Image.Image:
        img = image.convert('L')
        img = img.filter(ImageFilter.MedianFilter(size=3))
        threshold = 128
        img = img.point(lambda x: 0 if x < threshold else 255, '1')
        enhancer = ImageEnhance.Contrast(img.convert('L'))
        img = enhancer.enhance(3.0)
        return img

    def ocr_solve(self, image_data: bytes) -> Optional[str]:
        if not TESSERACT_AVAILABLE:
            return None
        try:
            img = Image.open(io.BytesIO(image_data))
            processed = self.preprocess_image(img)
            text = pytesseract.image_to_string(processed, config='--psm 7 -c tessedit_char_whitelist=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
            text = re.sub(r'[^a-zA-Z0-9]', '', text).strip()
            return text if text else None
        except:
            return None

    def audio_solve(self, audio_data: bytes) -> Optional[str]:
        try:
            import tempfile
            import subprocess
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as f:
                f.write(audio_data)
                fpath = f.name
            result = subprocess.run(
                ['whisper', fpath, '--output_format', 'txt'],
                capture_output=True, text=True, timeout=30
            )
            os.unlink(fpath)
            text = re.sub(r'[^a-zA-Z0-9]', '', result.stdout).strip()
            return text if text else None
        except:
            return None

    def service_solve(self, image_data: bytes, service_url: str, api_key: str) -> Optional[str]:
        try:
            import base64
            b64 = base64.b64encode(image_data).decode()
            resp = requests.post(service_url, json={
                'key': api_key,
                'method': 'base64',
                'body': b64
            }, timeout=30)
            data = resp.json()
            return data.get('request') if data.get('status') == 1 else None
        except:
            return None

    def download_captcha(self, url: str) -> Optional[bytes]:
        try:
            resp = self.client.get(url, timeout=15)
            if resp.status_code == 200 and len(resp.content) < 5 * 1024 * 1024:
                return resp.content
            return None
        except:
            return None


class CaptchaTester:
    def __init__(self, client: AxiomClient, solver: CaptchaSolver):
        self.client = client
        self.solver = solver

    def detect_captcha_type(self, html: str) -> Dict:
        result = {'has_captcha': False, 'types': [], 'details': {}}
        patterns = {
            'recaptcha_v2': r'google\.com/recaptcha/api\.js|g-recaptcha|data-sitekey',
            'recaptcha_v3': r'recaptcha/api\.js.*render=|recaptcha\.execute',
            'hcaptcha': r'hcaptcha\.com|h-captcha|data-sitekey.*hcaptcha',
            'cloudflare_turnstile': r'challenges\.cloudflare\.com/turnstile|cf-turnstile',
            'image_captcha': r'captcha\.(jpg|png|gif)|/captcha/image|src=.*captcha',
            'audio_captcha': r'captcha.*audio|/captcha/audio|type=.*audio',
            'text_captcha': r'captcha_text|text_captcha|enter.*code.*below',
            'math_captcha': r'math.*captcha|what.is.*\d+.*[+\-*/].*\d+|solve.*equation',
            'custom_captcha': r'captcha_code|verify_captcha|sec_code',
        }
        for ctype, pattern in patterns.items():
            if re.search(pattern, html, re.IGNORECASE):
                result['has_captcha'] = True
                result['types'].append(ctype)
                match = re.search(r'data-sitekey[\s]*=[\s]*["\']([^"\']+)', html)
                if match:
                    result['details']['sitekey'] = match.group(1)
        return result

    def test_endpoints(self, url: str) -> Dict:
        result = {'url': url, 'endpoints': [], 'rate_limited': False, 'captcha_triggered': False}
        endpoints = [url, f'{url}/login', f'{url}/register', f'{url}/contact']

        for endpoint in endpoints[:3]:
            for _ in range(5):
                try:
                    resp = self.client.get(endpoint, timeout=10)
                    html = resp.text.lower()
                    if any(x in html for x in ['captcha', 'recaptcha', 'hcaptcha', 'turnstile', 'cf-challenge']):
                        result['captcha_triggered'] = True
                        result['endpoints'].append({
                            'url': endpoint,
                            'triggered_after': _ + 1,
                            'type': self.detect_captcha_type(resp.text)
                        })
                        break
                    if resp.status_code == 429 or 'rate limit' in html or 'too many' in html:
                        result['rate_limited'] = True
                        result['endpoints'].append({
                            'url': endpoint,
                            'rate_limit_after': _ + 1,
                            'status': resp.status_code
                        })
                        break
                except:
                    continue
        return result

    def bypass_rate_limit(self, url: str, method: str = 'GET', num_requests: int = 20) -> Dict:
        result = {'total': 0, 'successful': 0, 'blocked': 0, 'blocked_after': None}
        headers_pool = [
            {'X-Forwarded-For': f'10.0.0.{i}', 'X-Real-IP': f'10.0.0.{i}'}
            for i in range(1, 256)
        ]

        for i in range(num_requests):
            try:
                h = headers_pool[i % len(headers_pool)]
                if method == 'GET':
                    resp = self.client.get(url, headers=h, timeout=10)
                else:
                    resp = self.client.post(url, headers=h, timeout=10)

                result['total'] += 1
                if resp.status_code == 200:
                    result['successful'] += 1
                else:
                    result['blocked'] += 1
                    if result['blocked_after'] is None:
                        result['blocked_after'] = i + 1
            except:
                result['blocked'] += 1

        return result
