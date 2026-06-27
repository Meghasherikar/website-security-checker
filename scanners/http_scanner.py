"""HTTP header scanner.

Performs a GET request and inspects common security headers.
"""
from typing import Dict
import requests


SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
]


def check_http_headers(url: str, timeout: int = 8) -> Dict:
    """Fetch the URL and return a report about required security headers."""
    resp = requests.get(url, timeout=timeout, allow_redirects=True)
    headers = {k: v for k, v in resp.headers.items()}

    report = {
        'status_code': resp.status_code,
        'headers': {},
        'https_available': url.startswith('https://'),
    }

    for header in SECURITY_HEADERS:
        report['headers'][header] = headers.get(header)

    return report
