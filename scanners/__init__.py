"""scanners package entrypoint.

Provides a simple `scan_url` function which aggregates results from
individual scanner modules (HTTP headers and SSL certificate checks).
"""
from .http_scanner import check_http_headers
from .ssl_scanner import check_ssl


def _calculate_security_score(http_result: dict, ssl_result: dict) -> tuple[int, str]:
    """Calculate a score out of 100 and determine the risk level."""
    score = 0

    if http_result.get('https_available'):
        score += 30

    valid_ssl = False
    if ssl_result and not ssl_result.get('error'):
        days_left = ssl_result.get('days_until_expiry')
        if isinstance(days_left, int) and days_left >= 0 and ssl_result.get('expires'):
            score += 30
            valid_ssl = True

    header_weights = {
        'Content-Security-Policy': 8,
        'Strict-Transport-Security': 8,
        'X-Frame-Options': 8,
        'X-Content-Type-Options': 8,
        'Referrer-Policy': 8,
    }

    for header, points in header_weights.items():
        if http_result.get('headers', {}).get(header):
            score += points

    score = min(score, 100)
    if score < 50:
        risk_level = 'High Risk'
    elif score < 80:
        risk_level = 'Medium Risk'
    else:
        risk_level = 'Low Risk'

    return score, risk_level


def _generate_recommendations(http_result: dict) -> list[str]:
    """Create recommendations based on missing security headers."""
    recommendations = []
    headers = http_result.get('headers', {}) if http_result else {}

    if not headers.get('Content-Security-Policy'):
        recommendations.append('Implement Content-Security-Policy to reduce XSS risks.')
    if not headers.get('Strict-Transport-Security'):
        recommendations.append('Enable HSTS to enforce HTTPS connections.')
    if not headers.get('X-Frame-Options'):
        recommendations.append('Enable X-Frame-Options to prevent clickjacking attacks.')
    if not headers.get('Referrer-Policy'):
        recommendations.append('Add Referrer-Policy to improve privacy.')
    if not headers.get('X-Content-Type-Options'):
        recommendations.append('Set X-Content-Type-Options to prevent MIME type sniffing.')

    return recommendations


def scan_url(url: str) -> dict:
    """Run safe security checks against the provided URL."""
    results = {
        'url': url,
        'http': None,
        'ssl': None,
        'security_score': 0,
        'risk_level': 'High Risk',
        'recommendations': [],
    }

    try:
        results['http'] = check_http_headers(url)
    except Exception as exc:
        results['http'] = {'error': str(exc), 'https_available': False, 'headers': {}}

    try:
        results['ssl'] = check_ssl(url)
    except Exception as exc:
        results['ssl'] = {'error': str(exc), 'host': None, 'issuer': {}, 'expires': None, 'days_until_expiry': None}

    score, risk_level = _calculate_security_score(results['http'], results['ssl'])
    recommendations = _generate_recommendations(results['http'])

    results['security_score'] = score
    results['risk_level'] = risk_level
    results['recommendations'] = recommendations

    return results
