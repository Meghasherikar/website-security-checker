"""SSL certificate scanner.

Performs a TLS handshake and extracts basic certificate information.
Uses the standard library `ssl` and `socket` modules for a best-effort
implementation without heavy dependencies.
"""
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime


def _connect_and_get_cert(hostname: str, port: int = 443, timeout: int = 8):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            return cert


def check_ssl(url: str) -> dict:
    """Check certificate details for the URL's host.

    Returns a dict with subject, issuer, validity and days until expiry.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme in ('https', '') else 443)
    if not hostname:
        raise ValueError('Invalid URL/hostname')

    cert = _connect_and_get_cert(hostname, port)

    # Extract common fields safely
    subject = dict(x[0] for x in cert.get('subject', ())) if cert.get('subject') else {}
    issuer = dict(x[0] for x in cert.get('issuer', ())) if cert.get('issuer') else {}
    not_after = cert.get('notAfter')

    expires = None
    days_left = None
    if not_after:
        try:
            expires = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
        except Exception:
            try:
                expires = datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
            except Exception:
                expires = None

        if expires:
            days_left = (expires - datetime.utcnow()).days

    return {
        'host': hostname,
        'port': port,
        'subject': subject,
        'issuer': issuer,
        'notAfter': not_after,
        'expires': expires.isoformat() if expires else None,
        'days_until_expiry': days_left,
    }
