"""Generate a simple PDF report from scan results using ReportLab.

This module returns PDF bytes suitable for sending as an attachment.
"""
import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas


def _write_line(c: canvas.Canvas, text: str, x: float, y: float, size: int = 10):
    c.setFont('Helvetica', size)
    c.drawString(x, y, text)


def generate_pdf(results: dict) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter

    margin = 0.7 * inch
    x = margin
    y = height - margin

    # Header
    c.setFont('Helvetica-Bold', 16)
    c.drawString(x, y, 'Website Security Scan Report')
    y -= 20

    c.setFont('Helvetica', 9)
    c.drawString(x, y, f"Generated: {datetime.utcnow().isoformat()} UTC")
    y -= 24

    # Basic info
    _write_line(c, f"URL: {results.get('url')}", x, y, 11)
    y -= 16
    _write_line(c, f"Security Score: {results.get('security_score')}/100", x, y, 11)
    y -= 16
    _write_line(c, f"Risk Level: {results.get('risk_level')}", x, y, 11)
    y -= 20

    # SSL details
    ssl = results.get('ssl') or {}
    _write_line(c, 'SSL Certificate:', x, y, 12)
    y -= 14
    issuer = ssl.get('issuer', {})
    _write_line(c, f"  Issuer: {issuer.get('organizationName') or issuer.get('commonName') or 'Unknown'}", x, y, 10)
    y -= 12
    _write_line(c, f"  Expires: {ssl.get('expires') or ssl.get('notAfter') or 'Unavailable'}", x, y, 10)
    y -= 18

    # Headers
    _write_line(c, 'Security Headers:', x, y, 12)
    y -= 14
    headers = results.get('http', {}).get('headers', {})
    for name, value in headers.items():
        if y < margin + 80:
            c.showPage()
            y = height - margin
        display = value if value else 'Missing'
        _write_line(c, f"  {name}: {display}", x, y, 9)
        y -= 12

    # Recommendations
    y -= 8
    _write_line(c, 'Recommendations:', x, y, 12)
    y -= 14
    recs = results.get('recommendations', [])
    if recs:
        for r in recs:
            if y < margin + 40:
                c.showPage()
                y = height - margin
            _write_line(c, f"  - {r}", x, y, 9)
            y -= 12
    else:
        _write_line(c, '  No recommendations. Headers are complete.', x, y, 10)
        y -= 12

    c.showPage()
    c.save()
    pdf = buf.getvalue()
    buf.close()
    return pdf
