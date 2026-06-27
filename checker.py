# empty
"""Flask entrypoint for Website Security Checker.

Run: `python checker.py` and open http://127.0.0.1:5000/
"""

from flask import Flask, render_template, request
from scanners import scan_url
from urllib.parse import urlparse
import db
import pdf_report
import io
from flask import send_file

app = Flask(__name__, static_folder='static', template_folder='templates')

# Ensure the SQLite database exists
db.init_db()


def _normalize_url(raw_url: str) -> str:
    """Ensure the URL has a scheme; default to https if missing."""
    parsed = urlparse(raw_url)
    if not parsed.scheme:
        raw_url = f"https://{raw_url}"
    return raw_url


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    raw_url = request.form.get('url', '').strip()
    if not raw_url:
        return render_template('index.html', error='Please enter a website URL.')

    url = _normalize_url(raw_url)
    try:
        results = scan_url(url)
    except Exception as exc:
        return render_template('index.html', error=f'Scan failed: {exc}')

    # Store minimal scan summary in the local database
    try:
        db.insert_scan(results.get('url', url), int(results.get('security_score', 0)), results.get('risk_level', ''))
    except Exception:
        # Do not block rendering on DB errors; log could be added here.
        pass

    return render_template('results.html', results=results)


@app.route('/download_pdf', methods=['POST'])
def download_pdf():
    raw_url = request.form.get('url', '').strip()
    if not raw_url:
        return render_template('index.html', error='Please enter a website URL.')

    url = _normalize_url(raw_url)
    try:
        results = scan_url(url)
    except Exception as exc:
        return render_template('index.html', error=f'Scan failed: {exc}')

    pdf_bytes = pdf_report.generate_pdf(results)
    buff = io.BytesIO(pdf_bytes)
    buff.seek(0)
    filename = f"scan_{urlparse(url).hostname}.pdf"
    return send_file(buff, mimetype='application/pdf', as_attachment=True, download_name=filename)


@app.route('/history')
def history():
    scans = []
    try:
        scans = db.fetch_scans(500)
    except Exception:
        scans = []
    return render_template('history.html', scans=scans)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
