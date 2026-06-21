import hashlib
import re
import ssl
import urllib.request


def _context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(url, host=None, timeout=10, context=None):
    if context is None:
        context = _context()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
    }
    if host:
        headers["Host"] = host
    req = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(req, timeout=timeout, context=context)


def get_title(html):
    match = re.search(rb"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    try:
        return match.group(1).decode("utf-8", "ignore").strip()
    except Exception:
        return ""


def body_hash(data, size=8192):
    return hashlib.sha256(data[:size]).hexdigest()


def favicon_hash(data):
    try:
        import mmh3
        return mmh3.hash(data)
    except Exception:
        return None


def fetch_reference(domain, timeout=10):
    reference = {}
    ctx = _context()
    try:
        resp = fetch(f"https://{domain}/", host=domain, timeout=timeout, context=ctx)
        data = resp.read(8192)
        reference["status"] = resp.status
        reference["title"] = get_title(data)
        reference["body_hash"] = body_hash(data)
    except Exception as exc:
        reference["error"] = str(exc)
    try:
        resp = fetch(f"https://{domain}/favicon.ico", host=domain, timeout=timeout, context=ctx)
        data = resp.read()
        reference["favicon_hash"] = favicon_hash(data)
    except Exception:
        reference["favicon_hash"] = None
    return reference


def compare(candidate, reference):
    score = 0.0
    reasons = []
    if candidate.get("status") and reference.get("status") and candidate["status"] == reference["status"]:
        score += 0.1
    c_title = candidate.get("title") or ""
    r_title = reference.get("title") or ""
    if c_title and r_title:
        if c_title == r_title:
            score += 0.5
            reasons.append("title")
        elif c_title in r_title or r_title in c_title:
            score += 0.2
            reasons.append("title_partial")
    c_body = candidate.get("body_hash")
    r_body = reference.get("body_hash")
    if c_body and r_body and c_body == r_body:
        score += 0.2
        reasons.append("body")
    c_fav = candidate.get("favicon_hash")
    r_fav = reference.get("favicon_hash")
    if c_fav is not None and r_fav is not None and c_fav == r_fav:
        score += 0.4
        reasons.append("favicon")
    return score, reasons
