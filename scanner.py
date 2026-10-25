"""Core scanning logic: security headers, cookies, information leaks and CORS."""
import re
from urllib.parse import urlparse

import requests

PENALTY = {"High": 20, "Medium": 10, "Low": 4}
EVIL_ORIGIN = "https://evil.example"

def is_local(host):
    return host in ("localhost", "127.0.0.1", "::1")

def http(url, method="GET", headers=None):
    return requests.request(method, url, headers=headers or {}, timeout=8, allow_redirects=False)

def scan_target(name, url):
    results = []
    def add(category, check, severity, detail, fix=""):
        results.append({"target": name, "category": category, "check": check,
                        "severity": severity, "detail": detail, "fix": fix})

    parsed = urlparse(url)
    is_https = parsed.scheme == "https"
    r = http(url)
    h = {k.lower(): v for k, v in r.headers.items()}

    # --- Transport ---------------------------------------------------------
    if is_https:
        if "strict-transport-security" not in h:
            add("Headers", "HSTS", "High", "Strict-Transport-Security header is missing.",
                "Add Strict-Transport-Security: max-age=31536000; includeSubDomains")
        else:
            add("Headers", "HSTS", "Pass", h["strict-transport-security"])
    elif is_local(parsed.hostname):
        add("Headers", "HSTS", "N/A", "Plain HTTP on localhost; HSTS only applies to HTTPS.")
    else:
        add("Headers", "HSTS", "High", "Site is served over plain HTTP, so HSTS and secure cookies cannot work.",
            "Serve the site over HTTPS and redirect all HTTP traffic.")

    # --- Content-Security-Policy ------------------------------------------
    csp = h.get("content-security-policy")
    if not csp:
        add("Headers", "Content-Security-Policy", "Medium", "No CSP header; the browser will run any injected script.",
            "Define a CSP such as default-src 'self'.")
    elif re.search(r"unsafe-inline|unsafe-eval|(^|[\s;])\*([\s;]|$)", csp):
        add("Headers", "Content-Security-Policy", "Medium", f"CSP is present but weak: {csp}",
            "Remove 'unsafe-inline', 'unsafe-eval' and wildcard sources; use nonces or hashes.")
    else:
        add("Headers", "Content-Security-Policy", "Pass", csp)

    # --- Clickjacking -----------------------------------------------------
    xfo = h.get("x-frame-options", "").upper()
    if xfo in ("DENY", "SAMEORIGIN") or (csp and "frame-ancestors" in csp):
        add("Headers", "Clickjacking protection", "Pass", xfo or "CSP frame-ancestors")
    else:
        add("Headers", "Clickjacking protection", "Medium", "Neither X-Frame-Options nor CSP frame-ancestors is set.",
            "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.")

    # --- Simple presence checks -------------------------------------------
    for hdr, sev, want, fix in [
        ("x-content-type-options", "Low", "nosniff", "Add X-Content-Type-Options: nosniff"),
        ("referrer-policy", "Low", None, "Add Referrer-Policy: strict-origin-when-cross-origin"),
        ("permissions-policy", "Low", None, "Add a Permissions-Policy that disables unused features."),
    ]:
        label = "-".join(w.capitalize() for w in hdr.split("-"))
        v = h.get(hdr)
        if v and (want is None or v.lower() == want):
            add("Headers", label, "Pass", v)
        else:
            add("Headers", label, sev, f"{label} header is missing or has an unexpected value.", fix)

    # --- Information leakage ----------------------------------------------
    srv = h.get("server", "")
    if re.search(r"\d", srv):
        add("Info leak", "Server version", "Low", f"Server header reveals version: {srv}",
            "Hide version details (for example server_tokens off).")
    else:
        add("Info leak", "Server version", "Pass", srv or "no Server header")
    if "x-powered-by" in h:
        add("Info leak", "X-Powered-By", "Low", f"X-Powered-By reveals technology: {h['x-powered-by']}",
            "Remove the X-Powered-By header.")
    else:
        add("Info leak", "X-Powered-By", "Pass", "header not present")

    # --- Cookies -----------------------------------------------------------
    cookies = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []
    if not cookies:
        for chk in ("Cookie HttpOnly", "Cookie SameSite", "Cookie Secure"):
            add("Cookies", chk, "N/A", "No cookies set on this page.")
    else:
        attrs = [c.lower().replace(" ", "").split(";") for c in cookies]
        cname = cookies[0].split("=")[0]
        if all("httponly" in a for a in attrs):
            add("Cookies", "Cookie HttpOnly", "Pass", f"{cname} has HttpOnly")
        else:
            add("Cookies", "Cookie HttpOnly", "Medium", f"Cookie {cname} can be read by JavaScript.",
                "Add the HttpOnly flag.")
        if all(any(x.startswith("samesite=") for x in a) for a in attrs):
            add("Cookies", "Cookie SameSite", "Pass", f"{cname} has SameSite")
        else:
            add("Cookies", "Cookie SameSite", "Low", f"Cookie {cname} has no SameSite attribute.",
                "Add SameSite=Lax or Strict.")
        if not is_https and is_local(parsed.hostname):
            add("Cookies", "Cookie Secure", "N/A", "Plain HTTP on localhost.")
        elif all("secure" in a for a in attrs):
            add("Cookies", "Cookie Secure", "Pass", f"{cname} has Secure")
        else:
            add("Cookies", "Cookie Secure", "Medium", f"Cookie {cname} can be sent over plain HTTP.",
                "Add the Secure flag.")

    # --- CORS ---------------------------------------------------------------
    def cors_of(origin, method="GET", extra=None):
        hdrs = {"Origin": origin}
        hdrs.update(extra or {})
        resp = http(url, method, hdrs)
        g = {k.lower(): v for k, v in resp.headers.items()}
        return g.get("access-control-allow-origin"), g.get("access-control-allow-credentials", "").lower() == "true", g

    acao, creds, _ = cors_of(EVIL_ORIGIN)
    if acao == EVIL_ORIGIN:
        add("CORS", "Reflected origin", "High" if creds else "Medium",
            f"Server echoes any Origin back{' and allows credentials' if creds else ''}; any website can read responses.",
            "Allow only a fixed list of trusted origins.")
    elif acao == "*":
        add("CORS", "Reflected origin", "Pass", "Origin is not reflected (wildcard checked below).")
    else:
        add("CORS", "Reflected origin", "Pass", "Untrusted origin was not allowed.")

    if acao == "*":
        add("CORS", "Wildcard origin", "Medium" if creds else "Low",
            "Access-Control-Allow-Origin is * so every site can read this response.",
            "Replace * with specific trusted origins unless the content is fully public.")
    else:
        add("CORS", "Wildcard origin", "Pass", "no wildcard")

    acao_n, creds_n, _ = cors_of("null")
    if acao_n == "null":
        add("CORS", "Null origin", "High" if creds_n else "Medium",
            "The 'null' origin is trusted (sandboxed iframes and local files can use it).",
            "Never allow the null origin.")
    else:
        add("CORS", "Null origin", "Pass", "null origin not trusted")

    acao_p, _, gp = cors_of(EVIL_ORIGIN, "OPTIONS", {"Access-Control-Request-Method": "DELETE"})
    methods = gp.get("access-control-allow-methods", "")
    if acao_p in (EVIL_ORIGIN, "*") and re.search(r"PUT|DELETE|PATCH", methods, re.I):
        add("CORS", "Preflight methods", "Low", f"Untrusted origins may use risky methods: {methods}",
            "Limit Access-Control-Allow-Methods to what the API needs.")
    else:
        add("CORS", "Preflight methods", "Pass", "no risky methods allowed to untrusted origins")

    return results

def score_and_grade(df_target):
    penalty = sum(PENALTY.get(s, 0) for s in df_target["severity"])
    score = max(0, 100 - penalty)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
    return score, grade


def summarize(findings):
    """Return {target: {"score", "grade", "High", "Medium", "Low", "Passed"}} from a list of result dicts."""
    out = {}
    targets = list(dict.fromkeys(f["target"] for f in findings))
    for t in targets:
        rows = [f for f in findings if f["target"] == t]
        sev = [r["severity"] for r in rows]
        penalty = sum(PENALTY.get(s, 0) for s in sev)
        score = max(0, 100 - penalty)
        grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
        out[t] = {"score": score, "grade": grade, "High": sev.count("High"), "Medium": sev.count("Medium"),
                  "Low": sev.count("Low"), "Passed": sev.count("Pass")}
    return out
