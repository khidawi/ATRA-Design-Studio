"""
Checks a running ASTRA server from the outside, the way an auditor or a security questionnaire would: HTTP goes to HTTPS, the certificate is good, the connection is
modern, the security headers are there, the application answers, the session cookie is marked Secure, and the internal ports are not reachable. Standard library only.

    python verify_https.py https://astra.example.org
    python verify_https.py https://localhost --insecure                  # a certificate from Caddy's own authority (ASTRA_TLS=internal, or localhost)
    python verify_https.py https://astra.example.org --email you@example.org --password '...'     # also checks the cookie ASTRA sets at sign-in

It changes nothing on the server (signing in only creates a session). Exit code 0 if every check passes, 1 otherwise.
"""
import argparse
import http.client
import json
import socket
import ssl
import sys
import urllib.parse
from datetime import datetime, timezone

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (("  " + str(detail)) if detail and not ok else ""))
    if not ok:
        fails.append(name)


def note(text):
    print("     " + text)


def conn(scheme, host, port, insecure):
    if scheme == "https":
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
    return http.client.HTTPConnection(host, port, timeout=10)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="the address people use, for example https://astra.example.org")
    ap.add_argument("--insecure", action="store_true", help="do not verify the certificate (a private certificate authority, or localhost)")
    ap.add_argument("--http-port", type=int, default=80)
    ap.add_argument("--email")
    ap.add_argument("--password")
    ap.add_argument("--skip-ports", action="store_true", help="do not probe the internal ports (use it when checking from inside the network)")
    a = ap.parse_args()
    u = urllib.parse.urlparse(a.url)
    if u.scheme != "https" or not u.hostname:
        sys.exit("Give the https address, for example https://astra.example.org")
    host, port = u.hostname, u.port or 443

    # ── HTTP goes to HTTPS
    try:
        c = conn("http", host, a.http_port, False)
        c.request("GET", "/api/health-check-path")
        r = c.getresponse()
        loc = r.getheader("Location") or ""
        check("plain HTTP is redirected to HTTPS, not answered", r.status in (301, 302, 307, 308) and loc.startswith("https://"), f"{r.status} {loc}")
        c = conn("http", host, a.http_port, False)
        c.request("POST", "/api/auth/login", body="{}", headers={"Content-Type": "application/json"})
        r = c.getresponse()
        check("a sign-in sent over plain HTTP is redirected too, and never reaches the application", r.status in (307, 308) and (r.getheader("Location") or "").startswith("https://"), r.status)
    except OSError as exc:
        check("port 80 answers with a redirect", False, exc)

    # ── the certificate and the connection
    try:
        ctx = ssl.create_default_context()
        if a.insecure:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
            ver = s.version()
            check("TLS 1.2 or 1.3 is negotiated", ver in ("TLSv1.2", "TLSv1.3"), ver)
            cert = s.getpeercert()
            if cert:
                left = (datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                check("the certificate is valid for this name and has more than 14 days left", left > 14, f"{left} days")
            elif a.insecure:
                note("certificate not inspected (--insecure)")
        # Old protocol versions: only meaningful if this machine's own TLS library is willing to offer one, so say so when it is not.
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            old.check_hostname, old.verify_mode = False, ssl.CERT_NONE
            try:
                old.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                old.maximum_version = ssl.TLSVersion.TLSv1_1
                old.set_ciphers("ALL:@SECLEVEL=0")
                offered = True
            except (ValueError, ssl.SSLError):
                offered = False
        if not offered:
            note("TLS 1.1 and older: not tested (this machine's TLS library will not offer them)")
        else:
            try:
                with socket.create_connection((host, port), timeout=10) as raw, old.wrap_socket(raw, server_hostname=host):
                    check("TLS 1.1 and older are refused", False, "accepted")
            except ssl.SSLError as exc:
                if "no protocols available" in str(exc).lower():
                    note("TLS 1.1 and older: not tested (this machine's TLS library will not offer them)")
                else:
                    check("TLS 1.1 and older are refused", True)
            except OSError:
                check("TLS 1.1 and older are refused", True)
    except (ssl.SSLCertVerificationError) as exc:
        check("the certificate is trusted (use --insecure for a private authority)", False, exc.verify_message)
    except OSError as exc:
        check("HTTPS answers", False, exc)
        return finish()

    # ── headers and the application
    c = conn("https", host, port, a.insecure)
    c.request("GET", "/")
    r = c.getresponse()
    h = {k.lower(): v for k, v in r.getheaders()}
    r.read()
    check("the page is served", r.status == 200, r.status)
    hsts = h.get("strict-transport-security", "")
    try:
        age = int(hsts.split("max-age=")[1].split(";")[0])
    except (IndexError, ValueError):
        age = 0
    check("HSTS is set for at least six months", age >= 15552000, hsts or "missing")
    check("content type sniffing is off", h.get("x-content-type-options", "").lower() == "nosniff")
    check("the page cannot be framed by another site", h.get("x-frame-options", "").upper() == "DENY" or "frame-ancestors 'none'" in h.get("content-security-policy", ""))
    check("the referrer is not sent to other sites", h.get("referrer-policy", "") in ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"))
    check("the server does not announce its software and version", "server" not in h or not any(ch.isdigit() for ch in h["server"]), h.get("server", ""))
    c = conn("https", host, port, a.insecure)
    c.request("GET", "/health")
    r = c.getresponse()
    body = r.read().decode()
    try:
        ok = r.status == 200 and json.loads(body).get("status") == "ok" and json.loads(body).get("database") == "ok"
    except ValueError:
        ok = False
    check("the application and its database answer", ok, body[:120])
    c = conn("https", host, port, a.insecure)
    c.request("GET", "/api/agents")
    r = c.getresponse()
    r.read()
    check("the API refuses a request with no sign-in", r.status == 401, r.status)

    # ── the session cookie
    if a.email and a.password:
        c = conn("https", host, port, a.insecure)
        c.request("POST", "/api/auth/login", body=json.dumps({"email": a.email, "password": a.password}), headers={"Content-Type": "application/json", "x-astra-csrf": "1"})
        r = c.getresponse()
        r.read()
        cookie = r.getheader("Set-Cookie") or ""
        check("sign-in works", r.status == 200, r.status)
        low = cookie.lower()
        check("the session cookie is HttpOnly, Secure and SameSite", "httponly" in low and "secure" in low and "samesite" in low, cookie.split("=")[0] + " ...")
    else:
        note("sign-in cookie not checked: give --email and --password to check it")

    # ── nothing internal is reachable from here
    if not a.skip_ports:
        for p, what in ((8765, "the API"), (5432, "the database"), (5173, "the studio's development port")):
            try:
                socket.create_connection((host, p), timeout=3).close()
                check(f"{what} (port {p}) is not reachable from outside", False, "it accepted a connection")
            except OSError:
                check(f"{what} (port {p}) is not reachable from outside", True)
    return finish()


def finish():
    print()
    print("All checks passed." if not fails else f"{len(fails)} check(s) failed: " + "; ".join(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
