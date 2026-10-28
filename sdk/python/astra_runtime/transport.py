"""
How the SDK reaches ASTRA, safely.

  * The address must be https, because the API key and the events travel in it. Plain http is accepted only to this machine (localhost, 127.0.0.1, ::1), for development; to anywhere
    else the SDK switches itself off and says why, rather than sending a key in clear. ASTRA_ALLOW_INSECURE=1 overrides it (a network you fully control, never the internet).
  * The server's certificate is always checked. If ASTRA is served with a certificate from your own authority (ASTRA_TLS=internal, or an internal CA), point ASTRA_CA_BUNDLE at that
    authority's certificate file; nothing needs to be installed on the machine.
  * Mutual TLS: if ASTRA requires a client certificate for data sent in (docker-compose.mtls.yml), set ASTRA_CLIENT_CERT and ASTRA_CLIENT_KEY to the application's certificate and key.
"""
import os
import ssl
import threading
import urllib.parse
from typing import Optional

_LOCAL = ("localhost", "127.0.0.1", "::1")
_lock = threading.Lock()
_ctx: Optional[ssl.SSLContext] = None
_ctx_for = None


def url_problem(url: str) -> Optional[str]:
    """Why this address must not be used, or None."""
    p = urllib.parse.urlparse(url or "")
    if p.scheme == "https":
        return None
    host = (p.hostname or "").lower()
    if p.scheme == "http" and (host in _LOCAL or host.endswith(".localhost")):
        return None
    if os.environ.get("ASTRA_ALLOW_INSECURE") == "1" and p.scheme == "http":
        return None
    if p.scheme == "http":
        return f"{url} is plain http: the API key and the events would cross the network unencrypted. Use the https address (or set ASTRA_ALLOW_INSECURE=1 on a network you fully control)"
    return f"{url!r} is not an http(s) address"


def ssl_context() -> ssl.SSLContext:
    """The TLS settings for every request: certificate and host name always verified, an optional private authority, an optional client certificate."""
    global _ctx, _ctx_for
    sig = (os.environ.get("ASTRA_CA_BUNDLE"), os.environ.get("ASTRA_CLIENT_CERT"), os.environ.get("ASTRA_CLIENT_KEY"))
    with _lock:
        if _ctx is None or _ctx_for != sig:
            ctx = ssl.create_default_context(cafile=sig[0]) if sig[0] else ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if sig[1]:
                ctx.load_cert_chain(sig[1], sig[2] or None)
            _ctx, _ctx_for = ctx, sig
        return _ctx
