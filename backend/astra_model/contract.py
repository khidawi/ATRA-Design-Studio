"""
The behavioural contract (paper section 3.6): canonical form, hash, signature and validity.

The contract is compiled from the estate, serialised in a canonical form, hashed with SHA-256 and signed with Ed25519 by the issuer. It is valid at time t when the
document has the required shape, the hash matches, the signature verifies against a known key, t lies in the validity window, and the status stored beside the
document is ACTIVE. That status is not part of the signed bytes, so a contract can be revoked without changing it.

This module is pure: it holds no key. A key is passed in; where keys live (and who may use them) is decided with the signing phase.
"""
import hashlib
import hmac
import json
from typing import Any, Dict, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .estate import Estate

SCHEMA_VERSION = "0.1"


def contract_of(E: Estate) -> Dict[str, Any]:
    agents = {}
    for n, a in sorted(E.agents.items()):
        agents[n] = dict(
            dept=a.dept, autonomy=a.autonomy, expires=a.expires,
            tools={t: {p: list(b) for p, b in sorted(bs.items())} for t, bs in sorted(a.tools.items())},
            resources=dict(sorted(a.resources.items())), may_delegate_to=sorted(a.may_delegate_to), accepts_from=sorted(a.accepts_from),
            deleg_mode=a.deleg_mode, max_depth=a.max_depth, hitl_tools=sorted(a.hitl_tools),
            prohibited_chains=sorted(list(x) for x in a.prohibited_chains), components=dict(sorted(a.components.items())),
            may_spawn=sorted(a.may_spawn))
    return dict(schema_version=SCHEMA_VERSION, agents=agents, resources={r: list(v) for r, v in sorted(E.res.items())}, tau=dict(sorted(E.tau.items())))


def canonical(doc: Dict[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(doc: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical(doc)).hexdigest()


def _message(h: str, key_id: str, not_before: int, expires: int) -> bytes:
    return f"{h}|{key_id}|{not_before}|{expires}".encode("utf-8")


def sign(doc: Dict[str, Any], key_id: str, private_key: Ed25519PrivateKey, not_before: int, expires: int) -> Dict[str, Any]:
    h = digest(doc)
    return dict(document=doc, hash=h, key_id=key_id, signature=private_key.sign(_message(h, key_id, not_before, expires)).hex(),
                not_before=not_before, expires=expires, status="ACTIVE")


def valid(c: Mapping[str, Any], public_keys: Mapping[str, Ed25519PublicKey], now: int) -> bool:
    """True only if every check passes. Any malformed input is simply invalid."""
    try:
        doc = c["document"]
        if doc.get("schema_version") is None or "agents" not in doc:
            return False
        h = digest(doc)
        if not hmac.compare_digest(h, c["hash"]):
            return False
        pub = public_keys.get(c["key_id"])
        if pub is None:
            return False
        try:
            pub.verify(bytes.fromhex(c["signature"]), _message(h, c["key_id"], c["not_before"], c["expires"]))
        except (InvalidSignature, ValueError):
            return False
        return c["status"] == "ACTIVE" and c["not_before"] <= now <= c["expires"]
    except (KeyError, TypeError, AttributeError):
        return False
