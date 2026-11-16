"""
Signing and verifying ASTRA behavioural contracts (Ed25519, ASTRA phase 5).

Keys are not the platform's encryption secret and never live in the database:

    ASTRA_SIGNING_KEY          "key_id:base64url(32-byte seed)"       the key that signs now
    ASTRA_SIGNING_PUBLIC_KEYS  "key_id:base64url(public key),..."     retired keys, kept so contracts signed with them still verify

    docker compose run --rm backend python astra_signing.py generate astra-2026-11       prints both values for a new key

A signature covers the SHA-256 of the canonical form of the contract document, the key id and the validity window. The document carries its own detached signature in
agent.signature as "ed25519:<key_id>:<hex>"; that field is left out of the canonical form, so a signed document can be checked on its own with the public key. The status of a
contract (active, superseded, revoked) is stored beside the document and is not signed, so revoking never changes the signed bytes.

Rotation: put the new key in ASTRA_SIGNING_KEY and the old public key in ASTRA_SIGNING_PUBLIC_KEYS. Nothing signed with the old key stops verifying.
"""
import base64
import copy
import hashlib
import hmac
import json
import os
import re
import sys
from typing import Any, Dict, List, Mapping, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
PREFIX = "ed25519:"


class SigningError(Exception):
    """Something about the keys or the signature that a person has to fix; the message says what."""


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def public_b64(key: Ed25519PrivateKey) -> str:
    return _b64e(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def generate(key_id: str) -> Tuple[str, str]:
    """(value for ASTRA_SIGNING_KEY, entry for ASTRA_SIGNING_PUBLIC_KEYS)."""
    if not KEY_ID.match(key_id):
        raise SigningError("A key id is 2 to 64 letters, digits, dots, dashes or underscores.")
    k = Ed25519PrivateKey.generate()
    seed = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return f"{key_id}:{_b64e(seed)}", f"{key_id}:{public_b64(k)}"


def load_signer(env: Optional[Mapping[str, str]] = None) -> Optional[Tuple[str, Ed25519PrivateKey]]:
    """The key that signs now, or None when none is configured."""
    raw = (env if env is not None else os.environ).get("ASTRA_SIGNING_KEY", "").strip()
    if not raw:
        return None
    key_id, _, seed = raw.partition(":")
    if not KEY_ID.match(key_id) or not seed:
        raise SigningError("ASTRA_SIGNING_KEY must look like key_id:base64url-seed.")
    try:
        return key_id, Ed25519PrivateKey.from_private_bytes(_b64d(seed))
    except Exception as exc:
        raise SigningError("ASTRA_SIGNING_KEY does not hold a valid Ed25519 seed.") from exc


def load_public_keys(env: Optional[Mapping[str, str]] = None) -> Dict[str, Ed25519PublicKey]:
    """Every key a signature may be checked against: the current key's public half and the retired ones."""
    e = env if env is not None else os.environ
    out: Dict[str, Ed25519PublicKey] = {}
    signer = load_signer(e)
    if signer is not None:
        out[signer[0]] = signer[1].public_key()
    for item in (e.get("ASTRA_SIGNING_PUBLIC_KEYS", "") or "").split(","):
        item = item.strip()
        if not item:
            continue
        key_id, _, pub = item.partition(":")
        if not KEY_ID.match(key_id) or not pub:
            raise SigningError("ASTRA_SIGNING_PUBLIC_KEYS must look like key_id:base64url-public-key, separated by commas.")
        try:
            out[key_id] = Ed25519PublicKey.from_public_bytes(_b64d(pub))
        except Exception as exc:
            raise SigningError(f"The public key {key_id!r} is not a valid Ed25519 public key.") from exc
    return out


def canonical(document: Mapping[str, Any]) -> bytes:
    """The document as signed: the detached signature field is not part of what it signs."""
    d = copy.deepcopy(dict(document))
    if isinstance(d.get("agent"), dict):
        d["agent"].pop("signature", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(document: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical(document)).hexdigest()


def _message(h: str, key_id: str, not_before: str, expires: str) -> bytes:
    return f"{h}|{key_id}|{not_before}|{expires}".encode("utf-8")


def sign(document: Mapping[str, Any], key_id: str, key: Ed25519PrivateKey, not_before: str, expires: str) -> Dict[str, Any]:
    """The signed document (agent.signature filled in), its hash and the signature."""
    h = digest(document)
    sig = key.sign(_message(h, key_id, not_before, expires)).hex()
    signed = copy.deepcopy(dict(document))
    signed["agent"]["signature"] = f"{PREFIX}{key_id}:{sig}"
    return {"document": signed, "contract_hash": h, "key_id": key_id, "signature": sig, "not_before": not_before, "expires_at": expires}


def verify(record: Mapping[str, Any], public_keys: Mapping[str, Ed25519PublicKey], now_iso: str) -> List[str]:
    """What is wrong with a signed contract record, one reason per problem; [] means it is valid right now.

    record: document, contract_hash, key_id, signature, not_before, expires_at (ISO 8601 strings in UTC, so they compare as text), status."""
    why: List[str] = []
    try:
        doc, h = record["document"], digest(record["document"])
        if not hmac.compare_digest(h, str(record["contract_hash"])):
            why.append("the document no longer matches its hash: it has been changed")
        embedded = (doc.get("agent") or {}).get("signature", "")
        if embedded != f"{PREFIX}{record['key_id']}:{record['signature']}":
            why.append("the signature inside the document is not the signature on record")
        pub = public_keys.get(record["key_id"])
        if pub is None:
            why.append(f"the signing key {record['key_id']!r} is not known to this platform")
        else:
            try:
                pub.verify(bytes.fromhex(record["signature"]), _message(h, record["key_id"], record["not_before"], record["expires_at"]))
            except (InvalidSignature, ValueError):
                why.append("the signature does not verify")
        if now_iso < record["not_before"]:
            why.append("it is not valid yet")
        if now_iso > record["expires_at"]:
            why.append("it has expired")
        if record.get("status") != "ACTIVE":
            why.append(f"it is {str(record.get('status', 'not active')).lower()}")
    except (KeyError, TypeError, AttributeError) as exc:
        why.append(f"the record is incomplete or malformed ({type(exc).__name__})")
    return why


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "generate":
        private, public = generate(sys.argv[2])
        print("Put this in the backend's environment (keep it secret, back it up with ASTRA_SECRET_KEY):")
        print(f"ASTRA_SIGNING_KEY={private}")
        print("When this key is later retired, keep its public half so old contracts still verify:")
        print(f"ASTRA_SIGNING_PUBLIC_KEYS={public}")
    else:
        sys.exit("usage: python astra_signing.py generate <key_id>")
