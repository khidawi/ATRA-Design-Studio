"""
Tests for signing and verifying behavioural contracts (astra_signing.py). Pure: no database.

    python -m tests.test_astra_signing
"""
import copy
import json
import subprocess
import sys
from pathlib import Path

import astra_signing as SG

DOC = json.loads((Path(__file__).parent / "fixtures" / "appendix_b_example.json").read_text(encoding="utf-8"))
NB, EXP, NOW = "2026-11-16T10:00:00Z", "2027-11-16T10:00:00Z", "2026-12-01T00:00:00Z"
PRIV, PUB = SG.generate("test-key-1")
ENV = {"ASTRA_SIGNING_KEY": PRIV}


def record(env=None, status="ACTIVE"):
    kid, key = SG.load_signer(env or ENV)
    return {**SG.sign(DOC, kid, key, NB, EXP), "status": status}


def keys(env=None):
    return SG.load_public_keys(env or ENV)


def test_a_signed_contract_verifies_and_carries_its_detached_signature():
    r = record()
    assert SG.verify(r, keys(), NOW) == []
    assert r["document"]["agent"]["signature"] == f"ed25519:test-key-1:{r['signature']}"
    assert SG.digest(r["document"]) == SG.digest(DOC), "the signature field is not part of what is signed"


def test_changing_any_part_of_the_record_breaks_it():
    base = record()

    def broken(**change):
        r = copy.deepcopy(base)
        r.update(change)
        return SG.verify(r, keys(), NOW)
    d = copy.deepcopy(base["document"])
    d["permitted_goals"][0]["statement"] = "something else"
    assert broken(document=d), "document"
    d = copy.deepcopy(base["document"])
    d["agent"]["owner"] = "someone.else@example.test"
    assert broken(document=d), "owner"
    assert broken(not_before="2026-01-01T00:00:00Z"), "not_before"
    assert broken(expires_at="2030-01-01T00:00:00Z"), "expires_at"
    assert broken(contract_hash="0" * 64), "hash"
    assert broken(signature="0" * 128), "signature"
    d = copy.deepcopy(base["document"])
    d["agent"]["signature"] = "ed25519:test-key-1:" + "0" * 128
    assert broken(document=d), "embedded signature"


def test_the_window_and_the_status_are_checked():
    r = record()
    assert any("not valid yet" in w for w in SG.verify(r, keys(), "2026-11-01T00:00:00Z"))
    assert any("expired" in w for w in SG.verify(r, keys(), "2028-01-01T00:00:00Z"))
    for st in ("REVOKED", "SUPERSEDED"):
        assert any(st.lower() in w for w in SG.verify(record(status=st), keys(), NOW)), st


def test_an_unknown_key_or_a_key_swap_fails():
    r = record()
    assert any("not known" in w for w in SG.verify(r, {}, NOW))
    other_priv, _ = SG.generate("test-key-1")             # same id, different key
    wrong = SG.load_public_keys({"ASTRA_SIGNING_KEY": other_priv})
    assert any("does not verify" in w for w in SG.verify(r, wrong, NOW))


def test_rotation_keeps_old_contracts_valid():
    old = record()
    new_priv, _ = SG.generate("test-key-2")
    env = {"ASTRA_SIGNING_KEY": new_priv, "ASTRA_SIGNING_PUBLIC_KEYS": PUB}
    assert SG.verify(old, keys(env), NOW) == []
    kid, key = SG.load_signer(env)
    assert kid == "test-key-2"
    assert SG.verify({**SG.sign(DOC, kid, key, NB, EXP), "status": "ACTIVE"}, keys(env), NOW) == []
    assert any("not known" in w for w in SG.verify(old, keys({"ASTRA_SIGNING_KEY": new_priv}), NOW)), "without the retired key it no longer verifies"


def test_malformed_configuration_and_records_say_what_is_wrong():
    assert SG.load_signer({}) is None
    for env in ({"ASTRA_SIGNING_KEY": "nokey"}, {"ASTRA_SIGNING_KEY": "k1:!!!"}):
        try:
            SG.load_signer(env)
        except SG.SigningError:
            pass
        else:
            raise AssertionError(env)
    try:
        SG.load_public_keys({"ASTRA_SIGNING_PUBLIC_KEYS": "k1:AAAA"})
    except SG.SigningError:
        pass
    else:
        raise AssertionError("a bad public key must be refused")
    assert any("incomplete" in w for w in SG.verify({}, keys(), NOW))
    try:
        SG.generate("x")
    except SG.SigningError:
        pass
    else:
        raise AssertionError("a one character key id must be refused")


def test_the_generate_command_prints_a_usable_key():
    out = subprocess.run([sys.executable, "astra_signing.py", "generate", "cli-key-1"], capture_output=True, text=True, check=True).stdout
    line = [x for x in out.splitlines() if x.startswith("ASTRA_SIGNING_KEY=")][0].split("=", 1)[1]
    kid, _ = SG.load_signer({"ASTRA_SIGNING_KEY": line})
    assert kid == "cli-key-1"


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}  {exc!r}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
