"""
Tests for packs.py (Task 7e): packs are built from real data, stored as hashed, chained, and verifiable.

    docker compose exec backend python -m tests.test_packs
"""
import sys

from fastapi.testclient import TestClient

import packs
from main import app
from tests._auth import authed_client
from tests.test_agent_registry import cleanup, doc

KEY = "zz-test-patient-agent"
REQ = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Compliance lead"}}
BODY = {"template": "ASSURANCE", "period": "30d", "generated_by": "Compliance lead"}


def clean_packs(*keys):
    from db.models import EvidencePack
    from db.session import SessionLocal
    seqs = [int(k.removeprefix("P-")) for k in keys]
    with SessionLocal() as s:
        for p in s.query(EvidencePack).filter(EvidencePack.seq.in_(seqs)).all():
            s.delete(p)
        s.commit()


def clean_findings():
    from db.models import Finding
    from db.session import SessionLocal
    with SessionLocal() as s:
        for f in s.query(Finding).filter(Finding.agent_key == KEY).all():
            s.delete(f)
        s.commit()


def test_hashing_is_order_independent_and_chained():
    assert packs.sha({"a": 1, "b": [1, 2]}) == packs.sha({"b": [1, 2], "a": 1})
    assert packs.sha({"a": 1}) != packs.sha({"a": 2})
    h = packs.sha({"x": 1})
    assert packs.pack_hash(packs.GENESIS, h) != packs.pack_hash("other", h)


def test_no_pack_without_an_agent_that_has_a_contract():
    with authed_client() as api:
        r = api.post("/api/packs", json=BODY)
        assert r.status_code == 409 and "nothing to attest" in r.json()["detail"]
        assert api.post("/api/packs", json={**BODY, "frameworks": []}).status_code == 422


def test_pack_content_chain_and_verification():
    with authed_client() as api:
        d = api.post("/api/designs", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc(req=REQ)}).json()
        c = api.post("/api/agents/ratify", json={"design_key": d["design_key"], "reviewer": "Compliance lead"}).json()["contract"]
        api.post("/api/agents/register", json={"name": "zz-test-sandbox"})
        api.post("/api/findings/simulate", json={"agent": KEY, "scenario": "write_tool_outside"})
        made = []
        try:
            a = api.post("/api/packs", json=BODY)
            assert a.status_code == 201, a.text
            a = a.json()
            made.append(a["pack_key"])
            x = a["content"]
            assert a["template"] == "ASSURANCE" and a["pack_key"].startswith("P-") and x["schema"] == "astra.pack/1"
            assert [r["agent"] for r in x["agents"]] == [KEY] and x["agents"][0]["contract"]["hash"] == c["contract_hash"]
            assert {e["ref"] for e in x["evidence"] if e["type"] == "contract"} == {c["contract_id"]}
            assert x["findings"]["counts"]["from_simulated_events"] == 1 and x["findings"]["counts"]["from_collected_events"] == 0
            assert any("simulated events" in l for l in x["limits"]) and any("signed-in" in l for l in x["limits"])
            gap_text = " ".join(g["text"] for g in x["gaps"])
            assert "zz-test-sandbox" in gap_text and "no active contract" in gap_text and "no owner" in gap_text            # stated, not hidden
            assert a["claims"] == len(x["claims"]) and a["gaps"] == len(x["gaps"]) and a["evidence_count"] == len(x["evidence"])
            assert a["previous_pack_hash"] and a["pack_hash"] == packs.pack_hash(a["previous_pack_hash"], a["content_hash"])
            assert packs.sha(x) == a["content_hash"]

            v = api.get(f"/api/packs/{a['pack_key']}/verify").json()
            assert v["ok"] and v["chain_ok"] and v["content_ok"] and v["contracts_checked"] == 1 and v["contracts_ok"] == 1

            b = api.post("/api/packs", json={**BODY, "template": "TRUST", "frameworks": ["OWASP_AGENTIC"]}).json()
            made.append(b["pack_key"])
            assert b["previous_pack_hash"] == a["pack_hash"]                                                               # chained to the one before
            t = b["content"]
            assert t["agents"][0]["agent"] == "Agent 1" and "owner" not in t["agents"][0] and "items" not in t["findings"]
            assert KEY not in str(t) and "zz-test-sandbox" not in str(t)                                                   # no internal names in a trust report
            assert "requirements" not in t["agents"][0] and t["frameworks"] == ["OWASP Top 10 for Agentic Applications"]
            assert [p["pack_key"] for p in api.get("/api/packs").json()][:2] == [b["pack_key"], a["pack_key"]]
            assert api.get("/api/packs/P-1").status_code == 404 and api.get("/api/packs/nope").status_code == 404

            # Editing an earlier pack breaks it and every pack after it.
            from db.models import EvidencePack
            from db.session import SessionLocal
            with SessionLocal() as s:
                row = s.query(EvidencePack).filter_by(seq=int(a["pack_key"][2:])).one()
                row.content = {**row.content, "generated_by": "Someone else"}
                s.commit()
            va, vb = api.get(f"/api/packs/{a['pack_key']}/verify").json(), api.get(f"/api/packs/{b['pack_key']}/verify").json()
            assert not va["ok"] and not va["content_ok"] and va["broken_at"] == a["pack_key"]
            assert not vb["ok"] and not vb["chain_ok"] and vb["broken_at"] == a["pack_key"]

            # A contract changing after the pack was made is reported.
            with SessionLocal() as s:
                row = s.query(EvidencePack).filter_by(seq=int(a["pack_key"][2:])).one()
                row.content = {**row.content, "generated_by": "Compliance lead"}
                s.commit()
            api.post(f"/api/contracts/{c['contract_id']}/revoke", json={"reviewer": "x", "reason": "testing packs"})
            v2 = api.get(f"/api/packs/{a['pack_key']}/verify").json()
            assert v2["ok"] and any("now revoked" in n for n in v2["notes"])                                               # still intact, but flagged
        finally:
            clean_packs(*made)
            clean_findings()
            cleanup(KEY, "zz-test-sandbox")


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for n, f in tests:
        try:
            f()
            print("PASS ", n)
        except Exception as exc:
            failed += 1
            print("FAIL ", n, repr(exc))
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
