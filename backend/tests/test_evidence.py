"""
Tests for evidence.py: a file or a page snapshot is kept as a record, counts only once someone independent has attested it, and the gate is decided on the declared or the verified
score by one switch that a person with sign-off permission flips, with a reason, and that is audited.

    docker compose exec backend python -m tests.test_evidence
"""
import base64
import sys

from sqlalchemy import delete, select

from db.models import AppSetting, AuditEvent, Design, EvidenceRecord
from db.session import SessionLocal
from tests._auth import authed_client
from tests.test_design_review import DOC, MET, forget, payload

FILE = {"kind": "FILE", "summary": "DPIA signed by the DPO", "filename": "dpia.txt", "content_base64": base64.b64encode(b"The impact assessment, signed.").decode()}


def clean(key):
    forget(key)
    with SessionLocal() as s:
        s.execute(delete(EvidenceRecord).where(EvidenceRecord.design_key == key))
        s.execute(delete(Design).where(Design.design_key == key))
        row = s.get(AppSetting, "gate_basis")
        if row is not None:
            s.delete(row)
        s.commit()


def score(api, key):
    r = api.post("/score", json={"registry": payload()["registry"], "design_key": key})
    assert r.status_code == 200, r.text
    return r.json()


def test_a_file_is_kept_with_its_hash_and_read_back_intact():
    with authed_client("engineer", "Sam Engineer") as eng, authed_client("compliance", "Rhea Patel") as comp:
        key = comp.post("/api/designs", json={"name": "Evidence test", "domain": "GENERAL", "document": DOC}).json()["design_key"]
        try:
            r = eng.post("/api/evidence", json={"design_key": key, "control": "SC-DPIA-1", **FILE})
            assert r.status_code == 201, r.text
            rec = r.json()
            assert rec["status"] == "UPLOADED" and len(rec["sha256"]) == 64 and rec["integrity"] == "intact" and not rec["counts"], rec
            d = comp.get(f"/api/evidence/{rec['id']}/download")
            assert d.status_code == 200 and d.content == b"The impact assessment, signed." and d.headers["x-evidence-sha256"] == rec["sha256"]
            assert eng.post("/api/evidence", json={"design_key": "no-such", "control": "SC-DPIA-1", **FILE}).status_code == 422          # evidence belongs to a saved design
            assert eng.post("/api/evidence", json={"design_key": key, "control": "SC-DPIA-1", "kind": "FILE", "summary": "Empty file here", "filename": "a", "content_base64": ""}).status_code == 422
            with SessionLocal() as s:                                                                                                    # the stored bytes are altered
                row = s.scalar(select(EvidenceRecord).where(EvidenceRecord.design_key == key))
                row.content = b"Something else entirely, longer than before."
                s.commit()
            assert comp.get(f"/api/evidence/{rec['id']}/download").status_code == 409                                                    # a changed file is never served
            assert comp.get(f"/api/evidence?design_key={key}").json()[0]["integrity"] == "changed"
        finally:
            clean(key)


def test_a_page_is_a_snapshot_and_only_public_addresses_are_read():
    with authed_client("engineer", "Sam Engineer") as eng, authed_client("compliance", "Rhea Patel") as comp:
        key = comp.post("/api/designs", json={"name": "Evidence url", "domain": "GENERAL", "document": DOC}).json()["design_key"]
        try:
            r = eng.post("/api/evidence", json={"design_key": key, "control": "SC-DPIA-1", "kind": "URL", "summary": "Policy page", "url": "http://127.0.0.1:8000/health"})
            assert r.status_code == 422 and "private network" in r.json()["detail"], r.text
            assert eng.post("/api/evidence", json={"design_key": key, "control": "SC-DPIA-1", "kind": "URL", "summary": "Policy page", "url": "file:///etc/passwd"}).status_code == 422
        finally:
            clean(key)


def test_attestation_needs_someone_independent_and_only_then_does_the_control_count():
    with authed_client("compliance", "Rhea Patel") as comp, authed_client("compliance", "Omar Wells") as other, authed_client("engineer", "Sam Engineer") as eng:
        key = comp.post("/api/designs", json={"name": "Evidence attest", "domain": "GENERAL", "document": DOC}).json()["design_key"]
        try:
            before = score(comp, key)["levels"]
            assert before["attested"] is True and before["basis"] == "declared" and set(before["unverified"]) == set(MET), before         # the text names a record, but nobody has attested it
            rec = comp.post("/api/evidence", json={"design_key": key, "control": "SC-DPIA-1", **FILE}).json()
            assert eng.post(f"/api/evidence/{rec['id']}/attest", json={}).status_code == 403                                           # sign-off permission is needed
            r = comp.post(f"/api/evidence/{rec['id']}/attest", json={})
            assert r.status_code == 403 and "uploaded this record" in r.json()["detail"], r.text                                       # not the person who uploaded it
            r = other.post(f"/api/evidence/{rec['id']}/attest", json={"holders": {"validator": "omar  WELLS"}})
            assert r.status_code == 403 and "validator" in r.json()["detail"], r.text                                                  # not the one who holds a role now
            ok = other.post(f"/api/evidence/{rec['id']}/attest", json={"holders": {"validator": "Mina Okafor"}})
            assert ok.status_code == 200 and ok.json()["status"] == "ATTESTED" and ok.json()["attested_by"] == "Omar Wells" and ok.json()["counts"], ok.text
            assert other.post(f"/api/evidence/{rec['id']}/attest", json={}).status_code == 409                                         # decided once
            after = score(comp, key)
            lv = after["levels"]
            assert "SC-DPIA-1" not in lv["unverified"] and len(lv["unverified"]) == len(MET) - 1, lv
            assert lv["verified"]["pcs"] <= before["verified"]["pcs"] and lv["declared"]["pcs"] == before["declared"]["pcs"], (before, lv)  # attesting raises the verified score only
            assert comp.post(f"/api/evidence/{rec['id']}/revoke", json={"reason": "no"}).status_code == 422
            assert comp.post(f"/api/evidence/{rec['id']}/revoke", json={"reason": "The document was superseded."}).status_code == 200
            assert set(score(comp, key)["levels"]["unverified"]) == set(MET)                                                            # a revoked record no longer counts
        finally:
            clean(key)


def test_the_gate_follows_the_switch_and_only_sign_off_flips_it():
    with authed_client("compliance", "Rhea Patel") as comp, authed_client("engineer", "Sam Engineer") as eng:
        key = comp.post("/api/designs", json={"name": "Evidence switch", "domain": "GENERAL", "document": DOC}).json()["design_key"]
        try:
            assert comp.get("/api/evidence/policy").json() == {"gate_basis": "declared"}                                              # starts on declared
            declared_gate = score(comp, key)["pcs_result"]["gate"]
            assert eng.put("/api/evidence/policy", json={"basis": "verified", "note": "Board decision"}).status_code == 403
            assert comp.put("/api/evidence/policy", json={"basis": "verified", "note": "no"}).status_code == 422                     # a reason is required
            assert comp.put("/api/evidence/policy", json={"basis": "declared", "note": "Already there"}).status_code == 409
            assert comp.put("/api/evidence/policy", json={"basis": "verified", "note": "The board agreed verified evidence decides."}).status_code == 200
            out = score(comp, key)
            assert out["levels"]["basis"] == "verified" and out["pcs_result"]["gate"] == out["levels"]["verified"]["gate"], out["levels"]      # the gate now uses the verified score
            assert out["pcs_result"]["gate"] == "BLOCKED" and declared_gate != "BLOCKED", (declared_gate, out["pcs_result"]["gate"])          # nothing attested: the veto controls do not count
            sent = {"registry": payload()["registry"], "design_key": key}
            sent["registry"]["gate_basis"] = "declared"
            sent["registry"]["attested_controls"] = sorted(MET)                                                                          # a caller cannot choose its own basis or attest for itself
            assert comp.post("/score", json=sent).json()["pcs_result"]["gate"] == "BLOCKED"
            with SessionLocal() as s:
                ev = [e for e in s.scalars(select(AuditEvent).where(AuditEvent.action == "evidence.gate_basis"))]
                assert ev and ev[-1].payload["detail"]["to"] == "verified" and "board" in ev[-1].payload["detail"]["note"], ev     # the change is in the audit log
            assert comp.put("/api/evidence/policy", json={"basis": "declared", "note": "Moving back for the pilot."}).status_code == 200  # and can be moved back
            assert score(comp, key)["pcs_result"]["gate"] == declared_gate
        finally:
            clean(key)


def test_an_attestation_can_lapse_and_then_stops_counting():
    from datetime import date, timedelta
    with authed_client("compliance", "Rhea Patel") as comp, authed_client("compliance", "Omar Wells") as other:
        key = comp.post("/api/designs", json={"name": "Evidence expiry", "domain": "GENERAL", "document": DOC}).json()["design_key"]
        try:
            rec = comp.post("/api/evidence", json={"design_key": key, "control": "SC-DPIA-1", **FILE}).json()
            assert other.post(f"/api/evidence/{rec['id']}/attest", json={"expires_on": date.today().isoformat()}).status_code == 422       # it has to run past today
            soon = (date.today() + timedelta(days=20)).isoformat()
            ok = other.post(f"/api/evidence/{rec['id']}/attest", json={"expires_on": soon})
            assert ok.status_code == 200 and ok.json()["expires_at"] == soon and ok.json()["counts"] and not ok.json()["expired"], ok.text
            assert "SC-DPIA-1" not in score(comp, key)["levels"]["unverified"]
            with SessionLocal() as s:                                                                                                    # the day passes
                row = s.scalar(select(EvidenceRecord).where(EvidenceRecord.design_key == key))
                row.expires_at = date.today() - timedelta(days=1)
                s.commit()
            lapsed = comp.get(f"/api/evidence?design_key={key}").json()[0]
            assert lapsed["expired"] and not lapsed["counts"] and lapsed["status"] == "ATTESTED", lapsed
            assert "SC-DPIA-1" in score(comp, key)["levels"]["unverified"]                                                               # back to declared only
        finally:
            clean(key)


def test_the_expiring_list_gathers_declarations_and_records_soonest_first():
    from datetime import date, timedelta
    from tests.test_agent_findings import agent_doc
    day = lambda n: (date.today() + timedelta(days=n)).isoformat()                                                                      # noqa: E731
    model_doc = {"nodes": [{"id": "c1", "kind": "CONSTRAINT", "x": 0, "y": 0, "data": {"constraintId": "SC-HITL-1", "status": "SATISFIED", "validUntil": day(5)}}], "edges": [], "n": 2}
    with authed_client("compliance", "Rhea Patel") as comp, authed_client("compliance", "Omar Wells") as other, authed_client("engineer", "Sam Engineer") as eng:
        m = comp.post("/api/designs", json={"name": "zz-expiring-model", "domain": "GENERAL", "document": model_doc}).json()["design_key"]
        a = comp.post("/api/designs", json={"name": "zz-expiring-agent", "domain": "OWASP_AGENTIC", "subject": "AGENT",
                                            "document": agent_doc("Platform team", {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Rhea Patel", "valid_until": day(12)}})}).json()["design_key"]
        try:
            rec = comp.post("/api/evidence", json={"design_key": m, "control": "SC-DPIA-1", **FILE}).json()
            assert other.post(f"/api/evidence/{rec['id']}/attest", json={"expires_on": day(40)}).status_code == 200
            rows = [r for r in eng.get("/api/evidence/expiring?within=30").json() if r["design"].startswith("zz-expiring")]
            assert [(r["subject"], r["control"], r["kind"]) for r in rows] == [("MODEL", "SC-HITL-1", "declaration"), ("AGENT", "dpia", "declaration")], rows     # the record lapses after 30 days
            assert [r["days_left"] for r in rows] == [5, 12] and rows == sorted(rows, key=lambda r: r["date"])
            assert rows[1]["gate_effect"]["now"] in ("APPROVE", "REVIEW", "BLOCK") and "moves_gate" in rows[1]["gate_effect"], rows[1]                              # an agent says what the gate would do
            assert "gate_effect" not in rows[0]
            wide = [r for r in eng.get("/api/evidence/expiring?within=60").json() if r["design"].startswith("zz-expiring")]
            assert [r["kind"] for r in wide] == ["declaration", "declaration", "record"] and wide[-1]["days_left"] == 40, wide
        finally:
            clean(m)
            clean(a)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS ", name)
            except Exception as e:           # noqa: BLE001
                failed += 1
                print("FAIL ", name, repr(e)[:700])
    print(f"\n{'ALL PASSED' if not failed else str(failed) + ' FAILED'}")
    sys.exit(1 if failed else 0)
