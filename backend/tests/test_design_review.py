"""
Tests for design_review.py through the real API and database: a gate that says REQUIRES_REVIEW holds the contract until a person who is allowed to, and who is not the
model's trainer, validator or deployer, records a review of this version of the design.

    docker compose exec backend python -m tests.test_design_review
"""
import copy
import sys

from sqlalchemy import delete

from db.models import Contract, DesignReview
from db.session import SessionLocal
from tests._auth import authed_client

DOC = {"nodes": [{"id": "n1", "kind": "AI_MODEL", "x": 10, "y": 20}], "edges": [], "n": 2}
VETO = ["SC-DPIA-1", "SC-HITL-1", "SC-HALLU-1", "SC-MAP-1", "SC-CHALL-1", "SC-LIAB-1"]
MET = VETO + ["SC-CONSENT-1", "SC-RCF-1"]          # the general domain also asks for consent provenance and role separation
GRAPH = {"nodes": [{"id": f"m{i}", "type": t, "props": p} for i, (t, p) in enumerate([
    ("AI_MODEL", {}), ("TRAINING_DATASET", {}), ("DEPLOYMENT_ENV", {}), ("LEGAL_BASIS", {}),
    ("ACTOR", {"subtype": "TRAINER"}), ("ACTOR", {"subtype": "VALIDATOR"}), ("ACTOR", {"subtype": "DEPLOYER"})])],
    "edges": [{"from": "m0", "to": "m1", "label": "TRAINED_ON"}, {"from": "m0", "to": "m2", "label": "RUNS_IN"},
              {"from": "m4", "to": "m0", "label": "TRAINS"}, {"from": "m5", "to": "m0", "label": "VALIDATES"}, {"from": "m6", "to": "m0", "label": "DEPLOYS"}]}


def payload():
    return {
        "domain": "GENERAL",
        "registry": {
            "actors": {"trainer": {"identity": "Diego Alvarez"}, "validator": {"identity": "Mina Okafor"}, "deployer": {"identity": "Priya Raman"},
                       "operator": {"identity": "Dispatchers"}, "consumer": {"identity": "Karim Haddad"}},
            "deployment_context": {"model_type": "LLM", "ai_criticality": "OPERATIONAL", "data_sensitivity": "SENSITIVE_PERSONAL"},
            "governance_state": {"constraints_declared": {c: {"status": "SATISFIED", "evidence": "see record"} for c in MET}},
        },
        "design_graph": GRAPH,
    }


def forget(key):
    """Remove what a test left behind: other suites expect no compiled model contract in the scratch database."""
    with SessionLocal() as s:
        s.execute(delete(Contract).where(Contract.deployment_id == key))
        s.execute(delete(DesignReview).where(DesignReview.design_key == key))
        s.commit()


def compile_body(p):
    return {**p, "graph": {"nodes": [], "edges": []}}


def test_review_holds_compile_until_an_independent_person_approves():
    with authed_client("compliance", "Rhea Patel") as comp, authed_client("engineer", "Sam Engineer") as eng:
        d = comp.post("/api/designs", json={"name": "Review test", "domain": "GENERAL", "document": DOC}).json()
        key = d["design_key"]
        p = payload()
        try:
            a = comp.post(f"/api/designs/{key}/assess", json=p).json()
            rv = a["review"]
            assert rv["gate"] == "REQUIRES_REVIEW" and rv["required"] and not rv["approved"] and rv["reviews"] == [], rv
            c = comp.post(f"/api/designs/{key}/compile", json=compile_body(p))
            assert c.status_code == 422 and "human review" in c.json()["detail"], c.text

            body = {**p, "decision": "APPROVED", "note": "Looked at the evidence for each constraint."}
            assert eng.post(f"/api/designs/{key}/review", json=body).status_code == 403                      # an engineer cannot sign off
            mine = copy.deepcopy(body)
            mine["registry"]["actors"]["validator"]["identity"] = "  rhea   PATEL "
            r = comp.post(f"/api/designs/{key}/review", json=mine)
            assert r.status_code == 403 and "validator" in r.json()["detail"], r.text                       # the reviewer is the model's own validator
            op = copy.deepcopy(body)
            op["registry"]["actors"]["operator"]["identity"] = "Rhea Patel"
            r = comp.post(f"/api/designs/{key}/review", json=op)
            assert r.status_code == 403 and "operator" in r.json()["detail"], r.text                          # nor can the person who runs it review it
            assert comp.post(f"/api/designs/{key}/review", json={**body, "note": "ok"}).status_code == 422   # a note is required
            assert comp.post("/api/designs/draft/review", json=body).status_code == 422                       # an unsaved design has nothing to review
            broken = copy.deepcopy(body)
            broken["design_graph"]["edges"] = []                                                              # nothing is connected to the model
            r = comp.post(f"/api/designs/{key}/review", json=broken)
            assert r.status_code == 422 and "once it is correct" in r.json()["detail"], r.text                 # a design is reviewed once it is correct

            r = comp.post(f"/api/designs/{key}/review", json=body)
            assert r.status_code == 201, r.text
            st = r.json()
            assert st["approved"] and not st["rejected"] and st["reviews"][0]["reviewer"] == "Rhea Patel" and st["reviews"][0]["current"], st
            assert comp.post(f"/api/designs/{key}/assess", json=p).json()["review"]["approved"]

            ok = comp.post(f"/api/designs/{key}/compile", json=compile_body(p))
            assert ok.status_code == 200, ok.text                                                            # the approved version compiles
            a = ok.json()["design_snapshot"]["assurance"]
            assert a["review"]["reviewer"] == "Rhea Patel" and a["review"]["decision"] == "APPROVED" and a["pcs"]["gate"] == "REQUIRES_REVIEW", a   # the contract carries the review

            changed = copy.deepcopy(p)
            changed["registry"]["actors"]["deployer"]["identity"] = "Someone Else"
            lapsed = comp.post(f"/api/designs/{key}/assess", json=changed).json()["review"]
            assert not lapsed["approved"] and lapsed["reviews"][0]["current"] is False, lapsed                 # any change to the design makes the review lapse
            assert comp.post(f"/api/designs/{key}/compile", json=compile_body(changed)).status_code == 422

            no = comp.post(f"/api/designs/{key}/review", json={**p, "decision": "REJECTED", "note": "Evidence for SC-HITL-1 does not hold up."})
            assert no.status_code == 201 and no.json()["rejected"] and not no.json()["approved"]
            assert comp.post(f"/api/designs/{key}/compile", json=compile_body(p)).status_code == 422          # a later rejection of the same version wins
        finally:
            assert comp.delete(f"/api/designs/{key}").status_code == 204
            forget(key)


def test_a_design_that_needs_no_review_compiles_without_one():
    with authed_client("compliance", "Rhea Patel") as comp:
        d = comp.post("/api/designs", json={"name": "No review needed", "domain": "GENERAL", "document": DOC}).json()
        key = d["design_key"]
        p = payload()
        p["registry"]["governance_state"]["constraints_declared"].update({c: {"status": "SATISFIED", "evidence": "see record"} for c in ("SC-TRAIN-1", "SC-MC-1")})
        try:
            st = comp.post(f"/api/designs/{key}/assess", json=p).json()["review"]
            if st["gate"] == "REQUIRES_REVIEW":          # the scoring says this design still needs a person: nothing to prove here
                return
            assert not st["required"]
            assert comp.post(f"/api/designs/{key}/compile", json=compile_body(p)).status_code == 200
        finally:
            comp.delete(f"/api/designs/{key}")
            forget(key)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS ", name)
            except Exception as e:           # noqa: BLE001
                failed += 1
                print("FAIL ", name, repr(e)[:600])
    print(f"\n{'ALL PASSED' if not failed else str(failed) + ' FAILED'}")
    sys.exit(1 if failed else 0)
