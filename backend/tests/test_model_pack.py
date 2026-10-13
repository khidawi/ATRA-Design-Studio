"""
Tests for Assurance Packs for AI models (model_pack.py, packs.py): scored on the server, hashed, chained, verifiable, and free of anything identifying.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_model_pack
"""
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from compliance_schema import CompiledContract, DesignRiskAssessment, RiskStatus, compute_contract_hash
from db.models import ApiKey, Contract, Design, EvidencePack, ModelMonitor
from db.session import SessionLocal
from design_store import store_contract
from main import app
from schema import RegistryBlock
from tests._auth import authed_client
from tests.test_agent_registry import cleanup

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:500] if detail and not ok else ""))
    if not ok:
        fails.append(name)


rng = random.Random(31)
NAME = "zz-test-pack-model"
SECRET_NAME = "Alice Smith"


def keyed(token):
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


def tidy():
    with SessionLocal() as s:
        for m in s.query(ModelMonitor).filter(ModelMonitor.key.like("zz-test%")).all():
            s.delete(m)
        for c in s.query(Contract).filter(Contract.deployment_id.like("zz-test%")).all():
            s.delete(c)
        for d in s.query(Design).filter(Design.name.like("zz-test%")).all():
            s.delete(d)
        s.query(ApiKey).filter(ApiKey.name.like("zz-test%")).delete(synchronize_session=False)
        s.commit()
    cleanup()


def forget_packs(keys):
    with SessionLocal() as s:
        for p in s.query(EvidencePack).filter(EvidencePack.seq.in_([int(k.removeprefix("P-")) for k in keys])).all():
            s.delete(p)
        s.commit()


def post(c, key, path, field, items):
    return c.post(f"/api/model-monitor/{key}/{path}", content=json.dumps({field: items}), headers={"content-type": "application/json"})


made = []
try:
    with authed_client("admin", "Compliance lead") as api, authed_client("auditor") as aud:
        tidy()
        before = api.post("/api/packs", json={"template": "ASSURANCE", "subject": "MODEL"})
        check("with no compiled model there is nothing to attest, and it says so", before.status_code == 409 and "compiled contract" in before.text, before.text)

        d = api.post("/api/designs", json={"name": NAME, "domain": "GENERAL", "subject": "MODEL", "document": {"nodes": [], "edges": [], "n": 1, "life": {"audit_frequency": "CONTINUOUS"}}}).json()
        dk = d["design_key"]
        with SessionLocal() as s:
            row = s.query(Design).filter(Design.design_key == dk).one()
            c = CompiledContract(contract_id=str(uuid.uuid4()), version="1.0.0", object_type="MODEL", deployment_id="zz-test-pack-model", domain="GENERAL",
                                 design_snapshot={"registry": RegistryBlock().model_dump(mode="json"), "graph": {}},
                                 risk_assessment=DesignRiskAssessment(overall_status=RiskStatus.GREEN), issued_at=datetime.now(timezone.utc), issued_by="Compliance lead")
            c.contract_hash = compute_contract_hash(c)
            store_contract(s, c, dk)
            s.commit()
            contract_hash = c.contract_hash

        # production evidence: a monitor with drifting traffic, a credential leak, and staff who accept everything
        col = keyed(api.post("/api/keys", json={"name": "zz-test-serving", "role": "collector"}).json()["key"])
        mk = api.post("/api/model-monitor", json={"name": NAME, "design_key": dk, "task": "generative", "baseline_target": 100, "features": [{"name": "topic", "kind": "categorical"}], "output": {"name": "reply", "kind": "categorical"}}).json()["key"]
        now = datetime.now(timezone.utc)

        def rec(i, at, ok=0.9, flags=None, version="v1"):
            r = {"inputs": {"topic": rng.choice(["a", "b", "c"])}, "output": "ok" if rng.random() < ok else "refuse", "latency_ms": 100, "model_version": version, "at": at.isoformat()}
            if flags:
                r["flags"] = flags
            return r
        post(col, mk, "records", "records", [rec(i, now - timedelta(hours=30, seconds=i)) for i in range(120)])
        post(col, mk, "records", "records", [rec(i, now - timedelta(minutes=20, seconds=i), ok=0.2, flags={"secret_in_prompt": True} if i == 4 else None, version="v2") for i in range(200)])
        post(col, mk, "decisions", "decisions", [{"role": "clerk", "action": "accepted", "review_seconds": 2, "model_correct": rng.random() > 0.2, "person": SECRET_NAME, "at": (now - timedelta(minutes=rng.randrange(1, 900))).isoformat()} for _ in range(260)])
        api.get(f"/api/model-monitor/{mk}")

        # ── the pack
        r = api.post("/api/packs", json={"template": "ASSURANCE", "subject": "MODEL", "period": "30d"})
        check("a model pack is generated and stored", r.status_code == 201 and r.json()["subject"] == "MODEL" and r.json()["claims"] > 0, r.text)
        p = r.json()
        made.append(p["pack_key"])
        x = p["content"]
        m = x["models"][0]
        check("it is about models, with the contract's hash", x["subject"] == "MODEL" and x["scope"]["models_in_scope"] == 1 and m["contract"]["hash"] == contract_hash, x["scope"])
        check("three scores are computed on the server: design time, declared and observed", all(m[k].get("pcs") is not None and m[k]["tier"] and m[k]["gate"] for k in ("design_time", "declared", "observed")), {k: m[k] for k in ("design_time", "declared", "observed")})
        check("production can only add risk: observed is never below declared", m["observed"]["pcs"] >= m["declared"]["pcs"])
        check("it says where production contradicts what was declared", any("human review" in t.lower() for t in m["contradictions"]), m["contradictions"])
        check("and records the gap, with the pillars that moved", m["assurance_gap"]["headline"] == round(m["observed"]["pcs"] - m["declared"]["pcs"], 1) and isinstance(m["assurance_gap"]["pillars_moved"], list))
        mb = m["monitors"][0]
        check("the monitor's state is evidenced as statistics", mb["records_received"] >= 320 and mb["versions"]["changes"] == 1 and mb["people"]["decisions"] >= 250 and mb["people"]["wrong_accepted"] is not None and mb["safety"]["flagged"].get("secret_in_prompt") == 1, mb)
        check("gaps are stated, never hidden", any("contradict" in g["text"].lower() or "human review" in g["text"].lower() for g in x["gaps"]) and all(g["id"].startswith("G-") for g in x["gaps"]), x["gaps"])
        check("claims cite evidence, and the limits say what is not claimed", all(k["evidence"] for k in x["claims"]) and any("No prompt, reply, record" in l for l in x["limits"]))
        kinds = {e["type"] for e in x["evidence"]}
        check("evidence covers the contract, the monitor and its incidents", {"contract", "monitor", "incident"} <= kinds, kinds)
        blob = json.dumps(x)
        check("no person's name is anywhere in it", SECRET_NAME not in blob and "Alice" not in blob)

        # ── trust form
        t = api.post("/api/packs", json={"template": "TRUST", "subject": "MODEL", "period": "30d"}).json()
        made.append(t["pack_key"])
        tb = json.dumps(t["content"])
        check("the trust form has no model or monitor name and no design key", NAME not in tb and dk not in tb and "Model 1" in tb and "name" not in t["content"]["models"][0]["monitors"][0], tb[:300])
        check("the trust form keeps the three scores", t["content"]["models"][0]["observed"]["pcs"] == m["observed"]["pcs"])

        # ── integrity
        v = api.get(f"/api/packs/{p['pack_key']}/verify").json()
        check("the hash chain verifies and the cited contract is re-hashed", v["ok"] and v["chain_ok"] and v["contracts_checked"] == 1 and v["contracts_ok"] == 1, v)
        check("the chain is shared: the second pack points at the first", t["previous_pack_hash"] == p["pack_hash"])
        lst = {x_["pack_key"]: x_ for x_ in api.get("/api/packs").json()}
        check("the list says what each pack is about", lst[p["pack_key"]]["subject"] == "MODEL")
        pdf = api.get(f"/api/export/packs/{p['pack_key']}.pdf")
        check("a PDF is produced", pdf.status_code == 200 and pdf.content[:4] == b"%PDF", pdf.status_code)
        check("and the JSON", api.get(f"/api/export/packs/{p['pack_key']}.json").status_code == 200)
        check("only compliance can generate one", aud.post("/api/packs", json={"template": "ASSURANCE", "subject": "MODEL"}).status_code == 403)

        # ── tampering is visible
        with SessionLocal() as s:
            row = s.query(Contract).filter(Contract.contract_id == m["contract"]["id"]).one()
            doc = dict(row.document)
            doc["issued_by"] = "someone else"
            row.document = doc
            s.commit()
        v2 = api.get(f"/api/packs/{p['pack_key']}/verify").json()
        check("editing the contract afterwards breaks verification", v2["ok"] is False and any("no longer matches" in q for q in v2["problems"]), v2)
finally:
    try:
        forget_packs(made)
        tidy()
    except Exception as exc:
        print("cleanup failed", exc)
sys.exit(1 if fails else 0)
