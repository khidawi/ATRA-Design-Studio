"""
Tests for method.py: every score says which method it was made under, a method is published deliberately by someone with sign-off permission, and a change to the rules is never
silently attributed to the method before it.

    docker compose exec backend python -m tests.test_method
"""
import sys

from sqlalchemy import delete, select, update

from db.models import MethodVersion, RcrRequirement
from db.session import SessionLocal
from tests._auth import authed_client

REGISTRY = {"actors": {"trainer": {"identity": "A"}, "validator": {"identity": "B"}, "deployer": {"identity": "C"}, "operator": {"identity": "D"}, "consumer": {"identity": "E"}},
            "deployment_context": {"model_type": "LLM", "ai_criticality": "OPERATIONAL", "data_sensitivity": "SENSITIVE_PERSONAL"}}


def numbers():
    with SessionLocal() as s:
        return [n for n in s.scalars(select(MethodVersion.number).order_by(MethodVersion.number))]


def drop_after(start):
    with SessionLocal() as s:
        s.execute(delete(MethodVersion).where(MethodVersion.number > start))
        s.commit()


def test_a_score_carries_the_method_it_was_made_under():
    with authed_client("engineer", "Sam Engineer") as api:
        m = api.post("/score", json={"registry": REGISTRY}).json()["method"]
        assert m["number"] >= 1 and len(m["fingerprint"]) == 64 and m["engine"] and m["unpublished"] is False, m
        again = api.post("/score", json={"registry": REGISTRY}).json()["method"]
        assert again["fingerprint"] == m["fingerprint"]                                  # the same rules give the same fingerprint
        graph = {"nodes": [{"id": "a", "type": "agent", "props": {"name": "x"}, "primary": True}], "edges": []}
        r = api.post("/api/rcr/score", json={"profile": "payments", "graph": graph, "declarations": {}}).json()
        assert r["method"]["fingerprint"] == m["fingerprint"], r["method"]               # models and agents are scored under the same method


def test_a_change_to_the_rules_is_not_attributed_to_the_published_method():
    with authed_client("engineer", "Sam Engineer") as api:
        before = api.post("/score", json={"registry": REGISTRY}).json()["method"]
        with SessionLocal() as s:
            req = s.scalar(select(RcrRequirement).limit(1))
            key, old = req.id, req.weight
            s.execute(update(RcrRequirement).where(RcrRequirement.id == key).values(weight=old + 1))
            s.commit()
        try:
            after = api.post("/score", json={"registry": REGISTRY}).json()["method"]
            assert after["number"] == before["number"] and after["unpublished"] is True and after["fingerprint"] != before["fingerprint"], after
            state = api.get("/api/method").json()
            assert state["changed_since_published"] == ["requirements"], state            # it says which part changed
        finally:
            with SessionLocal() as s:
                s.execute(update(RcrRequirement).where(RcrRequirement.id == key).values(weight=old))
                s.commit()
        assert api.post("/score", json={"registry": REGISTRY}).json()["method"]["unpublished"] is False


def test_publishing_is_deliberate_named_and_refused_when_nothing_changed():
    start = max(numbers() or [0])
    with authed_client("compliance", "Rhea Patel") as comp, authed_client("engineer", "Sam Engineer") as eng:
        try:
            state = comp.get("/api/method").json()
            start = state["current"]["number"]
            assert eng.post("/api/method/publish", json={"note": "Weights reviewed."}).status_code == 403          # only sign-off permission publishes
            r = comp.post("/api/method/publish", json={"note": "Weights reviewed."})
            assert r.status_code == 409 and "Nothing has changed" in r.json()["detail"], r.text                    # nothing to publish yet
            with SessionLocal() as s:
                req = s.scalar(select(RcrRequirement).limit(1))
                key, old = req.id, req.weight
                s.execute(update(RcrRequirement).where(RcrRequirement.id == key).values(weight=old + 1))
                s.commit()
            try:
                assert comp.post("/api/method/publish", json={"note": "no"}).status_code == 422                     # a reason is required
                r = comp.post("/api/method/publish", json={"note": "Raised a weight after the review."})
                assert r.status_code == 201, r.text
                st = r.json()
                assert st["current"]["number"] == start + 1 and st["current"]["unpublished"] is False, st["current"]
                top = st["history"][0]
                assert top["number"] == start + 1 and top["published_by"] == "Rhea Patel" and top["changed"] == ["requirements"], top
            finally:
                with SessionLocal() as s:
                    s.execute(update(RcrRequirement).where(RcrRequirement.id == key).values(weight=old))
                    s.commit()
            assert comp.get("/api/method").json()["current"]["unpublished"] is True                               # putting it back is itself a change to publish
        finally:
            drop_after(start)


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
