"""
Tests for class-level coverage, the assurance dossier, the pack section, the security view and the regulation-change watch (ASTRA phase 12).

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_astra_assurance        # see tests/_guard.py

Part one is pure (the verdict rule of a row, the clause matching). Part two goes through the API on a scratch database with a signed contract that declares constraints and maps them to clauses.
"""
import copy
import sys
import uuid
from datetime import date, datetime, timedelta, timezone

import astra_assurance as AS
import astra_regwatch as RW
from astra_model.classes import CLASSES


# ── pure ──────────────────────────────────────────────────────────────────────────────────────────────────────

def test_a_row_is_covered_only_when_the_contract_the_probe_and_real_monitoring_all_hold():
    assert AS.row_verdict(True, "pass", "receiving")["verdict"] == "Covered"
    assert AS.row_verdict(True, "pass", "idle")["verdict"] == "Partial"
    assert AS.row_verdict(True, "none", "receiving")["verdict"] == "Partial"
    assert AS.row_verdict(False, "pass", "receiving")["verdict"] == "Partial"
    assert AS.row_verdict(False, "none", "idle")["verdict"] == "Gap"
    assert AS.row_verdict(False, "stale", "idle")["verdict"] == "Gap"
    for c in (True, False):
        for m in ("receiving", "idle", "none"):
            assert AS.row_verdict(c, "fail", m)["verdict"] == "Gap", "a missed scenario is a gap whatever else is true"
    capped = AS.row_verdict(True, "pass", "none")
    assert capped["verdict"] == "Partial" and any("cannot be monitored" in w for w in capped["why"]), "a row no class signals can never be covered"
    stale = AS.row_verdict(True, "stale", "receiving")
    assert stale["verdict"] == "Partial" and any("earlier version" in w for w in stale["why"])
    assert AS.worst([]) == "No data" and AS.worst(["Covered", "Gap", "Partial"]) == "Gap" and AS.worst(["Covered", "Partial"]) == "Partial"


def test_every_row_knows_its_classes_and_the_ones_with_none_are_the_ones_that_cannot_be_monitored():
    none = [r for r in AS.ROWS if not AS.classes_of(r)]
    assert none == ["ASI08"], none
    assert sorted({c for r in AS.ROWS for c in AS.classes_of(r)}) == sorted(CLASSES), "every class signals at least one row"
    assert AS.classes_of("ASI02") == ["DVG-TOOL-01", "DVG-TOOL-02", "DVG-TOOL-03"]


def test_a_clause_anchor_matches_the_article_it_names_and_not_its_neighbours():
    p = RW._pattern("Art.14")
    for yes in ("Art. 14", "Art.14", "Article 14", "Art. 14(2)", "art 14 - oversight"):
        assert p.search(yes), yes
    for no in ("Art. 140", "Art. 141", "Art. 4", "Annex 14", "Art. 1"):
        assert not p.search(no), no
    assert RW._pattern("supplier-controls") is None and RW._pattern("A.9.2") is None or RW._pattern("A.9.2") is not None


# ── through the API ───────────────────────────────────────────────────────────────────────────────────────────────

def world(fn):
    from tests.test_astra_probe import probed
    return probed(fn)


def doc_with_constraints(clauses):
    from tests.test_astra_verdicts import DOC
    d = copy.deepcopy(DOC)
    d["constraints"] = [{"asi": "ASI02", "control": "human_approval_on_every_write_tool"}, {"asi": "ASI09", "control": "confirmation_with_raw_action"}]
    d["regulatory_mappings"] = [{"control": "human_approval_on_every_write_tool", "clauses": clauses}]
    return d


def sign(doc):
    from tests.test_astra_verdicts import sign_row
    sign_row(doc=doc)


def row(cov, code):
    return next(r for r in cov["rows"] if r["code"] == code)


def clean_extra():
    from db.models import CoverageAssignment, RegulationReview, Regulation, Rule
    from db.session import SessionLocal
    with SessionLocal() as s:
        s.query(RegulationReview).filter(RegulationReview.clause.like("ZZ-%")).delete(synchronize_session=False)
        s.query(CoverageAssignment).filter(CoverageAssignment.code.in_(("ASI02", "ASI09"))).delete(synchronize_session=False)
        s.query(Rule).filter(Rule.rule_key.like("ZZ-TEST-%")).delete(synchronize_session=False)
        s.query(Regulation).filter(Regulation.instrument == "ZZ Test Act").delete(synchronize_session=False)
        s.commit()


def extra(fn):
    def run():
        from fastapi.testclient import TestClient
        from main import app
        with TestClient(app):                                           # the application brings the scratch database up to date when it starts
            pass
        clean_extra()
        try:
            fn()
        finally:
            clean_extra()
    run.__name__ = fn.__name__
    return run


@extra
def test_coverage_is_per_row_from_the_contract_the_probe_and_events_actually_received():
    from tests.test_astra_assessment_api import KEY, NAME
    from tests.test_astra_verdicts import send

    @world
    def body(one, two, eng):
        sign(doc_with_constraints(["EU-AI-Act:Art.14"]))
        cov = eng.get("/api/astra/coverage").json()
        assert cov["agents_in_scope"] == 1 and len(cov["rows"]) == 10 and cov["covered"] == 0
        r2 = row(cov, "ASI02")
        assert r2["verdict"] == "Partial" and r2["agents"][0]["facts"] == {"constraint": True, "probe": False, "monitored": False} and any("no Probe scenario" in w for w in r2["reasons"])
        assert row(cov, "ASI08")["verdict"] == "Gap" and row(cov, "ASI08")["classes"] == []
        assert row(cov, "ASI01")["verdict"] == "Gap", "no constraint, no probe, no events"
        eng.post("/api/astra/probe/run", json={"design_key": KEY})
        send(eng, "tool_call", name="lookup", params={"amount": 5})
        cov = eng.get("/api/astra/coverage").json()
        r2 = row(cov, "ASI02")
        assert r2["verdict"] == "Covered" and r2["agents"][0]["facts"] == {"constraint": True, "probe": True, "monitored": True}, r2
        assert any(c["id"] == "DVG-TOOL-01" and c["events_30d"] >= 1 and c["probe"] == "pass" for c in r2["agents"][0]["classes"])
        r9 = row(cov, "ASI09")
        assert r9["verdict"] == "Covered", "the confirmation classes are judged on the same tool calls"
        r1 = row(cov, "ASI01")
        assert r1["verdict"] == "Partial" and r1["agents"][0]["facts"] == {"constraint": False, "probe": True, "monitored": False} and r1["agents"][0]["monitored"] == "idle", r1["agents"][0]
        send(eng, "tool_call", name="refund")                                    # a write tool with no word on a confirmation: unverified, so not counted for the row it concerns
        assert row(eng.get("/api/astra/coverage").json(), "ASI02")["agents"][0]["classes"][0]["events_30d"] == 1
        assert cov["covered"] >= 1
    body()


@extra
def test_a_missed_probe_scenario_is_a_gap_even_with_a_constraint_and_monitoring():
    from tests.test_astra_assessment_api import KEY
    from tests.test_astra_probe import drop, mutated
    from tests.test_astra_verdicts import send

    @world
    def body(one, two, eng):
        sign(doc_with_constraints(["EU-AI-Act:Art.14"]))
        send(eng, "tool_call", name="lookup", params={"amount": 5})
        with mutated(drop("DVG-TOOL-01")):
            eng.post("/api/astra/probe/run", json={"design_key": KEY})
        r2 = row(eng.get("/api/astra/coverage").json(), "ASI02")
        assert r2["verdict"] == "Gap" and r2["agents"][0]["probe"] == "fail" and any("missed" in w for w in r2["reasons"]), r2
        eng.post("/api/astra/probe/run", json={"design_key": KEY})
        assert row(eng.get("/api/astra/coverage").json(), "ASI02")["verdict"] == "Covered"
    body()


@extra
def test_a_changed_design_makes_the_probe_evidence_stale_and_owners_and_dates_are_kept_per_row():
    from tests.test_astra_assessment_api import KEY, guarded_doc, set_doc
    from tests.test_astra_verdicts import send

    @world
    def body(one, two, eng):
        sign(doc_with_constraints(["EU-AI-Act:Art.14"]))
        eng.post("/api/astra/probe/run", json={"design_key": KEY})
        send(eng, "tool_call", name="lookup", params={"amount": 5})
        assert row(eng.get("/api/astra/coverage").json(), "ASI02")["verdict"] == "Covered"
        d = guarded_doc()
        d["nodes"].append({"id": "t9", "type": "tool", "name": "lookup", "p": {}})
        d["edges"].append({"from": "a1", "to": "t9", "label": "uses"})
        set_doc(d)
        r2 = row(eng.get("/api/astra/coverage").json(), "ASI02")
        assert r2["verdict"] == "Partial" and r2["agents"][0]["probe"] == "stale" and any("earlier version" in w for w in r2["reasons"]), r2
        cov = eng.get("/api/astra/coverage").json()
        assert row(cov, "ASI02")["unowned"] and cov["rows_without_owner"] >= 1
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        assert one.put("/api/coverage/ASI02", json={"owner": "Rhea One", "due": yesterday, "note": "Re-run the Probe."}).status_code == 200
        r2 = row(eng.get("/api/astra/coverage").json(), "ASI02")
        assert r2["owner"] == "Rhea One" and r2["due"] == yesterday and r2["overdue"] and not r2["unowned"]
    body()


@extra
def test_the_dossier_resolves_every_claim_to_a_record_and_a_clause_and_states_its_gaps():
    from tests.test_astra_assessment_api import KEY, NAME
    from tests.test_astra_verdicts import send
    from db.models import AstraSignedContract
    from db.session import SessionLocal
    from sqlalchemy import select

    @world
    def body(one, two, eng):
        sign(doc_with_constraints(["EU-AI-Act:Art.14", "ISO-42001:supplier-controls"]))
        assert one.post(f"/api/agents/designs/{KEY}/assessments").status_code == 201
        run = eng.post("/api/astra/probe/run", json={"design_key": KEY}).json()
        send(eng, "tool_call", name="lookup", params={"amount": 5})
        d = eng.get(f"/api/astra/assurance/agent/{NAME}").json()
        with SessionLocal() as s:
            signed = s.scalar(select(AstraSignedContract).where(AstraSignedContract.agent_key == NAME, AstraSignedContract.status == "ACTIVE"))
            sid = str(signed.id)
        assert d["contract"]["id"] == sid and d["contract"]["valid_now"] and d["contract"]["contract_hash"] and d["contract"]["baseline"]["accepted_by"] == "Zz Acceptor"
        assert [c["row"] for c in d["claims"]] == AS.ROWS
        c2 = next(c for c in d["claims"] if c["row"] == "ASI02")
        assert c2["verdict"] == "Covered"
        kinds = {e["fact"]: e for e in c2["evidence"]}
        assert kinds["constraint"]["record"]["id"] == sid and kinds["constraint"]["record"]["constraint"] == "human_approval_on_every_write_tool"
        assert kinds["probe"]["record"] == {"kind": "probe run", "id": run["id"]} and kinds["probe"]["result"] == "pass"
        assert kinds["monitored"]["record"]["kind"] == "runtime events" and kinds["monitored"]["events"] >= 1
        assert "EU-AI-Act:Art.14" in c2["clauses"] and "ISO-42001:supplier-controls" in c2["clauses"] and "EU-AI-Act:Art.15" in c2["clauses"], c2["clauses"]
        assert d["unmapped_rows"] == ["ASI05", "ASI08", "ASI09"], "the rows the specification gives no clause anchor are named, not hidden"
        assert all(c["clauses"] for c in d["claims"] if c["row"] not in d["unmapped_rows"]) and all("no regulatory clause" in " ".join(c["why"]) for c in d["claims"] if c["row"] in d["unmapped_rows"])
        gaps = {g["row"]: g for g in d["gaps"]}
        assert "ASI08" in gaps and "ASI02" not in gaps and gaps["ASI01"]["why"], "what is not covered is stated, with the reason"
        assert d["assessments"] and d["assessments"][0]["verdict"] in ("APPROVED", "REQUIRES_REVIEW", "BLOCKED")
        assert d["probe"]["id"] == run["id"] and d["probe"]["current"] and len(d["probe"]["results"]) == 22
        assert len(d["monitored_classes"]) == 22 and d["limits"] and d["summary"]["Covered"] >= 1
        again = eng.get(f"/api/astra/assurance/agent/{NAME}").json()
        assert again["hash"] == d["hash"], "the same records give the same hash"
        assert eng.get("/api/astra/assurance/agent/zz-nobody").status_code == 404
        with SessionLocal() as s:
            s.scalar(select(AstraSignedContract).where(AstraSignedContract.agent_key == NAME)).status = "REVOKED"
            s.commit()
        assert eng.get(f"/api/astra/assurance/agent/{NAME}").status_code == 404, "a revoked contract is not something to state coverage for"
    body()


@extra
def test_the_pack_section_carries_counts_for_the_short_form_and_detail_for_the_full_form():
    import packs
    from db.session import SessionLocal
    from tests.test_astra_assessment_api import NAME

    @world
    def body(one, two, eng):
        sign(doc_with_constraints(["EU-AI-Act:Art.14"]))
        with SessionLocal() as s:
            short = AS.pack_section(s, True)
            full = AS.pack_section(s, False)
        assert short["agents_with_signed_contract"] == 1 and set(short["rows"]) == {"covered", "partial", "gap", "no_data"} and short["divergence_classes"]["total"] == 22
        assert "agents" not in short and "rows_detail" not in short and NAME not in repr(short), "the short form names no agent"
        assert [r["code"] for r in full["rows_detail"]] == AS.ROWS and full["agents"][0]["agent"] == NAME and full["agents"][0]["contract"]["hash"]
        assert full["limits"] == short["limits"] and any("simulated" in x for x in full["limits"])
        assert "astra_assurance.pack_section(session, trust)" in open(packs.__file__, encoding="utf-8").read(), "build_content puts the section into every pack"
    body()


@extra
def test_the_security_view_lists_what_is_wrong_and_the_security_role_reads_and_runs_but_never_signs_off():
    from tests._auth import authed_client
    from tests.test_astra_assessment_api import KEY, NAME
    from tests.test_astra_verdicts import send, sign_row

    @world
    def body(one, two, eng):
        sign_row(expires=datetime.now(timezone.utc) + timedelta(days=5), doc=doc_with_constraints(["EU-AI-Act:Art.14"]))
        r = send(eng, "tool_call", name="shell")
        assert r["verdict"] == "DIVERGENT"
        send(eng, "goal_set", name="Sell the data", source="retrieved document", semantic="out_of_scope")
        sec = eng.get("/api/astra/security").json()
        assert [e["agent"] for e in sec["contracts"]["expiring"]] == [NAME] and sec["contracts"]["invalid"] == []
        assert sec["findings"]["open"] >= 2 and sec["findings"]["pending_adjudication"] >= 1 and any(c["class"] == "DVG-TOOL-01" for c in sec["findings"]["by_class"])
        assert sec["verdicts"]["counts"]["APPROVED"] + sec["verdicts"]["counts"]["REQUIRES_REVIEW"] + sec["verdicts"]["counts"]["BLOCKED"] >= 1
        assert set(sec["coverage"]) >= {"covered", "partial", "gap", "no_data", "rows_without_owner", "worst"} and sec["regulation_watch"]["needing_review"] >= 1
        with authed_client("security", "Sam Security") as sx:
            assert sx.get("/api/astra/security").status_code == 200 and sx.get("/api/astra/coverage").status_code == 200
            assert sx.post("/api/astra/probe/run", json={"design_key": KEY}).status_code == 201, "a security person can run the Probe"
            assert sx.get("/api/audit").status_code == 200, "and read the audit log"
            assert sx.post("/api/astra/regwatch/review", json={"clause": "EU-AI-Act:Art.14", "note": "Reviewed."}).status_code == 403
            assert sx.post(f"/api/astra/probe/scenarios/{uuid.uuid4()}/approve", json={}).status_code == 403
            assert sx.post("/api/astra/learned/tgn/rollback").status_code == 403, "nothing is signed off by the security role"
    body()


@extra
def test_the_regulation_watch_flags_a_mapping_when_the_rules_behind_it_change_until_a_person_reviews_it():
    from tests._auth import authed_client
    from db.models import Regulation, Rule
    from db.session import SessionLocal
    from sqlalchemy import select

    @world
    def body(one, two, eng):
        with SessionLocal() as s:
            reg = Regulation(instrument="ZZ Test Act", name="Test Act", kind="REGULATION", description="")
            s.add(reg)
            s.flush()
            s.add(Rule(rule_key="ZZ-TEST-ART7", regulation_id=reg.id, citation="Art. 7", title="Keep a log", description="Keep a log of every action.", severity="REQUIRED", subject="AGENT",
                       check_type="ATTESTATION", status="APPROVED"))
            s.add(Rule(rule_key="ZZ-TEST-ART70", regulation_id=reg.id, citation="Art. 70", title="Something else", description="Not this one.", severity="REQUIRED", subject="AGENT",
                       check_type="ATTESTATION", status="APPROVED"))
            s.commit()
        sign(doc_with_constraints(["ZZ-Test-Act:Art.7", "ZZ-Nothing:Sec.9"]))
        w = {m["clause"]: m for m in eng.get("/api/astra/regwatch").json()["mappings"]}
        assert w["ZZ-Test-Act:Art.7"]["status"] == "UNREVIEWED" and w["ZZ-Test-Act:Art.7"]["rules"] == ["ZZ-TEST-ART7"], "Art. 7 does not pick up Art. 70"
        assert w["ZZ-Nothing:Sec.9"]["status"] == "UNRESOLVED" and "indicative" in w["ZZ-Nothing:Sec.9"]["why"]
        assert eng.post("/api/astra/regwatch/review", json={"clause": "ZZ-Test-Act:Art.7", "note": "Looks right."}).status_code == 403, "an engineer cannot review"
        assert one.post("/api/astra/regwatch/review", json={"clause": "ZZ-Test-Act:Art.7", "note": "a"}).status_code == 422
        assert one.post("/api/astra/regwatch/review", json={"clause": "ZZ-No-Such:Art.1", "note": "Looks right."}).status_code == 404
        r = one.post("/api/astra/regwatch/review", json={"clause": "ZZ-Test-Act:Art.7", "note": "The mapping holds for this rule."})
        assert r.status_code == 201 and r.json()["status"] == "CURRENT" and r.json()["reviewed_by"] == "Rhea One", r.text
        with SessionLocal() as s:                                                          # the rule is edited afterwards
            rule = s.scalar(select(Rule).where(Rule.rule_key == "ZZ-TEST-ART7"))
            rule.description = "Keep a tamper-evident log of every action."
            s.commit()
        w = {m["clause"]: m for m in eng.get("/api/astra/regwatch").json()["mappings"]}
        assert w["ZZ-Test-Act:Art.7"]["status"] == "CHANGED" and "changed since" in w["ZZ-Test-Act:Art.7"]["why"], "a mapping that was right is flagged, not left to drift"
        counts = eng.get("/api/astra/regwatch").json()["counts"]
        assert counts["CHANGED"] == 1 and counts["UNRESOLVED"] == 1
        assert two.post("/api/astra/regwatch/review", json={"clause": "ZZ-Test-Act:Art.7", "note": "Reviewed again after the edit."}).json()["status"] == "CURRENT"
        with SessionLocal() as s:                                                          # a rule is retired
            s.scalar(select(Rule).where(Rule.rule_key == "ZZ-TEST-ART7")).status = "RETIRED"
            s.commit()
        assert {m["clause"]: m for m in eng.get("/api/astra/regwatch").json()["mappings"]}["ZZ-Test-Act:Art.7"]["status"] == "CHANGED"
        acc = one.post("/api/astra/regwatch/review", json={"clause": "ZZ-Nothing:Sec.9", "note": "No rule corresponds; the anchor is indicative."}).json()
        assert acc["status"] == "CURRENT" and "no rule" in acc["why"], "an unresolved mapping can be acknowledged for what it is"
    body()


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    failed_n = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed_n += 1
            print(f"FAIL  {name}  {exc!r}")
    print(f"{len(tests) - failed_n}/{len(tests)} passed")
    sys.exit(1 if failed_n else 0)
