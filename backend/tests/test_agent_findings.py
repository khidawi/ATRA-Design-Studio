"""
Tests for agent_findings.py and agent_review.py: the design checks for an AI agent, the fix for each, and the review a design waits for before it is ratified.

    docker compose exec backend python -m tests.test_agent_findings
"""
import sys

from agent_findings import design_fingerprint, formal_findings
from db.models import Agent, Contract, Design, DesignReview
from db.session import SessionLocal
from rule_checks import DesignGraph, GEdge, GNode
from tests._auth import authed_client

PASSED = FAILED = 0


def check(name, ok, detail=""):
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print("PASS ", name)
    else:
        FAILED += 1
        print("FAIL ", name, detail)


def graph(nodes, edges):
    return DesignGraph([GNode(i, t, {"name": n, **p}, bool(prim)) for i, t, n, p, prim in nodes], [GEdge(a, b, label) for a, b, label in edges])


BASE = [("a1", "agent", "Refund agent", {"owner": "Payments team"}, True), ("g1", "goal", "Refund customers", {}, False), ("t1", "tool", "refunds.write", {"write": True}, False),
        ("h1", "human", "Customer", {}, False), ("i1", "input", "Support inbox", {}, False), ("p1", "approval", "Manager approval", {}, False), ("m1", "memory", "Case memory", {}, False),
        ("r1", "guardrail", "Injection filter", {}, False), ("c1", "constraint", "Retention", {}, False), ("d1", "data", "Orders", {}, False)]
EDGES = [("a1", "g1", "pursues"), ("a1", "t1", "uses"), ("h1", "a1", "requests"), ("i1", "a1", "feeds"), ("p1", "t1", "gates"), ("a1", "m1", "stores"), ("r1", "a1", "limits"),
         ("c1", "m1", "restricts"), ("a1", "d1", "reads")]


def ids(fs):
    return sorted(f.finding_id for f in fs)


def test_a_correct_design_has_no_findings():
    check("every element joined by its own relationship: no findings", formal_findings(graph(BASE, EDGES)) == [], ids(formal_findings(graph(BASE, EDGES))))


def test_each_element_must_be_joined_by_its_relationship():
    fs = {f.finding_id: f for f in formal_findings(graph(BASE, [e for e in EDGES if "t1" != e[1] or e[2] != "uses"]))}
    check("a tool the agent does not use is an error that blocks ratification", fs["unconnected-t1"].severity == "error" and fs["unconnected-t1"].blocks == ["ratify"], list(fs))
    f = fs["unconnected-t1"].fix
    check("the fix draws the relationship the studio would have drawn", (f["type"], f["a"], f["b"], f["label"]) == ("connect", "a1", "t1", "uses"), f)
    fs = {f.finding_id: f for f in formal_findings(graph(BASE, [e for e in EDGES if e[0] != "h1"]))}
    check("a person who requests of the agent is drawn towards it", (fs["unconnected-h1"].fix["a"], fs["unconnected-h1"].fix["b"], fs["unconnected-h1"].fix["label"]) == ("h1", "a1", "requests"))
    via_inbox = [e for e in EDGES if e[0] != "h1"] + [("h1", "i1", "writes")]
    check("a person who writes to the input that feeds the agent is connected too (the studio's own sample is drawn so)", "unconnected-h1" not in ids(formal_findings(graph(BASE, via_inbox))))
    check("an external system the agent calls is a meaningful line", not [f for f in formal_findings(graph(BASE + [("x1", "external", "CRM", {}, False)], EDGES + [("a1", "x1", "calls")])) if f.finding_id.startswith("edge-")])
    fs = {f.finding_id: f for f in formal_findings(graph(BASE, [e for e in EDGES if e[2] != "gates"]))}
    check("an approval is connected to the write-capable tool it gates", (fs["unconnected-p1"].fix["a"], fs["unconnected-p1"].fix["b"]) == ("p1", "t1"), fs["unconnected-p1"].fix)
    wrong = [e for e in EDGES if e[2] != "uses"] + [("a1", "t1", "feeds")]
    check("a line with the wrong relationship does not connect the tool", "unconnected-t1" in ids(formal_findings(graph(BASE, wrong))))


def test_lines_the_model_gives_no_meaning_to():
    fs = {f.finding_id: f for f in formal_findings(graph(BASE, EDGES + [("t1", "d1", "likes")]))}
    f = fs["edge-t1-d1"]
    check("a line with no relationship in the model is a warning with a way to remove it", f.severity == "warning" and f.blocks == [] and f.fix["type"] == "unlink", list(fs))


def test_one_named_primary_agent():
    none = [("a1", "agent", "Refund agent", {}, False)]
    check("no primary agent is an error", ids(formal_findings(graph(none, []))) == ["primary-missing"])
    two = [("a1", "agent", "One", {}, True), ("a2", "agent", "Two", {}, True)]
    check("two primary agents is an error", "primary-many" in ids(formal_findings(graph(two, [("a1", "a2", "delegates")]))))
    unnamed = [("a1", "agent", "  ", {}, True)]
    check("an unnamed primary agent is an error with the box to edit", [f.fix["field"] for f in formal_findings(graph(unnamed, [])) if f.finding_id == "primary-unnamed"] == ["name"])


def test_the_fingerprint_is_the_design_not_its_status():
    doc = {"nodes": [{"id": "a"}], "edges": [], "profile": "payments", "req": {"dpia": {"status": "Covered", "evidence": "DOC-9"}}, "policy": "block", "ratified": False, "provenance": None}
    same = dict(doc, policy="warn", ratified=True, provenance={"filename": "x"})
    check("the drift policy, the ratified flag and the provenance are not part of it", design_fingerprint(doc) == design_fingerprint(same))
    changed = dict(doc, req={"dpia": {"status": "Covered", "evidence": "DOC-10"}})
    check("a changed declaration is", design_fingerprint(doc) != design_fingerprint(changed))
    check("so is a changed element", design_fingerprint(doc) != design_fingerprint(dict(doc, nodes=[{"id": "b"}])))


def test_the_wording_helper_drafts_for_a_requirement_of_an_agent():
    import chat
    seen = {}
    real = chat.chat_json
    chat.chat_json = lambda messages, schema, **kw: seen.update(messages=messages) or {"note": "A [DPIA reference] approved by [who]."}
    try:
        out = chat.draft_evidence(chat.DraftEvidenceRequest(kind="requirement", name="GDPR Art. 35 \u2014 DPIA", instrument="GDPR", model_name="refund-agent"))
    finally:
        chat.chat_json = real
    prompt = seen["messages"][1]["content"]
    check("the requirement and the agent are in the prompt", "DPIA" in prompt and "GDPR" in prompt and "refund-agent" in prompt, prompt)
    check("the draft leaves the real references as placeholders", "[DPIA reference]" in out.note)
    check("the system prompt forbids inventing references", "Never invent" in seen["messages"][0]["content"])


NAME = "zz-test-review-agent"


def agent_doc(owner, req=None):
    return {
        "nodes": [{"id": "h1", "type": "human", "name": "Clinician", "p": {}}, {"id": "g1", "type": "goal", "name": "Summarise records", "p": {}},
                  {"id": "a1", "type": "agent", "name": NAME, "p": {"owner": owner, "auto": "approval"}, "primary": True},
                  {"id": "t1", "type": "tool", "name": "ehr.records.read", "p": {"write": False}}, {"id": "t2", "type": "tool", "name": "email.send.external", "p": {"write": True}}],
        "edges": [{"from": "h1", "to": "a1", "label": "requests"}, {"from": "a1", "to": "g1", "label": "pursues"}, {"from": "a1", "to": "t1", "label": "uses"}, {"from": "a1", "to": "t2", "label": "uses"}],
        "n": 100, "profile": "healthcare", "req": req or {}, "policy": "block"}


def forget(key):
    with SessionLocal() as s:
        for c in s.query(Contract).filter(Contract.deployment_id == NAME).all():
            s.delete(c)
        for a in s.query(Agent).filter(Agent.agent_key == NAME).all():
            s.delete(a)
        for r in s.query(DesignReview).filter(DesignReview.design_key == key).all():
            s.delete(r)
        for d in s.query(Design).filter(Design.name.like("zz-test%")).all():
            s.delete(d)
        s.commit()


def test_ratifying_waits_for_someone_who_does_not_own_the_agent():
    req = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Rhea Patel"}}
    with authed_client("compliance", "Rhea Patel") as rhea, authed_client("compliance", "Sam Reviewer") as sam:
        d = rhea.post("/api/designs", json={"name": "zz-test review design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": agent_doc("Rhea Patel", req)}).json()
        key = d["design_key"]
        try:
            st = rhea.get(f"/api/agents/designs/{key}/review").json()
            check("the owner is told a review is needed, and why", st["required"] and st["reason"] in ("gate", "issuer") and st["issuer_role"] == "owner", st)
            r = rhea.post("/api/agents/ratify", json={"design_key": key})
            check("the owner cannot ratify their own agent alone", r.status_code == 422 and ("owner" in r.json()["detail"] or "REVIEW" in r.json()["detail"]), r.text)
            body = {"decision": "APPROVED", "note": "Read the evidence for each requirement."}
            check("the owner cannot review it either", rhea.post(f"/api/agents/designs/{key}/review", json=body).status_code == 403)
            check("a note is required", sam.post(f"/api/agents/designs/{key}/review", json={"decision": "APPROVED", "note": "ok"}).status_code == 422)
            r = sam.post(f"/api/agents/designs/{key}/review", json=body)
            check("someone else can review it", r.status_code == 201 and r.json()["approved"] and r.json()["reviews"][0]["reviewer"] == "Sam Reviewer", r.text)
            ok = rhea.post("/api/agents/ratify", json={"design_key": key})
            check("then the owner can ratify", ok.status_code == 200, ok.text)
            a = ok.json()["contract"]["design_snapshot"]["assurance"]
            check("the contract records the score, the review and that the owner ratified it",
                  a["review"]["reviewer"] == "Sam Reviewer" and a["ratified_by_is_owner"] and set(a["rcr"]) == {"score", "band", "gate"}, a)
            full = rhea.get(f"/api/designs/{key}").json()
            changed = agent_doc("Rhea Patel", {**req, "dpia": {**req["dpia"], "evidence": "DPIA report DOC-10"}})
            rhea.put(f"/api/designs/{key}", json={"name": "zz-test review design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": changed, "version": full["version"]})
            check("a change to the design makes the review lapse", rhea.post("/api/agents/ratify", json={"design_key": key}).status_code == 422)
        finally:
            forget(key)


def test_an_unconnected_element_stops_ratification_and_review():
    doc = agent_doc("Platform team", {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Rhea Patel"}})
    doc["edges"] = [e for e in doc["edges"] if e["to"] != "t2"]               # the write tool is no longer used by the agent
    with authed_client("compliance", "Rhea Patel") as rhea:
        d = rhea.post("/api/designs", json={"name": "zz-test broken design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc}).json()
        key = d["design_key"]
        try:
            r = rhea.post("/api/agents/ratify", json={"design_key": key})
            check("ratification is refused for a design that is not correct", r.status_code == 422 and "not correct" in r.json()["detail"], r.text)
            r = rhea.post(f"/api/agents/designs/{key}/review", json={"decision": "APPROVED", "note": "Looked at everything."})
            check("so is a review", r.status_code == 422 and "once it is correct" in r.json()["detail"], r.text)
            a = rhea.post("/api/agents/analyse", json={"graph": {"nodes": [{"id": n["id"], "type": n["type"], "props": {"name": n["name"], **n["p"]}, "primary": bool(n.get("primary"))} for n in doc["nodes"]],
                                                                  "edges": [{"from": e["from"], "to": e["to"], "label": e["label"]} for e in doc["edges"]]}}).json()
            check("the analysis hands the findings to the studio", [f["finding_id"] for f in a["formal_findings"]] == ["unconnected-t2"] and a["rows"][0].get("instrument"), a["formal_findings"])
        finally:
            forget(key)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"\n{PASSED}/{PASSED + FAILED} passed")
    sys.exit(1 if FAILED else 0)
