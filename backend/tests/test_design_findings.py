"""
Tests for design_findings.py: the formal-model check, the fix attached to a rule that is not met, and that the explanation never changes a signed contract's hash.

    docker compose exec backend python -m tests.test_design_findings
"""
import copy
import json

from compliance_engine import assess_design, compile_design
from compliance_schema import (
    CompiledContract, ComplianceDomain, ElementVerdict, RegulationRule, RiskStatus, compute_contract_hash,
)
from design_findings import fix_for_rule, formal_findings
from rule_checks import DesignGraph, GEdge, GNode
from schema import RegistryBlock, VETO_CLASS_CONSTRAINTS

PASSED = FAILED = 0


def check(name, ok, detail=""):
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print("PASS ", name)
    else:
        FAILED += 1
        print("FAIL ", name, detail)


def registry(actors=None, sensitivity="INTERNAL", satisfied=()):
    names = {"trainer": "Data Science", "validator": "Clinical Safety", "deployer": "Digital Services", "operator": "Care Team", "consumer": "Social Workers"}
    names.update(actors or {})
    decl = {c: ({"status": "SATISFIED", "evidence": "see record"} if c in satisfied else {"status": "NOT_YET_DETERMINED"}) for c in set(VETO_CLASS_CONSTRAINTS) | set(satisfied)}
    return RegistryBlock.model_validate({
        "actors": {k: {"identity": v} for k, v in names.items()},
        "deployment_context": {"data_sensitivity": sensitivity},
        "governance_state": {"constraints_declared": decl},
    })


LINK = {"TRAINING_DATASET": "TRAINED_ON", "DEPLOYMENT_ENV": "RUNS_IN", "REGULATORY_REQ": "COVERED_BY"}
ROLE = {"TRAINER": "TRAINS", "VALIDATOR": "VALIDATES", "DEPLOYER": "DEPLOYS", "OPERATOR": "OPERATES"}


def graph(*types):
    nodes = [GNode(f"n{i}", t, {"subtype": s} if s else {}) for i, (t, s) in enumerate(types)]
    model = next((n for n in nodes if n.type == "AI_MODEL"), None)
    return DesignGraph(nodes, [GEdge(model.id, n.id, LINK[n.type]) if n.type in LINK else GEdge(n.id, model.id, ROLE[n.props["subtype"]])
                               for n in nodes if model and n is not model and (n.type in LINK or n.type == "ACTOR")])


FULL = (("AI_MODEL", None), ("TRAINING_DATASET", None), ("DEPLOYMENT_ENV", None), ("LEGAL_BASIS", None))
ALL_MET = tuple(VETO_CLASS_CONSTRAINTS) + ("SC-TRAIN-1", "SC-MC-1")
ids = lambda fs: sorted(f.finding_id for f in fs)        # noqa: E731


def test_a_correct_design_has_no_findings():
    fs = formal_findings(registry(satisfied=ALL_MET), {}, graph(*FULL))
    check("a correct design has no formal findings", fs == [], ids(fs))


def test_roles_must_be_named():
    fs = formal_findings(registry(actors={"validator": "", "consumer": ""}, satisfied=ALL_MET), {}, graph(*FULL))
    by = {f.finding_id: f for f in fs}
    check("an unnamed validator is an error that blocks compile", by["role-validator"].severity == "error" and "compile" in by["role-validator"].blocks)
    check("an unnamed consumer is only a warning", by["role-consumer"].severity == "warning" and by["role-consumer"].blocks == [])
    check("the fix adds the missing actor with the right subtype", by["role-validator"].fix["kind"] == "ACTOR" and by["role-validator"].fix["data"] == {"subtype": "VALIDATOR"})


def test_checkers_must_be_different_people():
    g = DesignGraph([GNode("m", "AI_MODEL"), GNode("a-t", "ACTOR", {"subtype": "TRAINER"}), GNode("a-v", "ACTOR", {"subtype": "VALIDATOR"}),
                     GNode("d", "TRAINING_DATASET"), GNode("e", "DEPLOYMENT_ENV"), GNode("l", "LEGAL_BASIS")],
                    [GEdge("a-t", "m", "TRAINS"), GEdge("a-v", "m", "VALIDATES"), GEdge("m", "d", "TRAINED_ON"), GEdge("m", "e", "RUNS_IN")])
    fs = formal_findings(registry(actors={"validator": "  data   science "}, satisfied=ALL_MET), {}, g)
    check("the same name (ignoring case and spacing) is caught", ids(fs) == ["same-trainer-validator"], ids(fs))
    f = fs[0]
    check("it points at the actor to change and raises the score", f.node_id == "a-v" and f.fix["field"] == "identity" and "score" in f.blocks)


def test_personal_data_needs_a_legal_basis():
    no_basis = graph(("AI_MODEL", None), ("TRAINING_DATASET", None), ("DEPLOYMENT_ENV", None))
    fs = formal_findings(registry(sensitivity="SPECIAL_CATEGORY", satisfied=ALL_MET), {}, no_basis)
    check("special-category data without a legal basis is an error", "legal-basis" in ids(fs), ids(fs))
    fs = formal_findings(registry(sensitivity="INTERNAL", satisfied=ALL_MET), {}, no_basis)
    check("internal data does not need one", fs == [], ids(fs))
    from design_findings import _constraint_fix
    check("SC-MAP-1 says the fairness metric is still needed", "fairness metric" in _constraint_fix("SC-MAP-1", {})["instruction"])


def test_elements_on_their_own_are_not_part_of_the_design():
    nodes = [GNode("m", "AI_MODEL"), GNode("d", "TRAINING_DATASET"), GNode("e", "DEPLOYMENT_ENV"), GNode("l", "LEGAL_BASIS"), GNode("a", "ACTOR", {"subtype": "OPERATOR", "identity": "Ops"}),
             GNode("c", "CONSTRAINT", {"constraintId": "SC-HITL-1"}), GNode("r", "REGULATORY_REQ", {"instrument": "GDPR", "clause": "Art. 6"})]
    g = DesignGraph(nodes, [GEdge("m", "d", "TRAINED_ON"), GEdge("m", "e", "RUNS_IN"), GEdge("a", "c", "ON_DEPENDENCY"), GEdge("m", "l", "ON_DEPENDENCY")])
    fs = {f.finding_id: f for f in formal_findings(registry(satisfied=ALL_MET), {}, g)}
    check("an actor, a constraint and a requirement without the model's relationship are each an error",
          {"unconnected-a", "unconnected-c", "unconnected-r"} <= set(fs) and not {"unconnected-d", "unconnected-e", "unconnected-l"} & set(fs), sorted(fs))
    check("a line the model gives no meaning to connects nothing, and is reported (but does not block)",
          "edge-a-c" in fs and "edge-m-l" in fs and fs["edge-a-c"].severity == "warning" and fs["edge-a-c"].blocks == [] and fs["edge-a-c"].fix["type"] == "unlink")
    check("they block compile", all(fs[k].severity == "error" and "compile" in fs[k].blocks for k in ("unconnected-a", "unconnected-c", "unconnected-r")))
    c = fs["unconnected-c"].fix
    check("a constraint is connected to the actor who imposes it", c["type"] == "connect" and (c["a"], c["b"]) == ("c", "a"), c)
    from design_findings import constraint_info
    check("the imposing role follows the catalogue, not the dependency order",
          [constraint_info(k)["imposer_role"] for k in ("SC-HALLU-1", "SC-TRAIN-1", "SC-MC-1", "SC-HITL-1", "SC-DPIA-1")] == ["TRAINER", "DEPLOYER", "VALIDATOR", "OPERATOR", "DEPLOYER"])
    r = fs["unconnected-r"].fix
    check("a requirement is connected to the model", (r["a"], r["b"]) == ("r", "m"), r)


def test_placeholder_evidence_is_not_evidence():
    from schema import is_placeholder_evidence
    check("junk is recognised", all(is_placeholder_evidence(t) for t in ("test", " Test. ", "tbd", "n/a", "xxxxxxxx", "ok", "", None)))
    check("a real pointer is not", not any(is_placeholder_evidence(t) for t in ("DPIA-2026-014", "Right to explanation and challenge documented", "Oversight SOP v3")))
    reg = registry(satisfied=ALL_MET)
    reg.governance_state.constraints_declared["SC-DPIA-1"].evidence = "test"
    fs = {f.finding_id: f for f in formal_findings(reg, {}, graph(*FULL))}
    check("a veto constraint 'Satisfied' on a placeholder is open, with the reason", "veto-SC-DPIA-1" in fs and "placeholder" in fs["veto-SC-DPIA-1"].detail and "gate" in fs["veto-SC-DPIA-1"].blocks, list(fs))
    reg.governance_state.constraints_declared["SC-RCF-1"] = type(reg.governance_state.constraints_declared["SC-DPIA-1"]).model_validate({"status": "SATISFIED", "evidence": "tbd"})
    fs = {f.finding_id: f for f in formal_findings(reg, {}, graph(*FULL))}
    check("any other constraint on a placeholder is an error that blocks compile", fs["evidence-SC-RCF-1"].severity == "error" and "compile" in fs["evidence-SC-RCF-1"].blocks, list(fs))
    from scoring_bridge import score_registry
    good, _ = score_registry(registry(satisfied=ALL_MET))
    junk = registry(satisfied=ALL_MET)
    for k in ("SC-HITL-1", "SC-CHALL-1"):
        junk.governance_state.constraints_declared[k].evidence = "test"
    bad, _ = score_registry(junk)
    check("the score gives no credit for a placeholder", bad.pcs_final > good.pcs_final, (good.pcs_final, bad.pcs_final))
    domain = ComplianceDomain(domain_id="T", name="T", subject="MODEL", rule_set=[rule(maps_to_constraint_id="SC-HITL-1")])
    a = assess_design(junk, domain, {}, graph(*FULL))
    check("a rule that rests on it is not green", a.element_verdicts[0].status != RiskStatus.GREEN and "placeholder" in a.element_verdicts[0].reason, a.element_verdicts[0].reason)


def test_open_veto_constraints_block_the_gate():
    fs = formal_findings(registry(satisfied=["SC-DPIA-1", "SC-HITL-1"]), {"SC-HALLU-1": "node-9"}, graph(*FULL))
    veto = {f.finding_id: f for f in fs}
    check("each open veto constraint is a finding", sorted(k for k in veto if k.startswith("veto-")) == sorted("veto-" + c for c in VETO_CLASS_CONSTRAINTS if c not in ("SC-DPIA-1", "SC-HITL-1")), sorted(veto))
    f = veto["veto-SC-HALLU-1"]
    check("it blocks the gate and compile, and points at the node on the canvas", f.blocks == ["gate", "compile"] and f.node_id == "node-9")
    check("the fix carries the catalogue's own words", f.fix["type"] == "constraint_evidence" and f.fix["constraint"]["name"] and f.fix["constraint"]["standard_refs"] and f.fix["constraint"]["because"])


def rule(**kw):
    base = dict(rule_id="R1", instrument="EU AI Act", citation="Art. 14", title="Human oversight", description="", check_type="CONSTRAINT")
    base.update(kw)
    return RegulationRule(**base)


def verdict(status=RiskStatus.RED, **kw):
    return ElementVerdict(node_id=kw.pop("node_id", "R1"), status=status, reason="not met", **kw)


def test_fix_for_a_rule_that_is_not_met():
    f = fix_for_rule(rule(maps_to_constraint_id="SC-HITL-1"), verdict(), {"SC-HITL-1": "n7"})
    check("a constraint rule is fixed by evidence on its constraint", f["type"] == "constraint_evidence" and f["node_id"] == "n7" and f["constraint_id"] == "SC-HITL-1")
    f = fix_for_rule(rule(check_type="ATTESTATION"), verdict(), {})
    check("an attestation rule is fixed by a regulatory requirement for the clause", f["type"] == "attestation" and (f["instrument"], f["clause"]) == ("EU AI Act", "Art. 14"))
    cfg = {"satisfied_if": {"count": {"select": {"type": "CONSTRAINT", "where": {"constraintId": {"eq": "SC-LOG-1"}}}, "op": ">=", "value": 1}}, "fix_label": "Add logging"}
    f = fix_for_rule(rule(check_type="GRAPH", description="The design must include a logging constraint.", check_config=cfg), verdict(), {})
    check("a policy that requires an element is fixed by adding it, prefilled", f["type"] == "add_element" and f["kind"] == "CONSTRAINT" and f["data"] == {"constraintId": "SC-LOG-1"} and f["label"] == "Add logging")
    cfg = {"satisfied_if": {"count": {"select": {"type": "AI_MODEL", "where": {"hostingEnvironment": {"eq": "TYPE_3_THIRDPARTY_API"}}}, "op": "==", "value": 0}}}
    f = fix_for_rule(rule(check_type="GRAPH", check_config=cfg), verdict(flagged_node_ids=["m2"]), {})
    check("a policy that forbids an element is never fixed by adding one", f["type"] == "policy" and "Remove or change the flagged element" in f["instruction"] and "TYPE_3_THIRDPARTY_API" in f["instruction"], f)
    cfg = {"satisfied_if": {"not": {"exists": {"type": "AI_MODEL"}}}}
    f = fix_for_rule(rule(check_type="GRAPH", description="No third-party models.", check_config=cfg), verdict(flagged_node_ids=["m2"]), {})
    check("any other policy is described, with the flagged elements", f["type"] == "policy" and f["flagged"] == ["m2"] and f["instruction"] == "No third-party models.")
    check("a rule that is met needs no fix", fix_for_rule(rule(maps_to_constraint_id="SC-HITL-1"), verdict(RiskStatus.GREEN), {}) is None)


def test_assessment_carries_the_findings_and_the_fixes():
    domain = ComplianceDomain(domain_id="T", name="T", subject="MODEL", rule_set=[rule(maps_to_constraint_id="SC-HITL-1", description="Documented oversight.")])
    a = assess_design(registry(), domain, {}, graph(*FULL))
    v = a.element_verdicts[0]
    check("a verdict says what the rule asks for and how to fix it", v.title == "Human oversight" and v.requirement == "Documented oversight." and v.fix["type"] == "constraint_evidence")
    check("the assessment lists the formal findings", len([f for f in a.formal_findings if f.finding_id.startswith("veto-")]) == len(VETO_CLASS_CONSTRAINTS))
    agent = ComplianceDomain(domain_id="A", name="A", subject="AGENT", rule_set=[])
    check("an agent assessment has no model findings", assess_design(registry(), agent, {}, graph(*FULL)).formal_findings == [])


def test_compile_needs_a_correct_design_and_a_green_assessment():
    domain = ComplianceDomain(domain_id="T", name="T", subject="MODEL", rule_set=[])
    try:
        compile_design(registry(), domain, {}, {}, "d1", None, graph(*FULL))
        refused = ""
    except ValueError as e:
        refused = str(e)
    check("a green assessment is still refused while the design is wrong", "formal model" in refused and "SC-" in refused, refused)
    c = compile_design(registry(satisfied=ALL_MET), domain, {}, {}, "d1", None, graph(*FULL))
    check("a correct design compiles", c.contract_hash != "")


def test_a_satisfied_constraint_lowers_the_pcs():
    from scoring_bridge import score_registry
    open_pcs, _ = score_registry(registry())
    met_pcs, _ = score_registry(registry(satisfied=ALL_MET))
    check("declaring the constraints Satisfied lowers the PCS the engine computes", met_pcs.pcs_final < open_pcs.pcs_final, (open_pcs.pcs_final, met_pcs.pcs_final))
    check("with every constraint met the gate is no longer BLOCKED", met_pcs.gate != "BLOCKED", (met_pcs.pcs_final, met_pcs.gate))
    one, _ = score_registry(registry(satisfied=["SC-HITL-1"]))
    check("each constraint moves the score on its own", one.pcs_final < open_pcs.pcs_final, (open_pcs.pcs_final, one.pcs_final))


def test_the_pcs_gate_blocks_compile_and_is_explained():
    import scoring_bridge
    domain = ComplianceDomain(domain_id="T", name="T", subject="MODEL", rule_set=[])
    real = scoring_bridge.score_registry
    res, warn = real(registry(satisfied=ALL_MET))
    blocked = res.model_copy(update={"gate": "BLOCKED", "pcs_final": 97.0, "tier": "CRITICAL"})
    scoring_bridge.score_registry = lambda reg: (blocked, warn)
    try:
        try:
            compile_design(registry(satisfied=ALL_MET), domain, {}, {}, "d1", None, graph(*FULL))
            refused = ""
        except ValueError as e:
            refused = str(e)
        fs = {f.finding_id: f for f in formal_findings(registry(satisfied=ALL_MET), {}, graph(*FULL))}
    finally:
        scoring_bridge.score_registry = real
    check("a BLOCKED gate refuses compile and says why", "97.0" in refused and "BLOCKED" in refused, refused)
    check("the Risk tab gets a finding that explains the score", "pcs-gate" in fs and "97" in fs["pcs-gate"].title and "compile" in fs["pcs-gate"].blocks, list(fs))


def test_the_contract_records_the_score_the_review_and_who_held_each_role():
    domain = ComplianceDomain(domain_id="T", name="T", subject="MODEL", rule_set=[])
    reg = registry(satisfied=ALL_MET, actors={"operator": "Khaoula Hidawi"})
    canvas = {"nodes": [{"kind": "ACTOR", "data": {"subtype": "OPERATOR", "identity": "Dispatchers"}}, {"kind": "ACTOR", "data": {"subtype": "TRAINER", "identity": "Data Science"}}], "edges": []}
    review = {"decision": "APPROVED", "reviewer": "Rhea Patel", "role": "compliance", "at": "2026-10-30T12:00:00+00:00", "note": "Read the evidence.", "pcs": 4.4, "tier": "LOW",
              "gate": "REQUIRES_REVIEW", "fingerprint": "f"}
    try:
        c = compile_design(reg, domain, canvas, {}, "d1", "  khaoula   hidawi ", graph(*FULL), reviewed=True, review=review)
    except ValueError as e:
        check("the contract compiles", False, str(e))
        return
    a = c.design_snapshot["assurance"]
    check("it records the PCS, tier and gate at signing", set(a["pcs"]) == {"final", "tier", "gate"} and a["pcs"]["gate"] != "BLOCKED", a["pcs"])
    check("it records the human review", a["review"] == review)
    check("it shows where the canvas and the current holder differ", a["role_holders"]["operator"]["differs"] and a["role_holders"]["operator"]["holder_now"] == "Khaoula Hidawi"
          and a["role_holders"]["operator"]["named_on_canvas"] == ["Dispatchers"] and not a["role_holders"]["trainer"]["differs"], a["role_holders"])
    check("it says when the person issuing it holds a role", a["issued_by_holds_role"] == "operator", a["issued_by_holds_role"])
    old = json.loads(c.model_dump_json())
    check("it is signed with the contract", compute_contract_hash(CompiledContract(**old)) == c.contract_hash)
    old["design_snapshot"]["assurance"]["review"]["reviewer"] = "Someone Else"
    check("changing the recorded review breaks the signature", compute_contract_hash(CompiledContract(**old)) != c.contract_hash)


def test_the_explanation_is_not_signed():
    domain = ComplianceDomain(domain_id="T", name="T", subject="MODEL", rule_set=[rule(maps_to_constraint_id="SC-HITL-1")])
    reg = registry(satisfied=ALL_MET)
    c = compile_design(reg, domain, {}, {}, "d1", None, graph(*FULL))
    # a contract signed before the explanation fields existed: the same document without them
    old = json.loads(c.model_dump_json())
    for v in old["risk_assessment"]["element_verdicts"]:
        for k in ("instrument", "check_type", "title", "requirement", "fix"):
            v.pop(k, None)
    old["risk_assessment"].pop("formal_findings", None)
    check("a stored contract written before the new fields still verifies", compute_contract_hash(CompiledContract(**old)) == c.contract_hash)
    changed = copy.deepcopy(old)
    changed["risk_assessment"]["element_verdicts"][0]["reason"] = "tampered"
    check("a change to what is signed is still detected", compute_contract_hash(CompiledContract(**changed)) != c.contract_hash)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"\n{PASSED}/{PASSED + FAILED} passed")
    raise SystemExit(1 if FAILED else 0)
