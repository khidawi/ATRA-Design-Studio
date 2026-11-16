"""
Operational validation case for the ST-AI v2.5 implementation, on a company file.

    docker compose run --rm --no-deps -v "$PWD:/repo" -w /repo/backend backend python st_ai_validation_case.py /repo/examples/company-helix-logistics.json MD-FORECAST --out /repo/docs/validation

It takes the company file the Organisation screen imports, and runs one AI model of it through scenarios, each of which changes ONE thing (an evidence record, a rationale, who
holds a role, the policy, the reporting structure). For every scenario the outcome the specification requires is written down BEFORE the run (the `expect` of the scenario, derived
from the paper's definitions), and the implementation's gate, triggers and blockers are compared with it. A mismatch is reported and the script exits with 1.

What this shows: that the implementation, on a real-shaped organisation, behaves as the specification says in each situation. What it does not show: that the specification is right
for real organisations, that any estimate is accurate, or that using it improves decisions. The data are a published sample (Helix Logistics), not a real organisation, and every
evidence record, rationale, interval and tolerance below is hypothetical.

Nothing is written to any database: the file is read, the registry built in memory (the same registry the studio builds), and scored by scoring_bridge.score_registry.
"""
import argparse
import copy
import json
import sys
from datetime import date, timedelta
from typing import Any, Callable, Dict, List, Optional

import company
import st_ai_company_check as CC
import st_ai_gate as G
import st_ai_guards
import st_ai_policy as P

TODAY = date.today()
D = lambda days: (TODAY + timedelta(days=days)).isoformat()                       # noqa: E731
HARD = ["SC-DPIA-1", "SC-HITL-1", "SC-HALLU-1", "SC-MAP-1", "SC-CHALL-1", "SC-LIAB-1"]
REVIEW = ["SC-MC-1", "SC-TRAIN-1", "SC-RCF-1", "SC-RCF-2", "SC-DOMAIN-1", "SC-CONSENT-1"]


def all_evidenced(extra: Optional[Dict[str, Any]] = None, until: int = 365) -> Dict[str, Any]:
    c = {cid: {"status": "SATISFIED", "evidence": f"record: hypothetical control report CR-{cid[-5:]}, {D(-30)}", "valid_until": D(until)} for cid in HARD + REVIEW}
    c.update(extra or {})
    return {"constraints": c}


def rationale(author="Diego Alvarez", reviewer="Marcus Lee", days=180):
    return {"applicable": False, "not_applicable": {"reason": "the forecast uses shipment volumes aggregated per depot; no individual is the subject of any output", "author": author, "reviewer": reviewer, "expires_on": D(days)}}


def with_risk(ev: Dict[str, Any], evidenced=None, until=None, bounded=None, criteria=True) -> Dict[str, Any]:
    out = copy.deepcopy(ev)
    if criteria:
        crit: Dict[str, Any] = {"id": "c1", "dimension": "Financial", "metric": "R", "note": "hypothetical: expected annual cost of forecast errors, thousands"}
        if evidenced:
            crit["evidenced"] = {"lower": evidenced[0], "upper": evidenced[1]}
            crit["evidenced_valid_until"] = until
        if bounded:
            crit["bounded"] = {"lower": bounded[0], "upper": bounded[1]}
        out["risk"] = {"criteria": [crit]}
    return out


def policy(basis="legacy_until_intervals", level="PERSON", tolerance: Optional[float] = 100.0, model_id="MD-FORECAST") -> Dict[str, Any]:
    tol: List[Dict[str, Any]] = []
    if tolerance is not None:
        tol = [{"scope": "organisation", "name": "organisation", "dimension": "Financial", "metric": "R", "value": 1000},
               {"scope": "unit", "name": "Data Science", "dimension": "Financial", "metric": "R", "value": 600, "parent": "organisation"},
               {"scope": "deployment", "name": model_id, "dimension": "Financial", "metric": "R", "value": tolerance, "parent": "Data Science"}]
    return {"independence": {"review": {"level": level, "mode": "AT_ACT"}, "approval": {"level": level, "mode": "AT_ACT"}}, "risk": {"basis": basis, "confidence_level": 0.95}, "tolerances": tol}


# ── changes to the company file ──────────────────────────────────────────────────────────────────────────────────────────
def separate_roles(doc: Dict[str, Any], model_id: str) -> Dict[str, Any]:
    """The deployer becomes a different person (the head of IT and Security), so trainer, validator and deployer are three people."""
    out = copy.deepcopy(doc)
    for s in out["ai_systems"]:
        if s["id"] == model_id:
            for q in s["people"]:
                if q["role"] == "deploys":
                    q["id"] = "EMP-510"
    return out


def reorganise(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Data Science now reports to IT and Security instead of to the Executive."""
    out = copy.deepcopy(doc)
    for d in out["departments"]:
        if d["id"] == "D-DATA":
            d["reports_to"] = "D-IT"
    return out


# ── the scenarios and what the specification requires of each ────────────────────────────────────────────────────────────
def scenarios(model_id: str) -> List[Dict[str, Any]]:
    ev_ok = all_evidenced({"SC-MAP-1": rationale()})
    base = dict(doc=separate_roles, ev=ev_ok, pol=policy())
    S = []

    def add(sid, title, spec, expect, **kw):
        S.append({"id": sid, "title": title, "spec": spec, "expect": expect, **{**base, **kw}})

    add("S1", "The file as imported: no evidence recorded", "A hard constraint that is unknown blocks release (gate step 2).",
        {"gate": "BLOCKED", "blockers_contain": ["hard constraint SC-DPIA-1 is unknown"]}, doc=lambda d, m: d, ev={}, pol=policy())
    add("S2", "Every control evidenced, SC-MAP-1 validly not applicable; but one person is both validator and deployer", "A review-class shortfall needs a review, which can clear it; role separation is derived from who holds the roles.",
        {"gate": "REQUIRES_REVIEW", "triggers": {"review_class_shortfall"}, "releasable": True, "status": {"SC-MAP-1": "NOT_APPLICABLE", "SC-RCF-2": "VIOLATED"}}, doc=lambda d, m: d)
    add("S3", "S2 with the deployer changed to a third person", "With every constraint met and a valid rationale, and no risk criteria stated, the legacy score (low) decides risk: approved.",
        {"gate": "APPROVED", "status": {"SC-RCF-2": "SATISFIED"}})
    add("S4", "S3, but the SC-MAP-1 rationale names one person as both author and reviewer", "Not applicable needs an independent reviewer; otherwise applicability is unknown and a review cannot clear it.",
        {"gate": "REQUIRES_REVIEW", "triggers": {"applicability_unknown"}, "releasable": False}, ev=all_evidenced({"SC-MAP-1": rationale(reviewer="Diego Alvarez")}))
    add("S5", "S3, but the rationale for SC-MAP-1 lapsed yesterday", "A lapsed rationale no longer counts: applicability is unknown again.",
        {"gate": "REQUIRES_REVIEW", "triggers": {"applicability_unknown"}, "releasable": False}, ev=all_evidenced({"SC-MAP-1": rationale(days=-1)}))
    add("S6", "S3, but the DPIA evidence expired yesterday", "Expired evidence no longer satisfies a control: a hard constraint becomes unknown and blocks.",
        {"gate": "BLOCKED", "blockers_contain": ["hard constraint SC-DPIA-1 is unknown"]}, ev=all_evidenced({"SC-MAP-1": rationale(), "SC-DPIA-1": {"status": "SATISFIED", "evidence": f"record: hypothetical DPIA report, {D(-400)}", "valid_until": D(-1)}}))
    iv = policy(basis="intervals", level="PERSON")
    add("S7", "Risk by intervals: evidenced interval [55, 85] against a tolerance of 100", "A pass needs the upper bound within the tolerance.",
        {"gate": "APPROVED", "risk": {"c1": "pass"}}, ev=with_risk(ev_ok, (55, 85), D(180), (55, 140)), pol=iv)
    add("S8", "S7 with the evidenced interval lapsed: only the bounded interval [55, 140] applies", "Losing effectiveness evidence turns a pass into an overlap; a review can clear an overlap.",
        {"gate": "REQUIRES_REVIEW", "triggers": {"interval_overlap"}, "releasable": True, "risk": {"c1": "overlap"}}, ev=with_risk(ev_ok, (55, 85), D(-1), (55, 140)), pol=iv)
    add("S9", "S7 with the interval re-estimated at [110, 160]", "A lower bound above the tolerance blocks.",
        {"gate": "BLOCKED", "risk": {"c1": "block"}}, ev=with_risk(ev_ok, (110, 160), D(180), (70, 160)), pol=iv)
    add("S10", "S9 after the evidence lapsed: the bounded interval alone is [70, 160]", "Ratchet: losing evidence of poor effectiveness never improves a blocked result.",
        {"gate": "BLOCKED", "risk": {"c1": "block"}, "risk_detail_contains": "ratchet"}, ev=with_risk(ev_ok, (110, 160), D(-1), (70, 160)), pol=iv)
    add("S11", "S7 with no tolerance allocated to this model", "A missing tolerance is a missing fact: unresolved, and a review cannot clear it.",
        {"gate": "REQUIRES_REVIEW", "triggers": {"risk_unresolved"}, "releasable": False, "risk": {"c1": "unresolved"}}, ev=with_risk(ev_ok, (55, 85), D(180), (55, 140)), pol=policy(basis="intervals", tolerance=None))
    add("S12", "Risk basis 'intervals' but the design states no risk criteria", "Nothing can be compared with a tolerance: unresolved, not clearable by a review.",
        {"gate": "REQUIRES_REVIEW", "triggers": {"risk_unresolved"}, "releasable": False}, ev=ev_ok, pol=iv)
    return S


def check_expectation(res: Dict[str, Any], expect: Dict[str, Any]) -> List[str]:
    bad: List[str] = []
    if res["gate"] != expect["gate"]:
        bad.append(f"gate is {res['gate']}, the specification requires {expect['gate']}")
    codes = {t["code"] for t in res["triggers"]}
    if "triggers" in expect and codes != expect["triggers"]:
        bad.append(f"triggers are {sorted(codes)}, required {sorted(expect['triggers'])}")
    if "releasable" in expect and res["releasable_with_a_review"] != expect["releasable"]:
        bad.append(f"releasable with a review is {res['releasable_with_a_review']}, required {expect['releasable']}")
    for frag in expect.get("blockers_contain", []):
        if not any(frag in b for b in res["blockers"]):
            bad.append(f"no blocker contains '{frag}'")
    st = {c["id"]: c["status"] for c in res["constraints"]}
    for cid, want in expect.get("status", {}).items():
        if st.get(cid) != want:
            bad.append(f"{cid} is {st.get(cid)}, required {want}")
    rk = {r["id"].split(" ")[0]: r for r in res.get("risks", [])}
    for rid, want in expect.get("risk", {}).items():
        if rk.get(rid, {}).get("state") != want:
            bad.append(f"risk criterion {rid} is {rk.get(rid, {}).get('state')}, required {want}")
    if "risk_detail_contains" in expect and not any(expect["risk_detail_contains"] in r["detail"] for r in res.get("risks", [])):
        bad.append(f"no risk detail contains '{expect['risk_detail_contains']}'")
    return bad


def independence_table(doc: Dict[str, Any], model_id: str, candidates: List[str]) -> Dict[str, Dict[str, str]]:
    """For each candidate reviewer and level: does the structure show them independent of the trainer, validator, deployer and operator of the model?"""
    graph = company.doc_to_graph(doc, set())
    N = {n["id"]: n for n in graph["nodes"]}
    company._graph = lambda session: (N, graph["edges"])
    desc = company.model_description(None, model_id)
    rb = CC.registry_for(desc, {}, {}, model_id)
    holders = st_ai_guards.role_holders(rb)
    s = st_ai_guards.structure_from_graph(N)
    out: Dict[str, Dict[str, str]] = {}
    for who in candidates:
        row = {}
        for level in (G.LEVEL_PERSON, G.LEVEL_REPORTING_LINE, G.LEVEL_UNIT):
            res = {r: G.independent(who, h, level, s) for r, h in holders.items()}
            row[level] = "no" if G.F in res.values() else ("unknown" if G.U in res.values() else "yes")
        out[who] = row
    return out


# what the specification requires of the candidates (checked, like a scenario): the head of IT is in another line; the Executive heads everyone; Finance has no head recorded
EXPECT_IND = {"Marcus Lee": {"PERSON": "yes", "REPORTING_LINE": "yes", "UNIT": "yes"}, "Nora Blake": {"PERSON": "yes", "REPORTING_LINE": "no", "UNIT": "no"},
              "Hana Sato": {"PERSON": "yes", "REPORTING_LINE": "unknown", "UNIT": "unknown"}, "Diego Alvarez": {"PERSON": "no", "REPORTING_LINE": "no", "UNIT": "no"}}
EXPECT_IND_AFTER = {"Marcus Lee": {"PERSON": "yes", "REPORTING_LINE": "no", "UNIT": "no"}}          # after Data Science reports to IT and Security


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("company_file")
    ap.add_argument("model_id")
    ap.add_argument("--out", help="directory to write the result (JSON and Markdown) to")
    args = ap.parse_args()
    doc = CC.load_doc(args.company_file)
    name = (doc.get("company") or {}).get("name", args.company_file)
    results: List[Dict[str, Any]] = []
    failed = 0
    for sc in scenarios(args.model_id):
        d = sc["doc"](doc, args.model_id)
        graph = company.doc_to_graph(d, set())
        assert not graph["errors"], graph["errors"]
        N = {n["id"]: n for n in graph["nodes"]}
        r = CC.check_model(N, graph["edges"], args.model_id, {args.model_id: sc["ev"]}, sc["pol"], G.LEVEL_REPORTING_LINE)
        bad = check_expectation(r, sc["expect"])
        failed += bool(bad)
        results.append({"id": sc["id"], "title": sc["title"], "specification": sc["spec"], "expected": {k: (sorted(v) if isinstance(v, set) else v) for k, v in sc["expect"].items()},
                        "gate": r["gate"], "triggers": [t["code"] for t in r["triggers"]], "blockers": r["blockers"][:4], "risks": r["risks"], "releasable_with_a_review": r["releasable_with_a_review"],
                        "matches_specification": not bad, "mismatches": bad})
        print(f"{sc['id']:<4}{'PASS' if not bad else 'FAIL'}  {r['gate']:<16} {sc['title']}" + ("" if not bad else "\n      " + "\n      ".join(bad)))
    ind = independence_table(doc, args.model_id, list(EXPECT_IND))
    ind_after = independence_table(reorganise(doc), args.model_id, list(EXPECT_IND_AFTER))
    ind_bad = [f"{who} at {lv}: {ind[who][lv]} (required {want})" for who, row in EXPECT_IND.items() for lv, want in row.items() if ind[who][lv] != want]
    ind_bad += [f"after reorganisation {who} at {lv}: {ind_after[who][lv]} (required {want})" for who, row in EXPECT_IND_AFTER.items() for lv, want in row.items() if ind_after[who][lv] != want]
    failed += bool(ind_bad)
    print("\nIndependence of candidate reviewers from the model's trainer, validator, deployer and operator:")
    for who, row in ind.items():
        print(f"  {who:<14} person: {row['PERSON']:<8} reporting line: {row['REPORTING_LINE']:<8} unit: {row['UNIT']}")
    print(f"  after Data Science is reorganised under IT and Security: Marcus Lee reporting line: {ind_after['Marcus Lee']['REPORTING_LINE']}, unit: {ind_after['Marcus Lee']['UNIT']}")
    for b in ind_bad:
        print("  FAIL", b)
    n = len(results)
    print(f"\n{n - sum(1 for r in results if not r['matches_specification'])} of {n} scenarios and {'all' if not ind_bad else 'not all'} independence checks match the specification.")
    payload = {"company": name, "model": args.model_id, "spec": G.SPEC, "run_date": TODAY.isoformat(), "scenarios": results,
               "independence": {"required": EXPECT_IND, "observed": ind, "after_reorganisation": ind_after, "mismatches": ind_bad},
               "limits": "A published sample company and hypothetical evidence. It shows the implementation behaves as the specification requires in these situations; it does not validate the specification, any estimate, or the model's effect on decisions."}
    if args.out:
        import os
        os.makedirs(args.out, exist_ok=True)
        stem = os.path.join(args.out, f"st-ai-company-validation-{args.model_id.lower()}")
        json.dump(payload, open(stem + ".json", "w", encoding="utf-8"), indent=2, default=str)
        md = [f"# ST-AI v2.5 implementation on a company file: {name}, model {args.model_id}", "", f"Run on {TODAY.isoformat()}. Every scenario changes one thing; the outcome the specification requires was written down before the run.", "",
              "| # | Situation | Specification requires | Implementation | Match |", "|---|---|---|---|---|"]
        for r in results:
            exp = r["expected"]
            req = exp["gate"] + (f" ({', '.join(exp['triggers'])})" if exp.get("triggers") else "") + (", clearable by a review" if exp.get("releasable") is True else ", not clearable by a review" if exp.get("releasable") is False else "")
            got = r["gate"] + (f" ({', '.join(r['triggers'])})" if r["triggers"] else "") + (", clearable by a review" if r["releasable_with_a_review"] and r["gate"] == "REQUIRES_REVIEW" else "")
            md.append(f"| {r['id']} | {r['title']} | {req} | {got} | {'yes' if r['matches_specification'] else 'NO'} |")
        md += ["", "Independence of candidate reviewers from the model's trainer, validator, deployer and operator, over the company's reporting structure:", "",
               "| Candidate | Person | Reporting line | Unit |", "|---|---|---|---|"] + [f"| {w} | {r['PERSON']} | {r['REPORTING_LINE']} | {r['UNIT']} |" for w, r in ind.items()]
        md += ["", f"After Data Science is reorganised under IT and Security, Marcus Lee: reporting line {ind_after['Marcus Lee']['REPORTING_LINE']}, unit {ind_after['Marcus Lee']['UNIT']}.", "", payload["limits"], ""]
        open(stem + ".md", "w", encoding="utf-8").write("\n".join(md))
        print("written", stem + ".json and .md")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
