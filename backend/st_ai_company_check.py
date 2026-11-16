"""
Run a company file through the ST-AI v2.5 gate, without a database and without touching any stored data.

    docker compose run --rm --no-deps backend python st_ai_company_check.py /app/../examples/company-helix-logistics.json
    docker compose run --rm --no-deps backend python st_ai_company_check.py company.json --evidence evidence.json --policy policy.json --json

The file is the same JSON the Organisation screen imports. For every AI model in it the script reads the departments, the people holding its lifecycle roles and the
reporting lines, builds the registry the studio would build (every constraint starts as not yet determined), applies the evidence file if one is given, and prints:
  * the gate (INVALID_MODEL, BLOCKED, REQUIRES_REVIEW or APPROVED), what blocks it, what a review could clear and what has to be recorded first;
  * the status of every constraint (satisfied, violated, unknown, not applicable);
  * who is independent of whom among the people holding the model's roles, at the level asked for (PERSON, REPORTING_LINE or UNIT) over the reporting structure of the file.

The evidence file maps a model id (or name) to the constraints it has evidence for and, optionally, to its risk estimates:
    {"MD-1": {"constraints": {"SC-DPIA-1": {"status": "SATISFIED", "evidence": "DPIA ref 2026-14, signed 2026-09-02", "valid_until": "2027-09-01"},
                              "SC-MAP-1":  {"applicable": false, "not_applicable": {"reason": "...", "author": "Ann", "reviewer": "Bo", "expires_on": "2027-01-31"}}},
              "risk": {"criteria": [{"id": "c1", "dimension": "Financial", "metric": "R", "evidenced": {"lower": 55, "upper": 85}, "evidenced_valid_until": "2027-06-30",
                                     "bounded": {"lower": 55, "upper": 140}}]}}}
The policy file has the parameters of the ST-AI policy (independence levels and modes, the risk basis, tolerances; see st_ai_policy.py). A deployment's tolerance is the
allocation whose name is the model's id. Without a policy the defaults apply.
Nothing is written anywhere.
"""
import argparse
import json
import sys
from datetime import date
from typing import Any, Dict, List

import company
import st_ai_gate as G
import st_ai_guards
import st_ai_policy as P
from schema import ConstraintDeclaration, DeploymentContext, Department, NotApplicableRationale, RegistryBlock
from scoring_bridge import score_registry

ROLES = ("trainer", "validator", "deployer", "operator", "consumer")


def load_doc(path: str) -> Dict[str, Any]:
    text = open(path, encoding="utf-8").read()
    return company.parse_doc(text)


def build_structure(N: Dict[str, Dict[str, Any]]) -> G.Structure:
    s = G.Structure()
    for i, n in N.items():
        if n["type"] == "department":
            s.parent[i] = n["props"].get("parent") or None
            s.head[i] = (N.get(n["props"].get("head") or "") or {}).get("name") if n["props"].get("head") else None
    for i, n in N.items():
        if n["type"] in company.PEOPLE:
            dept = n["props"].get("department")
            s.unit_of[n["name"]] = dept if dept in s.parent else None
    return s


def registry_for(desc: Dict[str, Any], evidence: Dict[str, Any], policy: Dict[str, Any], model_id: str) -> RegistryBlock:
    d = desc["description"]
    rb = RegistryBlock()
    m = (d.get("ai_models") or [{}])[0]
    rb.deployment_context = DeploymentContext(model_type=m.get("model_type", "CLASSICAL_ML"), ai_criticality=m.get("ai_criticality", "OPERATIONAL"),
                                              data_sensitivity=m.get("data_sensitivity", "NON_PERSONAL"), domain=m.get("domain") or "")
    for a in d.get("actors", []):
        role = a["subtype"].lower()
        if role in ROLES:
            setattr(rb.actors, role, type(rb.actors.trainer)(identity=a.get("identity", ""), department_id=a.get("department_temp_id")))
    rb.departments = [Department(id=x["temp_id"], name=x["name"], reports_to_department_id=x.get("reports_to_temp_id")) for x in d.get("departments", [])]
    decls = rb.governance_state.constraints_declared
    for cid, e in (evidence.get("constraints") or {}).items():
        if cid not in decls:
            print(f"  note: {cid} is not a constraint of this platform; ignored", file=sys.stderr)
            continue
        kw: Dict[str, Any] = {}
        if "status" in e:
            kw["status"] = e["status"]
        for k in ("evidence", "valid_until"):
            if k in e:
                kw[k] = e[k]
        if "applicable" in e:
            kw["applicable"] = e["applicable"]
        if e.get("not_applicable"):
            kw["not_applicable"] = NotApplicableRationale(**e["not_applicable"])
        decls[cid] = ConstraintDeclaration(**kw)
    if evidence.get("risk"):
        from schema import RiskBlock
        rb.risk = RiskBlock(**evidence["risk"])
    pol = P.normalise(policy)
    pol["number"] = (policy or {}).get("number", 0)
    rb.st_ai = {"design_key": model_id, "policy": pol}
    return rb


def check_model(N, edges, ext_id: str, evidence: Dict[str, Any], policy: Dict[str, Any], level: str) -> Dict[str, Any]:
    company._graph = lambda session: (N, edges)                    # read the file, not a database
    desc = company.model_description(None, ext_id)
    rb = registry_for(desc, evidence.get(ext_id) or evidence.get(N[ext_id]["name"]) or {}, policy, ext_id)
    res, _ = score_registry(rb)
    st = res.raw_breakdown["st_ai"]
    s = build_structure(N)
    holders = {r: getattr(rb.actors, r).identity for r in ROLES if getattr(rb.actors, r).identity}
    uses = {u: P.independence_requirement(policy, u) for u in ("approval", "review")}
    pairs = []
    names = sorted(holders)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            pairs.append({"roles": f"{a} / {b}", "people": f"{holders[a]} / {holders[b]}", "independent": G.independent(holders[a], holders[b], level, s)})
    return {"model": N[ext_id]["name"], "id": ext_id, "gate": res.gate, "legacy_pcs": {"score": res.pcs_final, "tier": res.tier, "gate": st["legacy_gate"]},
            "blockers": st["blockers"], "triggers": st["triggers"], "releasable_with_a_review": st["releasable_with_review"], "constraints": st["constraints"],
            "risk_basis": st["risk_basis"], "risks": st["risks"], "unresolvable": st["unresolvable"],
            "role_holders": holders, "independence": {"level": level, "head_rule_holds": s.head_rule_holds(), "pairs": pairs, "policy": {u: f"{lv} ({md})" for u, (lv, md) in uses.items()}},
            "skipped": desc.get("skipped", []), "notes": desc.get("notes", [])}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("company_file")
    ap.add_argument("--evidence", help="JSON file mapping a model id or name to its constraint evidence")
    ap.add_argument("--policy", help="JSON file with the ST-AI policy parameters (independence, risk basis, tolerances)")
    ap.add_argument("--level", default=G.LEVEL_REPORTING_LINE, choices=[G.LEVEL_PERSON, G.LEVEL_REPORTING_LINE, G.LEVEL_UNIT], help="independence level of the table printed at the end")
    ap.add_argument("--json", action="store_true", help="print the full result as JSON")
    args = ap.parse_args()

    doc = load_doc(args.company_file)
    graph = company.doc_to_graph(doc, set())
    if graph["errors"]:
        print("The file cannot be imported:", *graph["errors"][:10], sep="\n  ")
        return 2
    N = {n["id"]: n for n in graph["nodes"]}
    edges = graph["edges"]
    evidence = json.load(open(args.evidence, encoding="utf-8")) if args.evidence else {}
    policy = json.load(open(args.policy, encoding="utf-8")) if args.policy else {}
    problems = P.validate(policy)
    if problems:
        print("The policy file has problems:", *problems[:8], sep="\n  ")
        return 2
    models = [i for i, n in N.items() if n["type"] == "model"]
    if not models:
        print("The file has no AI model (an 'ai_systems' entry of type model).")
        return 2
    results: List[Dict[str, Any]] = []
    for ext_id in models:
        try:
            results.append(check_model(N, edges, ext_id, evidence, policy, args.level))
        except Exception as exc:                                  # a model the studio cannot describe is reported, not hidden
            results.append({"model": N[ext_id]["name"], "id": ext_id, "gate": "NOT_ASSESSED", "error": str(getattr(exc, "detail", exc))})
    if args.json:
        print(json.dumps({"company": graph.get("company_name"), "spec": G.SPEC, "date": date.today().isoformat(), "models": results}, indent=2, default=str))
        return 0
    print(f"{graph.get('company_name') or args.company_file}: {len(models)} AI model(s), ST-AI v2.5 gate (independence level {args.level})\n")
    for r in results:
        print(f"== {r['model']} ({r['id']}): {r['gate']}")
        if r.get("error"):
            print("   not assessed:", r["error"])
            continue
        print(f"   risk decided by: {r['risk_basis']} (legacy score {r['legacy_pcs']['score']}, {r['legacy_pcs']['tier']}, legacy gate {r['legacy_pcs']['gate']}); releasable with a review: {r['releasable_with_a_review']}")
        for rk in r["risks"]:
            print(f"   RISK {rk['state'].upper()}: {rk['id']}: {rk['detail']}")
        for b in r["blockers"][:8]:
            print("   BLOCKER:", b)
        for t in r["triggers"][:8]:
            print(f"   REVIEW TRIGGER ({'a review can clear it' if t['resolvable'] else 'record the fact first'}):", t["detail"])
        counts: Dict[str, int] = {}
        for c in r["constraints"]:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        print("   constraints:", ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
        print("   role holders:", ", ".join(f"{k}: {v}" for k, v in r["role_holders"].items()) or "none named")
        print(f"   independence ({r['independence']['level']}; head rule holds: {r['independence']['head_rule_holds']}):")
        for p in r["independence"]["pairs"]:
            print(f"     {p['roles']:<22} {p['people']:<40} {p['independent']}")
        for sk in r["skipped"][:4]:
            print("   skipped:", sk)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
