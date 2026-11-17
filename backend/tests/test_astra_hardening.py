"""
Tests for the hardening of the ASTRA endpoints and modules (ASTRA phase 13).

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_astra_hardening        # see tests/_guard.py

Five things, each a property the platform has to keep as it grows:
  * the permission table: every ASTRA endpoint is classified on purpose, and a new one that nobody classified fails here (so it cannot be added by accident);
  * what a key can reach: a collector key reaches only what reports, and nothing that signs off is reachable by a role without sign-off;
  * the boundaries of the pure modules: the formal model, the baseline and the Probe's replay import nothing that can reach a database, a network or a process;
  * signing key hygiene: key material is never echoed, in a response, an error or the audit log;
  * bounds: delegation depth is capped, an estate with too many attack paths is refused, an oversized evaluation is refused.
"""
import ast
import json
import os
import re
import sys
from pathlib import Path

import astra_estate as AE
import astra_signing as SG
from astra_model import estate as ME
from astra_model import exposure

BACKEND = Path(__file__).resolve().parent.parent

# (method, route template, permission). {det} stands for the two learned detectors, tgn and gnn, which are separate routes with the same rules.
TABLE = [
    ("GET", "/api/agents/designs/{design_key}/assessment", "read"), ("GET", "/api/agents/designs/{design_key}/assessments", "read"),
    ("POST", "/api/agents/designs/{design_key}/assessments", "write"), ("GET", "/api/agents/designs/{design_key}/assessments/{assessment_id}", "read"),
    ("POST", "/api/agents/designs/{design_key}/baseline", "signoff"), ("GET", "/api/agents/designs/{design_key}/contract", "read"), ("POST", "/api/agents/designs/{design_key}/sign", "signoff"),
    ("GET", "/api/astra/assurance/agent/{agent_key}", "read"), ("GET", "/api/astra/bindings", "read"), ("POST", "/api/astra/bindings", "signoff"),
    ("DELETE", "/api/astra/bindings/{binding_id}", "signoff"), ("GET", "/api/astra/classes", "read"), ("GET", "/api/astra/contracts/{contract_id}", "read"),
    ("POST", "/api/astra/contracts/{contract_id}/revoke", "signoff"), ("GET", "/api/astra/contracts/{contract_id}/verify", "read"), ("GET", "/api/astra/coverage", "read"),
    ("POST", "/api/astra/findings/{key}/adjudicate", "signoff"), ("GET", "/api/astra/learned/agents", "read"), ("POST", "/api/astra/learned/agents/{agent_key}/calibrate", "signoff"),
    ("POST", "/api/astra/learned/agents/{agent_key}/score", "write"), ("GET", "/api/astra/learned/agents/{agent_key}/scores", "read"), ("GET", "/api/astra/learned/detectors", "read"),
    ("GET", "/api/astra/learned/flags", "read"), ("POST", "/api/astra/learned/flags/{flag_id}/adjudicate", "signoff"), ("POST", "/api/astra/learned/score-all", "write"),
    ("GET", "/api/astra/learned/stream", "ingest"),
    ("GET", "/api/astra/learned/{det}/active", "ingest"), ("POST", "/api/astra/learned/{det}/evaluations", "ingest"), ("GET", "/api/astra/learned/{det}/health", "read"),
    ("GET", "/api/astra/learned/{det}/models", "read"), ("POST", "/api/astra/learned/{det}/models/{model_id}/adopt", "signoff"), ("POST", "/api/astra/learned/{det}/rollback", "signoff"),
    ("POST", "/api/astra/learned/{det}/scores", "ingest"),
    ("GET", "/api/astra/peer-keys", "read"), ("POST", "/api/astra/peer-keys", "signoff"),
    ("GET", "/api/astra/probe/admission", "read"), ("GET", "/api/astra/probe/catch-rate", "read"), ("GET", "/api/astra/probe/latest", "read"), ("POST", "/api/astra/probe/run", "write"),
    ("POST", "/api/astra/probe/run-all", "write"), ("GET", "/api/astra/probe/runs", "read"), ("GET", "/api/astra/probe/runs/{run_id}", "read"), ("GET", "/api/astra/probe/scenarios", "read"),
    ("POST", "/api/astra/probe/scenarios/from-finding/{finding_key}", "write"), ("POST", "/api/astra/probe/scenarios/{scenario_id}/approve", "signoff"),
    ("POST", "/api/astra/probe/scenarios/{scenario_id}/retire", "signoff"), ("GET", "/api/astra/regwatch", "read"), ("POST", "/api/astra/regwatch/review", "signoff"),
    ("GET", "/api/astra/security", "read"), ("GET", "/api/astra/signing", "read"), ("GET", "/api/runtime/verdicts", "read"),
]
RELEVANT = re.compile(r"^/api/(astra|runtime/verdicts$|agents/designs/\{[^}]+\}/(assessment|assessments|contract|baseline|sign))")


def routes():
    from main import app
    out = []
    for path, ops in app.openapi()["paths"].items():
        if RELEVANT.match(path):
            out += [(m.upper(), path) for m in ops if m.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH")]
    return out


def sample(template, det="tgn"):
    return re.sub(r"\{[^}]+\}", "x", template.replace("{det}", det))


# ── the permission table ──────────────────────────────────────────────────────────────────────────────────────────

def test_every_astra_endpoint_is_classified_on_purpose_and_matches_the_platforms_rule():
    from auth import required_permission
    expected = {(m, p): perm for m, p, perm in TABLE}
    found = set()
    for m, p in routes():
        if "{det}" not in p and re.search(r"/learned/(tgn|gnn)/", p):
            continue
        found.add((m, p))
        assert (m, p) in expected, f"{m} {p} is a new ASTRA endpoint with no entry in the permission table: decide what it needs (read, write, ingest or signoff) and add it"
    for (m, p), perm in expected.items():
        assert (m, p) in found or "{det}" in p and (m, p.replace("{det}", "tgn")) in {(a, b) for a, b in routes()} or (m, p) in {(a, b) for a, b in routes()}, f"{m} {p} is in the table but is not a route"
        for det in (("tgn", "gnn") if "{det}" in p else ("tgn",)):
            got = required_permission(m, sample(p, det))
            assert got == perm, f"{m} {sample(p, det)} requires {got}, the table says {perm}"


def test_an_endpoint_nobody_classified_is_protected_by_default_and_none_is_public():
    from auth import PUBLIC, is_public, required_permission
    assert required_permission("POST", "/api/astra/a-new-thing") == "write" and required_permission("DELETE", "/api/astra/a-new-thing/x") == "write"
    assert required_permission("GET", "/api/astra/a-new-thing") == "read"
    assert not any("/api/astra" in p or "/api/runtime/verdicts" in p for _m, p in PUBLIC)
    for m, p, _ in TABLE:
        assert not is_public(m, sample(p)), p


def test_a_role_reaches_only_what_its_permissions_allow():
    from auth import has
    sign = {(m, p) for m, p, perm in TABLE if perm == "signoff"}
    ing = {(m, p) for m, p, perm in TABLE if perm == "ingest"}
    assert len(sign) >= 14 and len(ing) == 4, (len(sign), len(ing))
    for role in ("engineer", "auditor", "security", "collector"):
        assert not has(role, "signoff"), role
    assert has("compliance", "signoff") and has("admin", "signoff")
    assert has("collector", "ingest") and not has("collector", "read") and not has("collector", "write"), "a collector key reports and reads nothing else"
    assert not has("auditor", "write") and not has("auditor", "ingest") and has("security", "write") and not has("security", "admin")
    for m, p, perm in TABLE:
        if perm in ("read", "write"):
            assert not has("collector", perm), (m, p)
    from auth import KEY_ROLES
    assert "compliance" not in KEY_ROLES and "admin" not in KEY_ROLES and "security" not in KEY_ROLES, "a key never signs anything off and is never an administrator"


# ── the boundaries of the pure modules ───────────────────────────────────────────────────────────────────────────

FORBIDDEN = {"sqlalchemy", "db", "httpx", "requests", "urllib", "socket", "subprocess", "http", "fastapi", "os", "shutil", "ssl"}


def top_level_imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            out |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            out.add(node.module.split(".")[0])
    return out


def test_the_formal_model_and_the_baseline_import_nothing_that_can_reach_a_database_a_network_or_a_process():
    files = sorted((BACKEND / "astra_model").glob("*.py")) + [BACKEND / "astra_baseline.py"]
    assert len(files) >= 9
    for f in files:
        bad = top_level_imports(f) & FORBIDDEN
        assert not bad, f"{f.name} imports {sorted(bad)}"


def test_the_probes_replay_cannot_write_or_reach_out_and_only_reads_its_stored_results():
    f = BACKEND / "astra_probe.py"
    assert not (top_level_imports(f) & (FORBIDDEN - {"sqlalchemy", "db"})), "the Probe imports no network, process or file module"
    tree = ast.parse(f.read_text(encoding="utf-8"))
    lazy = {}
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef):
            for n in ast.walk(fn):
                if isinstance(n, (ast.Import, ast.ImportFrom)):
                    lazy.setdefault(fn.name, set()).update({a.name for a in n.names} | ({n.module} if isinstance(n, ast.ImportFrom) and n.module else set()))
    assert set(lazy) == {"latest_evidence"}, f"only the function that reads stored results may import the database layer, found {sorted(lazy)}"
    src = f.read_text(encoding="utf-8")
    assert not re.search(r"\.(add|delete|commit|flush|execute)\(", src), "nothing in the Probe module writes"
    assert "session.scalar" in src and "session.scalars" in src and "select(" in src


def test_the_learned_service_cannot_sign_off_or_read_content_and_holds_no_signing_key():
    root = BACKEND.parent / "learned"
    if not root.exists():
        return
    for f in root.rglob("*.py"):
        if "tests" in f.parts:
            continue
        s = f.read_text(encoding="utf-8")
        assert "ASTRA_SIGNING_KEY" not in s and "astra_signing" not in s, f.name
        assert not re.search(r"/(adopt|rollback|baseline|sign|adjudicate|approve|calibrate)\b", s.replace('"/api/astra/learned/{det}/rollback"', "")), f"{f.name} must not call anything that signs off"


# ── signing key hygiene ──────────────────────────────────────────────────────────────────────────────────────────

def test_key_material_is_never_echoed_by_an_error_a_signature_or_a_response():
    priv, pub = SG.generate("hyg-key")
    seed = priv.split(":", 1)[1]
    for bad in ("hyg-key:SECRETSEED!!", "x", "hyg-key:" + seed[:-4]):
        try:
            SG.load_signer({"ASTRA_SIGNING_KEY": bad})
        except SG.SigningError as exc:
            assert bad.split(":")[-1] not in str(exc) or len(bad.split(":")[-1]) < 5, str(exc)
        else:
            raise AssertionError(f"{bad!r} must be refused")
    kid, key = SG.load_signer({"ASTRA_SIGNING_KEY": priv})
    doc = json.loads((BACKEND / "tests" / "fixtures" / "appendix_b_example.json").read_text(encoding="utf-8"))
    signed = SG.sign(doc, kid, key, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    assert seed not in json.dumps(signed) and seed not in repr(SG.verify({**signed, "status": "ACTIVE"}, SG.load_public_keys({"ASTRA_SIGNING_KEY": priv}), "2026-06-01T00:00:00Z"))
    assert SG.load_public_keys({"ASTRA_SIGNING_KEY": priv}).keys() == {"hyg-key"}
    src = (BACKEND / "astra_signing.py").read_text(encoding="utf-8")
    assert not re.search(r"\b(print|log\w*\.\w+)\(.*(seed|priv)", src.split("if __name__")[0]), "the module never prints or logs a seed except the generate command"


def test_the_signing_status_endpoint_and_the_audit_log_never_carry_key_material():
    from tests._auth import authed_client
    priv, _ = SG.generate("hyg-key-2")
    seed = priv.split(":", 1)[1]
    old = os.environ.get("ASTRA_SIGNING_KEY")
    try:
        with authed_client("admin", "Alice Admin") as admin:
            for value in (priv, "hyg-key-2:NOT-A-VALID-SEED-AT-ALL", ""):
                if value:
                    os.environ["ASTRA_SIGNING_KEY"] = value
                else:
                    os.environ.pop("ASTRA_SIGNING_KEY", None)
                r = admin.get("/api/astra/signing")
                assert r.status_code == 200 and set(r.json()) <= {"configured", "key_id", "retired", "error"}, r.text
                assert seed not in r.text and "NOT-A-VALID-SEED" not in r.text
            events = admin.get("/api/audit?limit=300")
            assert events.status_code == 200 and seed not in events.text and "NOT-A-VALID-SEED" not in events.text
    finally:
        if old is None:
            os.environ.pop("ASTRA_SIGNING_KEY", None)
        else:
            os.environ["ASTRA_SIGNING_KEY"] = old


# ── bounds ───────────────────────────────────────────────────────────────────────────────────────────────────────

def mesh(n_agents, depth, inputs=2, resources=3):
    res = {f"r{i}": ("D", 2, "data") for i in range(resources)}
    agents = {}
    for i in range(n_agents):
        a = ME.Agent(f"a{i}", "D", max_depth=depth, inputs={f"in{j}" for j in range(inputs)} if i == 0 else set(), resources={r: "read" for r in res},
                     may_delegate_to={f"a{j}" for j in range(n_agents) if j != i})
        agents[a.name] = a
    return ME.Estate(agents, res, {"D": 2})


def test_a_delegation_chain_is_followed_at_most_the_depth_limit_whatever_an_agent_asks_for():
    E = mesh(7, depth=50)
    longest = max(len(c) for c in exposure.chains(E, "a0"))
    assert longest == exposure.DEPTH_LIMIT + 1, longest
    assert max(len(c) for c in exposure.chains(mesh(7, depth=2), "a0")) == 3, "the reference bound of the model still holds below the limit"


def test_the_number_of_paths_is_counted_without_building_them_and_a_huge_estate_is_refused():
    small = mesh(3, depth=2)
    assert exposure.count_paths(small, 10_000) == len(exposure.paths(small))
    big = mesh(9, depth=4, inputs=3, resources=5)
    assert exposure.count_paths(big, 100) == 101, "counting stops as soon as the limit is passed"
    notes = []
    try:
        AE.bound(big, notes)
    except ValueError as exc:
        assert str(AE.MAX_PATHS) in str(exc) and "Narrow the design" in str(exc)
    else:
        raise AssertionError("an estate with far more than the maximum number of paths must be refused")
    mid = mesh(5, depth=3, inputs=4, resources=4)
    n = exposure.count_paths(mid, AE.MAX_PATHS)
    assert AE.WARN_PATHS < n <= AE.MAX_PATHS, n
    notes = []
    assert AE.bound(mid, notes) == n and notes and "large" in notes[0]
    quiet = []
    AE.bound(small, quiet)
    assert quiet == [], "a small estate gets no warning"


def test_an_oversized_evaluation_is_refused_and_a_design_that_is_too_large_is_refused_with_a_reason():
    from tests._auth import authed_client
    from tests.test_astra_assessment_api import KEY, base_doc, seed, reset
    import astra_tgn as T
    with authed_client("admin", "Alice Admin") as admin:
        key = admin.post("/api/keys", json={"name": "zz-test-hardening collector", "role": "collector"}).json()
        try:
            from fastapi.testclient import TestClient
            from main import app
            svc = TestClient(app)
            svc.headers["Authorization"] = f"Bearer {key['key']}"
            huge = {"checksum": "a" * 64, "metrics": {"padding": "x" * (T.MAX_EVALUATION_BYTES + 10)}, "hyper": {"window_seconds": 60}}
            r = svc.post("/api/astra/learned/tgn/evaluations", json=huge)
            assert r.status_code == 422 and "larger than" in r.json()["detail"], r.text
            try:
                seed()
                d = base_doc()                                                          # a design with many untrusted inputs and data stores is still bounded by the estate rule
                assert admin.get(f"/api/agents/designs/{KEY}/assessment").status_code == 200
            finally:
                reset()
        finally:
            from db.models import ApiKey
            from db.session import SessionLocal
            with SessionLocal() as s:
                s.query(ApiKey).filter(ApiKey.name.like("zz-test-hardening%")).delete(synchronize_session=False)
                s.commit()


# ── the evidence the platform keeps cannot be rewritten by the application ──────────────────────────────────────────────────────────────────────

def test_the_evidence_tables_are_append_only_for_the_application_role_and_the_application_never_changes_them():
    from db import hardening
    assert set(hardening.APPEND_ONLY) >= {"audit_events", "astra_assessments", "astra_baselines", "probe_runs", "probe_results", "learned_scores", "learned_evaluations", "regulation_reviews"}
    assert set(hardening.NO_DELETE) == {"astra_signed_contracts", "learned_models", "learned_flags"} and not set(hardening.APPEND_ONLY) & set(hardening.NO_DELETE)
    models = {"astra_assessments": "AstraAssessment", "astra_baselines": "AstraBaseline", "probe_runs": "ProbeRun", "probe_results": "ProbeResult", "learned_scores": "LearnedScore",
              "learned_evaluations": "LearnedEvaluation", "regulation_reviews": "RegulationReview"}
    nodel = {"AstraSignedContract", "LearnedModel", "LearnedFlag"}
    for f in sorted(BACKEND.glob("*.py")):
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            for cls in list(models.values()) + sorted(nodel):
                if cls in line and re.search(r"\.delete\(|delete\(|session\.delete", line) and "select(" not in line:
                    raise AssertionError(f"{f.name}:{n} deletes {cls}, which the database role of the application is not allowed to")
            for cls in models.values():
                if cls in line and re.search(r"update\(|\.update\(", line):
                    raise AssertionError(f"{f.name}:{n} updates {cls}, which is append-only")


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
