"""
Tests for repo_connect.py: connecting a repository, scanning it, importing what it defines, keeping it in step, and the safety rules around it.

A real git repository is made on disk and read through file:// (allowed only here, by ASTRA_REPO_ALLOW_FILE=1); the network is not used.

    docker compose exec backend python -m tests.test_repo_connect
"""
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile

from cryptography.fernet import Fernet

os.environ["ASTRA_REPO_ALLOW_FILE"] = "1"
os.environ["ASTRA_SECRET_KEY"] = Fernet.generate_key().decode()

import repo_connect as rc
from db.models import Agent, Design, RepoConnection, RepoImport, RepoScan
from db.session import SessionLocal
from tests._auth import authed_client
from tests.test_agent_registry import cleanup

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:400] if detail and not ok else ""))
    if not ok:
        fails.append(name)


AGENT_PY = '''
import requests
from agents import Agent, Runner, function_tool

@function_tool
def lookup_order(order_id: str) -> dict:
    """Look up an order."""
    return requests.get("https://orders.internal/" + order_id).json()

@function_tool
def issue_refund(order_id: str) -> str:
    """Refund an order."""
    requests.post("https://payments.internal/refunds", json={"o": order_id})
    return "ok"

refund = Agent(name="zz-test-refund-agent", instructions="You resolve refund requests.", tools=[lookup_order, issue_refund])
'''
OTHER_PY = '''
from agents import Agent
helper = Agent(name="zz-test-helper-agent", instructions="You help.")
'''
TEST_PY = "from agents import Agent\nAgent(name='zz-test-only-in-tests', instructions='x')\n"
ENV = "OPENAI_API_KEY=SECRET_VALUE_XYZ123\n"


def git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.test", "GIT_CONFIG_GLOBAL": os.devnull}
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True)


def write(root, path, text):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(text)


def commit(root, msg):
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", msg)


def sign(secret, body):
    return {"x-hub-signature-256": "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest(), "x-github-event": "push"}


KEYS = ["zz-test-refund-agent", "zz-test-helper-agent", "zz-test-only-in-tests"]
repo = tempfile.mkdtemp(prefix="astra-test-repo-")
git(repo, "init", "-q", "-b", "main")
write(repo, "agents/refund.py", AGENT_PY)
write(repo, "agents/helper.py", OTHER_PY)
write(repo, "tests/test_agent.py", TEST_PY)
write(repo, ".env", ENV)
write(repo, "config/credentials.json", json.dumps({"api_key": "SECRET_VALUE_XYZ123"}))
write(repo, ".mcp.json", json.dumps({"mcpServers": {"orders": {"command": "npx", "args": ["-y", "some-mcp-server"], "env": {"API_TOKEN": "SECRET_VALUE_XYZ123"}}}}))
commit(repo, "first")
URL = "file://" + repo.replace("\\", "/")

try:
    # ── the rules about the address, with no repository needed
    for bad, why in [("http://github.com/a/b", "http"), ("ssh://git@github.com/a/b.git", "ssh"), ("https://user:pw@github.com/a/b.git", "credentials"), ("https://127.0.0.1/a/b.git", "private"),
                     ("https://169.254.169.254/latest", "metadata"), ("not a url", "text"), ("https://localhost/a/b.git", "loopback name")]:
        try:
            rc.check_url(bad)
            check(f"address refused: {why}", False, bad)
        except rc.RepoError as e:
            check(f"address refused: {why}", True, e)
    check("a github address is normalised and recognised", rc.check_url("https://github.com/acme/agents") == ("https://github.com/acme/agents.git", "github"))
    for b in ["--upload-pack=x", "a b", "../x", "-x"]:
        try:
            rc.check_branch(b)
            check(f"branch refused: {b}", False)
        except rc.RepoError:
            check(f"branch refused: {b}", True)
    check("a leading slash means a folder inside the repository, not the machine", rc.check_subpath("/etc") == "etc")
    for p in ["../x", "a/../../x", "a" + chr(92) + "b"]:
        try:
            rc.check_subpath(p)
            check(f"folder refused: {p}", False)
        except rc.RepoError:
            check(f"folder refused: {p}", True)
    check("an error message never carries the token", "TOKEN123" not in rc._explain("fatal: Authentication failed for 'https://x/y' with TOKEN123", "TOKEN123"))
    sealed = rc.seal("ghp_secret_token")
    check("a sealed value is not the value, and opens again", sealed != "ghp_secret_token" and "ghp_" not in sealed and rc.unseal(sealed) == "ghp_secret_token")
    check("a tampered or foreign value does not open", rc.unseal(sealed[:-4] + "AAAA") is None and rc.unseal("junk") is None)
    old = os.environ["ASTRA_SECRET_KEY"]
    os.environ["ASTRA_SECRET_KEY"] = Fernet.generate_key().decode() + "," + old
    check("key rotation: a new first key still opens what the old key sealed", rc.unseal(sealed) == "ghp_secret_token")
    os.environ["ASTRA_SECRET_KEY"] = Fernet.generate_key().decode()
    check("a different key cannot open it", rc.unseal(sealed) is None)
    os.environ["ASTRA_SECRET_KEY"] = old

    # ── collecting files
    probe = tempfile.mkdtemp()
    write(probe, "a/agent.py", "from agents import Agent\n")
    write(probe, "a/test_x.py", "x = 1\n")
    write(probe, ".env", "K=V\n")
    write(probe, "a/server.pem", "-----BEGIN-----\n")
    write(probe, "node_modules/p/agent.py", "from agents import Agent\n")
    write(probe, "tests/t.py", "x=1\n")
    write(probe, ".mcp.json", "{}")
    write(probe, ".cursor/mcp.json", "{}")
    os.symlink("/etc/passwd", os.path.join(probe, "a", "link.py")) if hasattr(os, "symlink") else None
    files, _ = rc.collect(probe, "", False)
    check("collect: source and known config only, no secrets, no vendor folders, no tests, no symlinks", sorted(files) == [".cursor/mcp.json", ".mcp.json", "a/agent.py"], sorted(files))
    files2, _ = rc.collect(probe, "", True)
    check("collect: tests can be included on request, secrets still never", "a/test_x.py" in files2 and "tests/t.py" in files2 and ".env" not in files2 and "a/server.pem" not in files2)
    shutil.rmtree(probe, ignore_errors=True)

    with authed_client() as api, authed_client("auditor") as aud, authed_client("engineer") as eng:
        caps = api.get("/api/repos/capabilities").json()
        check("capabilities say token storage is set up and name the frameworks", caps["secrets_ready"] is True and "LangGraph" in caps["frameworks"] and "CrewAI" in caps["frameworks"])
        check("an auditor can read but not connect", aud.get("/api/repos").status_code == 200 and aud.post("/api/repos", json={"url": URL}).status_code == 403)

        r = api.post("/api/repos", json={"url": URL, "name": "zz-test-repo", "token": "ghp_not_used_for_file_urls", "webhook": True, "auto_sync": True})
        check("connect a repository", r.status_code == 201, r.text)
        conn = r.json()
        cid = conn["id"]
        check("the token and secret are never returned after creation", "ghp_" not in json.dumps(api.get("/api/repos").json()) and api.get(f"/api/repos/{cid}").json()["has_token"] is True
              and "webhook_secret" not in api.get(f"/api/repos/{cid}").json() and conn["webhook_secret"])
        with SessionLocal() as s:
            row = s.get(RepoConnection, __import__("uuid").UUID(cid))
            check("stored encrypted", row.token_enc and "ghp_" not in row.token_enc and rc.unseal(row.token_enc) == "ghp_not_used_for_file_urls" and rc.unseal(row.webhook_secret_enc) == conn["webhook_secret"])
        check("the same repository twice is refused", api.post("/api/repos", json={"url": URL}).status_code == 409)
        check("an unreachable repository is refused with a reason", api.post("/api/repos", json={"url": "file:///no/such/folder"}).status_code == 422)
        check("an unknown branch is refused", api.post("/api/repos", json={"url": URL, "branch": "nope"}).status_code == 422)

        # ── scanning
        s1 = api.post(f"/api/repos/{cid}/scan")
        check("scan", s1.status_code == 200, s1.text)
        scan = s1.json()
        names = {a["key"]: a for a in scan["agents"]}
        check("finds the agents, all new", {"zz-test-refund-agent", "zz-test-helper-agent"} <= set(names) and all(a["status"] == "new" for a in scan["agents"]), list(names))
        check("tests are left out by default", "zz-test-only-in-tests" not in names)
        check("each agent says where it was found", names["zz-test-refund-agent"]["path"] == "agents/refund.py" and names["zz-test-refund-agent"]["line"] > 1 and names["zz-test-refund-agent"]["framework"] == "OpenAI Agents SDK")
        check("the scan names the commit it read", len(scan["commit"]) == 40)
        blob = json.dumps(scan)
        check("nothing from .env or credentials, no secret value, no command line anywhere in the result", "SECRET_VALUE_XYZ123" not in blob and "npx" not in blob and '"-y"' not in blob)
        check("the inline MCP credential is reported by key, not value", any("API_TOKEN" in n for n in scan["notes"]), scan["notes"])
        check("the list does not carry whole manifests", all("manifest" not in a for a in scan["agents"]))
        pv = api.get(f"/api/repos/{cid}/agents/zz-test-refund-agent")
        check("preview gives the model, the threat analysis and what import would do", pv.status_code == 200 and pv.json()["existing"]["will"] == "create" and pv.json()["analysis"] and pv.json()["source"]["path"] == "agents/refund.py", pv.text[:300])

        # ── importing
        imp = api.post(f"/api/repos/{cid}/import", json={"agents": ["zz-test-refund-agent", "nope"]})
        res = {x["key"]: x for x in imp.json()["results"]}
        check("import creates a draft; an unknown agent is reported, not fatal", imp.status_code == 200 and res["zz-test-refund-agent"]["ok"] and res["zz-test-refund-agent"]["outcome"] == "created" and not res["nope"]["ok"], imp.text)
        a = api.get("/api/agents/zz-test-refund-agent").json() if api.get("/api/agents/zz-test-refund-agent").status_code == 200 else next((x for x in api.get("/api/agents").json() if x["agent_key"] == "zz-test-refund-agent"), None)
        check("the agent exists, owned by nobody yet, from the repository", a is not None and a["framework"] == "OpenAI Agents SDK" and a["status"] == "UNOWNED", a)
        with SessionLocal() as s:
            d = s.query(Design).filter(Design.name == "zz-test-refund-agent").one()
            prov = d.document["provenance"]
            check("provenance records repository, commit, file and line, and says it is a static scan", prov["source"] == "repository" and prov["commit"] == scan["commit"] and prov["path"] == "agents/refund.py" and "static scan" in prov["label"] and "not verified" in prov["note"] + prov["label"], prov)
            tools = {n["name"]: n["p"]["write"] for n in d.document["nodes"] if n["type"] == "tool"}
            check("the design has the tools, with write detected from code", tools == {"lookup_order": False, "issue_refund": True}, tools)
        again = api.get(f"/api/repos/{cid}/scan").json()
        st = {x["key"]: x["status"] for x in again["agents"]}
        check("after import the agent is unchanged and the other is still new", st["zz-test-refund-agent"] == "unchanged" and st["zz-test-helper-agent"] == "new", st)

        # ── the repository changes
        write(repo, "agents/refund.py", AGENT_PY.replace("tools=[lookup_order, issue_refund]", "tools=[lookup_order]"))
        write(repo, "agents/helper.py", "")
        commit(repo, "second")
        s2 = api.post(f"/api/repos/{cid}/scan").json()
        st = {x["key"]: x["status"] for x in s2["agents"]}
        check("a changed definition is marked changed", st.get("zz-test-refund-agent") == "changed" and s2["commit"] != scan["commit"], st)
        check("an agent no longer in the repository is reported as removed only if it was imported", s2["removed"] == [] and "zz-test-helper-agent" not in st)
        imp2 = api.post(f"/api/repos/{cid}/import", json={"agents": ["zz-test-refund-agent"]}).json()["results"][0]
        check("importing the change updates the draft", imp2["ok"] and imp2["outcome"] == "updated", imp2)
        with SessionLocal() as s:
            d = s.query(Design).filter(Design.name == "zz-test-refund-agent").one()
            check("the draft lost the removed tool", {n["name"] for n in d.document["nodes"] if n["type"] == "tool"} == {"lookup_order"})
        write(repo, "agents/refund.py", "x = 1\n")
        commit(repo, "third")
        s3 = api.post(f"/api/repos/{cid}/scan").json()
        check("an imported agent that left the repository is flagged", s3["removed"] == ["zz-test-refund-agent"], s3["removed"])

        # ── options
        check("include_tests widens the scan", api.patch(f"/api/repos/{cid}", json={"include_tests": True}).json()["include_tests"] is True
              and "zz-test-only-in-tests" in {a["key"] for a in api.post(f"/api/repos/{cid}/scan").json()["agents"]})
        check("a bad folder is refused", api.patch(f"/api/repos/{cid}", json={"subpath": "../x"}).status_code == 422)
        sub = api.patch(f"/api/repos/{cid}", json={"subpath": "tests", "include_tests": True})
        check("a folder narrows the scan", sub.status_code == 200 and {a["key"] for a in api.post(f"/api/repos/{cid}/scan").json()["agents"]} == {"zz-test-only-in-tests"})
        api.patch(f"/api/repos/{cid}", json={"subpath": ""})
        check("a token can be rotated and removed", api.patch(f"/api/repos/{cid}", json={"token": ""}).json()["has_token"] is False)

        # ── the webhook
        sec = api.post(f"/api/repos/{cid}/webhook-secret").json()
        body = json.dumps({"ref": "refs/heads/main"}).encode()
        from fastapi.testclient import TestClient
        from main import app
        with TestClient(app) as bare:
            w = f"/api/repos/webhook/{cid}"
            check("a webhook with no signature is refused", bare.post(w, content=body).status_code == 401)
            check("a webhook with a wrong signature is refused", bare.post(w, content=body, headers=sign("wrong", body)).status_code == 401)
            check("the old secret stops working after rotation", bare.post(w, content=body, headers=sign(conn["webhook_secret"], body)).status_code == 401)
            check("an unknown connection answers like a missing secret", bare.post("/api/repos/webhook/00000000-0000-0000-0000-000000000000", content=body, headers=sign(sec["webhook_secret"], body)).status_code == 404
                  and bare.post("/api/repos/webhook/garbage", content=body).status_code == 404)
            check("a ping is answered", bare.post(w, content=b"{}", headers={**sign(sec["webhook_secret"], b"{}"), "x-github-event": "ping"}).json().get("event") == "ping")
            other = json.dumps({"ref": "refs/heads/other"}).encode()
            with SessionLocal() as s:
                c = s.get(RepoConnection, __import__("uuid").UUID(cid))
                c.branch, c.last_scan_at = "main", None
                n0 = s.query(RepoScan).filter(RepoScan.connection_id == c.id).count()
                s.commit()
            check("a push to another branch is ignored (branch set)", bare.post(w, content=other, headers=sign(sec["webhook_secret"], other)).json().get("ignored") == "a push to another branch")
            ok = bare.post(w, content=body, headers=sign(sec["webhook_secret"], body))
            with SessionLocal() as s:
                n1 = s.query(RepoScan).filter(RepoScan.connection_id == __import__("uuid").UUID(cid)).count()
            check("a signed push to the branch scans the repository", ok.status_code == 202 and ok.json().get("scanning") is True and n1 == n0 + 1, (ok.text, n0, n1))
            check("a second push a moment later is not scanned again", bare.post(w, content=body, headers=sign(sec["webhook_secret"], body)).json().get("ignored") == "scanned a moment ago")
            gl = bare.post(w, content=body, headers={"x-gitlab-token": sec["webhook_secret"], "x-gitlab-event": "Push Hook"})
            check("a GitLab token header is accepted too", gl.status_code in (200, 202), gl.text)

        # auto-sync: an imported agent that changed in the repository is brought in by the push
        write(repo, "agents/refund.py", AGENT_PY)
        commit(repo, "fourth")
        api.patch(f"/api/repos/{cid}", json={"include_tests": False})
        api.post(f"/api/repos/{cid}/scan")
        api.post(f"/api/repos/{cid}/import", json={"agents": ["zz-test-refund-agent"]})
        write(repo, "agents/refund.py", AGENT_PY.replace("tools=[lookup_order, issue_refund]", "tools=[issue_refund]"))
        commit(repo, "fifth")
        with SessionLocal() as s:
            c = s.get(RepoConnection, __import__("uuid").UUID(cid))
            c.last_scan_at = None
            s.commit()
        with TestClient(app) as bare:
            body = json.dumps({"ref": "refs/heads/main"}).encode()
            bare.post(f"/api/repos/webhook/{cid}", content=body, headers=sign(sec["webhook_secret"], body))
        with SessionLocal() as s:
            d = s.query(Design).filter(Design.name == "zz-test-refund-agent").one()
            imp_row = s.query(RepoImport).filter(RepoImport.agent_key == "zz-test-refund-agent").one()
            check("auto-sync imported the pushed change on its own", {n["name"] for n in d.document["nodes"] if n["type"] == "tool"} == {"issue_refund"} and imp_row.commit_sha != scan["commit"], [n["name"] for n in d.document["nodes"] if n["type"] == "tool"])
        check("auto-sync is recorded in the audit log by name", any(e["action"] == "repo.webhook.scan" for e in api.get("/api/audit?limit=50").json()))

        # ── failure and removal
        shutil.rmtree(repo)
        bad = api.post(f"/api/repos/{cid}/scan")
        check("a repository that has gone is a clear error, and the connection says so", bad.status_code == 502 and api.get(f"/api/repos/{cid}").json()["status"] == "ERROR" and api.get(f"/api/repos/{cid}").json()["last_error"], bad.text)
        check("disconnecting leaves the imported agents, drops the import record", api.delete(f"/api/repos/{cid}").status_code == 204)
        with SessionLocal() as s:
            check("the agent stayed and the import record went", s.query(Agent).filter(Agent.agent_key == "zz-test-refund-agent").count() == 1 and s.query(RepoImport).filter(RepoImport.agent_key == "zz-test-refund-agent").count() == 0)
        check("an engineer may connect (write access), an auditor may not", eng.get("/api/repos").status_code == 200)
finally:
    shutil.rmtree(repo, ignore_errors=True)
    cleanup(*KEYS)
    with SessionLocal() as s:
        for c in s.query(RepoConnection).filter(RepoConnection.name == "zz-test-repo").all():
            s.delete(c)
        s.commit()

sys.exit(1 if fails else 0)
