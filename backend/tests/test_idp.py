"""
Tests for the identity-provider connectors: idp_providers.py (Entra ID, Okta, Auth0, Keycloak), idp_manifest.py and idp_connect.py.

The providers are faked with an httpx mock transport that answers like their real APIs; the network is not used.

    docker compose exec backend python -m tests.test_idp
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import httpx
from cryptography.fernet import Fernet

os.environ["ASTRA_SECRET_KEY"] = Fernet.generate_key().decode()

import idp_connect as ic
import idp_manifest as im
import idp_providers as ip
from db.models import Agent, Design, IdpConnection, IdpImport
from db.session import SessionLocal
from tests._auth import authed_client
from tests.test_agent_registry import cleanup

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:400] if detail and not ok else ""))
    if not ok:
        fails.append(name)


NOW = datetime.now(timezone.utc)
iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
SECRET = "SUPER-SECRET-VALUE-123"
CALLS = []                                   # (method, url, headers, params) of every request the connectors made


def respond(request: httpx.Request) -> httpx.Response:
    u = request.url
    CALLS.append((request.method, str(u), dict(request.headers), dict(u.params)))
    host, path, q = u.host, u.path, dict(u.params)
    J = lambda body, status=200, headers=None: httpx.Response(status, json=body, headers=headers or {})
    auth = request.headers.get("authorization", "")
    # ---- Entra
    if host == "login.microsoftonline.com":
        return J({"access_token": "ENTRA-TOKEN"}) if b"client_secret=" + SECRET.encode() in request.content else J({"error": "invalid_client"}, 401)
    if host == "graph.microsoft.com":
        if auth != "Bearer ENTRA-TOKEN":
            return J({}, 401)
        if path == "/v1.0/organization":
            return J({"value": [{"displayName": "Contoso"}]})
        if path == "/v1.0/servicePrincipals":
            if "zz-no-such-tag" in q.get("$filter", ""):
                return J({"value": []})
            return J({"value": [
                {"id": "sp1", "displayName": "zz-test-payments-agent", "description": "Pays approved supplier invoices. Runs nightly.", "tags": ["astra-agent"], "servicePrincipalType": "Application", "accountEnabled": True,
                 "passwordCredentials": [{"displayName": "nightly", "startDateTime": iso(NOW - timedelta(days=20)), "endDateTime": iso(NOW + timedelta(days=10))}], "keyCredentials": []},
                {"id": "sp2", "displayName": "zz-test-claims-agent", "description": "", "tags": ["astra-agent"], "servicePrincipalType": "ManagedIdentity", "accountEnabled": True,
                 "passwordCredentials": [], "keyCredentials": []}]})
        if path == "/v1.0/servicePrincipals/sp1/owners":
            return J({"value": [{"displayName": "Hana Sato", "userPrincipalName": "hana@contoso.com"}]})
        if path == "/v1.0/servicePrincipals/sp2/owners":
            return J({"value": []})
        if path.endswith("/appRoleAssignments"):
            return J({"value": [{"resourceId": "graph", "appRoleId": "r1", "resourceDisplayName": "Microsoft Graph"}, {"resourceId": "graph", "appRoleId": "r2", "resourceDisplayName": "Microsoft Graph"}]} if "sp1" in path else {"value": [{"resourceId": "graph", "appRoleId": "r3", "resourceDisplayName": "Microsoft Graph"}]})
        if path == "/v1.0/servicePrincipals/graph":
            return J({"appRoles": [{"id": "r1", "value": "Mail.Send"}, {"id": "r2", "value": "Directory.ReadWrite.All"}, {"id": "r3", "value": "User.Read.All"}]})
        if path.endswith("/oauth2PermissionGrants"):
            return J({"value": [{"scope": "User.Read offline_access"}]} if "sp1" in path else {"value": []})
    # ---- Okta
    if host == "acme.okta.com":
        if auth != "SSWS OKTA-TOKEN":
            return J({}, 401)
        svc = lambda i, label, status="ACTIVE": {"id": i, "label": label, "status": status, "signOnMode": "OPENID_CONNECT", "settings": {"oauthClient": {"application_type": "service", "grant_types": ["client_credentials"]}}, "profile": {"description": "Reconciles ledgers"}}
        if path == "/api/v1/org":
            return J({"companyName": "Acme Inc"})
        if path == "/api/v1/groups":
            return J([{"id": "g1", "profile": {"name": "AI-Agents"}}, {"id": "g2", "profile": {"name": "AI-Agents-Old"}}])
        if path == "/api/v1/groups/g1/apps":
            if q.get("after") == "p2":
                return J([svc("a3", "zz-test-okta-ledger-agent")])
            return J([svc("a1", "zz-test-okta-billing-agent"), {"id": "a2", "label": "Intranet", "status": "ACTIVE", "signOnMode": "SAML_2_0", "settings": {}},
                      {"id": "a9", "label": "Web portal", "status": "ACTIVE", "signOnMode": "OPENID_CONNECT", "settings": {"oauthClient": {"application_type": "web", "grant_types": ["authorization_code"]}}}],
                     headers={"link": '<https://acme.okta.com/api/v1/groups/g1/apps?after=p2>; rel="next"'})
        if path == "/api/v1/apps":
            return J([svc("a1", "agent-one"), svc("a4", "Billing portal service")])
        if path.endswith("/grants"):
            return J([{"scopeId": "okta.users.read", "status": "ACTIVE", "issuer": "https://acme.okta.com"}, {"scopeId": "okta.apps.manage", "status": "ACTIVE", "issuer": "https://acme.okta.com"}, {"scopeId": "okta.logs.read", "status": "REVOKED"}])
        if path.endswith("/credentials/secrets"):
            return J([{"id": "s1", "status": "ACTIVE", "created": iso(NOW - timedelta(days=400))}, {"id": "s2", "status": "ACTIVE", "created": iso(NOW - timedelta(days=5))}])
    # ---- Auth0
    if host == "acme.eu.auth0.com":
        if path == "/oauth/token":
            return J({"access_token": "A0-TOKEN"}) if json.loads(request.content).get("client_secret") == SECRET else J({"error": "access_denied"}, 401)
        if auth != "Bearer A0-TOKEN":
            return J({}, 401)
        if path == "/api/v2/clients":
            return J([{"client_id": "c1", "name": "zz-test-a0-refund-agent", "description": "Issues refunds", "app_type": "non_interactive", "client_metadata": {"astra-agent": "true", "owner": "Pat Lee"}},
                      {"client_id": "c2", "name": "Batch exporter", "app_type": "non_interactive", "client_metadata": {}}])
        if path == "/api/v2/client-grants":
            return J([{"audience": "https://api.acme.com", "scope": ["read:orders", "write:refunds"]}])
    # ---- Keycloak
    if host == "sso.acme.com":
        if path.endswith("/protocol/openid-connect/token"):
            return J({"access_token": "KC-TOKEN"})
        if auth != "Bearer KC-TOKEN":
            return J({}, 401)
        if path == "/admin/realms/acme/clients":
            return J([{"id": "k1", "clientId": "zz-test-kc-ops-agent", "name": "Ops agent", "serviceAccountsEnabled": True, "enabled": True, "attributes": {"astra-agent": "true"}, "defaultClientScopes": ["profile"], "optionalClientScopes": []},
                      {"id": "k2", "clientId": "web-ui", "serviceAccountsEnabled": False, "attributes": {}}])
        if path.endswith("/service-account-user"):
            return J({"id": "u1"})
        if path.endswith("/role-mappings"):
            return J({"realmMappings": [{"name": "manage-users"}], "clientMappings": {"realm-management": {"mappings": [{"name": "view-clients"}]}}})
    return J({"error": "not found"}, 404)


ip._TRANSPORT = httpx.MockTransport(respond)
ic.HOST_CHECK = lambda host: None


def ident(provider, cfg, rule, secret=SECRET):
    return ip.PROVIDERS[provider](cfg, secret).list_identities(rule)


ENTRA = {"tenant": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111", "cloud": "global"}
OKTA = {"domain": "https://acme.okta.com"}
AUTH0 = {"domain": "acme.eu.auth0.com", "client_id": "clientid12345"}
KC = {"base_url": "https://sso.acme.com", "realm": "acme", "client_id": "astra-reader"}


def _private_refused(api):
    ic.HOST_CHECK = ic._check_host
    try:
        r = api.post("/api/idps", json={"provider": "okta", "name": "zz-test-private", "config": {"domain": "https://127.0.0.1"}, "secret": "t", "rule": {"mode": "all", "value": ""}})
        return r.status_code == 422 and "private" in r.text
    finally:
        ic.HOST_CHECK = lambda host: None

# ── the providers, one by one
recs, notes = ident("entra", ENTRA, {"mode": "tag", "value": "astra-agent"})
by = {r["name"]: r for r in recs}
check("Entra: tagged service principals found, with the tag filter sent to Microsoft", set(by) == {"zz-test-payments-agent", "zz-test-claims-agent"} and any("tags/any" in c[3].get("$filter", "") and c[2].get("consistencylevel") == "eventual" for c in CALLS), list(by))
p1 = by["zz-test-payments-agent"]
check("Entra: owners, application and delegated permissions, role names resolved", p1["owners"] == ["Hana Sato"] and {(p["name"], p["kind"]) for p in p1["permissions"]} == {("Mail.Send", "application"), ("Directory.ReadWrite.All", "application"), ("User.Read", "delegated"), ("offline_access", "delegated")}, p1["permissions"])
check("Entra: a managed identity is recognised", by["zz-test-claims-agent"]["kind"] == "managed-identity")
check("Entra: the secret value is never in the result, only dates", SECRET not in json.dumps(recs) and "ENTRA-TOKEN" not in json.dumps(recs) and p1["credentials"][0]["ends"])
for bad in ["x') or (1 eq 1", "a;b", "x" * 101, ""]:
    try:
        ident("entra", ENTRA, {"mode": "tag", "value": bad})
        check(f"Entra: an unsafe filter value is refused ({bad[:12]!r})", False)
    except ip.IdpError:
        check(f"Entra: an unsafe filter value is refused ({bad[:12]!r})", True)
try:
    ip.PROVIDERS["entra"](ENTRA, "wrong").verify()
    check("Entra: wrong credentials are refused in words", False)
except ip.IdpError as e:
    check("Entra: wrong credentials are refused in words", "refused the credentials" in str(e) and "wrong" not in str(e), e)

recs, _ = ident("okta", OKTA, {"mode": "group", "value": "AI-Agents"}, "OKTA-TOKEN")
names = {r["name"] for r in recs}
check("Okta: apps of the group, followed across pages, only OAuth service apps", names == {"zz-test-okta-billing-agent", "zz-test-okta-ledger-agent"}, names)
o1 = next(r for r in recs if r["name"] == "zz-test-okta-billing-agent")
check("Okta: active grants become permissions, revoked ones do not; secrets are dates only", {p["name"] for p in o1["permissions"]} == {"okta.users.read", "okta.apps.manage"} and len(o1["credentials"]) == 2 and "OKTA-TOKEN" not in json.dumps(recs))
recs2, _ = ident("okta", OKTA, {"mode": "name_prefix", "value": "agent-"}, "OKTA-TOKEN")
check("Okta: label prefix", [r["name"] for r in recs2] == ["agent-one"])
try:
    ident("okta", OKTA, {"mode": "group", "value": "No-Such"}, "OKTA-TOKEN")
    check("Okta: an unknown group is said so", False)
except ip.IdpError as e:
    check("Okta: an unknown group is said so", "No group named" in str(e))
for d in ["http://acme.okta.com", "https://acme.okta.com/path", "acme.okta.com", "https://a b.com"]:
    try:
        ip.Okta.check_config({"domain": d})
        check(f"Okta: address refused {d!r}", False)
    except ip.IdpError:
        check(f"Okta: address refused {d!r}", True)

recs, _ = ident("auth0", AUTH0, {"mode": "metadata", "value": "astra-agent=true"})
check("Auth0: clients with the metadata, scopes from the grants, owner from metadata", [r["name"] for r in recs] == ["zz-test-a0-refund-agent"] and recs[0]["owners"] == ["Pat Lee"] and {p["name"] for p in recs[0]["permissions"]} == {"read:orders", "write:refunds"}, recs)
recs, _ = ident("keycloak", KC, {"mode": "attribute", "value": "astra-agent=true"})
check("Keycloak: service-account clients with the attribute, roles and scopes", [r["name"] for r in recs] == ["zz-test-kc-ops-agent"] and {p["name"] for p in recs[0]["permissions"]} == {"profile", "manage-users", "view-clients"}, recs)

# ── safety in the transport
ip._TRANSPORT = httpx.MockTransport(lambda r: httpx.Response(302, headers={"location": "https://evil.example/"}))
try:
    ip.Okta(OKTA, "t").verify()
    check("a redirect is not followed", False)
except ip.IdpError as e:
    check("a redirect is not followed", "redirect" in str(e))
ip._TRANSPORT = httpx.MockTransport(lambda r: httpx.Response(200, json=[{"id": "a1", "label": "x", "signOnMode": "OPENID_CONNECT", "settings": {"oauthClient": {"application_type": "service"}}}], headers={"link": '<https://evil.example/api/v1/apps?after=1>; rel="next"'}))
try:
    ip.Okta(OKTA, "t").list_identities({"mode": "all", "value": ""})
    check("a next-page address on another host is refused", False)
except ip.IdpError as e:
    check("a next-page address on another host is refused", "another host" in str(e))
ip._TRANSPORT = httpx.MockTransport(lambda r: httpx.Response(403, json={}))
try:
    ip.Okta(OKTA, "t").verify()
    check("a missing permission says what to do", False)
except ip.IdpError as e:
    check("a missing permission says what to do", "lack a permission" in str(e))
ip._TRANSPORT = httpx.MockTransport(respond)

# ── turning an identity into an agent proposal
a1 = im.to_agent(p1)
m = a1["manifest"]
tools = {t["name"]: t["write"] for t in m["tools"]}
check("permissions become tools; write and read told apart", tools.get("Microsoft Graph:Mail.Send") is True and tools.get("User.Read") is False and tools.get("Microsoft Graph:Directory.ReadWrite.All") is True, tools)
check("privileged permissions are flagged", "Microsoft Graph:Directory.ReadWrite.All" in a1["privileged"] and any("Privileged or tenant-wide" in w for w in m["warnings"]))
check("owner and goal come from the identity; the framework says where it came from", m["owner"] == "Hana Sato" and m["goal"].startswith("Pays approved supplier invoices") and a1["framework"] == "Microsoft Entra ID identity")
check("hygiene: a secret expiring soon is reported", any("expires in" in h for h in a1["hygiene"]), a1["hygiene"])
a2 = im.to_agent(by["zz-test-claims-agent"])
check("hygiene: no owner is reported", any("owner" in h for h in a2["hygiene"]))
old = {"provider": "okta", "external_id": "x", "name": "old-secret-agent", "description": "", "kind": "oauth-service-app", "enabled": False, "owners": ["a"], "permissions": [], "tags": [],
       "credentials": [{"kind": "secret", "created": iso(NOW - timedelta(days=400)), "ends": None, "active": True}, {"kind": "secret", "created": iso(NOW - timedelta(days=3)), "ends": None, "active": True},
                       {"kind": "certificate", "created": iso(NOW - timedelta(days=900)), "ends": iso(NOW - timedelta(days=2)), "label": "old"}], "notes": [], "last_sign_in": None}
hy = im.hygiene(old)
check("hygiene: disabled, an old secret, two active secrets and an expired certificate", len(hy) == 4 and any("disabled" in h for h in hy) and any("days old" in h for h in hy) and any("active at the same time" in h for h in hy) and any("expired" in h for h in hy), hy)
many = {**old, "permissions": [{"name": f"Thing.Read{i}", "resource": "R", "kind": "application"} for i in range(60)] + [{"name": "Directory.ReadWrite.All", "resource": "R", "kind": "application"}]}
am = im.to_agent(many)
check("more permissions than the model holds: the privileged one is kept, a warning says so", len(am["manifest"]["tools"]) == 40 and any("Directory.ReadWrite.All" in t["name"] for t in am["manifest"]["tools"]) and any("more permissions" in w for w in am["manifest"]["warnings"]))
f1 = im.fingerprint(p1)
check("a refreshed credential does not change the fingerprint, an added permission does", im.fingerprint({**p1, "credentials": []}) == f1 and im.fingerprint({**p1, "permissions": p1["permissions"] + [{"name": "Files.ReadWrite.All", "resource": "Microsoft Graph", "kind": "application"}]}) != f1)

# ── the connector against the database
NAMES = ["zz-test-payments-agent", "zz-test-claims-agent", "zz-test-okta-billing-agent", "zz-test-okta-ledger-agent", "zz-test-a0-refund-agent", "zz-test-kc-ops-agent"]
try:
    with authed_client() as api, authed_client("auditor") as aud:
        caps = api.get("/api/idps/capabilities").json()
        check("capabilities list the four providers with their fields and tag rules", {p["id"] for p in caps["providers"]} == {"entra", "okta", "auth0", "keycloak"} and caps["secrets_ready"] is True and all(p["modes"] and p["fields"] for p in caps["providers"]))
        body = {"provider": "entra", "name": "zz-test-entra", "config": ENTRA, "secret": SECRET, "rule": {"mode": "tag", "value": "astra-agent"}}
        check("an auditor cannot connect", aud.post("/api/idps", json=body).status_code == 403 and aud.get("/api/idps").status_code == 200)
        check("wrong credentials are refused with a reason and nothing is stored", api.post("/api/idps", json={**body, "secret": "wrong"}).status_code == 422 and api.get("/api/idps").json() == [])
        check("a rule that needs a value must have one", api.post("/api/idps", json={**body, "rule": {"mode": "tag", "value": ""}}).status_code == 422)
        check("an unknown tag mode is refused", api.post("/api/idps", json={**body, "rule": {"mode": "magic", "value": "x"}}).status_code == 422)
        check("a private address is refused for a self-hosted server", _private_refused(api))
        os.environ["ASTRA_SECRET_KEY"], saved = "", os.environ["ASTRA_SECRET_KEY"]
        r = api.post("/api/idps", json=body)
        os.environ["ASTRA_SECRET_KEY"] = saved
        check("without ASTRA_SECRET_KEY it refuses to store a credential, and says how to fix it", r.status_code == 422 and "ASTRA_SECRET_KEY" in r.text, r.text)
        r = api.post("/api/idps", json=body)
        check("connect Entra ID", r.status_code == 201 and r.json()["account"] == "Contoso", r.text)
        eid = r.json()["id"]
        check("the secret is never returned, and is stored encrypted", SECRET not in json.dumps(api.get("/api/idps").json()) and SECRET not in api.get(f"/api/idps/{eid}").text)
        with SessionLocal() as s:
            row = s.get(IdpConnection, __import__("uuid").UUID(eid))
            check("stored encrypted", SECRET not in row.secret_enc and SECRET not in json.dumps(row.config))
        check("the same name twice is refused", api.post("/api/idps", json=body).status_code == 409)

        sc = api.post(f"/api/idps/{eid}/scan")
        check("scan", sc.status_code == 200, sc.text)
        scan = sc.json()
        ag = {a["key"]: a for a in scan["agents"]}
        check("both tagged identities found, new, with counts, privileged and hygiene", set(ag) == {"zz-test-payments-agent", "zz-test-claims-agent"} and all(a["status"] == "new" for a in ag.values())
              and ag["zz-test-payments-agent"]["counts"]["privileged"] == 1 and ag["zz-test-claims-agent"]["counts"]["privileged"] == 1 and ag["zz-test-payments-agent"]["hygiene"] and scan["stats"]["with_privileged"] == 2, scan["stats"])
        check("the scan list does not carry whole manifests or credentials", all("manifest" not in a for a in scan["agents"]) and SECRET not in json.dumps(scan))
        pv = api.get(f"/api/idps/{eid}/agents/zz-test-payments-agent")
        check("preview: the model, the threat analysis, and what import would do", pv.status_code == 200 and pv.json()["existing"]["will"] == "create" and pv.json()["analysis"] and pv.json()["source"]["provider"] == "Microsoft Entra ID", pv.text[:200])

        imp = api.post(f"/api/idps/{eid}/import", json={"agents": ["zz-test-payments-agent", "nope"]}).json()["results"]
        res = {x["key"]: x for x in imp}
        check("import creates a draft; an unknown identity is reported, not fatal", res["zz-test-payments-agent"]["ok"] and res["zz-test-payments-agent"]["outcome"] == "created" and not res["nope"]["ok"], imp)
        ag_row = next(x for x in api.get("/api/agents").json() if x["agent_key"] == "zz-test-payments-agent")
        check("the agent has its owner from the identity, so it waits to be ratified, and its framework", ag_row["owner"] == "Hana Sato" and ag_row["status"] == "TO_RATIFY" and ag_row["framework"] == "Microsoft Entra ID identity", ag_row)
        with SessionLocal() as s:
            d = s.query(Design).filter(Design.name == "zz-test-payments-agent").one()
            prov = d.document["provenance"]
            check("provenance names the provider and says it was not verified against code", prov["source"] == "identity-provider" and prov["provider"] == "Microsoft Entra ID" and "not verified" in prov["label"] and SECRET not in json.dumps(d.document))
        st = {x["key"]: x["status"] for x in api.get(f"/api/idps/{eid}/scan").json()["agents"]}
        check("after import it is unchanged, the other still new", st == {"zz-test-payments-agent": "unchanged", "zz-test-claims-agent": "new"}, st)

        # an added permission is the change that matters
        ORIG = respond
        def with_extra(request):
            r = ORIG(request)
            if request.url.path == "/v1.0/servicePrincipals/graph":
                d = r.json()
                d["appRoles"].append({"id": "r9", "value": "Files.ReadWrite.All"})
                return httpx.Response(200, json=d)
            if request.url.path == "/v1.0/servicePrincipals/sp1/appRoleAssignments":
                d = r.json()
                d["value"].append({"resourceId": "graph", "appRoleId": "r9", "resourceDisplayName": "Microsoft Graph"})
                return httpx.Response(200, json=d)
            return r
        ip._TRANSPORT = httpx.MockTransport(with_extra)
        st = {x["key"]: x["status"] for x in api.post(f"/api/idps/{eid}/scan").json()["agents"]}
        check("an added permission marks the agent changed", st["zz-test-payments-agent"] == "changed", st)
        again = api.post(f"/api/idps/{eid}/import", json={"agents": ["zz-test-payments-agent"]}).json()["results"][0]
        with SessionLocal() as s:
            d = s.query(Design).filter(Design.name == "zz-test-payments-agent").one()
            tools = {n["name"] for n in d.document["nodes"] if n["type"] == "tool"}
        check("importing it updates the draft with the new permission", again["ok"] and again["outcome"] == "updated" and "Microsoft Graph:Files.ReadWrite.All" in tools, (again, tools))
        ip._TRANSPORT = httpx.MockTransport(respond)

        # an agent that is already known keeps its design: the identity's permissions are merged in
        from agent_import import ImportRequest, import_agent
        with SessionLocal() as s:
            from auth import AuthUser
            import uuid
            import_agent(ImportRequest(content="agent: zz-test-claims-agent\nowner: Platform\ntools:\n  - name: erp.read\n    access: read\nmcp_servers:\n  - name: mcp://erp\n", filename="a.yaml"), s, AuthUser(id=uuid.uuid4(), email="x@example.test", name="Test", role="admin"))
        st = {x["key"]: x["status"] for x in api.get(f"/api/idps/{eid}/scan").json()["agents"]}
        check("an agent already in the inventory is shown as such", st["zz-test-claims-agent"] == "exists", st)
        pv = api.get(f"/api/idps/{eid}/agents/zz-test-claims-agent").json()
        check("preview says the identity will be merged into the existing design", pv["existing"]["merges"] is True and any("erp.read" == n["name"] for n in pv["nodes"]) and any("User.Read.All" in n["name"] for n in pv["nodes"]), [n["name"] for n in pv["nodes"]])
        r = api.post(f"/api/idps/{eid}/import", json={"agents": ["zz-test-claims-agent"]}).json()["results"][0]
        with SessionLocal() as s:
            d = s.query(Design).filter(Design.name == "zz-test-claims-agent").one()
            names_ = {(n["type"], n["name"]) for n in d.document["nodes"]}
        check("the merge keeps what was there and adds the permissions", r["ok"] and r["merged"] is True and ("tool", "erp.read") in names_ and ("mcp", "mcp://erp") in names_ and ("tool", "Microsoft Graph:User.Read.All") in names_, (r, names_))

        # the other providers through the connector
        oid = api.post("/api/idps", json={"provider": "okta", "name": "zz-test-okta", "config": OKTA, "secret": "OKTA-TOKEN", "rule": {"mode": "group", "value": "AI-Agents"}}).json()["id"]
        osc = api.post(f"/api/idps/{oid}/scan").json()
        check("Okta through the connector: agents found, secrets old, no owner recorded", {a["key"] for a in osc["agents"]} == {"zz-test-okta-billing-agent", "zz-test-okta-ledger-agent"} and any("days old" in h for a in osc["agents"] for h in a["hygiene"]) and any("owner" in h for a in osc["agents"] for h in a["hygiene"]), osc["stats"])
        aid = api.post("/api/idps", json={"provider": "auth0", "name": "zz-test-auth0", "config": AUTH0, "secret": SECRET, "rule": {"mode": "metadata", "value": "astra-agent=true"}}).json()["id"]
        check("Auth0 through the connector", [a["key"] for a in api.post(f"/api/idps/{aid}/scan").json()["agents"]] == ["zz-test-a0-refund-agent"])
        kid = api.post("/api/idps", json={"provider": "keycloak", "name": "zz-test-kc", "config": KC, "secret": SECRET, "rule": {"mode": "attribute", "value": "astra-agent=true"}}).json()["id"]
        check("Keycloak through the connector", [a["key"] for a in api.post(f"/api/idps/{kid}/scan").json()["agents"]] == ["zz-test-kc-ops-agent"])

        # settings
        check("the tag rule can be changed", api.patch(f"/api/idps/{eid}", json={"rule": {"mode": "tag", "value": "zz-no-such-tag"}}).json()["rule"]["value"] == "zz-no-such-tag")
        sc2 = api.post(f"/api/idps/{eid}/scan").json()
        check("a rule that matches nothing finds nothing, and an imported agent that dropped out is flagged", sc2["agents"] == [] and "zz-test-payments-agent" in sc2["removed"], sc2["removed"])
        check("a new secret is checked before it replaces the old one", api.patch(f"/api/idps/{eid}", json={"secret": "wrong"}).status_code == 422 and api.patch(f"/api/idps/{eid}", json={"secret": SECRET}).status_code == 200)
        ip._TRANSPORT = httpx.MockTransport(lambda r: httpx.Response(401, json={}))
        bad = api.post(f"/api/idps/{eid}/scan")
        check("an identity provider that stops answering is a clear error, and the connection says so", bad.status_code == 502 and api.get(f"/api/idps/{eid}").json()["status"] == "ERROR" and api.get(f"/api/idps/{eid}").json()["last_error"], bad.text)
        ip._TRANSPORT = httpx.MockTransport(respond)
        check("disconnecting leaves the agents and drops the import records", api.delete(f"/api/idps/{eid}").status_code == 204)
        with SessionLocal() as s:
            check("the agent stayed, its import record went", s.query(Agent).filter(Agent.agent_key == "zz-test-payments-agent").count() == 1 and s.query(IdpImport).filter(IdpImport.agent_key == "zz-test-payments-agent").count() == 0)
finally:
    cleanup(*NAMES)
    with SessionLocal() as s:
        for c in s.query(IdpConnection).filter(IdpConnection.name.like("zz-test-%")).all():
            s.delete(c)
        s.commit()

sys.exit(1 if fails else 0)
