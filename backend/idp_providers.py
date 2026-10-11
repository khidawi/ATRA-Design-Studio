"""
Read-only clients for identity providers: Microsoft Entra ID, Okta, Auth0 and Keycloak.

Each one answers the same two questions for the identity connector (idp_connect.py): "can I sign in with these credentials?" and "which
service accounts and OAuth clients are tagged as AI agents, and what are they allowed to do?". The answer is a list of normalised identity
records; nothing else leaves this module. They only ever call GET endpoints (plus the token request each provider needs), never create,
change or delete anything in the identity provider, and ask for the narrowest read permission each one offers.

What a record carries: a name and description, whether it is enabled, its owners where the provider has them, the permissions or scopes it
holds, the age and expiry of its credentials (never the credentials themselves), and the tags that marked it as an agent.

Safety rules that apply to every provider: https only; redirects are never followed (a redirect with credentials attached is how a request is
steered somewhere else); every request has a time limit and a size limit; a "next page" address the provider returns is only followed if it is on
the same host; filter values typed by a person are checked before they go into a query; a credential never appears in an error message.
"""
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

import httpx

TIMEOUT_SECONDS = 20.0
MAX_BODY_BYTES = 5_000_000
MAX_IDENTITIES = 500
MAX_PAGES = 60
VALUE_RX = re.compile(r"^[A-Za-z0-9 ._:@/#+=-]{1,100}$")
_TRANSPORT: Optional[httpx.BaseTransport] = None              # tests put a fake transport here; production leaves it None


class IdpError(Exception):
    """The identity provider could not be read; the message is safe to show and says what to do."""


def safe_value(value: str, what: str) -> str:
    value = (value or "").strip()
    if not VALUE_RX.match(value):
        raise IdpError(f"The {what} may contain letters, digits, spaces and . _ : @ / # + = - only, up to 100 characters.")
    return value


class _Http:
    def __init__(self, secrets: Tuple[str, ...] = ()):
        self.secrets = tuple(s for s in secrets if s)
        self.c = httpx.Client(transport=_TRANSPORT, timeout=TIMEOUT_SECONDS, follow_redirects=False, headers={"User-Agent": "ASTRA-identity-connector", "Accept": "application/json"})

    def _scrub(self, text: str) -> str:
        for s in self.secrets:
            text = text.replace(s, "***")
        return text

    def request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        if urlparse(url).scheme != "https":
            raise IdpError("Only https addresses are used for an identity provider.")
        try:
            r = self.c.request(method, url, **kw)
        except httpx.TimeoutException:
            raise IdpError("The identity provider did not answer in time.")
        except httpx.HTTPError:
            raise IdpError("The identity provider could not be reached from the platform.")
        if 300 <= r.status_code < 400:
            raise IdpError("The identity provider answered with a redirect, which is not followed. Check the address (a custom domain, the right region).")
        if r.status_code == 401:
            raise IdpError("The identity provider refused the credentials. Check the client id, the secret or token, and that they have not expired.")
        if r.status_code == 403:
            raise IdpError("The credentials are valid but lack a permission this connector needs (read access to applications or clients). See the permissions listed for this provider.")
        if r.status_code == 404:
            raise IdpError("The identity provider does not know that address. Check the tenant, domain or realm.")
        if r.status_code == 429:
            raise IdpError("The identity provider is rate limiting this connection. Try again in a few minutes.")
        if r.status_code >= 500:
            raise IdpError("The identity provider reported an error. Try again later.")
        if r.status_code >= 400:
            raise IdpError(self._scrub(f"The identity provider refused the request ({r.status_code})."))
        if len(r.content) > MAX_BODY_BYTES:
            raise IdpError("The identity provider's answer was larger than the limit.")
        return r

    def json(self, method: str, url: str, **kw: Any) -> Any:
        r = self.request(method, url, **kw)
        try:
            return r.json()
        except ValueError:
            raise IdpError("The identity provider's answer could not be read.")


def _record(provider: str, ext_id: str, name: str, **kw: Any) -> Dict[str, Any]:
    return {"provider": provider, "external_id": str(ext_id), "name": (name or "").strip()[:200], "description": (kw.get("description") or "")[:500], "kind": kw.get("kind", "service-account"),
            "enabled": kw.get("enabled", True), "owners": [o for o in kw.get("owners", []) if o][:10], "permissions": kw.get("permissions", []), "credentials": kw.get("credentials", []),
            "tags": kw.get("tags", []), "last_sign_in": kw.get("last_sign_in"), "notes": kw.get("notes", [])}


def _same_host(url: str, base: str) -> bool:
    return urlparse(url).netloc.lower() == urlparse(base).netloc.lower() and urlparse(url).scheme == "https"


class Provider:
    id = ""
    label = ""
    fields: List[Dict[str, Any]] = []                       # what a person fills in to connect
    modes: List[Dict[str, Any]] = []                        # how an identity is marked as an agent
    permissions_help = ""

    def __init__(self, cfg: Dict[str, str], secret: str):
        self.cfg, self.secret = cfg, secret
        self.http = _Http((secret,))

    def verify(self) -> str:
        raise NotImplementedError

    def list_identities(self, rule: Dict[str, Any], limit: int = MAX_IDENTITIES) -> Tuple[List[Dict[str, Any]], List[str]]:
        raise NotImplementedError

    @staticmethod
    def check_config(cfg: Dict[str, str]) -> Dict[str, str]:
        return cfg


# ── Microsoft Entra ID (Graph) ──────────────────────────────────────────────

class Entra(Provider):
    id, label = "entra", "Microsoft Entra ID"
    fields = [{"id": "tenant", "label": "Tenant ID or domain", "placeholder": "contoso.onmicrosoft.com", "required": True}, {"id": "client_id", "label": "Application (client) ID", "placeholder": "00000000-0000-0000-0000-000000000000", "required": True},
              {"id": "cloud", "label": "Cloud", "options": [["global", "Microsoft 365 / Azure (global)"], ["usgov", "US Government"], ["china", "China (21Vianet)"]], "required": False}]
    modes = [{"id": "tag", "label": "Service principal tag", "value": True, "help": "The tag is set on the enterprise application (Properties → Tags)."},
             {"id": "name_prefix", "label": "Name starts with", "value": True, "help": "For example agent-"}, {"id": "all", "label": "Every service principal", "value": False, "help": "Large tenants have thousands: use a tag where you can."}]
    permissions_help = "Register an application with the Microsoft Graph application permissions Application.Read.All and Directory.Read.All (admin consent), create a client secret, and enter its values."
    CLOUDS = {"global": ("https://login.microsoftonline.com", "https://graph.microsoft.com"), "usgov": ("https://login.microsoftonline.us", "https://graph.microsoft.us"), "china": ("https://login.chinacloudapi.cn", "https://microsoftgraph.chinacloudapi.cn")}

    @staticmethod
    def check_config(cfg: Dict[str, str]) -> Dict[str, str]:
        tenant, cid, cloud = (cfg.get("tenant") or "").strip(), (cfg.get("client_id") or "").strip(), (cfg.get("cloud") or "global").strip()
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]{2,120}$", tenant):
            raise IdpError("Enter the tenant as its ID or its domain, for example contoso.onmicrosoft.com.")
        if not re.match(r"^[0-9a-fA-F-]{36}$", cid):
            raise IdpError("The client ID is a GUID like 00000000-0000-0000-0000-000000000000.")
        if cloud not in Entra.CLOUDS:
            raise IdpError("Choose the cloud the tenant is in.")
        return {"tenant": tenant, "client_id": cid, "cloud": cloud}

    def _urls(self) -> Tuple[str, str]:
        return self.CLOUDS[self.cfg.get("cloud", "global")]

    def _auth(self) -> Dict[str, str]:
        login, graph = self._urls()
        d = self.http.json("POST", f"{login}/{quote(self.cfg['tenant'])}/oauth2/v2.0/token", data={"client_id": self.cfg["client_id"], "client_secret": self.secret, "scope": f"{graph}/.default", "grant_type": "client_credentials"})
        if not d.get("access_token"):
            raise IdpError("Microsoft did not return an access token.")
        return {"Authorization": "Bearer " + d["access_token"]}

    def verify(self) -> str:
        _, graph = self._urls()
        d = self.http.json("GET", f"{graph}/v1.0/organization", params={"$select": "displayName"}, headers=self._auth())
        return ((d.get("value") or [{}])[0].get("displayName")) or self.cfg["tenant"]

    def _pages(self, url: str, params: Dict[str, str], headers: Dict[str, str], cap: int) -> List[Dict[str, Any]]:
        _, graph = self._urls()
        out: List[Dict[str, Any]] = []
        for _ in range(MAX_PAGES):
            d = self.http.json("GET", url, params=params, headers=headers)
            out += d.get("value") or []
            nxt = d.get("@odata.nextLink")
            if not nxt or len(out) >= cap:
                break
            if not _same_host(nxt, graph):
                raise IdpError("The identity provider pointed at another host for the next page, so it was not followed.")
            url, params = nxt, None                    # the next-page address already carries its own query
        return out[:cap]

    def list_identities(self, rule: Dict[str, Any], limit: int = MAX_IDENTITIES) -> Tuple[List[Dict[str, Any]], List[str]]:
        _, graph = self._urls()
        hdr = self._auth()
        params = {"$select": "id,appId,displayName,description,tags,servicePrincipalType,accountEnabled,passwordCredentials,keyCredentials", "$top": "100"}
        notes: List[str] = []
        mode, value = rule.get("mode", "tag"), rule.get("value", "")
        if mode == "tag":
            params["$filter"] = "tags/any(t:t eq '%s')" % safe_value(value, "tag").replace("'", "''")
            params["$count"] = "true"
            hdr = {**hdr, "ConsistencyLevel": "eventual"}
        elif mode == "name_prefix":
            params["$filter"] = "startswith(displayName,'%s')" % safe_value(value, "name prefix").replace("'", "''")
        elif mode != "all":
            raise IdpError("That way of marking agents is not offered for Entra ID.")
        sps = self._pages(f"{graph}/v1.0/servicePrincipals", params, hdr, limit + 1)
        if len(sps) > limit:
            sps = sps[:limit]
            notes.append(f"More than {limit} service principals matched; only the first {limit} were read. Narrow the rule.")
        role_cache: Dict[str, Dict[str, str]] = {}
        out = []
        for sp in sps:
            sid = sp["id"]
            owners = [(o.get("displayName") or o.get("userPrincipalName") or o.get("mail") or "") for o in self._safe_pages(f"{graph}/v1.0/servicePrincipals/{sid}/owners", {"$select": "displayName,userPrincipalName,mail", "$top": "20"}, hdr, notes, sp)]
            perms = []
            for a in self._safe_pages(f"{graph}/v1.0/servicePrincipals/{sid}/appRoleAssignments", {"$top": "100"}, hdr, notes, sp):
                rid = a.get("resourceId")
                if rid and rid not in role_cache:
                    try:
                        r = self.http.json("GET", f"{graph}/v1.0/servicePrincipals/{rid}", params={"$select": "displayName,appRoles"}, headers=hdr)
                        role_cache[rid] = {x["id"]: x.get("value") or x.get("displayName") or x["id"] for x in r.get("appRoles") or []}
                    except IdpError:
                        role_cache[rid] = {}
                perms.append({"name": role_cache.get(rid, {}).get(a.get("appRoleId"), a.get("appRoleId") or "role"), "resource": a.get("resourceDisplayName") or "", "kind": "application"})
            for g in self._safe_pages(f"{graph}/v1.0/servicePrincipals/{sid}/oauth2PermissionGrants", {"$top": "100"}, hdr, notes, sp):
                for sc in (g.get("scope") or "").split():
                    perms.append({"name": sc, "resource": "", "kind": "delegated"})
            creds = [{"kind": "secret", "created": c.get("startDateTime"), "ends": c.get("endDateTime"), "label": c.get("displayName") or ""} for c in sp.get("passwordCredentials") or []]
            creds += [{"kind": "certificate", "created": c.get("startDateTime"), "ends": c.get("endDateTime"), "label": c.get("displayName") or ""} for c in sp.get("keyCredentials") or []]
            out.append(_record("entra", sid, sp.get("displayName"), description=sp.get("description"), kind="managed-identity" if sp.get("servicePrincipalType") == "ManagedIdentity" else "service-principal",
                               enabled=sp.get("accountEnabled", True), owners=owners, permissions=perms, credentials=creds, tags=sp.get("tags") or []))
        return out, notes

    def _safe_pages(self, url: str, params: Dict[str, str], hdr: Dict[str, str], notes: List[str], sp: Dict[str, Any]) -> List[Dict[str, Any]]:
        try:
            return self._pages(url, params, hdr, 500)
        except IdpError as e:
            note = f"{sp.get('displayName')}: part of its details could not be read ({e})"
            if note not in notes:
                notes.append(note)
            return []


# ── Okta ────────────────────────────────────────────────────────────────────

class Okta(Provider):
    id, label = "okta", "Okta"
    fields = [{"id": "domain", "label": "Okta address", "placeholder": "https://acme.okta.com", "required": True}]
    modes = [{"id": "group", "label": "Member of the group", "value": True, "help": "Assign the agent's OAuth service app to a group such as AI-Agents."},
             {"id": "name_prefix", "label": "App label starts with", "value": True, "help": "For example agent-"},
             {"id": "description", "label": "Description contains", "value": True, "help": "For example [astra-agent]"}, {"id": "all", "label": "Every OAuth service app", "value": False, "help": ""}]
    permissions_help = "Create an API token under a read-only administrator (Security → API → Tokens). The connector only reads apps, grants, groups and credentials metadata."

    @staticmethod
    def check_config(cfg: Dict[str, str]) -> Dict[str, str]:
        d = (cfg.get("domain") or "").strip().rstrip("/")
        if not d.startswith("https://") or not re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?$", d):
            raise IdpError("Enter the Okta address as https://your-company.okta.com (no path).")
        return {"domain": d}

    def _h(self) -> Dict[str, str]:
        return {"Authorization": "SSWS " + self.secret}

    def verify(self) -> str:
        d = self.http.json("GET", self.cfg["domain"] + "/api/v1/org", headers=self._h())
        return d.get("companyName") or d.get("subdomain") or self.cfg["domain"]

    def _pages(self, url: str, params: Dict[str, str], cap: int) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for _ in range(MAX_PAGES):
            r = self.http.request("GET", url, params=params, headers=self._h())
            try:
                out += r.json()
            except ValueError:
                raise IdpError("The identity provider's answer could not be read.")
            nxt = r.links.get("next", {}).get("url")
            if not nxt or len(out) >= cap:
                break
            if not _same_host(nxt, self.cfg["domain"]):
                raise IdpError("The identity provider pointed at another host for the next page, so it was not followed.")
            url, params = nxt, None                    # the next-page address already carries its own query
        return out[:cap]

    def list_identities(self, rule: Dict[str, Any], limit: int = MAX_IDENTITIES) -> Tuple[List[Dict[str, Any]], List[str]]:
        base = self.cfg["domain"]
        notes: List[str] = []
        mode, value = rule.get("mode", "group"), rule.get("value", "")
        if mode == "group":
            name = safe_value(value, "group name")
            groups = [g for g in self._pages(f"{base}/api/v1/groups", {"q": name, "limit": "20"}, 50) if (g.get("profile") or {}).get("name", "").lower() == name.lower()]
            if not groups:
                raise IdpError(f"No group named {name} was found in Okta.")
            apps = self._pages(f"{base}/api/v1/groups/{groups[0]['id']}/apps", {"limit": "200"}, limit + 1)
        else:
            params = {"limit": "200"}
            if mode == "name_prefix":
                params["q"] = safe_value(value, "name prefix")
            elif mode not in ("description", "all"):
                raise IdpError("That way of marking agents is not offered for Okta.")
            apps = self._pages(f"{base}/api/v1/apps", params, 5000)
        if mode == "name_prefix":
            apps = [a for a in apps if (a.get("label") or "").lower().startswith(value.strip().lower())]
        if mode == "description":
            v = value.strip().lower()
            apps = [a for a in apps if v in ((a.get("label") or "") + " " + ((a.get("settings") or {}).get("app") or {}).get("description", "") + " " + str((a.get("profile") or {}).get("description", ""))).lower()]
        out = []
        for a in apps:
            oc = (a.get("settings") or {}).get("oauthClient") or {}
            if a.get("signOnMode") != "OPENID_CONNECT" or not (oc.get("application_type") == "service" or "client_credentials" in (oc.get("grant_types") or [])):
                continue                                                      # only OAuth service apps are agents' identities
            if len(out) >= limit:
                notes.append(f"More than {limit} apps matched; only the first {limit} were read. Narrow the rule.")
                break
            aid = a["id"]
            perms, creds = [], []
            try:
                for g in self._pages(f"{base}/api/v1/apps/{aid}/grants", {"limit": "200"}, 500):
                    if g.get("status", "ACTIVE") == "ACTIVE":
                        perms.append({"name": g.get("scopeId") or "", "resource": g.get("issuer") or "Okta", "kind": "application"})
            except IdpError as e:
                notes.append(f"{a.get('label')}: its granted scopes could not be read ({e})")
            try:
                for s in self._pages(f"{base}/api/v1/apps/{aid}/credentials/secrets", {}, 20):
                    creds.append({"kind": "secret", "created": s.get("created"), "ends": None, "label": s.get("status") or "", "active": s.get("status", "ACTIVE") == "ACTIVE"})
            except IdpError:
                pass
            out.append(_record("okta", aid, a.get("label"), description=str((a.get("profile") or {}).get("description", "")), kind="oauth-service-app", enabled=a.get("status") == "ACTIVE",
                               owners=[], permissions=[p for p in perms if p["name"]], credentials=creds, tags=[value] if mode == "group" else [],
                               notes=["Okta does not record an owner for an app: assign one in ASTRA."]))
        return out, notes


# ── Auth0 ───────────────────────────────────────────────────────────────────

class Auth0(Provider):
    id, label = "auth0", "Auth0"
    fields = [{"id": "domain", "label": "Tenant domain", "placeholder": "acme.eu.auth0.com", "required": True}, {"id": "client_id", "label": "Machine-to-machine client ID", "placeholder": "", "required": True}]
    modes = [{"id": "metadata", "label": "Client metadata key = value", "value": True, "help": "Set on the client (Settings → Advanced → Metadata), for example astra-agent=true"},
             {"id": "name_prefix", "label": "Client name starts with", "value": True, "help": "For example agent-"}, {"id": "all", "label": "Every machine-to-machine client", "value": False, "help": ""}]
    permissions_help = "Authorise a machine-to-machine application for the Auth0 Management API with read:clients and read:client_grants only."

    @staticmethod
    def check_config(cfg: Dict[str, str]) -> Dict[str, str]:
        d = (cfg.get("domain") or "").strip().removeprefix("https://").rstrip("/")
        cid = (cfg.get("client_id") or "").strip()
        if not re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", d):
            raise IdpError("Enter the tenant domain, for example acme.eu.auth0.com.")
        if not re.match(r"^[A-Za-z0-9_-]{8,64}$", cid):
            raise IdpError("Enter the client ID of the machine-to-machine application.")
        return {"domain": d, "client_id": cid}

    def _auth(self) -> Dict[str, str]:
        d = self.cfg["domain"]
        t = self.http.json("POST", f"https://{d}/oauth/token", json={"client_id": self.cfg["client_id"], "client_secret": self.secret, "audience": f"https://{d}/api/v2/", "grant_type": "client_credentials"})
        if not t.get("access_token"):
            raise IdpError("Auth0 did not return an access token.")
        return {"Authorization": "Bearer " + t["access_token"]}

    def verify(self) -> str:
        self.http.json("GET", f"https://{self.cfg['domain']}/api/v2/clients", params={"per_page": "1", "fields": "client_id", "include_fields": "true"}, headers=self._auth())
        return self.cfg["domain"]

    def list_identities(self, rule: Dict[str, Any], limit: int = MAX_IDENTITIES) -> Tuple[List[Dict[str, Any]], List[str]]:
        d, hdr = self.cfg["domain"], self._auth()
        mode, value = rule.get("mode", "metadata"), rule.get("value", "")
        key = val = ""
        if mode == "metadata":
            key, _, val = safe_value(value, "metadata").partition("=")
            key, val = key.strip(), (val.strip() or "true")
        elif mode == "name_prefix":
            safe_value(value, "name prefix")
        elif mode != "all":
            raise IdpError("That way of marking agents is not offered for Auth0.")
        clients: List[Dict[str, Any]] = []
        for page in range(MAX_PAGES):
            batch = self.http.json("GET", f"https://{d}/api/v2/clients", params={"per_page": "100", "page": str(page), "app_type": "non_interactive", "fields": "client_id,name,description,app_type,client_metadata,grant_types", "include_fields": "true"}, headers=hdr)
            clients += batch if isinstance(batch, list) else []
            if len(batch) < 100:
                break
        notes: List[str] = []
        if mode == "metadata":
            clients = [c for c in clients if str((c.get("client_metadata") or {}).get(key, "")).lower() == val.lower()]
        elif mode == "name_prefix":
            clients = [c for c in clients if (c.get("name") or "").lower().startswith(value.strip().lower())]
        if len(clients) > limit:
            clients = clients[:limit]
            notes.append(f"More than {limit} clients matched; only the first {limit} were read. Narrow the rule.")
        out = []
        for c in clients:
            perms = []
            try:
                g = self.http.json("GET", f"https://{d}/api/v2/client-grants", params={"client_id": c["client_id"], "per_page": "100"}, headers=hdr)
                for grant in g if isinstance(g, list) else (g.get("client_grants") or []):
                    for sc in grant.get("scope") or []:
                        perms.append({"name": sc, "resource": grant.get("audience") or "", "kind": "application"})
            except IdpError as e:
                notes.append(f"{c.get('name')}: its grants could not be read ({e})")
            meta = c.get("client_metadata") or {}
            out.append(_record("auth0", c["client_id"], c.get("name"), description=c.get("description"), kind="machine-to-machine", enabled=True, owners=[meta.get("owner", "")], permissions=perms,
                               credentials=[], tags=[f"{key}={val}"] if mode == "metadata" else [],
                               notes=["Auth0 does not expose client secret expiry through the Management API."]))
        return out, notes


# ── Keycloak ────────────────────────────────────────────────────────────────

class Keycloak(Provider):
    id, label = "keycloak", "Keycloak"
    fields = [{"id": "base_url", "label": "Keycloak address", "placeholder": "https://sso.acme.com", "required": True}, {"id": "realm", "label": "Realm", "placeholder": "acme", "required": True}, {"id": "client_id", "label": "Service account client ID", "placeholder": "", "required": True}]
    modes = [{"id": "attribute", "label": "Client attribute key = value", "value": True, "help": "Set on the client (Advanced → Attributes), for example astra-agent=true"},
             {"id": "name_prefix", "label": "Client ID starts with", "value": True, "help": "For example agent-"}, {"id": "all", "label": "Every client with a service account", "value": False, "help": ""}]
    permissions_help = "Create a confidential client with a service account in the realm and give that account the view-clients and view-users roles of realm-management."

    @staticmethod
    def check_config(cfg: Dict[str, str]) -> Dict[str, str]:
        b, realm, cid = (cfg.get("base_url") or "").strip().rstrip("/"), (cfg.get("realm") or "").strip(), (cfg.get("client_id") or "").strip()
        if not re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._-]+)*$", b):
            raise IdpError("Enter the Keycloak address as https://sso.your-company.com.")
        if not re.match(r"^[A-Za-z0-9._-]{1,100}$", realm) or not re.match(r"^[A-Za-z0-9._:@-]{1,100}$", cid):
            raise IdpError("The realm and the client ID may contain letters, digits and . _ - only.")
        return {"base_url": b, "realm": realm, "client_id": cid}

    def _auth(self) -> Dict[str, str]:
        t = self.http.json("POST", f"{self.cfg['base_url']}/realms/{quote(self.cfg['realm'])}/protocol/openid-connect/token", data={"grant_type": "client_credentials", "client_id": self.cfg["client_id"], "client_secret": self.secret})
        if not t.get("access_token"):
            raise IdpError("Keycloak did not return an access token.")
        return {"Authorization": "Bearer " + t["access_token"]}

    def verify(self) -> str:
        self.http.json("GET", f"{self.cfg['base_url']}/admin/realms/{quote(self.cfg['realm'])}/clients", params={"first": "0", "max": "1"}, headers=self._auth())
        return self.cfg["realm"]

    def list_identities(self, rule: Dict[str, Any], limit: int = MAX_IDENTITIES) -> Tuple[List[Dict[str, Any]], List[str]]:
        admin, hdr = f"{self.cfg['base_url']}/admin/realms/{quote(self.cfg['realm'])}", self._auth()
        mode, value = rule.get("mode", "attribute"), rule.get("value", "")
        key = val = ""
        if mode == "attribute":
            key, _, val = safe_value(value, "attribute").partition("=")
            key, val = key.strip(), (val.strip() or "true")
        elif mode == "name_prefix":
            safe_value(value, "name prefix")
        elif mode != "all":
            raise IdpError("That way of marking agents is not offered for Keycloak.")
        clients: List[Dict[str, Any]] = []
        for page in range(MAX_PAGES):
            batch = self.http.json("GET", f"{admin}/clients", params={"first": str(page * 100), "max": "100"}, headers=hdr)
            clients += batch if isinstance(batch, list) else []
            if len(batch) < 100:
                break
        clients = [c for c in clients if c.get("serviceAccountsEnabled")]
        if mode == "attribute":
            clients = [c for c in clients if str((c.get("attributes") or {}).get(key, "")).lower() == val.lower()]
        elif mode == "name_prefix":
            clients = [c for c in clients if (c.get("clientId") or "").lower().startswith(value.strip().lower())]
        notes: List[str] = []
        if len(clients) > limit:
            clients = clients[:limit]
            notes.append(f"More than {limit} clients matched; only the first {limit} were read. Narrow the rule.")
        out = []
        for c in clients:
            perms = [{"name": s, "resource": "client scope", "kind": "application"} for s in (c.get("defaultClientScopes") or []) + (c.get("optionalClientScopes") or [])]
            try:
                u = self.http.json("GET", f"{admin}/clients/{c['id']}/service-account-user", headers=hdr)
                rm = self.http.json("GET", f"{admin}/users/{u['id']}/role-mappings", headers=hdr)
                perms += [{"name": r["name"], "resource": "realm", "kind": "application"} for r in rm.get("realmMappings") or []]
                for cid, m in (rm.get("clientMappings") or {}).items():
                    perms += [{"name": r["name"], "resource": cid, "kind": "application"} for r in m.get("mappings") or []]
            except (IdpError, KeyError):
                notes.append(f"{c.get('clientId')}: its service-account roles could not be read")
            attrs = c.get("attributes") or {}
            out.append(_record("keycloak", c["id"], c.get("clientId"), description=c.get("description") or c.get("name"), kind="service-account-client", enabled=c.get("enabled", True),
                               owners=[attrs.get("owner", "")], permissions=perms, credentials=[], tags=[f"{key}={val}"] if mode == "attribute" else [],
                               notes=["Keycloak does not expose client secret age through the Admin API."]))
        return out, notes


PROVIDERS: Dict[str, Callable[..., Provider]] = {"entra": Entra, "okta": Okta, "auth0": Auth0, "keycloak": Keycloak}


def describe() -> List[Dict[str, Any]]:
    return [{"id": p.id, "label": p.label, "fields": p.fields, "modes": p.modes, "permissions_help": p.permissions_help} for p in PROVIDERS.values()]


def parse_time(v: Any) -> Optional[datetime]:
    if not v:
        return None
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
