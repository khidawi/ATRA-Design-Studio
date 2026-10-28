"""
First-pass screening of a list of AI agents from their descriptions (Essex demo, Phase 1).

A public register of agents gives a name and a short description for each, and nothing about tools, data stores, approval steps or monitoring. The design-time
checks (agent_analysis.py, rcr.py) need those, so they cannot run on a description. What can be done on a description alone is a coarse screen: does it say the agent
touches decisions about people, vulnerable groups, sensitive data, or acts on its own? This is that screen, and it is deliberately plain:

  * every signal is a visible phrase in the description, with a weight and a reason, so a reviewer can see exactly why an agent was flagged;
  * mitigations (a person reviews it, no personal data, anonymised, internal only) lower the score, but only a little, because a description that says it is
    reviewed is a claim, not evidence;
  * the output says what the description does not tell us, which is exactly what a structured intake or the full design check would then ask.

It is not a risk assessment and says so. Its use is (a) to rank a long list so people look at the right ones first, (b) to compare with a screening done by hand
(agreement and Cohen's kappa), and (c) to pick a sample for a deeper look.

Nothing is stored by the screen itself. Importing a chosen set (POST /api/agents/triage/import) is a separate, explicit step: it adds those agents to the inventory
with what the screen found, and, if asked, a draft design in the Design studio for each, so they can be opened, completed, checked, compared and ratified like any
other agent. It recomputes the screen on the server rather than trusting what a page sends.
"""
import csv
import io
import random
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_registry import agent_key
from auth import AuthUser, current_user
from db.models import Agent, Design, RcrProfile
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/agents", tags=["agents"])

MAX_ROWS = 5000
HIGH_AT, MODERATE_AT = 6, 3

# (key, weight, reason, regular expression over the lower-cased text). Weights are judgement-assigned, like the RCR weights, and not calibrated.
SIGNALS: List[Tuple[str, int, str, str]] = [
    ("decision", 3, "Influences a decision about a person (assessment, eligibility, triage, prediction)",
     r"\b(eligib\w*|assess\w*|determin\w+ (?:whether|if)|decid\w*|decision\w*|approv\w+ or (?:refus|reject|den)\w*|triag\w*|prioriti[sz]\w*|risk scor\w*|scor(?:e|es|ing|er) (?:\w+ )?(?:applications?|applicants?|claims?|bids?|candidates?|cases?|referrals?|people|residents?)|risk of|predict\w*|likelihood|recommend\w* (?:support|service|placement|care))"),
    ("vulnerable", 3, "Concerns children, vulnerable adults or care",
     r"\b(child\w*|young people|safeguard\w*|social care|adult care|care plan\w*|care needs|care home\w*|looked[- ]after|foster\w*|adopt\w*|vulnerab\w*|older (?:people|adults)|disabilit\w*|disabled|special educational|send\b|mental health|homeless\w*|domestic abuse|carer\w*)"),
    ("sensitive", 2, "Uses sensitive or special category data",
     r"\b((?<!environmental )health\w*|medical\w*|clinical\w*|diagnos\w*|ethnic\w*|religio\w*|biometric\w*|criminal\w*|offend\w*|case notes?|case records?|care records?|disclosure|immigration|sexual\w*|trade union)"),
    ("personal", 1, "Handles personal data about residents, service users or staff",
     r"\b(personal data|resident\w*|citizen\w*|service users?|client\w*|pupil\w*|student\w*|employee\w*|staff records?|applicant\w*|claimant\w*|tenant\w*|household\w*|names?\b|addresses|email addresses)"),
    ("autonomous", 2, "Acts on its own (updates records, sends messages, triggers actions)",
     r"\b(automatic\w*|autonomous\w*|without (?:human|manual|staff)|sends? (?:letters?|emails?|messages?|notifications?)|updates? (?:the |case |client )?(?:record|system|case)\w*|writes? (?:to|back)|triggers?|auto-?(?:approv|decid|respond|send)\w*)"),
    ("generative", 1, "Generates free text or letters (generative AI, assistants, copilots)",
     r"\b(generat\w*|draft\w*|summari[sz]\w*|chatbots?|copilot\w*|assistant\w*|large language|llm|gpt|letters?|write[s]? (?:reports?|notes?|emails?))"),
    ("public_facing", 1, "Talks to the public directly",
     r"\b(public[- ]facing|residents? can|customers?|website|web ?chat|citizen portal|self[- ]service|telephone|call centre|voice)"),
    ("third_party", 1, "Provided by an outside supplier or hosted outside the organisation",
     r"\b(supplier|vendor|third[- ]party|cloud|saas|microsoft|google|openai|amazon|aws|azure|palantir|external provider)"),
]
MITIGATIONS: List[Tuple[str, int, str, str]] = [
    ("human_review", -2, "Says a person reviews or approves the output",
     r"\b(human (?:review|in the loop|oversight|check)\w*|reviewed by|approved by|checked by|signed off|oversight|final decision (?:is )?(?:made )?by|a (?:member of staff|social worker|officer|manager) (?:reviews|checks|approves))"),
    ("no_personal", -3, "Says it uses no personal data or only anonymised or aggregate data",
     r"\b(no personal data|anonymi[sz]ed|aggregate\w*|statistical|non-personal|open data|public data|no (?:individual|personal) (?:information|records?))"),
    ("internal_only", -1, "Says it is for internal use or analytics only",
     r"\b(internal (?:use|only|tool)|staff only|analytics only|dashboard|reporting|search tool|document search|translation|transcription|spell|accessibility)"),
]
# What a description rarely says, and what a deeper look would need.
QUESTIONS: List[Tuple[str, str, str]] = [
    ("review", "Does a person review the output before it is used or acted on?", r"\b(human|review\w*|approv\w*|oversight|checked|signed off)"),
    ("data", "Which data does it read and write, and is any of it personal or special category?", r"\b(data|records?|notes?|database|files?|documents?)"),
    ("model", "Which model or supplier sits behind it, and where is it hosted?", r"\b(model|gpt|llm|supplier|vendor|openai|microsoft|google|hosted|cloud|in-house)"),
    ("owner", "Who owns it and who can stop it?", r"\b(owner|owned by|responsible|service manager|head of|team)"),
    ("monitoring", "Is its behaviour logged and monitored after it goes live?", r"\b(monitor\w*|logg\w*|audit\w*|trace\w*)"),
]

COLUMN_ALIASES = {
    "id": ("id", "ref", "reference", "agent id", "agent_id"),
    "name": ("name", "agent", "agent name", "title", "tool", "system"),
    "description": ("description", "summary", "purpose", "what it does", "short description", "details"),
    "department": ("department", "service", "directorate", "team", "area", "function"),
    "supplier": ("supplier", "vendor", "provider", "built by", "technology"),
    "their_flag": ("their_flag", "flagged", "needs further investigation", "further investigation", "risk", "risk tier", "their_tier", "screening", "screening outcome", "rag"),
}
TRUE_WORDS = ("y", "yes", "true", "1", "flag", "flagged", "high", "moderate", "medium", "moderate-to-high", "moderate to high", "amber", "red", "investigate", "further investigation")
FALSE_WORDS = ("n", "no", "false", "0", "low", "green", "none", "not flagged", "")


def _flag(value: Any) -> Optional[bool]:
    if value is None:
        return None
    v = str(value).strip().lower()
    if v in TRUE_WORDS:
        return True
    if v in FALSE_WORDS:
        return False
    return None


def screen(description: str, department: str = "", supplier: str = "", high_at: int = HIGH_AT, moderate_at: int = MODERATE_AT) -> Dict[str, Any]:
    """One agent: the signals found in its description, the score they add up to, and what the description leaves out."""
    text = " ".join(x for x in (description, department, supplier) if x).lower()
    hits: List[Dict[str, Any]] = []
    for key, weight, reason, pattern in SIGNALS + MITIGATIONS:
        found = sorted({m.group(0) for m in re.finditer(pattern, text)})
        if found:
            hits.append({"key": key, "weight": weight, "reason": reason, "phrases": found[:4]})
    positive = sum(h["weight"] for h in hits if h["weight"] > 0)
    mitigation = max(sum(h["weight"] for h in hits if h["weight"] < 0), -3)        # a claim in a description is worth little: cap the credit
    score = max(0, positive + mitigation)
    tier = "High" if score >= high_at else ("Moderate" if score >= moderate_at else "Low")
    missing = [q for key, q, pattern in QUESTIONS if not re.search(pattern, text)] if tier != "Low" else []
    if not description.strip():
        tier, missing = "Unknown", ["There is no description to screen. Add one, or assess the design directly."]
    return {"score": score, "tier": tier, "needs_investigation": tier in ("High", "Moderate", "Unknown"), "signals": hits, "not_stated": missing}


def _cols(header: List[str]) -> Dict[str, int]:
    found: Dict[str, int] = {}
    norm = [h.strip().lower() for h in header]
    for field, aliases in COLUMN_ALIASES.items():
        for a in aliases:
            if a in norm:
                found[field] = norm.index(a)
                break
    return found


def rows_from_csv(text: str) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = list(csv.reader(io.StringIO(text), dialect))
    if len(reader) < 2:
        raise HTTPException(status_code=422, detail="The file needs a header row and at least one agent.")
    cols = _cols(reader[0])
    if "description" not in cols:
        raise HTTPException(status_code=422, detail="No description column found. Name a column description, summary or purpose (found: " + ", ".join(reader[0][:12]) + ").")
    out = []
    for i, r in enumerate(reader[1:], 1):
        if not any(c.strip() for c in r):
            continue
        get = lambda f: r[cols[f]].strip() if f in cols and cols[f] < len(r) else ""   # noqa: E731
        out.append({"id": get("id") or str(i), "name": get("name") or f"Agent {i}", "description": get("description"), "department": get("department"),
                    "supplier": get("supplier"), "their_flag": get("their_flag") if "their_flag" in cols else None})
    return out, {f: reader[0][i] for f, i in cols.items()}


def kappa(both: int, ours_only: int, theirs_only: int, neither: int) -> Optional[float]:
    n = both + ours_only + theirs_only + neither
    if n == 0:
        return None
    po = (both + neither) / n
    pe = ((both + ours_only) * (both + theirs_only) + (neither + theirs_only) * (neither + ours_only)) / (n * n)
    return None if pe == 1 else round((po - pe) / (1 - pe), 3)


class Row(BaseModel):
    id: Optional[str] = None
    name: str = ""
    description: str = ""
    department: str = ""
    supplier: str = ""
    their_flag: Optional[Any] = None


class SampleSpec(BaseModel):
    size: int = Field(100, ge=1, le=MAX_ROWS)
    flagged_share: float = Field(0.7, ge=0, le=1)       # of the sample, how much to take from the agents the other screening flagged
    seed: int = 7


class TriageRequest(BaseModel):
    csv: Optional[str] = Field(None, max_length=8_000_000)
    rows: Optional[List[Row]] = None
    high_at: int = Field(HIGH_AT, ge=1, le=20)
    moderate_at: int = Field(MODERATE_AT, ge=1, le=20)
    sample: Optional[SampleSpec] = None


def pick_sample(results: List[Dict[str, Any]], spec: SampleSpec) -> Dict[str, Any]:
    """A repeatable stratified sample: some from the agents the other screening flagged, the rest from the ones it did not (or, with no such column, from ours)."""
    rng = random.Random(spec.seed)
    has_theirs = any(r["their_flag"] is not None for r in results)
    flagged = [r for r in results if (r["their_flag"] if has_theirs else r["needs_investigation"])]
    other = [r for r in results if not (r["their_flag"] if has_theirs else r["needs_investigation"])]
    want_f = min(len(flagged), round(spec.size * spec.flagged_share))
    want_o = min(len(other), spec.size - want_f)
    want_f = min(len(flagged), spec.size - want_o)                  # top up from the flagged if the others ran short
    chosen = rng.sample(flagged, want_f) + rng.sample(other, want_o)
    return {"size": len(chosen), "from_flagged": want_f, "from_not_flagged": want_o, "basis": "their screening" if has_theirs else "our screening", "seed": spec.seed,
            "ids": [r["id"] for r in sorted(chosen, key=lambda r: r["order"])]}


def _screened(body: TriageRequest) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """The request's list, read and screened: one result per agent."""
    if body.moderate_at > body.high_at:
        raise HTTPException(status_code=422, detail="The moderate line cannot be above the high line.")
    if body.csv:
        rows, columns = rows_from_csv(body.csv)
        rows = [Row(**r) for r in rows]
    elif body.rows:
        rows, columns = body.rows, {}
    else:
        raise HTTPException(status_code=422, detail="Send the list as csv text or as rows.")
    if len(rows) > MAX_ROWS:
        raise HTTPException(status_code=422, detail=f"At most {MAX_ROWS} agents at a time.")
    results = []
    for i, r in enumerate(rows):
        s = screen(r.description, r.department, r.supplier, body.high_at, body.moderate_at)
        results.append({"order": i, "id": r.id or str(i + 1), "name": r.name or f"Agent {i + 1}", "department": r.department, "supplier": r.supplier,
                        "description": r.description, "their_flag": _flag(r.their_flag) if r.their_flag not in (None, "") else None, **s})
    return results, columns


@router.post("/triage")
def triage(body: TriageRequest) -> Dict[str, Any]:
    results, columns = _screened(body)
    tiers = {t: sum(1 for r in results if r["tier"] == t) for t in ("High", "Moderate", "Low", "Unknown")}
    out: Dict[str, Any] = {"count": len(results), "tiers": tiers, "needs_investigation": sum(1 for r in results if r["needs_investigation"]), "columns": columns,
                           "lines": {"high_at": body.high_at, "moderate_at": body.moderate_at},
                           "note": "A first-pass screen of the descriptions only. It ranks agents for a closer look and is not a risk assessment.", "results": results}
    compared = [r for r in results if r["their_flag"] is not None]
    if compared:
        both = sum(1 for r in compared if r["their_flag"] and r["needs_investigation"])
        ours = sum(1 for r in compared if not r["their_flag"] and r["needs_investigation"])
        theirs = sum(1 for r in compared if r["their_flag"] and not r["needs_investigation"])
        neither = len(compared) - both - ours - theirs
        out["agreement"] = {"compared": len(compared), "both_flag": both, "only_we_flag": ours, "only_they_flag": theirs, "neither_flag": neither,
                            "agreement": round((both + neither) / len(compared), 3), "kappa": kappa(both, ours, theirs, neither),
                            "their_flagged": both + theirs, "our_flagged": both + ours}
    if body.sample:
        out["sample"] = pick_sample(results, body.sample)
    return out


# ── Importing a chosen set into the inventory, with a draft design each ──────────────────────────────────────────────

MAX_IMPORT = 2000


class ImportRequest(TriageRequest):
    ids: Optional[List[str]] = None          # which of the list's agents (by their id); none means all of them
    create_designs: bool = True
    profile: Optional[str] = None            # the requirements profile the draft designs are judged by; default social_care if it exists, else payments


def _first_sentence(text: str, limit: int = 90) -> str:
    t = re.split(r"(?<=[.!?])\s", text.strip(), maxsplit=1)[0].strip()
    return (t[: limit - 1].rstrip() + "\u2026") if len(t) > limit else (t or "Purpose not stated")


def skeleton(name: str, description: str, found: Dict[str, Any], profile: str) -> Dict[str, Any]:
    """A first draft of an agent design from what its description says. It adds only what the description states (who is affected, what kind of data), and never
    credits a control the description merely claims (a reviewer, a guardrail): those have to be added and evidenced by a person."""
    keys = {h["key"] for h in found["signals"]}
    nodes: List[Dict[str, Any]] = [
        {"id": "a1", "type": "agent", "name": name, "p": {"owner": "", "auto": "autonomous" if "autonomous" in keys else "approval"}, "primary": True},
        {"id": "g1", "type": "goal", "name": _first_sentence(description), "p": {}}]
    edges: List[Dict[str, Any]] = [{"from": "a1", "to": "g1", "label": "pursues"}]
    if keys & {"decision", "vulnerable", "public_facing"}:
        nodes.append({"id": "h1", "type": "human", "name": "People affected (from the description)", "p": {}})
        edges.append({"from": "h1", "to": "a1", "label": "requests"})
    if keys & {"sensitive", "personal"}:
        nodes.append({"id": "d1", "type": "data", "name": ("Sensitive data" if "sensitive" in keys else "Personal data") + " (from the description)", "p": {}})
        edges.append({"from": "a1", "to": "d1", "label": "reads"})
    return {"nodes": nodes, "edges": edges, "n": 100, "profile": profile, "req": {}, "policy": "block", "source": "screening",
            "screening": {"tier": found["tier"], "score": found["score"], "basis": "description only"}}


@router.post("/triage/import")
def import_screened(body: ImportRequest, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    results, _ = _screened(body)
    if body.ids is not None:
        wanted = {str(i) for i in body.ids}
        results = [r for r in results if r["id"] in wanted]
    if not results:
        raise HTTPException(status_code=422, detail="No agents selected.")
    if len(results) > MAX_IMPORT:
        raise HTTPException(status_code=422, detail=f"Import at most {MAX_IMPORT} agents at a time; choose the ones that need a closer look.")
    profile = body.profile
    if profile is not None and session.scalar(select(RcrProfile.id).where(RcrProfile.profile_key == profile)) is None:
        raise HTTPException(status_code=422, detail=f"Unknown requirements profile {profile!r}.")
    if profile is None:
        profile = "social_care" if session.scalar(select(RcrProfile.id).where(RcrProfile.profile_key == "social_care")) else "payments"
    org = current_organisation(session)
    now = datetime.now(timezone.utc).isoformat()
    taken = {k for k in session.scalars(select(Agent.agent_key))}
    seen: Dict[str, int] = {}
    items: List[Dict[str, Any]] = []
    for r in results:
        base = agent_key(r["name"])
        if len(base) < 2:
            items.append({"id": r["id"], "name": r["name"], "action": "skipped", "reason": "The name needs letters or digits."})
            continue
        seen[base] = seen.get(base, 0) + 1
        key = base if seen[base] == 1 else f"{base[:76]}-{seen[base]}"
        shown = {"tier": r["tier"], "score": r["score"], "needs_investigation": r["needs_investigation"], "signals": r["signals"], "not_stated": r["not_stated"],
                 "description": r["description"][:600], "department": r["department"], "supplier": r["supplier"], "their_flag": r["their_flag"],
                 "basis": "description only", "screened_at": now, "screened_by": user.name}
        agent = session.scalar(select(Agent).where(Agent.agent_key == key)) if key in taken else None
        if agent is not None and agent.origin == "DEMO":
            items.append({"id": r["id"], "name": r["name"], "agent_key": key, "action": "skipped", "reason": "A demo agent has this name."})
            continue
        action = "updated"
        if agent is None:
            agent = Agent(agent_key=key, organisation_id=org.id, name=r["name"].strip()[:80], framework="From a screened list", status="UNOWNED", mode="NOT_RUNNING",
                          origin="SCREENED", tools_count=0, note=(f"Screened {r['tier']}" + (f" \u00b7 {r['department']}" if r["department"] else ""))[:200])
            session.add(agent)
            taken.add(key)
            action = "created"
        agent.screening = shown                      # a new dict each time, so the change is seen
        agent.updated_at = func.now()
        design_key: Optional[str] = None
        if body.create_designs and agent.design_id is None:
            doc = skeleton(agent.name, r["description"], r, profile)
            d = Design(design_key="d-" + secrets.token_hex(5), organisation_id=org.id, subject="AGENT", name=agent.name, domain_key="OWASP_AGENTIC", document=doc)
            session.add(d)
            session.flush()
            agent.design_id = d.id
            design_key = d.design_key
        elif agent.design_id is not None:
            design_key = session.scalar(select(Design.design_key).where(Design.id == agent.design_id))
        items.append({"id": r["id"], "name": agent.name, "agent_key": key, "tier": r["tier"], "action": action, "design_key": design_key,
                      "design_created": bool(body.create_designs and design_key and action == "created")})
    session.commit()
    done = [i for i in items if i["action"] != "skipped"]
    return {"profile": profile, "created": sum(1 for i in items if i["action"] == "created"), "updated": sum(1 for i in items if i["action"] == "updated"),
            "skipped": sum(1 for i in items if i["action"] == "skipped"), "designs_created": sum(1 for i in done if i.get("design_created")), "items": items}
