"""
Regulation ingestion (Task 5): propose candidate rules from a source page, for a person to approve.

The local model reads one passage at a time and proposes obligations, each with a quote copied from
the passage. The program, not the model, then checks that the quote really appears in the source,
word for word (after whitespace and punctuation are normalised); a proposal whose quote is not found
is dropped, so a candidate that survives always points at real text. Candidates are stored PENDING and
are never evaluated. A person approves one (and chooses where it applies) before it becomes a rule, and
the rule they get is an attestation rule: the design must hold a Regulatory requirement for that clause
with evidence. The model never writes a check that runs against a design.

Some sources cannot be fetched by a program (EUR-Lex answers plain requests with HTTP 202, ISO is
paywalled). The run then fails with a clear message and the same text can be pasted instead.
"""
import hashlib
import ipaddress
import logging
import re
import socket
import threading
import unicodedata
import uuid
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Dict, List, Literal, Optional, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import Domain, DomainRule, IngestionRun, Regulation, Rule, RuleCandidate
from db.session import SessionLocal, get_session
import ollama_client

log = logging.getLogger("stai.ingestion")
router = APIRouter(prefix="/api/ingestion", tags=["ingestion"])

PASSAGE_CHARS = 2800
MAX_PASSAGES_PER_RUN = 12
DEFAULT_PASSAGES = 4
MAX_PROPOSALS_PER_PASSAGE = 3
MIN_QUOTE_CHARS = 30
MAX_FETCH_BYTES = 4_000_000
OBLIGATION_WORDS = re.compile(r"\b(shall|must|required|requires|require|ensure|should|obliged|mandatory|need to)\b", re.I)
USER_AGENT = "ST-AI-Design-Studio/1.0 (regulation ingestion; contact: the platform operator)"


# ── Text handling (pure) ────────────────────────────────────────────────────

class _TextExtractor(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "head", "nav", "footer", "form", "iframe"}
    BLOCK = {"p", "div", "li", "br", "tr", "section", "article", "h1", "h2", "h3", "h4", "h5", "h6", "table", "ul", "ol"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    lines = (" ".join(line.split()) for line in "".join(parser.parts).splitlines())
    return "\n".join(line for line in lines if line)


_PUNCT = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-", "−": "-", " ": " "})


def normalise(text: str) -> str:
    """The form two passages are compared in: no case, one kind of quote and dash, single spaces."""
    return " ".join(unicodedata.normalize("NFKC", text).translate(_PUNCT).casefold().split())


def quote_in_source(quote: str, source: str) -> bool:
    q = normalise(quote).strip(" .\"'")
    return len(q) >= MIN_QUOTE_CHARS and q in normalise(source)


def split_passages(text: str, size: int = PASSAGE_CHARS) -> List[str]:
    """Paragraph-aligned windows of about `size` characters; a paragraph longer than that is cut."""
    passages: List[str] = []
    current = ""
    for para in text.split("\n"):
        while len(para) > size:
            cut = para.rfind(". ", 0, size)
            cut = cut + 1 if cut > size // 3 else size
            if current:
                passages.append(current)
                current = ""
            passages.append(para[:cut].strip())
            para = para[cut:].strip()
        if current and len(current) + len(para) + 1 > size:
            passages.append(current)
            current = ""
        current = f"{current}\n{para}" if current else para
    if current.strip():
        passages.append(current)
    return passages


def has_obligation(passage: str) -> bool:
    return bool(OBLIGATION_WORDS.search(passage))


# ── Fetching ────────────────────────────────────────────────────────────────

def check_fetchable(url: str) -> None:
    """Only public http(s) pages: the server must not be turned into a way to reach its own network."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Only http and https addresses can be read.")
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise ValueError(f"The address {parsed.hostname!r} could not be resolved.") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("Addresses inside a private network are not read.")


def fetch_text(url: str) -> str:
    check_fetchable(url)
    try:
        with httpx.stream("GET", url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,text/plain"},
                          timeout=30.0, follow_redirects=True) as resp:
            if resp.status_code == 202:
                raise ValueError("The site answered HTTP 202 (it does not serve this page to programs, as EUR-Lex does). "
                                 "Open the page in a browser, copy the text, and paste it instead.")
            if resp.status_code in (401, 403):
                raise ValueError(f"The site refused access (HTTP {resp.status_code}); it may be paywalled. Paste the text instead.")
            if resp.status_code != 200:
                raise ValueError(f"The site answered HTTP {resp.status_code}.")
            ctype = resp.headers.get("content-type", "").lower()
            if "pdf" in ctype:
                raise ValueError("The address is a PDF, which is not read yet. Paste the text instead.")
            if ctype and "html" not in ctype and "text" not in ctype:
                raise ValueError(f"The address returned {ctype.split(';')[0]}, not a web page.")
            body = b""
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) > MAX_FETCH_BYTES:
                    raise ValueError("The page is larger than 4 MB. Paste the section you need instead.")
            raw = body.decode(resp.encoding or "utf-8", errors="replace")
    except httpx.HTTPError as exc:
        raise ValueError(f"The page could not be fetched: {exc}") from exc
    text = html_to_text(raw) if "<" in raw[:2000] else raw
    if len(text.strip()) < 200:
        raise ValueError("The page has almost no readable text (it may need JavaScript). Paste the text instead.")
    return text


# ── The model call ──────────────────────────────────────────────────────────

SCHEMA = {
    "type": "object",
    "properties": {"requirements": {"type": "array", "maxItems": MAX_PROPOSALS_PER_PASSAGE, "items": {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "Short plain-English name of the obligation"},
            "citation": {"type": "string", "description": "Article, clause or section number as written, e.g. 'Art. 35'"},
            "quote": {"type": "string", "description": "A sentence copied word for word from the passage that states the obligation"},
            "severity": {"type": "string", "enum": ["REQUIRED", "RECOMMENDED"]},
        },
        "required": ["title", "citation", "quote", "severity"],
    }}},
    "required": ["requirements"],
}


def propose(instrument: str, passage: str) -> List[Dict[str, Any]]:
    messages = [
        {"role": "system", "content": (
            "You read a passage from a regulation or standard and list obligations that a team building or "
            "deploying an AI system or AI agent would have to meet in its design. Copy the quote exactly as "
            "written in the passage, never reword it. Use REQUIRED for 'shall' and 'must', RECOMMENDED for "
            "'should'. If the passage holds no such obligation, return an empty list. Do not invent anything.")},
        {"role": "user", "content": f"Source: {instrument}\n\nPassage:\n{passage}"},
    ]
    out = ollama_client.chat_json(messages, SCHEMA, temperature=0.0)
    items = out.get("requirements") if isinstance(out, dict) else None
    return [i for i in (items or []) if isinstance(i, dict)][:MAX_PROPOSALS_PER_PASSAGE]


# ── The run ─────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def execute_run(run_id: uuid.UUID, text: Optional[str]) -> None:
    """Runs on its own thread (a CPU-only model takes minutes per passage) with its own session."""
    with SessionLocal() as session:
        run = session.get(IngestionRun, run_id)
        regulation = session.get(Regulation, run.regulation_id)
        try:
            if text is None:
                text = fetch_text(run.source_url)
            run.fetched_chars = len(text)
            run.source_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
            passages = [p for p in split_passages(text) if has_obligation(p)]
            run.passages_total = len(passages)
            window = passages[run.passage_offset: run.passage_offset + run.passages_planned]
            run.passages_planned = len(window)
            session.commit()
            known = {normalise(q) for (q,) in session.execute(
                select(RuleCandidate.quote).where(RuleCandidate.regulation_id == regulation.id))}
            known |= {normalise(q) for (q,) in session.execute(
                select(Rule.source_quote).where(Rule.regulation_id == regulation.id, Rule.source_quote.is_not(None)))}
            for passage in window:
                for item in propose(regulation.instrument, passage):
                    run.proposed += 1
                    quote, title, citation = str(item.get("quote", "")), str(item.get("title", "")).strip(), str(item.get("citation", "")).strip()
                    if not title or not quote_in_source(quote, passage):
                        run.dropped_unverified += 1
                    elif normalise(quote) in known:
                        run.dropped_duplicate += 1
                    else:
                        known.add(normalise(quote))
                        run.kept += 1
                        session.add(RuleCandidate(
                            run_id=run.id, regulation_id=regulation.id, source_url=run.source_url, title=title[:300],
                            citation=(citation or "Unspecified")[:120], quote=quote.strip(),
                            severity="REQUIRED" if item.get("severity") == "REQUIRED" else "RECOMMENDED"))
                run.passages_done += 1
                session.commit()
            run.status = "DONE"
        except HTTPException as exc:   # the model could not be reached or answered badly
            run.status, run.error = "FAILED", str(exc.detail)
        except ValueError as exc:      # the source could not be read
            run.status, run.error = "FAILED", str(exc)
        except Exception as exc:       # keep the run row honest whatever went wrong
            log.exception("Ingestion run %s failed", run_id)
            run.status, run.error = "FAILED", f"Unexpected error: {exc}"
        run.finished_at = _now()
        session.commit()


def fail_interrupted_runs(session: Session) -> None:
    """A restart kills the thread; a run still marked RUNNING would otherwise look alive forever."""
    for run in session.scalars(select(IngestionRun).where(IngestionRun.status == "RUNNING")):
        run.status, run.error, run.finished_at = "FAILED", "The server restarted while this run was in progress.", _now()
    session.commit()


# ── API ─────────────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    instrument: str
    url: Optional[str] = None            # defaults to the regulation's own source address
    text: Optional[str] = None           # pasted text, for sources a program cannot fetch
    passages: int = Field(DEFAULT_PASSAGES, ge=1, le=MAX_PASSAGES_PER_RUN)
    offset: int = Field(0, ge=0)

    @field_validator("url", "text", mode="before")
    @classmethod
    def blank_is_none(cls, v):
        return v.strip() or None if isinstance(v, str) else v


class RunOut(BaseModel):
    id: str
    instrument: str
    source_url: Optional[str]
    source_kind: str
    status: str
    model: str
    fetched_chars: int
    passages_total: int
    passage_offset: int
    passages_planned: int
    passages_done: int
    proposed: int
    kept: int
    dropped_unverified: int
    dropped_duplicate: int
    error: Optional[str]
    started_at: datetime
    finished_at: Optional[datetime]


def _run_out(run: IngestionRun, instrument: str) -> RunOut:
    return RunOut(id=str(run.id), instrument=instrument, source_url=run.source_url, source_kind=run.source_kind,
                  status=run.status, model=run.model, fetched_chars=run.fetched_chars, passages_total=run.passages_total,
                  passage_offset=run.passage_offset, passages_planned=run.passages_planned, passages_done=run.passages_done,
                  proposed=run.proposed, kept=run.kept, dropped_unverified=run.dropped_unverified,
                  dropped_duplicate=run.dropped_duplicate, error=run.error, started_at=run.started_at,
                  finished_at=run.finished_at)


def _regulation(session: Session, instrument: str) -> Regulation:
    reg = session.scalar(select(Regulation).where(Regulation.instrument == instrument))
    if reg is None or reg.kind == "ORG_POLICY":
        raise HTTPException(status_code=422, detail=f"Unknown regulation or standard: {instrument!r}")
    return reg


@router.post("/runs", response_model=RunOut, status_code=202)
def start_run(req: RunRequest, session: Session = Depends(get_session)) -> RunOut:
    reg = _regulation(session, req.instrument)
    if session.scalar(select(func.count()).select_from(IngestionRun).where(IngestionRun.status == "RUNNING")):
        raise HTTPException(status_code=409, detail="Another ingestion run is still in progress. The local model reads one passage at a time.")
    url = None if req.text else (req.url or reg.source_url)
    if req.text is None:
        if not url:
            raise HTTPException(status_code=422, detail="Give an address or paste the text.")
        try:
            check_fetchable(url)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    elif len(req.text) < 200:
        raise HTTPException(status_code=422, detail="The pasted text is too short to hold a requirement.")
    run = IngestionRun(regulation_id=reg.id, source_url=url or req.url or reg.source_url, source_kind="PASTE" if req.text else "URL",
                       status="RUNNING", model=ollama_client.OLLAMA_MODEL, passage_offset=req.offset, passages_planned=req.passages)
    session.add(run)
    session.commit()
    threading.Thread(target=execute_run, args=(run.id, req.text), daemon=True, name=f"ingest-{run.id}").start()
    return _run_out(run, reg.instrument)


@router.get("/runs", response_model=List[RunOut])
def list_runs(limit: int = 20, session: Session = Depends(get_session)) -> List[RunOut]:
    rows = session.execute(select(IngestionRun, Regulation.instrument).join(Regulation, Regulation.id == IngestionRun.regulation_id)
                           .order_by(IngestionRun.started_at.desc()).limit(min(max(limit, 1), 100))).all()
    return [_run_out(r, i) for r, i in rows]


@router.get("/runs/{run_id}", response_model=RunOut)
def get_run(run_id: uuid.UUID, session: Session = Depends(get_session)) -> RunOut:
    run = session.get(IngestionRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="No such run.")
    return _run_out(run, session.get(Regulation, run.regulation_id).instrument)


class CandidateOut(BaseModel):
    id: str
    instrument: str
    run_id: str
    source_url: Optional[str]
    title: str
    citation: str
    quote: str
    severity: str
    status: str
    rule_key: Optional[str]
    decision_note: Optional[str]
    created_at: datetime


def _candidate_out(c: RuleCandidate, instrument: str) -> CandidateOut:
    return CandidateOut(id=str(c.id), instrument=instrument, run_id=str(c.run_id), source_url=c.source_url, title=c.title,
                        citation=c.citation, quote=c.quote, severity=c.severity, status=c.status, rule_key=c.rule_key,
                        decision_note=c.decision_note, created_at=c.created_at)


@router.get("/candidates", response_model=List[CandidateOut])
def list_candidates(status: Optional[Literal["PENDING", "APPROVED", "REJECTED"]] = None, instrument: Optional[str] = None,
                    session: Session = Depends(get_session)) -> List[CandidateOut]:
    q = select(RuleCandidate, Regulation.instrument).join(Regulation, Regulation.id == RuleCandidate.regulation_id)
    if status:
        q = q.where(RuleCandidate.status == status)
    if instrument:
        q = q.where(Regulation.instrument == instrument)
    return [_candidate_out(c, i) for c, i in session.execute(q.order_by(RuleCandidate.created_at.desc()))]


def _slug(text: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "-", text.upper()).strip("-")[:30] or "X"


class ApproveRequest(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    citation: str = Field(min_length=1, max_length=120)
    severity: Literal["REQUIRED", "RECOMMENDED"]
    subject: Literal["MODEL", "AGENT"]
    domains: List[str] = Field(default_factory=list)
    description: str = ""

    @field_validator("title", "citation", mode="before")
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


def _pending(session: Session, candidate_id: uuid.UUID) -> RuleCandidate:
    c = session.get(RuleCandidate, candidate_id)
    if c is None:
        raise HTTPException(status_code=404, detail="No such candidate.")
    if c.status != "PENDING":
        raise HTTPException(status_code=409, detail=f"This candidate was already {c.status.lower()}.")
    return c


@router.post("/candidates/{candidate_id}/approve", response_model=CandidateOut)
def approve(candidate_id: uuid.UUID, body: ApproveRequest, session: Session = Depends(get_session)) -> CandidateOut:
    c = _pending(session, candidate_id)
    reg = session.get(Regulation, c.regulation_id)
    domains = []
    for key in body.domains:
        d = session.scalar(select(Domain).where(Domain.domain_key == key))
        if d is None or d.subject != body.subject:
            raise HTTPException(status_code=422, detail=f"{key!r} is not a {body.subject.lower()} domain.")
        domains.append(d)
    base = f"{_slug(reg.instrument)}-{_slug(body.citation)}"
    key, n = base, 1
    while session.scalar(select(Rule.id).where(Rule.rule_key == key)):
        n += 1
        key = f"{base}-{n}"
    desc = body.description.strip() or (
        f"Attested by a Regulatory requirement node for {reg.instrument}, clause {body.citation}, marked Satisfied with evidence.")
    rule = Rule(rule_key=key, regulation_id=reg.id, citation=body.citation, title=body.title, description=desc,
                severity=body.severity, check_type="ATTESTATION", check_config={}, subject=body.subject, status="APPROVED",
                origin="EXTRACTED", source_url=c.source_url, source_quote=c.quote)
    session.add(rule)
    session.flush()
    for d in domains:
        pos = session.scalar(select(func.coalesce(func.max(DomainRule.position), -1)).where(DomainRule.domain_id == d.id)) + 1
        session.add(DomainRule(domain_id=d.id, rule_id=rule.id, position=pos))
    c.status, c.rule_key, c.decided_at = "APPROVED", key, _now()
    c.title, c.citation, c.severity = body.title, body.citation, body.severity
    session.commit()
    return _candidate_out(c, reg.instrument)


class RejectRequest(BaseModel):
    note: str = ""


@router.post("/candidates/{candidate_id}/reject", response_model=CandidateOut)
def reject(candidate_id: uuid.UUID, body: RejectRequest, session: Session = Depends(get_session)) -> CandidateOut:
    c = _pending(session, candidate_id)
    c.status, c.decision_note, c.decided_at = "REJECTED", body.note.strip() or None, _now()
    session.commit()
    return _candidate_out(c, session.get(Regulation, c.regulation_id).instrument)
