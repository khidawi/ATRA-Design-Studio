"""
The ASTRA runtime client: reports what an agent does, while it runs, to an ASTRA platform.

Design rules that matter in a production agent:
  * It never raises into your agent. Reporting is best effort; a down platform, a bad key or a full queue is logged (once) and ignored.
  * It never blocks your agent. Events go on an in-memory queue and a background thread sends them in batches, with back-off and
    Retry-After honoured. The queue is bounded: when it is full the oldest events are dropped and counted.
  * It sends facts, not content. Only the kind of event and a name (a tool, a server, an agent) are sent, never arguments or results.
  * It uses only the standard library, so it adds nothing to your dependency tree.
  * Optionally (enforce=True) it refuses a tool call, delegation or server connection that the agent's active contract does not allow, using
    the contract summary it fetches from the platform. With no contract, or if the platform cannot be reached, it allows (fail open), unless
    strict=True.
"""
import atexit
import contextvars
import functools
import inspect
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from collections import deque

from . import transport
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional

log = logging.getLogger("astra_runtime")
__version__ = "0.1.0"

_current_agent: "contextvars.ContextVar[Optional[str]]" = contextvars.ContextVar("astra_agent", default=None)


class AstraBlocked(RuntimeError):
    """Raised by an enforcing client when the agent's contract does not allow what it is about to do."""


class Client:
    def __init__(self, url: Optional[str] = None, api_key: Optional[str] = None, agent: Optional[str] = None, *, framework: Optional[str] = None, discover: bool = True,
                 enforce: bool = False, strict: bool = False, batch_size: int = 50, flush_interval: float = 1.0, max_queue: int = 5000, timeout: float = 5.0,
                 contract_refresh: float = 60.0, on_error: Optional[Callable[[str], None]] = None, start: bool = True) -> None:
        self.url = (url or os.environ.get("ASTRA_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("ASTRA_KEY", "")
        self.agent = agent or os.environ.get("ASTRA_AGENT", "")
        self.framework, self.discover, self.enforce, self.strict = framework, discover, enforce, strict
        self.batch_size, self.flush_interval, self.timeout, self.contract_refresh = batch_size, flush_interval, timeout, contract_refresh
        self.on_error = on_error
        self.dropped = 0
        self.sent = 0
        self.disabled_reason: Optional[str] = None
        self._q: Deque[Dict[str, Any]] = deque()
        self._max_queue = max_queue
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._backoff = 0.0
        self._warned: set = set()
        self._contract: Dict[str, Dict[str, Any]] = {}
        self._contract_at: Dict[str, float] = {}
        self._thread: Optional[threading.Thread] = None
        if not (self.url and self.api_key):
            self._disable("ASTRA_URL and ASTRA_KEY are not set, so nothing is reported")
        elif transport.url_problem(self.url):
            self._disable(transport.url_problem(self.url))
        elif start:
            self._thread = threading.Thread(target=self._run, name="astra-runtime", daemon=True)
            self._thread.start()
            atexit.register(self.close)

    # ── reporting ──────────────────────────────────────────────────────────

    def record(self, type: str, name: str = "", *, agent: Optional[str] = None, **attrs: Any) -> None:
        """Queue one event. Never raises."""
        try:
            who = agent or _current_agent.get() or self.agent
            if not who or self.disabled_reason:
                return
            ev = {"type": type, "name": str(name)[:200], "at": datetime.now(timezone.utc).isoformat(), "_agent": who}
            ev.update({k: v for k, v in attrs.items() if v is not None})
            with self._lock:
                if len(self._q) >= self._max_queue:
                    self._q.popleft()
                    self.dropped += 1
                self._q.append(ev)
                full = len(self._q) >= self.batch_size
            if full:
                self._wake.set()
        except Exception as exc:                                   # pragma: no cover - reporting must never break the agent
            self._warn("record", f"could not queue an event: {exc}")

    def tool_call(self, name: str, *, write: Optional[bool] = None, agent: Optional[str] = None, params: Optional[Dict[str, float]] = None, prev_tool: Optional[str] = None,
                  confirmed: Optional[bool] = None, presented_hash: Optional[str] = None, executed_hash: Optional[str] = None) -> None:
        """params: the numeric parameters of the call (numbers only, for the contract's bounds); prev_tool: the tool called just before (for prohibited chains); confirmed, presented_hash
        and executed_hash: for a tool that needs a person, whether one confirmed and the fingerprints (see fingerprint()) of what they were shown and of what ran."""
        self.record("tool_call", name, write=write, agent=agent, params=params, prev_tool=prev_tool, confirmed=confirmed, presented_hash=presented_hash, executed_hash=executed_hash)

    def delegation(self, to_agent: str, *, agent: Optional[str] = None, mode: Optional[str] = None, depth: Optional[int] = None) -> None:
        self.record("delegation", to_agent, agent=agent, mode=mode, depth=depth)

    def delegation_in(self, from_agent: str, *, agent: Optional[str] = None) -> None:
        """Work was handed to this agent by another."""
        self.record("delegation_in", from_agent, agent=agent)

    def mcp_connect(self, server: str, *, signed: Optional[bool] = None, agent: Optional[str] = None, in_aibom: Optional[bool] = None, provenance: Optional[bool] = None) -> None:
        self.record("mcp_connect", server, signed=signed, agent=agent, in_aibom=in_aibom, provenance=provenance)

    def component(self, name: str, *, signed: Optional[bool] = None, in_aibom: Optional[bool] = None, provenance: Optional[bool] = None, agent: Optional[str] = None) -> None:
        """A model, plugin or library the agent loaded: whether it is signed, has provenance and is in the AI bill of materials."""
        self.record("component", name, signed=signed, in_aibom=in_aibom, provenance=provenance, agent=agent)

    def data_access(self, store: str, *, agent: Optional[str] = None, write: Optional[bool] = None) -> None:
        self.record("data_access", store, agent=agent, write=write)

    def memory_write(self, scope: str = "session", *, agent: Optional[str] = None, validated: Optional[bool] = None, provenance: Optional[bool] = None) -> None:
        self.record("memory_write", "", scope=scope, agent=agent, validated=validated, provenance=provenance)

    def execution(self, *, sandboxed: Optional[bool] = None, host: Optional[str] = None, agent: Optional[str] = None) -> None:
        """The agent ran code or reached out: inside the sandbox or not, and to which host."""
        self.record("exec", "", sandboxed=sandboxed, host=host, agent=agent)

    def goal_set(self, goal: str, *, source: Optional[str] = None, semantic: Optional[str] = None, agent: Optional[str] = None) -> None:
        """The agent took on a goal. semantic ("out_of_scope" or "integrity") is the verdict of your own classifier, if you run one; a person adjudicates it on the platform."""
        self.record("goal_set", goal, source=source, semantic=semantic, agent=agent)

    def message(self, sender: str, *, payload: Optional[str] = None, signature: Optional[str] = None, key_id: Optional[str] = None, verified: Optional[bool] = None, agent: Optional[str] = None) -> None:
        """A message arrived from another agent. Send the payload, its Ed25519 signature (hex) and the key id so the platform checks it itself; verified is only your own claim."""
        self.record("msg", sender, payload=payload, signature=signature, key_id=key_id, verified=verified, agent=agent)

    def identity(self, claimed: str, *, agent: Optional[str] = None) -> None:
        self.record("id", claimed, agent=agent)

    def life(self, *, agent: Optional[str] = None) -> None:
        """The agent is running now; the platform checks its lifecycle against the contract with its own clock."""
        self.record("life", "", agent=agent)

    def spawn(self, child: str, *, agent: Optional[str] = None) -> None:
        self.record("spawn", child, agent=agent)

    @staticmethod
    def fingerprint(action: Any) -> str:
        """A short hash of an action as a person saw it or as it ran, to compare the two (presented_hash and executed_hash). Only the hash leaves your process."""
        import hashlib
        import json
        return hashlib.sha256(json.dumps(action, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()[:32]

    def heartbeat(self, *, agent: Optional[str] = None) -> None:
        self.record("heartbeat", "", agent=agent)

    def as_agent(self, name: str):
        """Report events inside the block as another agent (a process that hosts several)."""
        client = self

        class _Scope:
            def __enter__(self_inner):
                self_inner.token = _current_agent.set(name)

            def __exit__(self_inner, *exc):
                _current_agent.reset(self_inner.token)
        return _Scope()

    # ── enforcement ────────────────────────────────────────────────────────

    def contract(self, agent: Optional[str] = None, *, force: bool = False) -> Optional[Dict[str, Any]]:
        """The agent's contract summary (what it allows), cached for contract_refresh seconds; None when it cannot be fetched."""
        who = agent or _current_agent.get() or self.agent
        if not who or self.disabled_reason:
            return None
        if not force and who in self._contract and time.monotonic() - self._contract_at.get(who, 0) < self.contract_refresh:
            return self._contract[who]
        status, body = self._http("GET", f"/api/runtime/contract/{urllib.request.quote(who)}")
        if status == 200 and isinstance(body, dict):
            self._contract[who], self._contract_at[who] = body, time.monotonic()
            return body
        return self._contract.get(who)

    def is_allowed(self, kind: str, name: str, *, agent: Optional[str] = None) -> bool:
        """Does the active contract allow this? kind is 'tool', 'delegation', 'mcp' or 'data'. True when there is no contract to say otherwise."""
        c = self.contract(agent)
        if not c or c.get("state") != "contract":
            return not self.strict
        allowed = c.get("allowed") or {}
        if kind == "tool":
            return name in {t["name"] for t in allowed.get("tools", [])}
        if kind == "delegation":
            return name in allowed.get("delegates_to", [])
        if kind == "mcp":
            return name in {m["name"] for m in allowed.get("mcp_servers", [])}
        if kind == "data":
            return name in allowed.get("data", [])
        return True

    def guard(self, kind: str, name: str, *, agent: Optional[str] = None) -> None:
        """Raise AstraBlocked if this client enforces and the contract does not allow it. The attempt is reported either way."""
        if self.enforce and not self.is_allowed(kind, name, agent=agent):
            raise AstraBlocked(f"The contract for {agent or _current_agent.get() or self.agent} does not allow {kind} '{name}'.")

    def tool(self, name: Optional[str] = None, *, write: Optional[bool] = None):
        """Decorator: report (and, if enforcing, guard) every call of a function the agent uses as a tool. Works for sync and async functions."""
        def wrap(fn: Callable) -> Callable:
            label = name or fn.__name__
            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def awrapper(*a, **k):
                    self.tool_call(label, write=write)          # the attempt is reported first, so a refused call is still visible
                    self.guard("tool", label)
                    return await fn(*a, **k)
                return awrapper

            @functools.wraps(fn)
            def wrapper(*a, **k):
                self.tool_call(label, write=write)              # the attempt is reported first, so a refused call is still visible
                self.guard("tool", label)
                return fn(*a, **k)
            return wrapper
        return wrap

    # ── plumbing ───────────────────────────────────────────────────────────

    def check(self) -> Dict[str, Any]:
        """Is the platform reachable and the key accepted? Returns what the platform says about this key, or {'ok': False, 'error': ...}."""
        status, body = self._http("GET", "/api/auth/me")
        if status == 200 and isinstance(body, dict):
            return {"ok": True, "key": body["user"]["full_name"], "role": body["user"]["role"]}
        return {"ok": False, "error": f"HTTP {status}: {body}"}

    def flush(self, timeout: float = 5.0) -> bool:
        """Send what is queued now. True if the queue is empty afterwards."""
        end = time.monotonic() + timeout
        while time.monotonic() < end and not self.disabled_reason:
            if not self._send_once():
                break
        with self._lock:
            return not self._q

    def close(self) -> None:
        if self._stop.is_set():
            return
        try:
            self.flush(timeout=3.0)
        finally:
            self._stop.set()
            self._wake.set()

    def _disable(self, why: str) -> None:
        self.disabled_reason = why
        self._warn("disabled", why)

    def _warn(self, key: str, msg: str) -> None:
        if key in self._warned:
            return
        self._warned.add(key)
        log.warning("astra_runtime: %s", msg)
        if self.on_error:
            try:
                self.on_error(msg)
            except Exception:                                      # pragma: no cover
                pass

    def _http(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json", "User-Agent": f"astra-runtime/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=transport.ssl_context()) as r:
                raw = r.read().decode("utf-8") or "null"
                return r.status, json.loads(raw)
        except urllib.error.HTTPError as e:
            try:
                body: Any = json.loads(e.read().decode("utf-8") or "null")
            except Exception:
                body = None
            if e.code == 429:
                self._backoff = max(self._backoff, float(e.headers.get("Retry-After", "5") or 5))
            return e.code, body
        except Exception as e:                                     # network down, DNS, timeout, bad URL
            return 0, str(e)

    def _send_once(self) -> bool:
        """Send one batch for one agent. True if something was sent (so the caller may try for more)."""
        with self._lock:
            if not self._q:
                return False
            who = self._q[0]["_agent"]
            batch: List[Dict[str, Any]] = []
            rest: Deque[Dict[str, Any]] = deque()
            while self._q:
                ev = self._q.popleft()
                (batch if ev["_agent"] == who and len(batch) < self.batch_size else rest).append(ev)
            self._q = rest
        status, body = self._http("POST", "/api/runtime/events", {"agent": who, "discover": self.discover, "framework": self.framework,
                                                                   "events": [{k: v for k, v in e.items() if k != "_agent"} for e in batch]})
        if status in (200, 202):
            self.sent += len(batch)
            self._backoff = 0.0
            if isinstance(body, dict) and body.get("discovered"):
                log.info("astra_runtime: %s was registered with the platform as a discovered agent", who)
            return True
        if status in (401, 403):
            self._disable(f"the platform refused the key (HTTP {status}): {body.get('detail') if isinstance(body, dict) else body}")
            return False
        if status in (400, 404, 409, 422) and status != 429:       # a bad request will not get better by retrying: drop it
            self._warn(f"bad{status}", f"the platform rejected a batch for {who} (HTTP {status}): {body.get('detail') if isinstance(body, dict) else body}")
            return True
        with self._lock:                                           # 429, 5xx or unreachable: put it back, in order, and wait
            self._q.extendleft(reversed(batch))
            while len(self._q) > self._max_queue:
                self._q.pop()
                self.dropped += 1
        self._backoff = min(30.0, max(self._backoff * 2, 1.0)) if status != 429 else self._backoff
        self._warn("unreachable", f"could not reach the platform (HTTP {status}); will keep retrying with back-off" if status in (0, 500, 502, 503, 504) else f"the platform answered HTTP {status}")
        return False

    def _run(self) -> None:
        last_beat = time.monotonic()
        while not self._stop.is_set():
            self._wake.wait(self.flush_interval)
            self._wake.clear()
            if self._stop.is_set() or self.disabled_reason:
                break
            if self._backoff:
                self._stop.wait(self._backoff)
            try:
                while self._send_once():
                    pass
                if self.agent and time.monotonic() - last_beat > 30:        # a heartbeat so a quiet agent still shows as live
                    last_beat = time.monotonic()
                    self.heartbeat()
            except Exception as exc:                                         # pragma: no cover
                self._warn("loop", f"internal error: {exc}")
