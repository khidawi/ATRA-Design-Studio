"""
ModelMonitor: report how a model in production behaves (what it was given, what it answered) to an ASTRA production monitor.

    from astra_runtime import ModelMonitor
    mon = ModelMonitor("credit-model")                    # ASTRA_URL and ASTRA_KEY come from the environment

    mon.log(inputs={"age": 41, "plan": "gold"}, output="approve", confidence=0.82, latency_ms=41, segments={"gender": "F"})

    # a model you call through a provider's API: say which version answered, so a silent swap behind the name is noticed
    mon.log(inputs={"topic": "refund"}, output=reply.text, model_version=reply.model)          # the model id or system fingerprint the API returns

    # a language model: scan prompt and reply HERE for personal data, keys and injection attempts; only yes/no flags are sent, never the text
    mon.log(inputs={"topic": "refund"}, output="ok", prompt_text=prompt, output_text=reply.text)

    # a fixed question with a known good answer, run on a schedule through the same route: a pass that turns into a fail means the model changed
    mon.run_canary("refund-policy", lambda: ask("What is the refund window?"), expect="30 days", model_version=...)

    # and what the person did with the output, by role (never a name, unless your compliance lead has signed off on counting individuals)
    mon.decision("accepted", role="loan officer", review_seconds=14, reason=False, confidence_shown=True)

    @mon.track(inputs=lambda applicant: {"age": applicant.age}, output=lambda r: r.decision, confidence=lambda r: r.score)
    def predict(applicant): ...                           # logs every call, with its latency, and an error as an error

The platform keeps statistics (histograms, counts, rates), never your records. Even so, send only the fields the monitor's schema declares, and leave
out anything you would not want counted. The same rules as the runtime client apply: it never raises into your code, never blocks it (records go on a
bounded in-memory queue that a background thread sends in batches, honouring Retry-After), and it uses only the standard library. `sample` sends a
fraction of the traffic (a random 10%, say) for a model with very high volume: drift shows up in a sample just as well.
"""
import atexit
import functools
import json
import logging
import os
import random
import re
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional

log = logging.getLogger("astra_runtime")
__version__ = "0.2.0"


def monitor_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:80]


class ModelMonitor:
    def __init__(self, model: str, url: Optional[str] = None, api_key: Optional[str] = None, *, sample: float = 1.0, batch_size: int = 200, flush_interval: float = 2.0,
                 max_queue: int = 20000, timeout: float = 5.0, on_error: Optional[Callable[[str], None]] = None, start: bool = True) -> None:
        self.key = monitor_key(model)
        self.url = (url or os.environ.get("ASTRA_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("ASTRA_KEY", "")
        self.sample, self.batch_size, self.flush_interval, self.timeout, self.on_error = max(0.0, min(1.0, sample)), batch_size, flush_interval, timeout, on_error
        self.sent = self.dropped = self.rejected = 0
        self._busy = 0                                    # batches taken off the queue and not yet answered
        self.status: Optional[str] = None                 # what the platform last said about the monitor: learning, OK, WATCH, DRIFT ...
        self.disabled_reason: Optional[str] = None
        self._q: Deque[Dict[str, Any]] = deque()
        self._max_queue = max_queue
        self._lock = threading.Lock()
        self._wake, self._stop = threading.Event(), threading.Event()
        self._backoff = 0.0
        self._warned: set = set()
        self._thread: Optional[threading.Thread] = None
        if not self.key:
            self._disable("the model needs a name")
        elif not (self.url and self.api_key):
            self._disable("ASTRA_URL and ASTRA_KEY are not set, so nothing is reported")
        elif start:
            self._thread = threading.Thread(target=self._run, name="astra-model-monitor", daemon=True)
            self._thread.start()
            atexit.register(self.close)

    # ── reporting ─────────────────────────────────────────────────

    def log(self, inputs: Dict[str, Any], output: Any, *, confidence: Optional[float] = None, latency_ms: Optional[float] = None, error: Optional[bool] = None,
            label: Any = None, segments: Optional[Dict[str, Any]] = None, flags: Optional[Dict[str, bool]] = None, at: Optional[datetime] = None, model_version: Optional[str] = None,
            prompt_text: Optional[str] = None, output_text: Optional[str] = None) -> None:
        """Queue one prediction. Never raises. `label` is the true answer, if you already know it; `segments` are the groups to compare for fairness."""
        try:
            if self.disabled_reason or (self.sample < 1.0 and random.random() > self.sample):
                return
            rec: Dict[str, Any] = {"inputs": inputs, "output": output, "at": (at or datetime.now(timezone.utc)).isoformat()}
            if prompt_text is not None or output_text is not None:             # scanned here; the text itself is never sent
                from .checks import llm_flags
                flags = {**llm_flags(prompt_text, output_text), **(flags or {})}
            for k, v in (("confidence", confidence), ("latency_ms", latency_ms), ("error", error), ("label", label), ("segments", segments), ("flags", flags), ("model_version", model_version)):
                if v is not None:
                    rec[k] = v
            self._enqueue(rec)
        except Exception as exc:                                         # pragma: no cover - reporting must never break the model
            self._warn("log", f"could not queue a record: {exc}")

    def decision(self, action: str, *, role: str = "unspecified", review_seconds: Optional[float] = None, reason: bool = False, confidence_shown: bool = False,
                 model_correct: Optional[bool] = None, person: Optional[str] = None, at: Optional[datetime] = None) -> None:
        """Queue what a person did with an output: accepted, edited, overridden, escalated or ignored. Counted by role. `person` is used only if the platform has a
        compliance sign-off for counting individuals (then it is kept as a one-way pseudonym); otherwise it is discarded by the platform. Never raises."""
        try:
            if self.disabled_reason:
                return
            rec: Dict[str, Any] = {"_d": True, "action": action, "role": role, "reason": bool(reason), "confidence_shown": bool(confidence_shown), "at": (at or datetime.now(timezone.utc)).isoformat()}
            for k, v in (("review_seconds", review_seconds), ("model_correct", model_correct), ("person", person)):
                if v is not None:
                    rec[k] = v
            self._enqueue(rec)
        except Exception as exc:                                         # pragma: no cover
            self._warn("decision", f"could not queue a decision: {exc}")

    def canary(self, name: str, passed: bool, *, model_version: Optional[str] = None, at: Optional[datetime] = None) -> None:
        """Report the result of a fixed check. Never raises."""
        try:
            if self.disabled_reason:
                return
            rec: Dict[str, Any] = {"_c": True, "canary": str(name)[:80], "passed": bool(passed), "at": (at or datetime.now(timezone.utc)).isoformat()}
            if model_version:
                rec["model_version"] = str(model_version)[:120]
            self._enqueue(rec)
        except Exception as exc:                                         # pragma: no cover
            self._warn("canary", f"could not queue a canary result: {exc}")

    def run_canary(self, name: str, ask: Callable[[], Any], expect: Any, *, model_version: Optional[str] = None) -> Optional[bool]:
        """Run `ask()` and judge its answer: `expect` is a substring (case-insensitive) or a function answer -> bool. An exception counts as a failure. Returns the
        verdict (None if it could not be judged). Schedule it yourself (cron, a background thread); ASTRA stores only pass or fail."""
        try:
            try:
                answer = ask()
            except Exception:
                self.canary(name, False, model_version=model_version)
                return False
            ok = bool(expect(answer)) if callable(expect) else str(expect).lower() in str(answer).lower()
            self.canary(name, ok, model_version=model_version)
            return ok
        except Exception as exc:                                         # pragma: no cover
            self._warn("canary", f"could not judge a canary: {exc}")
            return None

    def _enqueue(self, rec: Dict[str, Any]) -> None:
        with self._lock:
            if len(self._q) >= self._max_queue:
                self._q.popleft()
                self.dropped += 1
            self._q.append(rec)
            full = len(self._q) >= self.batch_size
        if full:
            self._wake.set()

    def track(self, *, inputs: Callable[..., Dict[str, Any]], output: Callable[[Any], Any], confidence: Optional[Callable[[Any], Optional[float]]] = None,
              segments: Optional[Callable[..., Dict[str, Any]]] = None, version: Optional[Callable[[Any], Optional[str]]] = None):
        """Decorator for a predict function: logs its inputs (as `inputs(*args, **kwargs)` says), its output, its latency, and an exception as an error (then re-raises)."""
        def wrap(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*a, **k):
                t0 = time.perf_counter()
                try:
                    result = fn(*a, **k)
                except Exception:
                    self._safe(lambda: self.log(inputs(*a, **k), None, latency_ms=(time.perf_counter() - t0) * 1000, error=True, segments=segments(*a, **k) if segments else None))
                    raise
                self._safe(lambda: self.log(inputs(*a, **k), output(result), confidence=confidence(result) if confidence else None, latency_ms=(time.perf_counter() - t0) * 1000,
                                            segments=segments(*a, **k) if segments else None, model_version=version(result) if version else None))
                return result
            return wrapper
        return wrap

    @staticmethod
    def _safe(fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception as exc:                                         # a bug in your extractor must not break the prediction
            log.warning("astra_runtime: could not describe a prediction: %s", exc)

    # ── plumbing ─────────────────────────────────────────────────

    def flush(self, timeout: float = 5.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end and not self.disabled_reason:
            if not self._send_once():
                break
        while time.monotonic() < end and self._busy and not self.disabled_reason:     # a batch the background thread is still sending
            time.sleep(0.05)
        with self._lock:
            return not self._q and not self._busy

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
            except Exception:                                            # pragma: no cover
                pass

    def _http(self, payload: Dict[str, Any], path: str = "records"):
        req = urllib.request.Request(f"{self.url}/api/model-monitor/{self.key}/{path}", data=json.dumps(payload, default=str).encode("utf-8"), method="POST",
                                     headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json", "User-Agent": f"astra-model-monitor/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read().decode("utf-8") or "null")
        except urllib.error.HTTPError as e:
            try:
                body: Any = json.loads(e.read().decode("utf-8") or "null")
            except Exception:
                body = None
            if e.code == 429:
                self._backoff = max(self._backoff, float(e.headers.get("Retry-After", "5") or 5))
            return e.code, body
        except Exception as e:
            return 0, str(e)

    def _send_once(self) -> bool:
        with self._lock:
            if not self._q:
                return False
            kind = lambda r: "decisions" if r.get("_d") else ("canaries" if r.get("_c") else "records")      # noqa: E731
            first = kind(self._q[0])
            batch: List[Dict[str, Any]] = []
            while self._q and len(batch) < self.batch_size and kind(self._q[0]) == first:
                batch.append(self._q.popleft())
            self._busy += 1
        try:
            return self._deliver(first, batch)
        finally:
            with self._lock:
                self._busy -= 1

    def _deliver(self, first: str, batch: List[Dict[str, Any]]) -> bool:
        if first == "decisions":
            status, body = self._http({"decisions": [{k: v for k, v in d.items() if k != "_d"} for d in batch]}, "decisions")
        elif first == "canaries":
            status, body = self._http({"results": [{k: v for k, v in d.items() if k != "_c"} for d in batch]}, "canaries")
        else:
            status, body = self._http({"records": batch})
        if status == 200:
            self.sent += len(batch)
            self._backoff = 0.0
            if isinstance(body, dict):
                if first == "records":
                    self.status = body.get("status")
                self.rejected += int(body.get("rejected") or 0)
            return True
        if status in (401, 403):
            self._disable(f"the platform refused the key (HTTP {status}): {body.get('detail') if isinstance(body, dict) else body}")
            return False
        if status in (400, 404, 413, 422):                               # a bad request will not get better by retrying: drop it and say why, once
            self._warn(f"bad{status}", f"the platform rejected a batch (HTTP {status}): {body.get('detail') if isinstance(body, dict) else body}")
            return True
        with self._lock:                                                 # 429, 5xx or unreachable: put it back, in order, and wait
            self._q.extendleft(reversed(batch))
            while len(self._q) > self._max_queue:
                self._q.pop()
                self.dropped += 1
        self._backoff = min(30.0, max(self._backoff * 2, 1.0)) if status != 429 else self._backoff
        self._warn("unreachable", f"could not reach the platform (HTTP {status}); will keep retrying with back-off")
        return False

    def _run(self) -> None:
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
            except Exception as exc:                                     # pragma: no cover
                self._warn("loop", f"internal error: {exc}")
