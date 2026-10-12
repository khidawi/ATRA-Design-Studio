"""
ModelMonitor: report how a model in production behaves (what it was given, what it answered) to an ASTRA production monitor.

    from astra_runtime import ModelMonitor
    mon = ModelMonitor("credit-model")                    # ASTRA_URL and ASTRA_KEY come from the environment

    mon.log(inputs={"age": 41, "plan": "gold"}, output="approve", confidence=0.82, latency_ms=41, segments={"gender": "F"})

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
            label: Any = None, segments: Optional[Dict[str, Any]] = None, flags: Optional[Dict[str, bool]] = None, at: Optional[datetime] = None) -> None:
        """Queue one prediction. Never raises. `label` is the true answer, if you already know it; `segments` are the groups to compare for fairness."""
        try:
            if self.disabled_reason or (self.sample < 1.0 and random.random() > self.sample):
                return
            rec: Dict[str, Any] = {"inputs": inputs, "output": output, "at": (at or datetime.now(timezone.utc)).isoformat()}
            for k, v in (("confidence", confidence), ("latency_ms", latency_ms), ("error", error), ("label", label), ("segments", segments), ("flags", flags)):
                if v is not None:
                    rec[k] = v
            with self._lock:
                if len(self._q) >= self._max_queue:
                    self._q.popleft()
                    self.dropped += 1
                self._q.append(rec)
                full = len(self._q) >= self.batch_size
            if full:
                self._wake.set()
        except Exception as exc:                                         # pragma: no cover - reporting must never break the model
            self._warn("log", f"could not queue a record: {exc}")

    def track(self, *, inputs: Callable[..., Dict[str, Any]], output: Callable[[Any], Any], confidence: Optional[Callable[[Any], Optional[float]]] = None,
              segments: Optional[Callable[..., Dict[str, Any]]] = None):
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
                                            segments=segments(*a, **k) if segments else None))
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
            except Exception:                                            # pragma: no cover
                pass

    def _http(self, payload: Dict[str, Any]):
        req = urllib.request.Request(f"{self.url}/api/model-monitor/{self.key}/records", data=json.dumps(payload, default=str).encode("utf-8"), method="POST",
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
            batch: List[Dict[str, Any]] = [self._q.popleft() for _ in range(min(self.batch_size, len(self._q)))]
        status, body = self._http({"records": batch})
        if status == 200:
            self.sent += len(batch)
            self._backoff = 0.0
            if isinstance(body, dict):
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
