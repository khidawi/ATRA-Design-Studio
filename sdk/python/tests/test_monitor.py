"""
Tests for astra_runtime.ModelMonitor against a real local HTTP server that behaves like the platform's records endpoint.

    cd sdk/python && python -m unittest discover -s tests
"""
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from astra_runtime.monitor import ModelMonitor, monitor_key   # noqa: E402


class Platform:
    def __init__(self):
        self.posts, self.script = [], []
        platform = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
                platform.posts.append((self.path, self.headers.get("Authorization"), body))
                code, resp, headers = platform.script.pop(0) if platform.script else (200, {"accepted": len(body.get("records") or body.get("decisions") or []), "rejected": 0, "status": "OK"}, {})
                raw = json.dumps(resp).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()


class ModelMonitorTests(unittest.TestCase):
    def setUp(self):
        self.p = Platform()

    def tearDown(self):
        self.p.stop()

    def mon(self, **kw):
        return ModelMonitor("Credit Model", url=self.p.url, api_key="astra_k", **kw)

    def test_a_name_becomes_the_monitors_key(self):
        self.assertEqual(monitor_key("Credit Model v2!"), "credit-model-v2")

    def test_records_are_sent_in_a_batch_with_the_key(self):
        m = self.mon(start=False)
        for i in range(3):
            m.log({"age": 40 + i}, "approve", confidence=0.8, latency_ms=12, segments={"g": "F"})
        self.assertTrue(m.flush())
        path, auth, body = self.p.posts[0]
        self.assertEqual((path, auth), ("/api/model-monitor/credit-model/records", "Bearer astra_k"))
        self.assertEqual(len(body["records"]), 3)
        self.assertEqual(body["records"][0]["inputs"], {"age": 40})
        self.assertEqual(m.sent, 3)
        self.assertEqual(m.status, "OK")

    def test_the_background_thread_sends_without_a_flush(self):
        m = self.mon(flush_interval=0.05)
        m.log({"a": 1}, "x")
        for _ in range(60):
            if self.p.posts:
                break
            time.sleep(0.05)
        m.close()
        self.assertTrue(self.p.posts)

    def test_it_never_raises_into_the_caller(self):
        m = ModelMonitor("x", url="http://127.0.0.1:1", api_key="k", start=False)
        m.log({"a": object()}, "y")                                   # not serialisable by the standard encoder: str() is used, and nothing is raised
        m.flush(timeout=0.2)
        ModelMonitor("x", url="", api_key="", start=False).log({"a": 1}, 1)
        ModelMonitor("", url="http://x", api_key="k", start=False).log({"a": 1}, 1)

    def test_a_refused_key_disables_it_once(self):
        self.p.script = [(401, {"detail": "no"}, {})]
        m = self.mon(start=False)
        m.log({"a": 1}, "x")
        m.flush()
        self.assertIn("refused the key", m.disabled_reason)
        m.log({"a": 2}, "x")
        self.assertEqual(len(m._q), 0)

    def test_429_puts_the_batch_back_and_waits(self):
        self.p.script = [(429, {"detail": "slow"}, {"Retry-After": "7"})]
        m = self.mon(start=False)
        m.log({"a": 1}, "x")
        self.assertFalse(m.flush(timeout=0.3))
        self.assertEqual(len(m._q), 1)
        self.assertGreaterEqual(m._backoff, 7)

    def test_a_bad_request_is_dropped_not_retried_forever(self):
        self.p.script = [(422, {"detail": "bad"}, {})]
        m = self.mon(start=False)
        m.log({"a": 1}, "x")
        self.assertTrue(m.flush())
        self.assertEqual(len(m._q), 0)

    def test_the_queue_is_bounded(self):
        m = self.mon(start=False, max_queue=5, batch_size=1000)
        for i in range(12):
            m.log({"a": i}, "x")
        self.assertEqual((len(m._q), m.dropped), (5, 7))

    def test_sampling_sends_a_fraction(self):
        m = self.mon(start=False, sample=0.2, batch_size=100000)
        for i in range(2000):
            m.log({"a": i}, "x")
        self.assertTrue(250 < len(m._q) < 550, len(m._q))

    def test_track_logs_a_call_with_latency_and_an_error_as_an_error(self):
        m = self.mon(start=False)

        @m.track(inputs=lambda x: {"x": x}, output=lambda r: r["label"], confidence=lambda r: r["p"])
        def predict(x):
            if x < 0:
                raise ValueError("bad input")
            return {"label": "yes", "p": 0.9}

        self.assertEqual(predict(3)["label"], "yes")
        with self.assertRaises(ValueError):
            predict(-1)
        m.flush()
        recs = self.p.posts[0][2]["records"]
        self.assertEqual((recs[0]["output"], recs[0]["confidence"]), ("yes", 0.9))
        self.assertGreaterEqual(recs[0]["latency_ms"], 0)
        self.assertTrue(recs[1]["error"] and recs[1]["output"] is None)

    def test_a_broken_extractor_does_not_break_the_prediction(self):
        m = self.mon(start=False)

        @m.track(inputs=lambda x: 1 / 0, output=lambda r: r)
        def predict(x):
            return x * 2

        self.assertEqual(predict(4), 8)

    def test_a_version_and_a_decision_go_to_their_own_endpoints(self):
        m = self.mon()
        m.log({"a": 1}, "yes", model_version="gpt-x-2026-04")
        m.decision("accepted", role="loan officer", review_seconds=12, model_correct=True, person="alice")
        m.decision("overridden", role="loan officer")
        m.log({"a": 2}, "no")
        self.assertTrue(m.flush())
        by_path = [(path.rsplit("/", 1)[-1], body) for path, _, body in self.p.posts]
        self.assertEqual([x[0] for x in by_path], ["records", "decisions", "records"])
        self.assertEqual(by_path[0][1]["records"][0]["model_version"], "gpt-x-2026-04")
        d = by_path[1][1]["decisions"]
        self.assertEqual([x["action"] for x in d], ["accepted", "overridden"])
        self.assertNotIn("_d", d[0])
        self.assertEqual(m.sent, 4)

    def test_track_can_say_which_version_answered(self):
        m = self.mon()

        class R:
            text, model = "hi", "gpt-x-2026-07"

        @m.track(inputs=lambda q: {"q": q}, output=lambda r: r.text, version=lambda r: r.model)
        def ask(q):
            return R()

        ask("x")
        m.flush()
        self.assertEqual(self.p.posts[0][2]["records"][0]["model_version"], "gpt-x-2026-07")

    def test_a_decision_never_raises(self):
        m = self.mon()
        m.decision(None, role=None, review_seconds=object())

if __name__ == "__main__":
    unittest.main()
