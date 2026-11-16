"""
Tests for astra-check against a stand-in platform (a real local HTTP server, no mocks of the CLI itself).

    cd sdk/python && python -m unittest discover -s tests
"""
import io
import json
import os
import sys
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from astra_runtime import check_cli   # noqa: E402

SUMMARY = {"passed": 20, "applicable": 21, "not_applicable": 1}


class Platform:
    def __init__(self, admit=True, reasons=None, run_status=201):
        self.admit, self.reasons, self.run_status, self.calls = admit, reasons or [], run_status, []
        p = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                p.calls.append(("POST", self.path, body, self.headers.get("Authorization")))
                if p.run_status != 201:
                    return self._send(p.run_status, {"detail": "no such design"})
                self._send(201, {"summary": SUMMARY})

            def do_GET(self):
                p.calls.append(("GET", self.path, None, self.headers.get("Authorization")))
                self._send(200, {"admit": p.admit, "reasons": p.reasons, "run": {"summary": SUMMARY}})

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = check_cli.main(args)
    return code, out.getvalue(), err.getvalue()


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.envs = {k: os.environ.pop(k, None) for k in ("ASTRA_URL", "ASTRA_KEY")}

    def tearDown(self):
        for k, v in self.envs.items():
            if v is not None:
                os.environ[k] = v

    def test_admitted_exits_zero_and_runs_the_probe_first_when_asked(self):
        p = Platform()
        self.addCleanup(p.stop)
        code, out, _ = run(["--design", "refund-agent", "--run", "--url", p.url, "--key", "astra_k_s"])
        self.assertEqual(code, 0)
        self.assertIn("ADMITTED: refund-agent (20 of 21 applicable scenarios passed, 1 not applicable)", out)
        self.assertEqual([c[0] for c in p.calls], ["POST", "GET"])
        self.assertEqual(p.calls[0][2], {"design_key": "refund-agent", "trigger": "admission"})
        self.assertTrue(all(c[3] == "Bearer astra_k_s" for c in p.calls))

    def test_refused_exits_one_and_prints_each_reason(self):
        p = Platform(admit=False, reasons=["Scenario DVG-TOOL-01 (Tool out of scope) failed: the planted defect was not caught.", "The newest Probe run is of an earlier version of the design. Run the Probe again."])
        self.addCleanup(p.stop)
        code, out, _ = run(["--design", "refund-agent", "--url", p.url, "--key", "k"])
        self.assertEqual(code, 1)
        self.assertEqual([c[0] for c in p.calls], ["GET"], "without --run nothing is run")
        self.assertIn("REFUSED: refund-agent", out)
        self.assertIn("  - Scenario DVG-TOOL-01", out)
        self.assertIn("  - The newest Probe run is of an earlier version", out)

    def test_a_check_that_could_not_be_made_is_exit_two_never_an_admission(self):
        code, _, err = run(["--design", "x"])
        self.assertEqual(code, 2)
        self.assertIn("ASTRA_URL and ASTRA_KEY", err)
        code, _, err = run(["--design", "x", "--url", "http://astra.example.org", "--key", "k"])
        self.assertEqual(code, 2)
        self.assertIn("plain http", err)
        code, _, err = run(["--design", "x", "--url", "http://127.0.0.1:9", "--key", "k", "--timeout", "1"])
        self.assertEqual(code, 2)
        self.assertIn("HTTP 0", err)
        p = Platform(run_status=404)
        self.addCleanup(p.stop)
        code, _, err = run(["--design", "zz", "--run", "--url", p.url, "--key", "k"])
        self.assertEqual(code, 2)
        self.assertIn("no such design", err)

    def test_json_output_is_the_answer_of_the_platform(self):
        p = Platform(admit=False, reasons=["r"])
        self.addCleanup(p.stop)
        code, out, _ = run(["--design", "d", "--url", p.url, "--key", "k", "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["reasons"], ["r"])


if __name__ == "__main__":
    unittest.main()
