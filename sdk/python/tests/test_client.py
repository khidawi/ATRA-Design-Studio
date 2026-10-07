"""
Tests for astra_runtime against a real local HTTP server that behaves like the platform (no mocks of the client's own code).

    cd sdk/python && python -m unittest discover -s tests
"""
import asyncio
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import astra_runtime as astra                                    # noqa: E402
from astra_runtime.adapters.openai_agents import AstraTracingProcessor, guess_write   # noqa: E402
from astra_runtime.client import AstraBlocked, Client           # noqa: E402


class Platform:
    """A stand-in for the ASTRA API with scripted behaviour."""

    def __init__(self):
        self.batches, self.script, self.contract, self.auth = [], [], {"state": "unknown"}, []
        platform = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, headers=None):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                platform.auth.append(self.headers.get("Authorization"))
                if platform.script:
                    code, headers = platform.script.pop(0)
                    if code != 202:
                        return self._send(code, {"detail": f"scripted {code}"}, headers)
                platform.batches.append(body)
                self._send(202, {"accepted": len(body["events"]), "discovered": False})

            def do_GET(self):
                platform.auth.append(self.headers.get("Authorization"))
                if self.path.startswith("/api/runtime/contract/"):
                    return self._send(200, platform.contract)
                if self.path == "/api/auth/me":
                    return self._send(200, {"user": {"full_name": "API key: test", "role": "collector"}})
                self._send(404, {})

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()

    def events(self):
        return [e for b in self.batches for e in b["events"]]


def wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.p = Platform()

    def tearDown(self):
        self.p.stop()

    def client(self, **kw):
        kw.setdefault("flush_interval", 0.05)
        c = Client(self.p.url, "astra_abcd1234_secret", "refund-agent", **kw)
        self.addCleanup(c.close)
        return c

    def test_events_are_delivered_in_a_batch_with_only_names(self):
        c = self.client()
        c.tool_call("stripe.refunds.create", write=True)
        c.delegation("notify-agent")
        c.mcp_connect("mcp://orders", signed=True)
        c.data_access("order-store")
        c.memory_write("long_term")
        self.assertTrue(c.flush())
        self.assertTrue(wait_for(lambda: len(self.p.events()) == 5))
        evs = self.p.events()
        self.assertEqual([e["type"] for e in evs], ["tool_call", "delegation", "mcp_connect", "data_access", "memory_write"])
        self.assertEqual(self.p.batches[0]["agent"], "refund-agent")
        self.assertEqual(evs[0]["write"], True)
        self.assertEqual(evs[4]["scope"], "long_term")
        self.assertTrue(all("at" in e and set(e) <= {"type", "name", "at", "write", "signed", "scope"} for e in evs))      # nothing else leaves the process
        self.assertTrue(all(a == "Bearer astra_abcd1234_secret" for a in self.p.auth))
        c.close()

    def test_a_down_platform_never_raises_and_the_queue_is_bounded(self):
        c = Client("http://127.0.0.1:9", "astra_x_y", "agent-a", max_queue=3, flush_interval=0.05, timeout=0.3)
        for i in range(10):
            c.tool_call(f"t{i}")                                                  # must not raise
        self.assertEqual(c.dropped, 7)
        self.assertFalse(c.flush(timeout=0.5))                                    # still queued, no exception
        self.assertEqual(len(c._q), 3)
        c.close()

    def test_a_failed_batch_is_retried_in_order(self):
        self.p.script = [(503, {})]
        c = self.client()
        for n in ("a", "b", "c"):
            c.tool_call(n)
        self.assertTrue(wait_for(lambda: len(self.p.events()) == 3, 8))
        self.assertEqual([e["name"] for e in self.p.events()], ["a", "b", "c"])
        c.close()

    def test_a_refused_key_disables_reporting_quietly(self):
        self.p.script = [(401, {})]
        errors = []
        c = self.client(on_error=errors.append)
        c.tool_call("x")
        self.assertTrue(wait_for(lambda: c.disabled_reason is not None))
        c.tool_call("y")                                                          # a no-op now, not an error
        self.assertIn("refused the key", c.disabled_reason)
        self.assertEqual(len(errors), 1)
        c.close()

    def test_too_many_requests_backs_off_by_retry_after(self):
        self.p.script = [(429, {"Retry-After": "1"})]
        c = self.client()
        c.tool_call("x")
        self.assertTrue(wait_for(lambda: c._backoff >= 1.0))
        self.assertTrue(wait_for(lambda: len(self.p.events()) == 1, 8))
        c.close()

    def test_enforcement_refuses_what_the_contract_does_not_allow(self):
        self.p.contract = {"state": "contract", "version": "1.0.0", "allowed": {"tools": [{"name": "lookup_order", "write": False}], "mcp_servers": [{"name": "mcp://orders"}],
                                                                              "delegates_to": ["notify-agent"], "data": ["order-store"], "long_term_memory": False}}
        c = self.client(enforce=True)
        calls = []

        @c.tool("lookup_order")
        def lookup(x):
            calls.append(x)
            return x

        @c.tool("shell.exec")
        def shell(x):
            calls.append(("shell", x))

        self.assertEqual(lookup(1), 1)
        with self.assertRaises(AstraBlocked):
            shell("rm -rf")
        self.assertEqual(calls, [1])                                              # the forbidden function never ran
        self.assertTrue(c.is_allowed("delegation", "notify-agent") and not c.is_allowed("delegation", "stranger"))
        self.assertTrue(c.is_allowed("mcp", "mcp://orders") and not c.is_allowed("mcp", "mcp://other"))
        self.assertTrue(c.is_allowed("data", "order-store") and not c.is_allowed("data", "customers"))
        c.close()

    def test_enforcement_fails_open_without_a_contract_and_closed_when_strict(self):
        self.p.contract = {"state": "no_contract"}
        self.assertTrue(self.client(enforce=True).is_allowed("tool", "anything"))
        self.assertFalse(self.client(enforce=True, strict=True).is_allowed("tool", "anything"))
        down = Client("http://127.0.0.1:9", "astra_x_y", "a-agent", enforce=True, timeout=0.2)
        self.assertTrue(down.is_allowed("tool", "anything"))                      # unreachable platform: the agent keeps working

    def test_the_decorator_handles_async_functions_and_keeps_the_signature(self):
        c = self.client()

        @c.tool(write=True)
        async def issue_refund(order_id, amount=1):
            """Refund."""
            return (order_id, amount)

        self.assertEqual(asyncio.run(issue_refund(7, amount=3)), (7, 3))
        self.assertEqual(issue_refund.__name__, "issue_refund")
        self.assertEqual(issue_refund.__doc__, "Refund.")
        c.flush()
        self.assertTrue(wait_for(lambda: any(e["name"] == "issue_refund" and e["write"] is True for e in self.p.events())))
        c.close()

    def test_one_process_can_report_several_agents(self):
        c = self.client()
        c.tool_call("a-tool")
        with c.as_agent("billing-agent"):
            c.tool_call("b-tool")
        c.flush()
        self.assertTrue(wait_for(lambda: len(self.p.batches) >= 2))
        self.assertEqual({b["agent"]: [e["name"] for e in b["events"]] for b in self.p.batches}, {"refund-agent": ["a-tool"], "billing-agent": ["b-tool"]})
        c.close()

    def test_check_and_missing_configuration(self):
        self.assertEqual(self.client().check(), {"ok": True, "key": "API key: test", "role": "collector"})
        bare = Client("", "", "x-agent")
        bare.tool_call("x")                                                       # no URL or key: quiet no-op
        self.assertIn("not set", bare.disabled_reason)
        self.assertTrue(bare.flush())

    def test_module_level_helpers_do_nothing_before_init_and_report_after(self):
        astra._default = None
        astra.tool_call("x")                                                      # no init: must not raise
        astra.init(self.p.url, "astra_a_b", "mod-agent", flush_interval=0.05)
        astra.tool_call("y", write=False)
        astra.flush()
        self.assertTrue(wait_for(lambda: any(e["name"] == "y" for e in self.p.events())))
        astra.client().close()
        astra._default = None


class Span:
    def __init__(self, sid, parent, **data):
        self.span_id, self.parent_id = sid, parent
        self.span_data = type("D", (), data)()


class OpenAIAdapterTests(unittest.TestCase):
    def test_function_handoff_and_mcp_spans_become_events_for_the_enclosing_agent(self):
        p = Platform()
        try:
            c = Client(p.url, "astra_a_b", "default-agent", flush_interval=0.05)
            proc = AstraTracingProcessor(c, write_tools={"lookup_account"})
            agent = Span("s1", None, type="agent", name="Refund agent")
            proc.on_span_start(agent)
            fn = Span("s2", "s1", type="function", name="issue_refund")
            proc.on_span_start(fn)
            proc.on_span_end(fn)
            read = Span("s3", "s1", type="function", name="lookup_account")
            proc.on_span_start(read)
            proc.on_span_end(read)
            hand = Span("s4", "s1", type="handoff", from_agent="Refund agent", to_agent="Notification agent")
            proc.on_span_start(hand)
            proc.on_span_end(hand)
            mcp = Span("s5", "s1", type="mcp_tools", server="orders")
            proc.on_span_start(mcp)
            proc.on_span_end(mcp)
            proc.on_span_end(agent)
            c.flush()
            self.assertTrue(wait_for(lambda: len(p.events()) == 4))
            by = {e["name"]: e for e in p.events()}
            self.assertEqual({b["agent"] for b in p.batches}, {"Refund agent"})
            self.assertTrue(by["issue_refund"]["write"] is True and by["lookup_account"]["write"] is True)       # explicit write_tools wins over the name
            self.assertEqual(by["Notification agent"]["type"], "delegation")
            self.assertEqual(by["mcp://orders"]["type"], "mcp_connect")
            c.close()
        finally:
            p.stop()

    def test_the_processor_survives_odd_spans_and_missing_clients(self):
        proc = AstraTracingProcessor(None)
        proc.on_span_end(Span("x", None, type="function", name="t"))              # no client initialised: nothing happens
        proc.on_span_end(object())
        proc.on_span_start(object())
        proc.shutdown()

    def test_write_guessing_is_cautious(self):
        self.assertTrue(guess_write("issue_refund") and guess_write("send_email"))
        self.assertFalse(guess_write("list_orders"))
        self.assertIsNone(guess_write("frobnicate"))


if __name__ == "__main__":
    unittest.main()
