"""
Tests for how the SDK reaches ASTRA safely (astra_runtime/transport.py).

    cd sdk/python && python -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from astra_runtime import transport                       # noqa: E402
from astra_runtime.client import Client                   # noqa: E402
from astra_runtime.monitor import ModelMonitor            # noqa: E402


class Transport(unittest.TestCase):
    def setUp(self):
        self.saved = {k: os.environ.pop(k, None) for k in ("ASTRA_ALLOW_INSECURE", "ASTRA_CA_BUNDLE", "ASTRA_CLIENT_CERT", "ASTRA_CLIENT_KEY")}

    def tearDown(self):
        for k, v in self.saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    def test_https_is_accepted(self):
        self.assertIsNone(transport.url_problem("https://astra.example.org"))

    def test_plain_http_is_accepted_only_to_this_machine(self):
        for ok in ("http://localhost:8765", "http://127.0.0.1:5173", "http://[::1]:8765", "http://astra.localhost"):
            self.assertIsNone(transport.url_problem(ok), ok)
        for bad in ("http://astra.example.org", "http://10.0.0.5:8765"):
            self.assertIn("plain http", transport.url_problem(bad), bad)

    def test_the_override_is_explicit(self):
        os.environ["ASTRA_ALLOW_INSECURE"] = "1"
        self.assertIsNone(transport.url_problem("http://10.0.0.5:8765"))

    def test_other_schemes_are_refused(self):
        self.assertIsNotNone(transport.url_problem("ftp://astra.example.org"))
        self.assertIsNotNone(transport.url_problem(""))

    def test_the_certificate_and_host_name_are_checked_and_old_tls_refused(self):
        ctx = transport.ssl_context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode.name, "CERT_REQUIRED")
        self.assertGreaterEqual(ctx.minimum_version.value, transport.ssl.TLSVersion.TLSv1_2.value)

    def test_an_unreadable_private_authority_is_an_error_not_a_silent_fallback(self):
        os.environ["ASTRA_CA_BUNDLE"] = os.path.join(os.path.dirname(__file__), "no-such-ca.pem")
        with self.assertRaises(OSError):
            transport.ssl_context()

    def test_a_client_that_would_send_its_key_in_clear_switches_itself_off(self):
        c = Client(url="http://astra.example.org", api_key="astra_x", agent="a", start=False)
        self.assertIn("plain http", c.disabled_reason or "")
        m = ModelMonitor("m", url="http://astra.example.org", api_key="astra_x", start=False)
        self.assertIn("plain http", m.disabled_reason or "")

    def test_a_client_to_https_or_to_this_machine_stays_on(self):
        for url in ("https://astra.example.org", "http://localhost:8765"):
            c = Client(url=url, api_key="astra_x", agent="a", start=False)
            self.assertIsNone(c.disabled_reason, url)
            m = ModelMonitor("m", url=url, api_key="astra_x", start=False)
            self.assertIsNone(m.disabled_reason, url)


if __name__ == "__main__":
    unittest.main()
