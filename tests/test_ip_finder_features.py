import contextlib
import io
import json
import os
import socket
import tempfile
import unittest
from unittest import mock

import ip_finder as app


class NewFeatureTests(unittest.TestCase):
    def setUp(self):
        app.load_optional_imports()

    def capture(self, function, *args, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return function(*args, **kwargs)

    def test_identity_and_menu_options_29_to_40(self):
        self.assertEqual(app.TOOL_NAME, "IP-FINDER")
        self.assertEqual(app.AUTHOR, "DevBrezz")
        self.assertEqual(app.VERSION, "1.0.0")
        menu = "\n".join(app.menu_lines())
        for number in range(1, 41):
            self.assertIn(f"[{number:02d}]", menu)
        dispatch_source = __import__("inspect").getsource(app._dispatch)
        for number in range(29, 41):
            self.assertIn(f'choice == "{number:02d}"', dispatch_source)

    def test_dns_query_comparison_rejects_invalid_values_before_network(self):
        self.assertIn("Error", self.capture(app.dns_query_comparison, "bad domain", "A")[0])
        self.assertIn("Error", self.capture(app.dns_query_comparison, "example.com", "BOGUS")[0])

    def test_route_diagnostics_rejects_invalid_host(self):
        result = self.capture(app.route_diagnostics, "bad host; command")
        self.assertIn("Error", result[0])

    def test_connection_monitor_bounds_and_invalid_inputs(self):
        self.assertIn("Error", self.capture(app.connection_stability_monitor, "example.com", 443, 31, 1)[0])
        self.assertIn("Error", self.capture(app.connection_stability_monitor, "not a host", 443, 2, 1)[0])

    def test_tls_checker_rejects_invalid_port(self):
        result = self.capture(app.tls_compatibility_check, "example.com", 70000)
        self.assertIn("Error", result[0])

    def test_http_method_checker_rejects_bad_url_without_network(self):
        result = self.capture(app.http_method_checker, "javascript:alert(1)")
        self.assertIn("Error", result[0])

    def test_ipv6_readiness_rejects_invalid_domain(self):
        self.assertIn("Error", self.capture(app.ipv6_readiness_check, "invalid domain")[0])

    def test_history_json_storage_is_local_and_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(app, "_local_data_dir", return_value=tmp):
                path = app._save_local_json("test.json", [{"value": 42}])
                self.assertTrue(os.path.isfile(path))
                self.assertEqual(app._load_local_json("test.json", []), [{"value": 42}])

    def test_batch_checker_rejects_missing_path(self):
        result = self.capture(app.batch_domain_checker, "")
        self.assertIn("Error", result[0])

    def test_email_dns_deep_check_rejects_invalid_domain(self):
        result = self.capture(app.email_dns_deep_check, "not a domain")
        self.assertIn("Error", result[0])

    def test_configuration_validator_is_local_only(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(app, "_local_data_dir", return_value=tmp):
            result = self.capture(app.configuration_validator)
        self.assertTrue(any("Python:" in line for line in result))
        self.assertTrue(any("does not contact external targets" in line for line in result))

    def test_uptime_monitor_rejects_too_many_checks(self):
        result = self.capture(app.uptime_history_monitor, "https://example.com", 31, 5)
        self.assertIn("Error", result[0])

    def test_diagnostic_profile_rejects_unknown_profile_without_network(self):
        result = self.capture(app.diagnostic_profiles, "stealth", "example.com")
        self.assertIn("Error", result[0])

    def test_dns_query_comparison_uses_existing_resolver_set(self):
        def fake_query(resolver_ip, domain, rtype, results):
            results[resolver_ip] = ["192.0.2.10"]
        with mock.patch.object(app, "_query_resolver", side_effect=fake_query):
            result = self.capture(app.dns_query_comparison, "example.com", "A")
        self.assertTrue(any("answers agree" in line for line in result))
        self.assertEqual(len(app.PUBLIC_RESOLVERS), 4)

    def test_route_diagnostics_uses_bounded_argument_list(self):
        completed = type("Completed", (), {"stdout": "hop 1 192.0.2.1", "stderr": "", "returncode": 0})()
        with mock.patch.object(app.shutil, "which", return_value="/usr/bin/traceroute"), \
             mock.patch.object(app.subprocess, "run", return_value=completed) as run:
            result = self.capture(app.route_diagnostics, "example.com")
        self.assertTrue(any("hop 1" in line for line in result))
        args, kwargs = run.call_args
        self.assertIn("-m", args[0])
        self.assertIn("12", args[0])
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(kwargs["timeout"], 18)

    def test_connection_stability_monitor_with_mocked_socket(self):
        with mock.patch.object(app.socket, "create_connection") as connect, \
             mock.patch.object(app.time, "sleep"):
            result = self.capture(app.connection_stability_monitor, "example.com", 443, 2, 1)
        self.assertTrue(any("Successful: 2/2" in line for line in result))
        self.assertEqual(connect.call_count, 2)

    def test_tls_compatibility_check_with_mocked_handshakes(self):
        context = mock.MagicMock()
        context.wrap_socket.return_value.__enter__.return_value.version.return_value = "TLSv1.2"
        with mock.patch.object(app.socket, "create_connection"), \
             mock.patch.object(app.ssl, "SSLContext", return_value=context):
            result = self.capture(app.tls_compatibility_check, "example.com", 443)
        self.assertTrue(any("TLSv1.2: negotiated" in line for line in result))

    def test_http_method_checker_sends_only_options(self):
        response = mock.MagicMock(status_code=204, headers={"Allow": "GET, HEAD, OPTIONS"})
        requests = mock.MagicMock()
        requests.options.return_value = response
        with mock.patch.object(app, "_requests", requests):
            result = self.capture(app.http_method_checker, "https://example.com")
        requests.options.assert_called_once()
        requests.get.assert_not_called()
        self.assertTrue(any("GET, HEAD, OPTIONS" in line for line in result))

    def test_ipv6_readiness_with_mocked_ipv6_route(self):
        info = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0))
        with mock.patch.object(app.socket, "getaddrinfo", return_value=[info]), \
             mock.patch.object(app.socket, "create_connection"):
            result = self.capture(app.ipv6_readiness_check, "example.com")
        self.assertTrue(any("IPv6 path reachable" in line for line in result))

    def test_historical_results_saves_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(app, "_local_data_dir", return_value=tmp), \
             mock.patch.object(app, "ask", return_value="1"):
            original = list(app.RESULTS.sections)
            app.RESULTS.sections[:] = [("test", ["sample result"])]
            try:
                result = self.capture(app.historical_results)
                saved = app._load_local_json("session_history.json", [])
            finally:
                app.RESULTS.sections[:] = original
        self.assertTrue(any("Saved snapshot" in line for line in result))
        self.assertEqual(saved[0]["sections"][0]["title"], "test")

    def test_batch_domain_checker_with_mocked_dns(self):
        import dns.resolver
        class Record:
            def to_text(self):
                return "192.0.2.10"
        resolver = mock.MagicMock()
        def resolve(name, rtype, lifetime=None):
            if rtype == "A":
                return [Record()]
            raise dns.resolver.NoAnswer()
        resolver.resolve.side_effect = resolve
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("example.com\n")
            filepath = handle.name
        try:
            with mock.patch("dns.resolver.Resolver", return_value=resolver):
                result = self.capture(app.batch_domain_checker, filepath)
        finally:
            os.unlink(filepath)
        self.assertTrue(any("example.com: A=192.0.2.10" in line for line in result))

    def test_email_dns_deep_check_with_mocked_records(self):
        import dns.resolver
        class Record:
            def __init__(self, value): self.value = value
            def to_text(self): return self.value
        def resolve(name, rtype, lifetime=None):
            if name == "example.com" and rtype == "MX": return [Record("10 mail.example.com.")]
            if name == "example.com" and rtype == "TXT": return [Record('"v=spf1 -all"')]
            if name == "_dmarc.example.com": return [Record('"v=DMARC1; p=reject"')]
            if name == "selector1._domainkey.example.com": return [Record('"v=DKIM1; p=abc"')]
            raise dns.resolver.NoAnswer()
        with mock.patch("dns.resolver.Resolver") as resolver_cls:
            resolver_cls.return_value.resolve.side_effect = resolve
            result = self.capture(app.email_dns_deep_check, "example.com")
        self.assertIn("  DMARC policy: reject", result)
        self.assertTrue(any("DKIM selector selector1: record found" in line for line in result))

    def test_uptime_history_persists_mocked_http_checks(self):
        response = mock.MagicMock(status_code=200)
        requests = mock.MagicMock()
        requests.get.return_value = response
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(app, "_local_data_dir", return_value=tmp), \
             mock.patch.object(app, "_requests", requests), \
             mock.patch.object(app.time, "sleep"):
            result = self.capture(app.uptime_history_monitor, "https://example.com", 2, 5)
            saved = app._load_local_json("uptime_history.json", [])
        self.assertTrue(any("100.0%" in line for line in result))
        self.assertEqual(len(saved), 1)
        self.assertEqual(len(saved[0]["checks"]), 2)
        self.assertEqual(requests.get.call_count, 2)

    def test_web_diagnostic_profile_uses_existing_tools(self):
        with mock.patch.object(app, "http_response_diagnostics", return_value=["HTTP: ok"]), \
             mock.patch.object(app, "security_headers_analyzer", return_value=["Headers: ok"]):
            result = self.capture(app.diagnostic_profiles, "Web", "https://example.com")
        self.assertIn("HTTP: ok", result)
        self.assertIn("Headers: ok", result)

    def test_original_syntax(self):
        import ast
        with open(app.__file__, "r", encoding="utf-8") as handle:
            ast.parse(handle.read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
