"""Offline/mock-based regression tests for IP-FINDER's original feature set."""
import contextlib
import io
from contextlib import ExitStack
import json
import os
import socket
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import dns.resolver
import requests

import ip_finder as app


class AllFeatureRegressionTests(unittest.TestCase):
    def setUp(self):
        app.load_optional_imports()

    def capture(self, function, *args, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return function(*args, **kwargs)

    def test_validation_and_url_normalization_edges(self):
        self.assertTrue(app.validate_ip("203.0.113.10"))
        self.assertTrue(app.validate_ip("2001:db8::1"))
        self.assertFalse(app.validate_ip("not-an-ip"))
        self.assertTrue(app.validate_domain("example.com"))
        self.assertFalse(app.validate_domain("bad..example.com"))
        self.assertIsNone(app.normalize_url("http://[::1"))
        self.assertIsNone(app.normalize_url("https://example.com:99999"))
        self.assertIsNone(app.normalize_url("javascript:alert(1)"))
        self.assertTrue(app.normalize_url("https://example.com/path"))
        self.assertEqual(app.classify_target("https://user:secret@example.com")[0], "invalid")
        self.assertEqual(app.classify_target("https://example.com:bad")[0], "invalid")
        self.assertIn("Error", self.capture(app.smart_diagnostic_report, "https://[::1")[0])
        self.assertIn("Error", self.capture(app.connection_stability_monitor, "https://[::1", 443, 1, 1)[0])
        self.assertIn("Error", self.capture(app.tls_compatibility_check, "https://[::1", 443)[0])
        self.assertIn("Error", self.capture(app.diagnostic_profiles, "Basic", "https://[::1")[0])

    def test_01_public_ip_lookup(self):
        response = SimpleNamespace(text="203.0.113.8", raise_for_status=lambda: None)
        fake_requests = mock.MagicMock()
        fake_requests.get.return_value = response
        with mock.patch.object(app, "_requests", fake_requests):
            self.assertEqual(self.capture(app.get_my_ip), "203.0.113.8")
        fake_requests.get.assert_called_once()

    def test_02_reverse_dns(self):
        with mock.patch.object(app.socket, "gethostbyaddr", return_value=("host.example.com", [], [])):
            self.assertEqual(self.capture(app.reverse_dns_lookup, "203.0.113.8"), "host.example.com")

    def test_03_domain_to_ip(self):
        infos = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.8", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::8", 0, 0, 0)),
        ]
        with mock.patch.object(app.socket, "getaddrinfo", return_value=infos):
            result = self.capture(app.domain_to_ip, "example.com")
        self.assertEqual(result, ["2001:db8::8", "203.0.113.8"])

    def test_04_dns_records(self):
        class Record:
            def to_text(self):
                return "203.0.113.8"
        def resolve(_domain, rtype, lifetime=None):
            if rtype == "A":
                return [Record()]
            raise dns.resolver.NoAnswer()
        with mock.patch("dns.resolver.resolve", side_effect=resolve):
            result = self.capture(app.lookup_dns_records, "example.com")
        self.assertEqual(result, {"A": ["203.0.113.8"]})

    def test_05_geoip(self):
        payload = {"success": True, "ip": "203.0.113.8", "country": "Example", "connection": {"isp": "Example ISP"}}
        with mock.patch.object(app, "http_get_json", return_value=(payload, None)):
            result = self.capture(app.ip_geo_info, "203.0.113.8")
        self.assertIn("Country: Example", result)
        self.assertIn("ISP: Example ISP", result)

    def test_06_whois(self):
        fake_whois = SimpleNamespace(whois=lambda _target: {"domain_name": "example.com", "creation_date": None})
        with mock.patch.object(app, "_whois", fake_whois):
            result = self.capture(app.whois_lookup, "example.com")
        self.assertEqual(result, {"domain_name": "example.com"})

    def test_07_port_scan(self):
        def fake_scan(_ip, port, results):
            results[port] = "OPEN" if port == 443 else "CLOSED"
        with mock.patch.object(app, "scan_port", side_effect=fake_scan):
            result = self.capture(app.port_scan, "203.0.113.8")
        self.assertEqual(len(result), len(app.COMMON_PORTS))
        self.assertIn("443/HTTPS: OPEN", result)

    def test_08_http_headers_streams_and_closes(self):
        response = mock.MagicMock(status_code=200, url="https://example.com/final", headers={"Server": "mock"})
        fake_requests = mock.MagicMock()
        fake_requests.exceptions = requests.exceptions
        fake_requests.get.return_value = response
        with mock.patch.object(app, "_requests", fake_requests):
            result = self.capture(app.grab_http_headers, "https://example.com")
        self.assertEqual(result["status"], "200")
        self.assertEqual(result["url"], "https://example.com/final")
        self.assertTrue(fake_requests.get.call_args.kwargs["stream"])
        response.close.assert_called_once()

    def test_09_tls_certificate(self):
        cert = {"subject": ((('commonName', 'example.com'),),), "issuer": ((('organizationName', 'Example CA'),),)}
        context = mock.MagicMock()
        tls_socket = mock.MagicMock()
        tls_socket.__enter__.return_value.getpeercert.return_value = cert
        context.wrap_socket.return_value = tls_socket
        with mock.patch.object(app.socket, "create_connection") as connect, \
             mock.patch.object(app.ssl, "create_default_context", return_value=context):
            result = self.capture(app.grab_https_cert, "example.com")
        self.assertTrue(any("commonName=example.com" in line for line in result))
        connect.assert_called_once()

    def test_10_subdomain_discovery(self):
        def resolve(host):
            if host == "www.example.com":
                return "203.0.113.8"
            raise socket.gaierror("not found")
        with mock.patch.object(app.socket, "gethostbyname", side_effect=resolve):
            result = self.capture(app.subdomain_enum, "example.com")
        self.assertEqual(result, ["www.example.com -> 203.0.113.8"])

    def test_11_asn_lookup_does_not_duplicate_as_prefix(self):
        payload = {"success": True, "ip": "8.8.8.8", "connection": {"asn": "AS15169", "org": "Example Org", "isp": "Example ISP"}}
        with mock.patch.object(app, "http_get_json", return_value=(payload, None)):
            result = self.capture(app.asn_lookup, "8.8.8.8")
        self.assertIn("ASN: AS15169", result)
        self.assertFalse(any("ASAS" in line for line in result))

    def test_12_rdap_lookup(self):
        payload = {"name": "example.com", "handle": "EXAMPLE", "status": ["active"], "nameservers": [{"ldhName": "ns1.example.com"}]}
        with mock.patch.object(app, "http_get_json", return_value=(payload, None)):
            result = self.capture(app.rdap_lookup, "example.com")
        self.assertIn("name: example.com", result)
        self.assertIn("Nameservers: ns1.example.com", result)

    def test_13_dns_propagation(self):
        def fake_query(_resolver_ip, _domain, _rtype, results):
            results[_resolver_ip] = ["203.0.113.8"]
        with mock.patch.object(app, "_query_resolver", side_effect=fake_query):
            result = self.capture(app.dns_propagation_check, "example.com", "A")
        self.assertTrue(any("STATUS: consistent" in line for line in result))

    def test_14_dnssec_inspection(self):
        class Record:
            def __init__(self, value): self.value = value
            def to_text(self): return self.value
        def resolve(_domain, rtype, lifetime=None):
            if rtype in ("DS", "DNSKEY", "RRSIG"):
                return [Record("mock-dnssec-record")]
            raise dns.resolver.NoAnswer()
        with mock.patch("dns.resolver.resolve", side_effect=resolve):
            result = self.capture(app.dnssec_check, "example.com")
        self.assertIn("Status: configured (records present, NOT validated)", result)

    def test_15_subnet_calculator(self):
        result = self.capture(app.subnet_calculator, "192.0.2.9/24")
        self.assertTrue(any("Network address  : 192.0.2.0" in line for line in result))
        self.assertTrue(any("Usable hosts     : 254" in line for line in result))

    def test_16_ip_reputation_uses_keyless_provider(self):
        response = mock.MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "success": True,
            "ip": "8.8.8.8",
            "score": 2,
            "risk": "low",
            "location": {"country": "United States", "city": "Example"},
            "asn": {"asn": "AS15169", "org": "Example Network"},
            "checks": {
                "vpn_detected": False,
                "commercial_proxy": False,
                "tor_exit": False,
                "blocklist_listed": False,
                "blocklist_count": 0,
            },
        }
        with mock.patch.object(app, "_requests") as fake_requests:
            fake_requests.get.return_value = response
            result = self.capture(app.ip_reputation_check, "8.8.8.8")
        fake_requests.get.assert_called_once()
        args, kwargs = fake_requests.get.call_args
        self.assertEqual(args[0], "https://ipaddress.to/api/score/8.8.8.8")
        self.assertIn("Risk score: 2/100 (provider estimate)", result)

    def test_17_email_domain_security(self):
        class Record:
            def __init__(self, value): self.value = value
            def to_text(self): return self.value
        def resolve(name, rtype, lifetime=None):
            if rtype == "MX": return [Record("10 mail.example.com.")]
            if name == "example.com": return [Record('"v=spf1 -all"')]
            if name == "_dmarc.example.com": return [Record('"v=DMARC1; p=reject"')]
            if name == "selector1._domainkey.example.com": return [Record('"v=DKIM1; p=abc"')]
            raise dns.resolver.NoAnswer()
        with mock.patch("dns.resolver.resolve", side_effect=resolve):
            result = self.capture(app.email_domain_security, "example.com", "selector1")
        self.assertTrue(any("v=spf1" in line for line in result))
        self.assertTrue(any("v=DMARC1" in line for line in result))
        self.assertTrue(any("v=DKIM1" in line for line in result))

    def test_18_http_response_diagnostics(self):
        response = mock.MagicMock(status_code=200, url="https://example.com", history=[],
                                  headers={"Content-Type": "text/html", "Server": "mock"})
        response.raw.read.return_value = b"sample"
        fake_requests = mock.MagicMock()
        fake_requests.get.return_value = response
        with mock.patch.object(app, "_requests", fake_requests):
            result = self.capture(app.http_response_diagnostics, "https://example.com")
        self.assertIn("Final status: 200", result)
        self.assertTrue(any("Content-Type: text/html" in line for line in result))
        response.close.assert_called_once()

    def test_19_local_network_information(self):
        info = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", 0))
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.getsockname.return_value = ("192.0.2.20", 1234)
        with mock.patch.object(app.socket, "getaddrinfo", return_value=[info]), \
             mock.patch.object(app.socket, "socket", return_value=sock):
            result = self.capture(app.local_network_information)
        self.assertTrue(any("192.0.2.20" in line for line in result))

    def test_20_dns_ttl_cache_inspector(self):
        class Record:
            def to_text(self): return "203.0.113.8"
        class Answer(list):
            rrset = SimpleNamespace(ttl=123)
        answer = Answer([Record()])
        with mock.patch("dns.resolver.resolve", return_value=answer):
            result = self.capture(app.dns_ttl_cache_inspector, "example.com", "A")
        self.assertIn("TTL: 123 seconds", result)
        self.assertTrue(any("203.0.113.8" in line for line in result))

    def test_21_cdn_waf_detector_uses_headers_and_closes(self):
        response = mock.MagicMock(status_code=200, url="https://example.com", headers={"CF-Ray": "abc"})
        fake_requests = mock.MagicMock()
        fake_requests.get.return_value = response
        with mock.patch.object(app, "_requests", fake_requests):
            result = self.capture(app.cdn_waf_detector, "https://example.com")
        self.assertTrue(any("Cloudflare" in line for line in result))
        self.assertTrue(fake_requests.get.call_args.kwargs["stream"])
        response.close.assert_called_once()

    def test_22_redirect_chain(self):
        hop = SimpleNamespace(status_code=301, url="http://example.com", headers={"Location": "https://example.com"})
        response = mock.MagicMock(status_code=200, url="https://example.com", history=[hop])
        fake_requests = mock.MagicMock()
        fake_requests.get.return_value = response
        with mock.patch.object(app, "_requests", fake_requests):
            result = self.capture(app.redirect_chain_analyzer, "https://example.com")
        self.assertTrue(any("Redirect count: 1" in line for line in result))
        response.close.assert_called_once()

    def test_23_http_performance_breakdown(self):
        response = mock.MagicMock(status_code=200, url="https://example.com", history=[])
        response.iter_content.return_value = [b"x" * 100]
        fake_requests = mock.MagicMock()
        fake_requests.get.return_value = response
        with mock.patch.object(app, "_requests", fake_requests):
            result = self.capture(app.http_performance_breakdown, "https://example.com")
        self.assertTrue(any("Bytes sampled: 100" in line for line in result))
        response.close.assert_called_once()

    def test_24_certificate_transparency_bounded_json(self):
        payload = json.dumps([{"name_value": "example.com\nwww.example.com"}]).encode()
        response = mock.MagicMock()
        response.iter_content.return_value = [payload]
        fake_requests = mock.MagicMock()
        fake_requests.get.return_value = response
        with mock.patch.object(app, "_requests", fake_requests):
            result = self.capture(app.certificate_transparency_lookup, "example.com")
        self.assertIn("example.com", result)
        self.assertIn("www.example.com", result)
        self.assertTrue(fake_requests.get.call_args.kwargs["stream"])
        response.close.assert_called_once()

    def test_25_security_headers_analyzer(self):
        response = mock.MagicMock(status_code=200, url="https://example.com",
                                  headers={"Strict-Transport-Security": "max-age=31536000"})
        fake_requests = mock.MagicMock()
        fake_requests.get.return_value = response
        with mock.patch.object(app, "_requests", fake_requests):
            result = self.capture(app.security_headers_analyzer, "https://example.com")
        self.assertIn("HSTS: max-age=31536000", result)
        self.assertIn("CSP: MISSING", result)
        response.close.assert_called_once()

    def test_26_latency_diagnostics(self):
        with mock.patch.object(app.socket, "gethostbyname", return_value="203.0.113.8"), \
             mock.patch.object(app.socket, "create_connection"), mock.patch.object(app.time, "sleep"):
            result = self.capture(app.latency_route_diagnostics, "example.com")
        self.assertTrue(any("TCP/443 successful samples: 4/4" in line for line in result))
        self.assertTrue(any("Resolved address:" in line for line in result))

    def test_27_dns_health_checker(self):
        class Record:
            def to_text(self): return "mock-record"
        class Answer(list):
            rrset = SimpleNamespace(ttl=60)
        answer = Answer([Record(), Record()])
        resolver = mock.MagicMock()
        resolver.resolve.return_value = answer
        with mock.patch("dns.resolver.Resolver", return_value=resolver):
            result = self.capture(app.dns_health_checker, "example.com")
        self.assertEqual(len([line for line in result if ": OK" in line]), 6)
        self.assertEqual(resolver.timeout, app.DNS_TIMEOUT)
        self.assertEqual(resolver.lifetime, app.DNS_TIMEOUT)

    def test_28_smart_diagnostic_report(self):
        response = mock.MagicMock(status_code=200, url="https://example.com", history=[],
                                  headers={"content-type": "text/html", "server": "mock"})
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.8", 0))]
        fake_requests = mock.MagicMock()
        fake_requests.get.return_value = response
        with mock.patch.object(app.socket, "getaddrinfo", return_value=infos), \
             mock.patch.object(app, "_requests", fake_requests):
            result = self.capture(app.smart_diagnostic_report, "https://example.com")
        self.assertTrue(any("DNS: resolved" in line for line in result))
        self.assertIn("HTTP: 200", result)
        response.close.assert_called_once()

    def test_dkim_timeout_is_not_reported_as_a_found_record(self):
        # Exercise the status conversion through the query helper.
        with mock.patch("dns.resolver.Resolver") as resolver_cls:
            resolver_cls.return_value.resolve.side_effect = dns.resolver.LifetimeTimeout()
            result = self.capture(app.email_dns_deep_check, "example.com")
        self.assertTrue(any("DKIM selector default: lookup inconclusive" in line for line in result))


    def test_every_menu_option_dispatches_to_its_handler(self):
        handler_names = [
            "get_my_ip", "reverse_dns_lookup", "domain_to_ip", "lookup_dns_records",
            "ip_geo_info", "whois_lookup", "port_scan", "grab_http_headers",
            "grab_https_cert", "subdomain_enum", "asn_lookup", "rdap_lookup",
            "dns_propagation_check", "dnssec_check", "subnet_calculator", "ip_reputation_check",
            "email_domain_security", "http_response_diagnostics", "local_network_information",
            "dns_ttl_cache_inspector", "cdn_waf_detector", "redirect_chain_analyzer",
            "http_performance_breakdown", "certificate_transparency_lookup", "security_headers_analyzer",
            "latency_route_diagnostics", "dns_health_checker", "smart_diagnostic_report",
            "dns_query_comparison", "route_diagnostics", "connection_stability_monitor",
            "tls_compatibility_check", "http_method_checker", "ipv6_readiness_check",
            "historical_results", "batch_domain_checker", "email_dns_deep_check",
            "configuration_validator", "uptime_history_monitor", "diagnostic_profiles",
            "export_results", "export_json_results", "about_and_dependencies",
        ]
        previous = list(app.RESULTS.sections)
        try:
            with ExitStack() as stack:
                handlers = {name: stack.enter_context(mock.patch.object(app, name, return_value=["mock result"]))
                            for name in handler_names}
                handlers["get_my_ip"].return_value = "203.0.113.8"
                handlers["lookup_dns_records"].return_value = {"A": ["203.0.113.8"]}
                handlers["whois_lookup"].return_value = {"domain_name": "example.com"}
                handlers["grab_http_headers"].return_value = {
                    "status": "200", "url": "https://example.com", "Server": "mock"
                }
                stack.enter_context(mock.patch.object(app, "ask", return_value="example.com"))
                for number in range(1, 41):
                    self.capture(app._dispatch, f"{number:02d}")
                for name, handler in handlers.items():
                    if name not in {"export_results", "export_json_results", "about_and_dependencies"}:
                        self.assertTrue(handler.called, f"Menu handler {name} was not called")
                self.capture(app._dispatch, "90")
                self.capture(app._dispatch, "91")
                self.capture(app._dispatch, "99")
                with self.assertRaises(SystemExit):
                    self.capture(app._dispatch, "00")
                self.assertTrue(handlers["export_results"].called)
                self.assertTrue(handlers["export_json_results"].called)
                self.assertTrue(handlers["about_and_dependencies"].called)
        finally:
            app.RESULTS.sections[:] = previous

    def test_history_view_and_compare_branches(self):
        history = [
            {"timestamp": "old", "sections": [{"title": "DNS", "lines": ["A=1"]}]},
            {"timestamp": "new", "sections": [{"title": "DNS", "lines": ["A=2"]},
                                                   {"title": "HTTP", "lines": ["200"]}]},
        ]
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(app, "_local_data_dir", return_value=tmp), \
             mock.patch.object(app, "_load_local_json", return_value=history):
            with mock.patch.object(app, "ask", return_value="2"):
                view = self.capture(app.historical_results)
            with mock.patch.object(app, "ask", side_effect=["3", "1", "2"]):
                compare = self.capture(app.historical_results)
        self.assertTrue(any("Saved snapshots: 2" in line for line in view))
        self.assertTrue(any("CHANGED: DNS" in line for line in compare))
        self.assertTrue(any("ADDED: HTTP" in line for line in compare))

    def test_optional_whois_dependency_does_not_block_core_tools(self):
        def fake_find_spec(name):
            return object() if name in {"requests", "dns"} else None
        with mock.patch.object(app.importlib.util, "find_spec", side_effect=fake_find_spec):
            ok, missing_required, missing_optional = app.check_dependencies()
        self.assertTrue(ok)
        self.assertEqual(missing_required, [])
        self.assertIn("python-whois", missing_optional)
        with mock.patch.object(app, "_whois", None):
            self.assertIsNone(self.capture(app.whois_lookup, "example.com"))

    def test_txt_and_json_exports(self):
        previous = list(app.RESULTS.sections)
        app.RESULTS.sections[:] = [("Test", ["sample line"])]
        try:
            with tempfile.TemporaryDirectory() as tmp:
                txt_path = os.path.join(tmp, "report.txt")
                json_path = os.path.join(tmp, "report.json")
                with mock.patch.object(app, "ask", side_effect=[txt_path]):
                    self.capture(app.export_results, "session")
                with mock.patch.object(app, "ask", side_effect=[json_path]):
                    self.capture(app.export_json_results, "session")
                with open(txt_path, encoding="utf-8") as handle:
                    self.assertIn("sample line", handle.read())
                with open(json_path, encoding="utf-8") as handle:
                    payload = json.load(handle)
                self.assertEqual(payload["tool"], "IP-FINDER")
                self.assertEqual(payload["results"][0]["title"], "Test")
        finally:
            app.RESULTS.sections[:] = previous


if __name__ == "__main__":
    unittest.main(verbosity=2)
