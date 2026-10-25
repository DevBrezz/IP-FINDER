import unittest
import ip_finder as app

class LatestFeatureTests(unittest.TestCase):
    def test_latest_menu_options(self):
        self.assertTrue(callable(app.show_menu))
        self.assertTrue(callable(app.menu))
        self.assertTrue(callable(app.dispatch))
        self.assertTrue(any("[59]" in line for line in app.menu()))
    def test_exports_exist(self):
        self.assertTrue(callable(app.export_txt))
        self.assertTrue(callable(app.export_json))
    def test_network_helpers_exist(self):
        for name in ("dns_resolve", "http_request", "whois_lookup", "tls_fetch_cert",
                     "port_probe", "banner_grab", "validate_ip", "validate_domain"):
            self.assertTrue(callable(getattr(app, name)), name)
    def test_all_tool_handlers_present(self):
        names = ("public_ip","reverse_dns","domain_to_ip","dns_records","geoip","whois",
        "port_scan","http_headers","tls_cert","subdomains","asn","rdap","propagation",
        "dnssec","subnet","ip_reputation","email_security","http_diag","local_network",
        "ttl","cdn_waf","redirects","http_perf","ct","security_headers","latency",
        "dns_health","smart","dns_compare","traceroute","connection_stability","tls_compat",
        "http_method","ipv6_readiness","historical","batch_domains","email_deep",
        "config_validator","uptime","profiles","web_ip","internetdb","banner",
        "zone_transfer","cname_chain","tls_sans","reverse_ip","security_txt","bulk_geo",
        "dnsbl","wayback","bgp","cymru_asn","cookies","cors","wildcard_dns","takeover",
        "basic_auth","tls_expiry")
        for i,name in enumerate(names,1):
            self.assertTrue(callable(getattr(app, f"tool_{i:02d}_{name}")), name)

if __name__ == "__main__":
    unittest.main()
