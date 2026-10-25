import unittest
import ip_finder as app

class LatestCoreTests(unittest.TestCase):
    def test_identity(self):
        self.assertEqual(app.TOOL_NAME, "IP-FINDER")
        self.assertTrue(app.VERSION)
    def test_ip_validation(self):
        self.assertTrue(app.validate_ip("8.8.8.8"))
        self.assertFalse(app.validate_ip("999.1.1.1"))
    def test_parse_ip(self):
        self.assertEqual(str(app.parse_ip("2001:4860:4860::8888")), "2001:4860:4860::8888")
    def test_domain_validation(self):
        self.assertTrue(app.validate_domain("example.com"))
        self.assertFalse(app.validate_domain("not a domain"))
    def test_normalize_url(self):
        self.assertTrue(app.normalize_url("example.com").startswith("http"))
    def test_result_collector(self):
        r=app.ResultCollector()
        self.assertTrue(r.empty())
        r.add("test", ["ok"])
        self.assertFalse(r.empty())
        self.assertIn("ok", r.render("example.com"))
    def test_latest_tools_exist(self):
        for n in range(1, 60):
            matches = [name for name in dir(app) if name.startswith(f"tool_{n:02d}_")]
            self.assertTrue(matches, f"missing tool handler {n:02d}")
            self.assertTrue(callable(getattr(app, matches[0])))
    def test_dispatch_exists(self):
        self.assertTrue(callable(app.dispatch))

if __name__ == "__main__":
    unittest.main()
