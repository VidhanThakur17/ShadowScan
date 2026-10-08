import unittest

from shadow_scan.recon.models import ScopeClass
from shadow_scan.recon.scope import ScopeEngine

SCOPE = [
    "example.com",
    "*.example.com",
    "https://portal.example.com",
    "!admin.example.com",
    r"!~\.internal\.example\.com$",
]


class ScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = ScopeEngine.parse(SCOPE)

    def test_exact_host(self) -> None:
        self.assertEqual(self.engine.classify_host("example.com"), ScopeClass.IN_SCOPE)
        self.assertEqual(self.engine.classify_host("EXAMPLE.com."), ScopeClass.IN_SCOPE)

    def test_wildcard_matches_subdomains_not_apex_sibling(self) -> None:
        self.assertEqual(self.engine.classify_host("api.example.com"), ScopeClass.IN_SCOPE)
        self.assertEqual(self.engine.classify_host("a.b.example.com"), ScopeClass.IN_SCOPE)
        self.assertEqual(self.engine.classify_host("notexample.com"), ScopeClass.UNKNOWN)
        self.assertEqual(self.engine.classify_host("example.com.evil.net"), ScopeClass.UNKNOWN)

    def test_exclusions_win_over_wildcard(self) -> None:
        self.assertEqual(self.engine.classify_host("admin.example.com"), ScopeClass.OUT_OF_SCOPE)
        self.assertEqual(self.engine.classify_host("db.internal.example.com"), ScopeClass.OUT_OF_SCOPE)

    def test_unknown_host(self) -> None:
        self.assertEqual(self.engine.classify_host("other.org"), ScopeClass.UNKNOWN)
        self.assertEqual(self.engine.classify_host(None), ScopeClass.OUT_OF_SCOPE)

    def test_url_scope_and_scheme(self) -> None:
        self.assertEqual(self.engine.classify_url("https://api.example.com/x"), ScopeClass.IN_SCOPE)
        self.assertEqual(self.engine.classify_url("ftp://api.example.com/x"), ScopeClass.OUT_OF_SCOPE)
        self.assertEqual(self.engine.classify_url("https://evil.com/x"), ScopeClass.UNKNOWN)
        self.assertEqual(self.engine.classify_url("https://admin.example.com/x"), ScopeClass.OUT_OF_SCOPE)

    def test_probe_gate_defaults_block_unknown(self) -> None:
        self.assertTrue(self.engine.may_probe_host("api.example.com"))
        self.assertFalse(self.engine.may_probe_host("other.org"))
        self.assertFalse(self.engine.may_probe_host("admin.example.com"))

    def test_probe_unknown_opt_in(self) -> None:
        lenient = ScopeEngine.parse(SCOPE, probe_unknown=True)
        self.assertTrue(lenient.may_probe_host("other.org"))
        self.assertFalse(lenient.may_probe_host("admin.example.com"), "exclusions still block")

    def test_port_directive(self) -> None:
        engine = ScopeEngine.parse(["example.com", "@ports 80,443,8443"])
        self.assertEqual(engine.classify_service("example.com", 8443), ScopeClass.IN_SCOPE)
        self.assertEqual(engine.classify_service("example.com", 22), ScopeClass.OUT_OF_SCOPE)
        self.assertEqual(engine.classify_url("http://example.com:22/"), ScopeClass.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
