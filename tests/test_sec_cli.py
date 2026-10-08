import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from shadow_scan.database import Database
from shadow_scan.secanalysis.cli import _load_endpoints_from_db, run_findings
from shadow_scan.secanalysis.findings import make_evidence
from shadow_scan.secanalysis.models import Finding
from shadow_scan.secanalysis.scope_compat import build_scope
from shadow_scan.secanalysis.sec_db import SecurityStore
from shadow_scan.recon.recon_db import ReconStore
from shadow_scan.recon.endpoints import make_endpoint, identity_string


class EndpointLoadingTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = Path(self.dir) / "r.db"
        db = Database(self.path); db.open()
        store = ReconStore(db); store.ensure_schema()
        with db.transaction():
            ep = make_endpoint("api.example.com", "/api/users/5", method="get", source="js")
            store.record_endpoint(ep, identity_string(ep), "t")
        db.close()

    def test_scope_applies_scheme_and_port(self):
        scope = build_scope(["http://api.example.com:8443", "@scheme http"])
        eps = _load_endpoints_from_db(self.path, "https", scope)
        self.assertEqual(len(eps), 1)
        self.assertEqual(eps[0].scheme, "http")
        self.assertEqual(eps[0].port, 8443)
        self.assertEqual(eps[0].url(), "http://api.example.com:8443/api/users/{id}")

    def test_default_scheme_when_unconstrained(self):
        scope = build_scope(["api.example.com"])
        eps = _load_endpoints_from_db(self.path, "https", scope)
        self.assertEqual(eps[0].scheme, "https")
        self.assertIsNone(eps[0].port)


class FindingsCliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = Path(self.dir) / "s.db"
        db = Database(self.path); db.open()
        store = SecurityStore(db); store.ensure_schema()
        with db.transaction():
            self.fid = store.upsert_finding(Finding(
                check_id="active.cors", asset="api.example.com", category="cors", endpoint="/api/status",
                title="CORS reflected", review_priority=70, source="active",
                evidence=[make_evidence("response", "reflected origin")]), "t")
        db.close()

    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = run_findings(argv)
        return rc, buf.getvalue()

    def test_list_shows_finding(self):
        rc, out = self._run(["--database", str(self.path)])
        self.assertEqual(rc, 0)
        self.assertIn("CORS reflected", out)
        self.assertIn(f"id={self.fid}", out)

    def test_show_detail(self):
        rc, out = self._run(["--database", str(self.path), "--show", str(self.fid)])
        self.assertEqual(rc, 0)
        self.assertIn("Evidence:", out)
        self.assertIn("reflected origin", out)

    def test_set_status(self):
        rc, out = self._run(["--database", str(self.path), "--set", str(self.fid), "confirmed"])
        self.assertEqual(rc, 0)
        self.assertIn("confirmed", out)
        # It no longer appears in the default (new/reviewing/confirmed includes confirmed) -> filter to new only.
        _, out2 = self._run(["--database", str(self.path), "--status", "new"])
        self.assertNotIn("CORS reflected", out2)

    def test_invalid_status_rejected(self):
        rc, _ = self._run(["--database", str(self.path), "--set", str(self.fid), "bogus"])
        self.assertEqual(rc, 1)

    def test_missing_database(self):
        rc, _ = self._run(["--database", str(Path(self.dir) / "nope.db")])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
