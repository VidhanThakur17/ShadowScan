import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing

from shadow_scan.database import Database
from shadow_scan.secanalysis.manualpkg import build_package
from shadow_scan.secanalysis.models import EndpointInfo, Finding, ValidationState
from shadow_scan.secanalysis.nuclei import NucleiAdapter, parse_findings
from shadow_scan.secanalysis.sec_db import SecurityStore
from shadow_scan.secanalysis.seccorrelation import AssetSecurityFacts, correlate


class NucleiTests(unittest.TestCase):
    def test_missing_executable(self):
        tool = NucleiAdapter()
        tool.available = lambda: False
        self.assertEqual(tool.run(["https://api.example.com"]), [])

    def test_safe_profile_excludes_intrusive_tags(self):
        tool = NucleiAdapter(profiles=("exposure", "misconfig"))
        args = tool.build_args(["https://api.example.com"])
        self.assertIn("-exclude-tags", args)
        excl = args[args.index("-exclude-tags") + 1]
        for bad in ("dos", "intrusive", "brute-force", "sqli", "rce"):
            self.assertIn(bad, excl)
        self.assertIn("-exclude-severity", args)
        # Only safe tags are selected.
        tags = args[args.index("-tags") + 1]
        self.assertNotIn("fuzz", tags)

    def test_result_parsing_and_unsafe_drop(self):
        lines = [
            json.dumps({"template-id": "tech-detect", "host": "https://api.example.com/x",
                        "matched-at": "https://api.example.com/x",
                        "info": {"name": "nginx", "severity": "info", "tags": ["tech"]}}),
            json.dumps({"template-id": "evil", "host": "https://api.example.com",
                        "info": {"name": "sqli", "severity": "high", "tags": ["sqli", "intrusive"]}}),
            "not json",
        ]
        findings = parse_findings(lines)
        self.assertEqual(len(findings), 1, "intrusive/sqli result must be dropped defensively")
        self.assertEqual(findings[0].asset, "api.example.com")
        self.assertEqual(findings[0].source, "nuclei")

    def test_critical_severity_excluded_in_parse(self):
        line = json.dumps({"template-id": "x", "host": "h",
                           "info": {"name": "x", "severity": "critical", "tags": ["misconfig"]}})
        self.assertEqual(parse_findings([line]), [])


class ManualPackageTests(unittest.TestCase):
    def test_bola_package_for_object_id(self):
        ep = EndpointInfo(host="api.example.com", path="/api/accounts/{account_id}", method="GET",
                          param_names=("account_id",))
        finding = Finding(check_id="c", asset="api.example.com", category="authorization",
                          title="authz review", endpoint="/api/accounts/{account_id}", parameter="account_id")
        pkg = build_package(finding, ep, required_auth="viewer")
        self.assertEqual(pkg["required_auth_context"], "viewer")
        self.assertIn("account_id", pkg["parameters"])
        self.assertTrue(any("BOLA" in t or "object-level" in t for t in pkg["suggested_manual_tests"]))
        self.assertIn("never destructively", pkg["safety_note"].lower())


class CorrelationTests(unittest.TestCase):
    def test_authz_object_access_tops(self):
        f = Finding(check_id="authz.x", asset="api.example.com", category="authorization", title="diff",
                    validation_state=ValidationState.VALIDATED_NON_DESTRUCTIVELY)
        facts = AssetSecurityFacts(asset="api.example.com", endpoint="/api/users/{id}",
                                   findings=[(1, f)], has_object_id_param=True, authz_context_diff=True)
        item = correlate(facts)
        self.assertGreaterEqual(item.review_priority, 97)
        self.assertEqual(item.validation_state, "validated_non_destructively")

    def test_scores_do_not_inflate_past_100(self):
        fs = [(i, Finding(check_id=f"c{i}", asset="h", category="authorization", title="t",
                          validation_state=ValidationState.SUSPECTED)) for i in range(10)]
        facts = AssetSecurityFacts(asset="h", findings=fs, authz_context_diff=True,
                                   has_object_id_param=True, js_changed_new_internal=True,
                                   has_access_control_param=True, new_openapi_admin_object=True)
        self.assertLessEqual(correlate(facts).review_priority, 100)

    def test_no_signals_returns_none(self):
        self.assertIsNone(correlate(AssetSecurityFacts(asset="h")))


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.dir, "g.db")); self.db.open()
        self.store = SecurityStore(self.db); self.store.ensure_schema()

    def tearDown(self):
        self.db.close()

    def test_graph_relationships(self):
        with self.db.transaction():
            js = self.store.node("js_file", "https://cdn/app.js", now="t")
            ep = self.store.node("endpoint", "GET api.example.com/api/internal/export", now="t")
            host = self.store.node("asset", "api.example.com", now="t")
            param = self.store.node("parameter", "account_id", now="t")
            self.store.edge(ep, js, "DISCOVERED_FROM")
            self.store.edge(ep, host, "RUNS_ON")
            self.store.edge(ep, param, "USES_PARAMETER")
        # "Which JS file exposed this endpoint?"
        src = self.store.neighbors("endpoint", "GET api.example.com/api/internal/export", "DISCOVERED_FROM")
        self.assertEqual([(r[0], r[1]) for r in src], [("js_file", "https://cdn/app.js")])
        # "Which endpoints run on this host?" (reverse edge)
        eps = self.store.nodes_pointing_to("asset", "api.example.com", "RUNS_ON")
        self.assertIn(("endpoint", "GET api.example.com/api/internal/export"), [(r[0], r[1]) for r in eps])

    def test_node_dedup(self):
        with self.db.transaction():
            a = self.store.node("asset", "h", now="t")
            b = self.store.node("asset", "h", now="t")
        self.assertEqual(a, b)
        with closing(sqlite3.connect(os.path.join(self.dir, "g.db"))) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0], 1)


class SecStoreFindingTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.dir, "s.db")); self.db.open()
        self.store = SecurityStore(self.db); self.store.ensure_schema()

    def tearDown(self):
        self.db.close()

    def test_upsert_dedups_by_key(self):
        from shadow_scan.secanalysis.findings import make_evidence
        f1 = Finding(check_id="c", asset="h", category="cors", endpoint="/x", title="CORS",
                     source="monitor", evidence=[make_evidence("header", "a")])
        f2 = Finding(check_id="c", asset="h", category="cors", endpoint="/x", title="CORS",
                     source="nuclei", review_priority=70, evidence=[make_evidence("response", "b")])
        with self.db.transaction():
            id1 = self.store.upsert_finding(f1, "t1")
            id2 = self.store.upsert_finding(f2, "t2")
        self.assertEqual(id1, id2)
        with closing(sqlite3.connect(os.path.join(self.dir, "s.db"))) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM security_findings").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM finding_evidence").fetchone()[0], 2)
            prio = conn.execute("SELECT review_priority FROM security_findings").fetchone()[0]
        self.assertEqual(prio, 70)

    def test_auth_metadata_has_no_secret_columns(self):
        with closing(sqlite3.connect(os.path.join(self.dir, "s.db"))) as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(auth_profiles_metadata)")}
        # Only identifiers / env var names; never a token/secret value column.
        self.assertEqual(cols, {"name", "host", "header_name", "token_env", "cookie_env", "description"})
        self.assertNotIn("token", cols)
        self.assertNotIn("secret", cols)


if __name__ == "__main__":
    unittest.main()
