import unittest

from shadow_scan.recon.models import DnsRecord
from shadow_scan.recon.openapi import parse_openapi
from shadow_scan.secanalysis.analyzers import (
    exposure_from_url,
    graphql_signals,
    openapi_security_hints,
    takeover_candidate,
)
from shadow_scan.secanalysis.budget import RequestGovernor
from shadow_scan.secanalysis.checks.active import ActiveCorsCheck, MethodAnalysisCheck, RedirectValidationCheck
from shadow_scan.secanalysis.checks.base import CheckContext, FetchRecord
from shadow_scan.secanalysis.checks.passive import PassiveCorsCheck, SecurityHeadersCheck
from shadow_scan.secanalysis.findings import deduplicate, make_evidence, redact
from shadow_scan.secanalysis.models import (
    CheckRequest,
    EndpointInfo,
    Finding,
    PolicyDecision,
    TestingPolicy,
    ValidationState,
)


def ep(path="/api/x", method="GET", params=(), host="api.example.com"):
    return EndpointInfo(host=host, path=path, method=method, param_names=tuple(params), identity=f"{method} {host}{path}")


def ctx(endpoint, decision_policy, fetcher, *, program_mode=TestingPolicy.SAFE_ACTIVE, stored_headers=None):
    return CheckContext(
        endpoint=endpoint,
        decision=PolicyDecision(decision_policy, "test"),
        governor=RequestGovernor(requests_per_second_per_host=1000),
        fetcher=fetcher,
        stored_headers=stored_headers or {},
        program_mode=program_mode,
    )


class RecordingFetcher:
    def __init__(self, record):
        self.record = record
        self.calls = []

    async def __call__(self, request: CheckRequest):
        self.calls.append(request)
        return self.record


class PassiveCheckTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_security_headers(self):
        c = ctx(ep(), TestingPolicy.PASSIVE_ONLY, RecordingFetcher(None),
                stored_headers={"Content-Type": "text/html"})
        findings = await SecurityHeadersCheck().run(c)
        self.assertTrue(findings)
        self.assertEqual(findings[0].category, "security_headers")

    async def test_passive_cors_credentialed_wildcard(self):
        c = ctx(ep(), TestingPolicy.PASSIVE_ONLY, RecordingFetcher(None),
                stored_headers={"Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Credentials": "true"})
        findings = await PassiveCorsCheck().run(c)
        self.assertTrue(findings)
        self.assertGreaterEqual(findings[0].review_priority, 40)

    async def test_passive_check_makes_no_requests(self):
        fetcher = RecordingFetcher(None)
        c = ctx(ep(), TestingPolicy.PASSIVE_ONLY, fetcher, stored_headers={"X": "y"})
        await SecurityHeadersCheck().run(c)
        self.assertEqual(fetcher.calls, [])


class ActiveCheckGatingTests(unittest.IsolatedAsyncioTestCase):
    async def test_active_cors_reflected_origin(self):
        rec = FetchRecord(200, {"Access-Control-Allow-Origin": "https://shadowscan-probe.example.net",
                                "Access-Control-Allow-Credentials": "true"}, "", "u")
        fetcher = RecordingFetcher(rec)
        c = ctx(ep(), TestingPolicy.SAFE_ACTIVE, fetcher)
        findings = await ActiveCorsCheck().run(c)
        self.assertEqual(len(fetcher.calls), 1)
        self.assertTrue(findings and "reflected" in findings[0].title)
        self.assertEqual(findings[0].validation_state, ValidationState.VALIDATED_NON_DESTRUCTIVELY)

    async def test_active_check_blocked_when_policy_not_safe_active(self):
        fetcher = RecordingFetcher(FetchRecord(200, {}, "", "u"))
        c = ctx(ep(), TestingPolicy.REVIEW_REQUIRED, fetcher)
        findings = await ActiveCorsCheck().run(c)
        self.assertEqual(fetcher.calls, [], "no request may be sent when policy is REVIEW_REQUIRED")
        self.assertEqual(findings, [])

    async def test_active_check_blocked_in_passive_program_mode(self):
        fetcher = RecordingFetcher(FetchRecord(200, {"Access-Control-Allow-Origin": "*"}, "", "u"))
        c = ctx(ep(), TestingPolicy.SAFE_ACTIVE, fetcher, program_mode=TestingPolicy.PASSIVE_ONLY)
        await ActiveCorsCheck().run(c)
        self.assertEqual(fetcher.calls, [], "PASSIVE_ONLY program mode forbids all active requests")

    async def test_cors_request_budget_capped(self):
        # Budget is 3; the check makes 1, but repeated runs share the host budget.
        rec = FetchRecord(200, {"Access-Control-Allow-Origin": "x"}, "", "u")
        fetcher = RecordingFetcher(rec)
        gov = RequestGovernor(requests_per_second_per_host=1000)
        for _ in range(5):
            c = CheckContext(ep(), PolicyDecision(TestingPolicy.SAFE_ACTIVE, "t"), gov, fetcher)
            await ActiveCorsCheck().run(c)
        self.assertLessEqual(len(fetcher.calls), 3, "active.cors host budget of 3 must cap total requests")

    async def test_redirect_validation_accepts_external(self):
        rec = FetchRecord(302, {"Location": "https://shadowscan-probe.example.net/benign"}, "", "u")
        fetcher = RecordingFetcher(rec)
        c = ctx(ep(path="/go", params=("redirect",)), TestingPolicy.SAFE_ACTIVE, fetcher)
        check = RedirectValidationCheck()
        self.assertTrue(check.supports(c.endpoint))
        findings = await check.run(c)
        self.assertTrue(findings and "accepted" in findings[0].title.lower())
        self.assertEqual(findings[0].parameter, "redirect")

    async def test_method_analysis_options_only(self):
        rec = FetchRecord(200, {"Allow": "GET, POST, PUT, DELETE"}, "", "u")
        fetcher = RecordingFetcher(rec)
        c = ctx(ep(), TestingPolicy.SAFE_ACTIVE, fetcher)
        findings = await MethodAnalysisCheck().run(c)
        self.assertEqual(fetcher.calls[0].method, "OPTIONS")
        self.assertTrue(findings and "PUT" in findings[0].title)


class AnalyzerTests(unittest.TestCase):
    def test_takeover_candidate_not_confirmed(self):
        dns = DnsRecord("old.example.com", status="nxdomain", cname_chain=("myapp.herokuapp.com",))
        finding = takeover_candidate("old.example.com", dns, "No such app", 404)
        self.assertIsNotNone(finding)
        self.assertIn("candidate", finding.title.lower())
        self.assertIn("unconfirmed", finding.title.lower())   # never a bare "confirmed" claim
        self.assertEqual(finding.validation_state, ValidationState.SUSPECTED)

    def test_takeover_requires_dangling_or_error(self):
        # Resolves fine and no error body => not a candidate.
        dns = DnsRecord("ok.example.com", status="resolves", a=("1.2.3.4",), cname_chain=("myapp.herokuapp.com",))
        self.assertIsNone(takeover_candidate("ok.example.com", dns, "Welcome", 200))

    def test_openapi_hints(self):
        spec_json = ('{"openapi":"3.0.0","paths":{"/admin/users/{id}":{"get":{"parameters":'
                     '[{"name":"id","in":"path"}]}},"/files/upload":{"post":{}}}}')
        spec = parse_openapi(spec_json, "api.example.com")
        findings = openapi_security_hints("api.example.com", spec, documents_auth=False)
        checks = {f.check_id for f in findings}
        self.assertIn("openapi.no_auth_declared", checks)
        self.assertIn("openapi.admin_object_access", checks)
        self.assertIn("openapi.upload", checks)

    def test_exposure_only_for_live_or_unknown(self):
        self.assertIsNotNone(exposure_from_url("h", "https://h/.env", "/.env", 200))
        self.assertIsNone(exposure_from_url("h", "https://h/.env", "/.env", 404))
        self.assertIsNotNone(exposure_from_url("h", "https://h/app.js.map", "/app.js.map", None))
        self.assertIsNone(exposure_from_url("h", "https://h/index.html", "/index.html", 200))

    def test_graphql_signals(self):
        off = graphql_signals("h", "/graphql", ["GetMe"], introspection_confirmed=False)
        self.assertEqual([f.check_id for f in off], ["graphql.endpoint"])
        on = graphql_signals("h", "/graphql", ["GetMe"], introspection_confirmed=True)
        self.assertIn("graphql.introspection", {f.check_id for f in on})


class RedactionAndDedupTests(unittest.TestCase):
    def test_redaction(self):
        self.assertIn("[REDACTED]", redact("Authorization: Bearer abcdef1234567890abcdef"))
        self.assertIn("[REDACTED]", redact("here is AKIAIOSFODNN7EXAMPLE in text"))
        self.assertIn("[REDACTED]", redact('{"password":"hunter2secret"}'))
        self.assertEqual(redact("nothing secret here"), "nothing secret here")

    def test_evidence_redacts_data(self):
        ev = make_evidence("response", "token is Bearer abcdef1234567890xyz",
                           data={"body": 'password=supersecretvalue'})
        self.assertIn("[REDACTED]", ev.summary)
        self.assertIn("[REDACTED]", ev.data["body"])

    def test_dedup_merges_same_issue_from_three_sources(self):
        base = dict(check_id="c", asset="h", category="cors", endpoint="/x", title="CORS")
        a = Finding(**base, source="monitor", evidence=[make_evidence("header", "from monitor")])
        b = Finding(**base, source="nuclei", confidence=0.9, evidence=[make_evidence("response", "from nuclei")])
        c = Finding(**base, source="active", review_priority=70, evidence=[make_evidence("response", "from active")])
        merged = deduplicate([a, b, c])
        self.assertEqual(len(merged), 1)
        self.assertEqual(set(merged[0].source.split(",")), {"monitor", "nuclei", "active"})
        self.assertEqual(merged[0].confidence, 0.9)
        self.assertEqual(merged[0].review_priority, 70)
        self.assertEqual(len(merged[0].evidence), 3)

    def test_dedup_keeps_distinct_issues(self):
        a = Finding(check_id="c", asset="h", category="cors", endpoint="/x", title="t")
        b = Finding(check_id="c", asset="h", category="open_redirect", endpoint="/x", title="t")
        self.assertEqual(len(deduplicate([a, b])), 2)


if __name__ == "__main__":
    unittest.main()
