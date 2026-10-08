import unittest

from shadow_scan.recon.correlation import (
    AssetFacts,
    apply_noise_ranking,
    correlate,
    review_summary,
)
from shadow_scan.recon.models import ReconEvent


class CorrelationTests(unittest.TestCase):
    def test_new_live_host_with_api_doc_tops(self) -> None:
        facts = AssetFacts(
            asset="api-new.example.com",
            events={ReconEvent.NEW_SUBDOMAIN, ReconEvent.DNS_BECAME_LIVE, ReconEvent.NEW_OPEN_PORT, ReconEvent.NEW_OPENAPI},
            http_status=200, new_ports=[8443], new_openapi_endpoint_count=27,
        )
        signals = correlate(facts)
        ids = [s.rule_id for s in signals]
        self.assertEqual(ids[0], "new_live_host_with_api_doc")
        self.assertGreaterEqual(signals[0].review_priority, 95)
        # Multiple supporting signals fire.
        self.assertIn("revived_host_new_port", ids)
        self.assertIn("new_openapi_many_endpoints", ids)

    def test_js_new_internal_endpoint(self) -> None:
        facts = AssetFacts(
            asset="portal.example.com",
            events={ReconEvent.JS_CHANGED, ReconEvent.NEW_JS_ENDPOINT},
            new_js_endpoints=["/api/internal/export", "/assets/main"],
            new_parameters=["account_id"],
        )
        signals = correlate(facts)
        top = signals[0]
        self.assertEqual(top.rule_id, "js_new_internal_endpoint")
        self.assertGreaterEqual(top.review_priority, 90)
        self.assertIn("sensitive_new_parameter", [s.rule_id for s in signals])

    def test_new_admin_subdomain(self) -> None:
        facts = AssetFacts(asset="admin-dev.example.com", events={ReconEvent.NEW_SUBDOMAIN},
                           http_status=200, title="Admin Console")
        signals = correlate(facts)
        self.assertEqual(signals[0].rule_id, "new_admin_subdomain")

    def test_dangling_cname_is_review_only(self) -> None:
        facts = AssetFacts(asset="old.example.com", events={ReconEvent.DANGLING_CNAME})
        [signal] = [s for s in correlate(facts) if s.rule_id == "dangling_cname"]
        self.assertNotIn("vulnerab", signal.reason.lower())
        self.assertIn("not confirmed", signal.reason.lower())

    def test_noise_ranking_downranks_generic_not_structural(self) -> None:
        noisy = AssetFacts(
            asset="news.example.com",
            events={ReconEvent.NEW_JS_ENDPOINT},
            new_js_endpoints=["/api/v2/articles"],
            content_change_magnitude="major", monitoring_priority=60, change_ratio=0.9,
        )
        signals = correlate(noisy)
        ranked = apply_noise_ranking(noisy, signals)
        by_id = {s.rule_id: s for s in ranked}
        # Structural JS-endpoint signal keeps full weight on a noisy asset...
        self.assertEqual(by_id["js_new_endpoint"].review_priority, 64)
        # ...while the generic content change is penalized.
        self.assertLess(by_id["content_change_generic"].review_priority, 30)
        self.assertIn("down-ranked", by_id["content_change_generic"].reason)

    def test_noise_ranking_noop_for_stable_asset(self) -> None:
        facts = AssetFacts(asset="x.example.com", events=set(),
                           content_change_magnitude="major", monitoring_priority=60, change_ratio=0.1)
        signals = correlate(facts)
        self.assertEqual(apply_noise_ranking(facts, signals), signals)

    def test_review_summary(self) -> None:
        facts = AssetFacts(asset="a.example.com", events={ReconEvent.NEW_SUBDOMAIN}, http_status=200)
        signals = correlate(facts)
        priority, headline, reasons = review_summary(facts, signals)
        self.assertEqual(priority, signals[0].review_priority)
        self.assertEqual(headline, signals[0].reason)
        self.assertEqual(len(reasons), len(signals))

    def test_no_signals_for_quiet_asset(self) -> None:
        self.assertEqual(correlate(AssetFacts(asset="quiet.example.com")), [])


if __name__ == "__main__":
    unittest.main()
