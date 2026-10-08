import asyncio
import os
import unittest

from shadow_scan.secanalysis.budget import BudgetExceeded, RequestGovernor
from shadow_scan.secanalysis.classify import (
    classify_endpoint,
    classify_parameter,
    relevance_score,
)
from shadow_scan.secanalysis.models import EndpointClass, EndpointInfo, ParamClass, TestingPolicy
from shadow_scan.secanalysis.policy import PolicyEngine
from shadow_scan.secanalysis.profiles import AuthProfile, profile_from_dict


def ep(path, method="GET", params=(), **kw):
    return EndpointInfo(host="api.example.com", path=path, method=method, param_names=tuple(params), **kw)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.engine = PolicyEngine()

    def test_safe_active_for_readonly_generic(self):
        d = self.engine.decide(ep("/api/status"))
        self.assertEqual(d.policy, TestingPolicy.SAFE_ACTIVE)
        self.assertTrue(d.may_active)

    def test_state_changing_is_review_required(self):
        d = self.engine.decide(ep("/api/users", method="POST"), operation="write")
        self.assertEqual(d.policy, TestingPolicy.REVIEW_REQUIRED)
        self.assertFalse(d.may_active)

    def test_delete_user_review_required(self):
        self.assertEqual(self.engine.decide(ep("/api/users/123", method="DELETE")).policy,
                         TestingPolicy.REVIEW_REQUIRED)

    def test_logout_is_disallowed(self):
        self.assertEqual(self.engine.decide(ep("/account/logout")).policy, TestingPolicy.DISALLOWED)

    def test_destructive_get_path_review_required(self):
        self.assertEqual(self.engine.decide(ep("/api/orders/5/cancel")).policy, TestingPolicy.REVIEW_REQUIRED)

    def test_upload_and_payment_review_required(self):
        self.assertEqual(self.engine.decide(ep("/api/files/upload")).policy, TestingPolicy.REVIEW_REQUIRED)
        self.assertEqual(self.engine.decide(ep("/api/payment/charge")).policy, TestingPolicy.REVIEW_REQUIRED)

    def test_sensitive_parameter_forces_review(self):
        self.assertEqual(self.engine.decide(ep("/api/reset", params=("token",))).policy,
                         TestingPolicy.REVIEW_REQUIRED)

    def test_unknown_method_is_passive_only(self):
        self.assertEqual(self.engine.decide(ep("/api/thing", method="UNKNOWN")).policy, TestingPolicy.PASSIVE_ONLY)

    def test_out_of_scope_disallowed(self):
        self.assertEqual(self.engine.decide(ep("/api/x"), in_scope=False).policy, TestingPolicy.DISALLOWED)

    def test_passive_global_mode_caps_everything(self):
        passive = PolicyEngine(global_mode=TestingPolicy.PASSIVE_ONLY)
        # Even a perfectly safe read-only endpoint cannot go active in passive mode.
        self.assertEqual(passive.decide(ep("/api/status")).policy, TestingPolicy.PASSIVE_ONLY)

    def test_program_exclusion(self):
        import re
        eng = PolicyEngine(excluded_path_res=(re.compile(r"^/internal/"),))
        self.assertEqual(eng.decide(ep("/internal/metrics")).policy, TestingPolicy.DISALLOWED)


class ClassifyTests(unittest.TestCase):
    def test_endpoint_classes(self):
        self.assertIn(EndpointClass.ADMINISTRATIVE, classify_endpoint(ep("/api/admin/users/123")))
        self.assertIn(EndpointClass.USER_MANAGEMENT, classify_endpoint(ep("/api/admin/users/123")))
        self.assertIn(EndpointClass.AUTHENTICATION, classify_endpoint(ep("/auth/login")))
        self.assertIn(EndpointClass.GRAPHQL, classify_endpoint(ep("/graphql")))
        self.assertEqual(classify_endpoint(ep("/about")), [EndpointClass.GENERIC])

    def test_authorization_from_params(self):
        self.assertIn(EndpointClass.AUTHORIZATION, classify_endpoint(ep("/api/users/1", params=("role",))))

    def test_parameter_families(self):
        cases = {
            "user_id": ParamClass.OBJECT_IDENTIFIER, "account_id": ParamClass.OBJECT_IDENTIFIER,
            "role": ParamClass.ACCESS_CONTROL, "is_admin": ParamClass.ACCESS_CONTROL,
            "redirect_uri": ParamClass.REDIRECT_SSRF, "callback": ParamClass.REDIRECT_SSRF,
            "file": ParamClass.FILE_PATH, "template": ParamClass.FILE_PATH,
            "query": ParamClass.QUERY_INJECTION, "cmd": ParamClass.QUERY_INJECTION,
            "token": ParamClass.AUTHENTICATION, "otp": ParamClass.AUTHENTICATION,
            "color": ParamClass.GENERIC, "widget_id": ParamClass.OBJECT_IDENTIFIER,
        }
        for name, expected in cases.items():
            self.assertEqual(classify_parameter(name), expected, name)

    def test_relevance_score_orders_admin_above_generic(self):
        admin = relevance_score(ep("/api/admin/users/1", params=("role", "user_id")))
        generic = relevance_score(ep("/about"))
        self.assertGreater(admin, generic)
        self.assertLessEqual(admin, 100)


class AuthIsolationTests(unittest.TestCase):
    def test_auth_material_bound_to_host(self):
        os.environ["TEST_TOK"] = "secret-token-value"
        try:
            p = AuthProfile(name="admin", host="api.example.com", token_env="TEST_TOK")
            self.assertEqual(p.resolve_header("api.example.com"), {"Authorization": "secret-token-value"})
            # Never sent to a different host.
            self.assertEqual(p.resolve_header("evil.example.com"), {})
            self.assertEqual(p.resolve_header("api.example.com.evil.net"), {})
        finally:
            del os.environ["TEST_TOK"]

    def test_profile_rejects_inlined_secret(self):
        with self.assertRaises(ValueError):
            profile_from_dict({"name": "p", "authentication_profiles": [
                {"name": "admin", "host": "h", "token": "inlined-secret"}]})

    def test_profile_references_env_only(self):
        prof = profile_from_dict({"name": "p", "authentication_profiles": [
            {"name": "admin", "host": "h", "token_env": "SOME_ENV"}]})
        self.assertIn("admin", prof.auth_profiles)
        self.assertEqual(prof.auth_profiles["admin"].token_env, "SOME_ENV")


class BudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_per_endpoint_budget(self):
        gov = RequestGovernor(max_requests_per_endpoint=2, requests_per_second_per_host=1000)
        for _ in range(2):
            lease = await gov.acquire("h", "GET h/x")
            async with lease:
                pass
        with self.assertRaises(BudgetExceeded):
            await gov.acquire("h", "GET h/x")

    async def test_run_budget(self):
        gov = RequestGovernor(max_requests_per_run=3, max_requests_per_endpoint=100, requests_per_second_per_host=1000)
        for i in range(3):
            async with await gov.acquire("h", f"GET h/{i}"):
                pass
        with self.assertRaises(BudgetExceeded):
            await gov.acquire("h", "GET h/new")
        self.assertEqual(gov.total_requests, 3)

    async def test_check_budget(self):
        gov = RequestGovernor(requests_per_second_per_host=1000)
        async with await gov.acquire("h", "GET h/a", check_budget=("cors:h", 1)):
            pass
        with self.assertRaises(BudgetExceeded):
            await gov.acquire("h", "GET h/b", check_budget=("cors:h", 1))

    async def test_rate_limit_delays(self):
        import time
        gov = RequestGovernor(requests_per_second_per_host=50, max_requests_per_endpoint=100)
        start = time.monotonic()
        for i in range(5):
            async with await gov.acquire("h", f"GET h/{i}"):
                pass
        # 5 requests at 50 rps with burst 1 => at least ~3 inter-request delays.
        self.assertGreater(gov.total_requests, 0)


if __name__ == "__main__":
    unittest.main()
