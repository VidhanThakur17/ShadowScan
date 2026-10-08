import unittest

from shadow_scan.recon.endpoints import (
    identity_string,
    make_endpoint,
    merge_endpoints,
    merge_parameters,
    normalize_path,
)
from shadow_scan.recon.jsanalyze import (
    analyze_js,
    analyze_source_map,
    companion_source_map_url,
    is_probable_secret,
)
from shadow_scan.recon.models import FindingType, MethodConfidence, ParamLocation, Parameter
from shadow_scan.recon.openapi import graphql_candidates_from_text, looks_like_openapi, parse_openapi
from shadow_scan.recon.tech import fingerprint
from shadow_scan.recon.urls import is_dangerous_path, normalize_url, query_param_names


class UrlTests(unittest.TestCase):
    def test_normalize_sorts_query_drops_default_port_and_fragment(self) -> None:
        self.assertEqual(
            normalize_url("HTTP://Example.com:80/a/../b/?b=2&a=1#frag"),
            "http://example.com/b/?a=1&b=2",
        )

    def test_relative_resolution_and_non_http_rejected(self) -> None:
        self.assertEqual(normalize_url("../x?z=1", base="https://h.example.com/a/b"), "https://h.example.com/x?z=1")
        self.assertIsNone(normalize_url("mailto:x@example.com"))
        self.assertIsNone(normalize_url("javascript:alert(1)"))

    def test_param_names(self) -> None:
        self.assertEqual(query_param_names("https://e.com/x?id=1&token=abc&id=2"), ("id", "token"))

    def test_dangerous_paths(self) -> None:
        for url in ("https://e.com/account/logout", "https://e.com/users/5/delete",
                    "https://e.com/admin/reset-password", "https://e.com/x?action=delete"):
            self.assertTrue(is_dangerous_path(url), url)
        for url in ("https://e.com/api/users", "https://e.com/products?id=5", "https://e.com/deletion-policy"):
            self.assertFalse(is_dangerous_path(url), url)


class JsAnalysisTests(unittest.TestCase):
    def test_extracts_endpoints_params_hosts_sourcemap(self) -> None:
        source = """
        //# sourceMappingURL=app.9381.js.map
        const API = "https://api.example.com";
        fetch("/api/v2/internal/export?account_id=5&format=json");
        var ws = "wss://events.example.com/stream";
        const cfg = { apiUrl: "https://cfg.example.com/v1", bucket: "https://my-bkt.s3.amazonaws.com/x" };
        goTo("/dashboard/settings");
        """
        findings = analyze_js(source, source_url="https://cdn.example.com/app.9381.js")
        by_type: dict[str, set[str]] = {}
        for f in findings:
            by_type.setdefault(f.finding_type.value, set()).add(f.value)
        self.assertIn("/api/v2/internal/export?account_id=5&format=json", by_type[FindingType.ENDPOINT_CANDIDATE.value])
        self.assertIn("wss://events.example.com/stream", by_type[FindingType.ENDPOINT_CANDIDATE.value])
        self.assertIn("app.9381.js.map", by_type[FindingType.SOURCE_MAP.value])
        self.assertIn("account_id", by_type[FindingType.PARAMETER_CANDIDATE.value])
        self.assertIn("/dashboard/settings", by_type.get(FindingType.ROUTE_CANDIDATE.value, set()))
        self.assertTrue(any("s3.amazonaws.com" in v for v in by_type[FindingType.CONFIG_REFERENCE.value]))

    def test_secret_detection_is_conservative(self) -> None:
        # Real-looking secret with key context is flagged.
        flagged = analyze_js('const config = { api_secret: "aZ3!xQ9rLp2mWv7Tn" };')
        self.assertTrue(any(f.finding_type is FindingType.SECRET_CANDIDATE for f in flagged))
        # Known provider token shape stands alone.
        self.assertTrue(any(f.finding_type is FindingType.SECRET_CANDIDATE
                            for f in analyze_js('x="AKIAIOSFODNN7EXAMPLE"')))
        # Non-secrets must NOT be flagged.
        for benign in ('var hash = "a1b2c3d4e5f6a7b8";',
                       'const id = "550e8400-e29b-41d4-a716-446655440000";',
                       'const key = "YOUR_API_KEY_HERE";',
                       'const path = "/static/js/app.1a2b3c4d.js";',
                       'const token = "{{csrf_token}}";'):
            secrets = [f for f in analyze_js(benign) if f.finding_type is FindingType.SECRET_CANDIDATE]
            self.assertEqual(secrets, [], benign)

    def test_is_probable_secret_rules(self) -> None:
        self.assertTrue(is_probable_secret("aZ3!xQ9rLp2mWv7Tn"))
        self.assertFalse(is_probable_secret("your_api_key"))
        self.assertFalse(is_probable_secret("/api/v1/users"))
        self.assertFalse(is_probable_secret("550e8400-e29b-41d4-a716-446655440000"))

    def test_source_map_analysis(self) -> None:
        import json
        sm = json.dumps({
            "sources": ["webpack:///src/api/client.ts", "webpack:///src/config.ts"],
            "sourcesContent": ['const u = "/api/internal/admin/export"; const r = "/home";'],
        })
        findings = analyze_source_map(sm)
        values = {f.value for f in findings}
        self.assertIn("webpack:///src/api/client.ts", values)
        self.assertIn("/api/internal/admin/export", values)

    def test_companion_source_map_url(self) -> None:
        self.assertEqual(companion_source_map_url("https://e.com/app.js?v=3"), "https://e.com/app.js.map")


class EndpointTests(unittest.TestCase):
    def test_path_normalization_placeholders(self) -> None:
        self.assertEqual(normalize_path("/api/users/123/orders/456"), "/api/users/{id}/orders/{id}")
        self.assertEqual(normalize_path("/u/550e8400-e29b-41d4-a716-446655440000"), "/u/{uuid}")
        self.assertEqual(normalize_path("/users/:id/profile"), "/users/{id}/profile")

    def test_identity_merges_sources_and_keeps_distinct_methods(self) -> None:
        eps = [
            make_endpoint("api.example.com", "/api/users/1", method="get", source="html"),
            make_endpoint("api.example.com", "/api/users/2", method="get", source="js"),
            make_endpoint("api.example.com", "/api/users/{id}", method="POST", source="openapi"),
            make_endpoint("api.example.com", "/api/users/9", source="history"),   # UNKNOWN method
        ]
        merged = merge_endpoints(eps)
        ids = {identity_string(e): e for e in merged}
        # Same path, different methods stay distinct; UNKNOWN is never folded into GET.
        self.assertEqual(set(ids), {
            "GET api.example.com/api/users/{id}",
            "POST api.example.com/api/users/{id}",
            "UNKNOWN api.example.com/api/users/{id}",
        })
        get_ep = ids["GET api.example.com/api/users/{id}"]
        self.assertEqual(get_ep.method_confidence, MethodConfidence.KNOWN)
        self.assertEqual(set(get_ep.source.split(",")), {"html", "js"})

    def test_unknown_method_is_not_get(self) -> None:
        ep = make_endpoint("e.com", "/x")
        self.assertEqual(ep.method, "UNKNOWN")
        self.assertEqual(ep.method_confidence, MethodConfidence.UNKNOWN)

    def test_parameter_dedup(self) -> None:
        params = [
            Parameter("id", ParamLocation.QUERY, "GET e.com/x", "html"),
            Parameter("id", ParamLocation.QUERY, "GET e.com/x", "js"),
            Parameter("id", ParamLocation.PATH, "GET e.com/x", "openapi"),
        ]
        merged = merge_parameters(params)
        self.assertEqual(len(merged), 2)  # query vs path are distinct locations


class OpenApiTests(unittest.TestCase):
    SPEC = """
    {"openapi":"3.0.0","info":{"title":"Demo API"},
     "servers":[{"url":"https://api.example.com/v2"}],
     "components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}},
     "paths":{
       "/users/{id}":{
         "parameters":[{"name":"id","in":"path"}],
         "get":{"parameters":[{"name":"expand","in":"query"}]},
         "put":{"deprecated":true,"requestBody":{"content":{}}}
       },
       "/admin/export":{"post":{"parameters":[{"name":"format","in":"query"}]}}
     }}
    """

    def test_detects_and_parses(self) -> None:
        self.assertTrue(looks_like_openapi(self.SPEC))
        result = parse_openapi(self.SPEC, "api.example.com")
        idents = {identity_string(e) for e in result.endpoints}
        self.assertEqual(idents, {
            "GET api.example.com/users/{id}",
            "PUT api.example.com/users/{id}",
            "POST api.example.com/admin/export",
        })
        self.assertEqual(result.title, "Demo API")
        self.assertIn("http", result.auth_schemes)
        self.assertEqual(result.server_urls, ["https://api.example.com/v2"])
        self.assertIn("PUT /users/{id}", result.deprecated)
        names = {(p.name, p.location.value) for p in result.parameters}
        self.assertIn(("id", "path"), names)
        self.assertIn(("expand", "query"), names)

    def test_non_spec_rejected(self) -> None:
        self.assertFalse(looks_like_openapi('{"just":"json"}'))
        self.assertIsNone(parse_openapi("not json", "e.com"))

    def test_graphql_body_recognition(self) -> None:
        self.assertTrue(graphql_candidates_from_text('{"query":"query { me { id } }"}'))
        self.assertFalse(graphql_candidates_from_text('{"q":"select"}'))


class TechTests(unittest.TestCase):
    def test_headers_cookies_html(self) -> None:
        techs = {t.name: t for t in fingerprint(
            headers={"Server": "nginx/1.25.3", "X-Powered-By": "Next.js", "CF-RAY": "abc"},
            html='<html><meta name="generator" content="WordPress 6.4"><div id="___gatsby"></div></html>',
            set_cookie="PHPSESSID=abc; path=/",
        )}
        self.assertEqual(techs["nginx"].version, "1.25.3")
        self.assertIn("Next.js", techs)
        self.assertIn("Cloudflare", techs)
        self.assertIn("PHP", techs)
        self.assertEqual(techs["WordPress"].version, "6.4")

    def test_no_false_versions(self) -> None:
        techs = fingerprint(headers={"Server": "Apache"})
        self.assertEqual(techs[0].name, "Apache")
        self.assertIsNone(techs[0].version)


if __name__ == "__main__":
    unittest.main()
