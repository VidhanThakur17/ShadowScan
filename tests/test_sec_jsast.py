import unittest

from shadow_scan.secanalysis.jsast import AST_AVAILABLE, MAX_RESOLVE_DEPTH, analyze


@unittest.skipUnless(AST_AVAILABLE, "tree-sitter not installed")
class JsAstTests(unittest.TestCase):
    def endpoints(self, src):
        return {(e.value, e.method) for e in analyze(src).endpoints}

    def test_fetch_literal(self):
        self.assertIn(("/api/users", "UNKNOWN"), self.endpoints('fetch("/api/users");'))

    def test_fetch_with_method_option(self):
        eps = self.endpoints('fetch("/api/login", {method: "POST"});')
        self.assertIn(("/api/login", "POST"), eps)

    def test_axios_methods(self):
        self.assertIn(("/api/users", "GET"), self.endpoints('axios.get("/api/users");'))
        self.assertIn(("/api/login", "POST"), self.endpoints('axios.post("/api/login", {});'))

    def test_template_literal_with_const_resolution(self):
        src = 'const base = "/api/v2"; fetch(`${base}/users/${id}`);'
        vals = {e.value for e in analyze(src).endpoints}
        self.assertIn("/api/v2/users/{id}", vals)

    def test_concatenation_resolution(self):
        src = 'const api = "/api"; const route = api + "/users"; fetch(route);'
        self.assertIn(("/api/users", "UNKNOWN"), self.endpoints(src))

    def test_route_object_extraction(self):
        src = 'const r = { path: "/admin/panel", method: "post" };'
        self.assertIn(("/admin/panel", "POST"), self.endpoints(src))

    def test_websocket(self):
        src = 'const ws = new WebSocket("wss://events.example.com/stream");'
        kinds = {(e.value, e.kind) for e in analyze(src).endpoints}
        self.assertIn(("wss://events.example.com/stream", "websocket"), kinds)

    def test_base_url_capture(self):
        src = 'const client = axios.create({ baseURL: "https://api.example.com/v1" });'
        self.assertIn("https://api.example.com/v1", analyze(src).base_urls)

    def test_dynamic_param_recorded(self):
        src = 'const base="/api"; fetch(`${base}/users/${userId}`);'
        res = analyze(src)
        self.assertIn("userId", res.route_params)
        self.assertTrue(any("{userId}" in e.value for e in res.endpoints))

    def test_graphql_operations(self):
        src = 'const q = gql`query GetMe { me { id } } mutation DoThing { x }`;'
        ops = set(analyze(src).graphql_ops)
        self.assertIn("GetMe", ops)
        self.assertIn("DoThing", ops)

    def test_depth_limit_caps_single_expression_nesting(self):
        # A single concatenation expression nested far beyond MAX_RESOLVE_DEPTH must
        # not fully resolve (per-expression depth cap), and must not hang/crash.
        deep = '"/a"' + ''.join(' + "/x"' for _ in range(MAX_RESOLVE_DEPTH + 10))
        res = analyze(f'fetch({deep});')
        self.assertTrue(all(e.value.count("/x") < MAX_RESOLVE_DEPTH + 10 for e in res.endpoints))

    def test_bounded_alias_chain_resolves(self):
        # A finite alias chain is legitimate data-flow and resolves (linear, bounded).
        lines = ['const a0 = "/api";'] + [f'const a{i} = a{i-1} + "/x";' for i in range(1, 4)]
        lines.append("fetch(a3);")
        res = analyze("\n".join(lines))
        self.assertIn("/api/x/x/x", {e.value for e in res.endpoints})

    def test_cyclic_reference_terminates(self):
        src = 'let a = b; let b = a; fetch(`${a}/x`);'
        res = analyze(src)   # must not hang or raise
        self.assertIsNotNone(res)

    def test_pathological_input_does_not_crash(self):
        for bad in ("((((((", 'fetch(', '`${', "const x = ;", "\x00\x01\x02", "fetch(`" + "${a}" * 500 + "`)"):
            self.assertIsNotNone(analyze(bad))

    def test_findings_conversion(self):
        src = 'fetch("/api/internal/export"); axios.post("/api/login", {});'
        findings = analyze(src).to_findings()
        values = {f.value for f in findings}
        self.assertIn("/api/internal/export", values)
        self.assertIn("/api/login", values)

    def test_to_findings_graphql_and_params(self):
        src = 'const b="/api"; fetch(`${b}/u/${uid}`); const q = gql`query Q { a }`;'
        findings = analyze(src).to_findings()
        types = {f.finding_type.value for f in findings}
        self.assertIn("parameter_candidate", types)
        self.assertIn("graphql_candidate", types)


class FallbackTests(unittest.TestCase):
    def test_graceful_when_unavailable(self):
        # Even if available, analyze() always returns a result object; never raises.
        self.assertIsNotNone(analyze("fetch('/x')"))


if __name__ == "__main__":
    unittest.main()
