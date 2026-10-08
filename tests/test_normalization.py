"""Each normalization rule in isolation, plus the guarantees that it stays conservative."""

import unittest

from shadow_scan.normalization import (
    DEFAULT_NORMALIZER,
    collapse_whitespace,
    mask_csrf_tokens,
    mask_nonces,
    mask_render_timestamps,
    mask_request_ids,
    strip_html_comments,
)
from shadow_scan.similarity import build_sketch, sketch_similarity


class RuleTests(unittest.TestCase):
    def test_strip_html_comments(self) -> None:
        self.assertEqual(strip_html_comments("<p>a<!-- rendered 12:00:01\n by web-3 -->b</p>"), "<p>ab</p>")

    def test_mask_csrf_meta_and_inputs(self) -> None:
        html = (
            '<meta name="csrf-token" content="AbC123==">'
            "<input type='hidden' value='tok-1' name='authenticity_token'>"
            '<input type="hidden" name="__VIEWSTATE" value="/wEPDwUK">'
        )
        masked = mask_csrf_tokens(html)
        for secret in ("AbC123==", "tok-1", "/wEPDwUK"):
            self.assertNotIn(secret, masked)
        # Same tokens with different values normalize identically.
        self.assertEqual(masked, mask_csrf_tokens(html.replace("AbC123==", "zzz").replace("tok-1", "tok-2")))

    def test_csrf_rule_leaves_other_inputs_alone(self) -> None:
        html = '<input type="hidden" name="role" value="admin"><input name="csrf_tokenizer_mode" value="x">'
        self.assertEqual(mask_csrf_tokens(html), html)

    def test_mask_nonces(self) -> None:
        a = '<script nonce="r4nd0m1">x()</script><style data-nonce=abc>p{}</style>'
        b = '<script nonce="0ther">x()</script><style data-nonce=xyz>p{}</style>'
        self.assertEqual(mask_nonces(a), mask_nonces(b))
        self.assertIn("x()", mask_nonces(a))
        # Not an attribute: left alone.
        self.assertEqual(mask_nonces("<p>nonce=abc</p>"), "<p>nonce=abc</p>")

    def test_mask_request_ids(self) -> None:
        a = ('<body data-request-id="3f2b8c1e-9d4a-4b7e-8f00-123456789abc">'
             '<meta name="trace-id" content="00-abcdef1234567890">'
             '<script>var c={"requestId":"r-12345678","user":"bob"}</script>')
        b = a.replace("3f2b8c1e", "aaaaaaaa").replace("abcdef1234567890", "1111111111111111").replace("r-12345678", "r-87654321")
        self.assertEqual(mask_request_ids(a), mask_request_ids(b))
        self.assertIn('"user":"bob"', mask_request_ids(a))

    def test_request_id_rule_ignores_plain_ids(self) -> None:
        html = '<div id="main-container" data-user-id="12345678">'
        self.assertEqual(mask_request_ids(html), html)

    def test_mask_render_timestamps(self) -> None:
        a = ('<div data-timestamp="1712345678901"><meta name="generated-at" content="2026-01-02T03:04:05Z">'
             '<script>{"serverTime": 1712345678, "version": "1.2.3"}</script>')
        b = a.replace("1712345678901", "1799999999999").replace("03:04:05", "09:09:09").replace(": 1712345678,", ": 1799999999,")
        self.assertEqual(mask_render_timestamps(a), mask_render_timestamps(b))
        self.assertIn('"version": "1.2.3"', mask_render_timestamps(a))

    def test_timestamp_rule_keeps_build_and_modified_times(self) -> None:
        # Build / modification times change when something was really deployed or edited.
        html = '<meta name="build-time" content="1712345678"><div data-modified="1712345678">'
        self.assertEqual(mask_render_timestamps(html), html)

    def test_collapse_whitespace(self) -> None:
        self.assertEqual(collapse_whitespace("<ul>\n  <li>a   b</li>\r\n</ul>\n"), "<ul><li>a b</li></ul>")


class ConservativenessTests(unittest.TestCase):
    """Security-relevant differences must survive normalization."""

    def assert_distinct(self, a: str, b: str) -> None:
        self.assertNotEqual(DEFAULT_NORMALIZER(a), DEFAULT_NORMALIZER(b))

    def test_meaningful_changes_are_preserved(self) -> None:
        cases = [
            ('<script src="/static/app.1a2b.js"></script>', '<script src="/static/app.9z8y.js"></script>'),
            ('<a href="/admin">Admin</a>', '<a href="/login">Login</a>'),
            ('<form action="/api/v1/upload">', '<form action="/api/v2/upload">'),
            ('<input type="hidden" name="debug" value="false">', '<input type="hidden" name="debug" value="true">'),
            ("<p>Welcome guest</p>", "<p>Welcome admin</p>"),
            ('<meta name="version" content="1.0.0">', '<meta name="version" content="1.0.1">'),
            ('<script src="/app.js?v=1712345678">', '<script src="/app.js?v=1799999999">'),
            ('{"status":"ok","role":"user"}', '{"status":"ok","role":"admin"}'),
        ]
        for a, b in cases:
            with self.subTest(a=a):
                self.assert_distinct(a, b)

    def test_volatile_only_changes_normalize_equal(self) -> None:
        page = ('<html>\n<head><meta name="csrf-token" content="{tok}"><!-- {ts} --></head>\n'
                '<body data-request-id="{rid}"><script nonce="{n}">init()</script><p>Hello</p></body></html>')
        a = page.format(tok="t1", ts="12:00", rid="3f2b8c1e-9d4a-4b7e-8f00-123456789abc", n="aaaa")
        b = page.format(tok="t2", ts="12:01", rid="11111111-2222-3333-4444-555555555555", n="bbbb").replace("\n", "\r\n  ")
        self.assertNotEqual(a, b)
        self.assertEqual(DEFAULT_NORMALIZER(a), DEFAULT_NORMALIZER(b))


class SimilarityTests(unittest.TestCase):
    @staticmethod
    def page(words: list[str]) -> str:
        return "<html><body>" + "".join(f"<p>{w} lorem ipsum dolor sit amet</p>" for w in words) + "</body></html>"

    def test_identical_and_disjoint(self) -> None:
        a = build_sketch(self.page([f"w{i}" for i in range(300)]), 1 << 20)
        self.assertEqual(sketch_similarity(a, a), 1.0)
        c = build_sketch("<div>" + " ".join(f"x{i}" for i in range(3000)) + "</div>", 1 << 20)
        self.assertLess(sketch_similarity(a, c), 0.05)

    def test_small_edit_scores_high_and_rewrite_scores_low(self) -> None:
        base = [f"w{i}" for i in range(300)]
        a = build_sketch(self.page(base), 1 << 20)
        small = build_sketch(self.page(base[:150] + ["CHANGED"] + base[151:]), 1 << 20)
        rewrite = build_sketch(self.page(base[:60] + [f"new{i}" for i in range(240)]), 1 << 20)
        self.assertGreaterEqual(sketch_similarity(a, small), 0.98)
        self.assertLess(sketch_similarity(a, rewrite), 0.8)

    def test_insertion_does_not_shift_every_chunk(self) -> None:
        base = [f"w{i}" for i in range(300)]
        a = build_sketch(self.page(base), 1 << 20)
        inserted = build_sketch(self.page(["INSERTED"] + base), 1 << 20)
        self.assertGreater(sketch_similarity(a, inserted), 0.95)

    def test_oversize_text_gets_no_sketch(self) -> None:
        self.assertIsNone(build_sketch("x" * 100, max_bytes=50))


if __name__ == "__main__":
    unittest.main()
