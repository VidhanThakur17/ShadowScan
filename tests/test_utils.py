import hashlib
import socket
import ssl
import unittest
from functools import partial
from types import SimpleNamespace

import aiohttp

from shadow_scan.fingerprint import (
    FingerprintEngine,
    NormalizedContentFingerprinter,
    RawSha256Fingerprinter,
    ResponseInfo,
    extract_title,
)
from shadow_scan.http_probe import classify_exception
from shadow_scan.models import ErrorType
from shadow_scan.utils import InvalidTargetError, ScopePolicy, normalize_target, parse_targets


class NormalizeTargetTests(unittest.TestCase):
    def test_scheme_less_target_tries_https_then_http(self) -> None:
        target = normalize_target("  Example.COM.  ")
        self.assertEqual(target.key, "example.com")
        self.assertIsNone(target.scheme)
        self.assertEqual(
            target.candidate_urls(http_fallback=True), ["https://example.com/", "http://example.com/"]
        )
        self.assertEqual(target.candidate_urls(http_fallback=False), ["https://example.com/"])

    def test_explicit_scheme_is_preserved_and_never_falls_back(self) -> None:
        target = normalize_target("http://legacy.example.com")
        self.assertEqual(target.key, "legacy.example.com")   # identity is host-based
        self.assertEqual(target.scheme, "http")              # intent is kept separately
        self.assertEqual(target.original, "http://legacy.example.com")
        self.assertEqual(target.candidate_urls(http_fallback=True), ["http://legacy.example.com/"])

    def test_default_port_trailing_slash_and_fragment_are_dropped(self) -> None:
        target = normalize_target("HTTPS://Portal.Example.com:443/#frag")
        self.assertEqual((target.key, target.scheme, target.port), ("portal.example.com", "https", None))

    def test_non_default_port_path_and_query_are_kept(self) -> None:
        target = normalize_target("https://api.example.com:8443/v1/health?x=1")
        self.assertEqual(target.key, "api.example.com:8443/v1/health?x=1")
        self.assertEqual(target.port, 8443)
        self.assertEqual(target.candidate_urls(True), ["https://api.example.com:8443/v1/health?x=1"])

    def test_ipv6_target(self) -> None:
        target = normalize_target("http://[::1]:8080")
        self.assertEqual(target.hostname, "::1")
        self.assertEqual(target.candidate_urls(True), ["http://[::1]:8080/"])

    def test_idna_hostname(self) -> None:
        self.assertEqual(normalize_target("bücher.example").hostname, "xn--bcher-kva.example")

    def test_invalid_targets_are_rejected(self) -> None:
        for raw in ("ftp://example.com", "*.example.com", "https://user:pw@example.com",
                    "example.com:99999", "exa mple.com", "-bad-.example.com", "https://"):
            with self.subTest(raw=raw), self.assertRaises(InvalidTargetError):
                normalize_target(raw)


class ParseTargetsTests(unittest.TestCase):
    def test_blank_comment_duplicate_and_invalid_lines(self) -> None:
        lines = [
            "example.com\n",
            "\n",
            "   \n",
            "# a comment\n",
            "EXAMPLE.com\n",            # duplicate after normalization
            "example.com/\n",           # duplicate after normalization
            "https://example.com\n",    # same asset: explicit HTTPS intent wins over auto
            "https://example.com:443/\n",
            "ftp://nope.example.com\n",
            "api.example.com\n",
        ]
        targets, stats = parse_targets(lines)
        self.assertEqual([t.key for t in targets], ["example.com", "api.example.com"])
        self.assertEqual(targets[0].scheme, "https")
        self.assertEqual(targets[0].candidate_urls(http_fallback=True), ["https://example.com/"])
        self.assertEqual(stats.duplicates, 4)
        self.assertEqual(stats.invalid, 1)
        self.assertEqual(stats.skipped_blank, 3)
        self.assertEqual(stats.unique, 2)

    def test_hostname_identity_merges_scheme_variants(self) -> None:
        targets, _ = parse_targets(["https://example.com", "example.com", "example.com:8443", "example.com/admin"])
        self.assertEqual([t.key for t in targets], ["example.com", "example.com:8443", "example.com/admin"])
        # An explicit scheme seen first is never downgraded to "auto" by a later line.
        self.assertEqual(targets[0].scheme, "https")

    def test_conflicting_explicit_schemes_keep_first(self) -> None:
        with self.assertLogs("shadow_scan.utils", level="WARNING"):
            targets, stats = parse_targets(["http://example.com", "https://example.com"])
        self.assertEqual([(t.key, t.scheme) for t in targets], [("example.com", "http")])
        self.assertEqual(stats.duplicates, 1)


class ScopePolicyTests(unittest.TestCase):
    def test_exact_scope(self) -> None:
        scope = ScopePolicy(["example.com"])
        self.assertTrue(scope.allows("EXAMPLE.com."))
        self.assertFalse(scope.allows("www.example.com"))
        self.assertFalse(scope.allows("evil.com"))
        self.assertFalse(scope.allows(None))

    def test_subdomain_scope(self) -> None:
        scope = ScopePolicy(["example.com"], allow_subdomains=True)
        self.assertTrue(scope.allows("a.b.example.com"))
        self.assertFalse(scope.allows("notexample.com"))
        self.assertFalse(scope.allows("example.com.evil.net"))


class FingerprintTests(unittest.TestCase):
    HTML = ResponseInfo(url=None, status=200, content_type="text/html; charset=utf-8")
    PNG = ResponseInfo(url=None, status=200, content_type="image/png")

    def test_streaming_sha256_matches_hashlib(self) -> None:
        session = FingerprintEngine().new_session(self.HTML)
        for chunk in (b"hello ", b"world"):
            session.update(chunk)
        self.assertEqual(
            session.finalize(truncated=False).values,
            {RawSha256Fingerprinter.name: hashlib.sha256(b"hello world").hexdigest()},
        )

    def test_normalizer_hook_runs_before_hashing(self) -> None:
        engine = FingerprintEngine([
            RawSha256Fingerprinter,
            partial(NormalizedContentFingerprinter, normalizer=lambda text: text.lower()),
        ])
        session = engine.new_session(self.HTML)
        session.update(b"HeLLo")
        result = session.finalize(truncated=False)
        self.assertEqual(result.values["normalized_sha256"], hashlib.sha256(b"hello").hexdigest())
        self.assertEqual(result.values["raw_sha256"], hashlib.sha256(b"HeLLo").hexdigest())
        self.assertIsNotNone(result.similarity_sketch)

    def test_binary_normalized_hash_equals_raw_and_has_no_sketch(self) -> None:
        body = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(range(256))
        # Declared binary type, and no Content-Type at all (sniffed by NUL bytes).
        for info in (self.PNG, ResponseInfo(url=None, status=200, content_type=None)):
            with self.subTest(content_type=info.content_type):
                session = FingerprintEngine.default().new_session(info)
                session.update(body)
                result = session.finalize(truncated=False)
                self.assertEqual(result.values["normalized_sha256"], result.values["raw_sha256"])
                self.assertIsNone(result.similarity_sketch)

    def test_truncated_body_has_no_normalized_hash(self) -> None:
        session = FingerprintEngine.default().new_session(self.HTML)
        session.update(b"<html>partial")
        result = session.finalize(truncated=True)
        self.assertIn("raw_sha256", result.values)
        self.assertNotIn("normalized_sha256", result.values)

    def test_oversize_text_is_not_buffered_or_normalized(self) -> None:
        session = FingerprintEngine.default(normalization_max_bytes=10).new_session(self.HTML)
        session.update(b"<html>" + b"x" * 100)
        result = session.finalize(truncated=False)
        self.assertNotIn("normalized_sha256", result.values)
        self.assertIsNone(result.similarity_sketch)

    def test_extract_title(self) -> None:
        body = b"<html><head><TITLE lang='en'>\n  Admin &amp; Login\n</title></head></html>"
        self.assertEqual(extract_title(body, "text/html; charset=utf-8"), "Admin & Login")
        self.assertIsNone(extract_title(body, "application/json"))
        self.assertEqual(extract_title(b"<!DOCTYPE html><title>x</title>", None), "x")
        self.assertIsNone(extract_title(b"<html>no title</html>", "text/html"))


class ClassifyExceptionTests(unittest.TestCase):
    KEY = SimpleNamespace(host="example.com", port=443, ssl=True)

    def test_classification(self) -> None:
        cases = [
            (aiohttp.ClientConnectorError(self.KEY, socket.gaierror(11001, "getaddrinfo failed")), ErrorType.DNS_FAILURE),
            (aiohttp.ClientConnectorError(self.KEY, ConnectionRefusedError(111, "refused")), ErrorType.CONNECTION_REFUSED),
            (aiohttp.ClientConnectorError(self.KEY, OSError(101, "network unreachable")), ErrorType.CONNECTION_ERROR),
            (aiohttp.ClientConnectorError(self.KEY, TimeoutError()), ErrorType.CONNECTION_TIMEOUT),
            (aiohttp.ConnectionTimeoutError("connect timed out"), ErrorType.CONNECTION_TIMEOUT),
            (aiohttp.SocketTimeoutError("read timed out"), ErrorType.READ_TIMEOUT),
            (TimeoutError(), ErrorType.READ_TIMEOUT),
            (ssl.SSLCertVerificationError("certificate verify failed"), ErrorType.TLS_ERROR),
            (aiohttp.InvalidURL("http://["), ErrorType.INVALID_URL),
            (aiohttp.ServerDisconnectedError(), ErrorType.CLIENT_ERROR),
            (RuntimeError("bug"), ErrorType.UNEXPECTED_ERROR),
        ]
        for exc, expected in cases:
            with self.subTest(exc=type(exc).__name__, expected=expected):
                error_type, message = classify_exception(exc)
                self.assertEqual(error_type, expected)
                self.assertLessEqual(len(message), 500)


if __name__ == "__main__":
    unittest.main()
