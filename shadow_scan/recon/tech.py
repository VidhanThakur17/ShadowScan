"""Lightweight, passive technology fingerprinting.

Evidence comes only from data already collected during probing: response
headers, cookies, a bounded slice of HTML, and asset-path hints. Detection is
conservative — a technology is reported only on a concrete signal, and a
version only when it appears verbatim. No active version probing.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from .models import Technology

# Each rule: (name, where, pattern, version_group). ``where`` selects the haystack.
_HEADER_RULES: tuple[tuple[str, str, re.Pattern[str], int | None], ...] = (
    ("nginx", "server", re.compile(r"nginx(?:/([\d.]+))?", re.I), 1),
    ("Apache", "server", re.compile(r"apache(?:/([\d.]+))?", re.I), 1),
    ("Microsoft-IIS", "server", re.compile(r"microsoft-iis(?:/([\d.]+))?", re.I), 1),
    ("ASP.NET", "x-powered-by", re.compile(r"asp\.net", re.I), None),
    ("ASP.NET", "x-aspnet-version", re.compile(r"([\d.]+)", re.I), 1),
    ("PHP", "x-powered-by", re.compile(r"php(?:/([\d.]+))?", re.I), 1),
    ("Express", "x-powered-by", re.compile(r"express", re.I), None),
    ("Next.js", "x-powered-by", re.compile(r"next\.js", re.I), None),
    ("Cloudflare", "server", re.compile(r"cloudflare", re.I), None),
    ("Cloudflare", "cf-ray", re.compile(r".+"), None),
    ("Akamai", "x-akamai-transformed", re.compile(r".+"), None),
    ("Varnish", "via", re.compile(r"varnish", re.I), None),
    ("Amazon S3", "server", re.compile(r"amazons3", re.I), None),
    ("Vercel", "server", re.compile(r"vercel", re.I), None),
)
_COOKIE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PHP", re.compile(r"\bPHPSESSID\b")),
    ("Java", re.compile(r"\bJSESSIONID\b")),
    ("ASP.NET", re.compile(r"\bASP\.NET_SessionId\b|\.ASPXAUTH\b")),
    ("Laravel", re.compile(r"\blaravel_session\b")),
    ("Django", re.compile(r"\bcsrftoken\b|\bsessionid\b")),
    ("WordPress", re.compile(r"\bwordpress_|wp-settings")),
    ("Express", re.compile(r"\bconnect\.sid\b")),
    ("Flask", re.compile(r"\bsession=eyJ")),
)
_HTML_RULES: tuple[tuple[str, re.Pattern[str], int | None], ...] = (
    ("WordPress", re.compile(r'/wp-content/|/wp-includes/|content="WordPress(?:\s+([\d.]+))?"', re.I), 1),
    ("Drupal", re.compile(r'content="Drupal(?:\s+([\d.]+))?"|/sites/default/files/', re.I), 1),
    ("Joomla", re.compile(r"/media/jui/|content=\"Joomla", re.I), None),
    ("React", re.compile(r"\bdata-reactroot\b|/static/js/main\.[0-9a-f]+\.chunk\.js", re.I), None),
    ("Angular", re.compile(r"\bng-version=\"([\d.]+)\"|\bng-app\b", re.I), 1),
    ("Vue.js", re.compile(r"\bdata-v-[0-9a-f]{8}\b|__vue__", re.I), None),
    ("Next.js", re.compile(r"/_next/static/|__NEXT_DATA__", re.I), None),
    ("Nuxt.js", re.compile(r"/_nuxt/|__NUXT__", re.I), None),
    ("Gatsby", re.compile(r"id=\"___gatsby\"", re.I), None),
)
_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)


def _headers_lower(headers: Mapping[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def fingerprint(
    headers: Mapping[str, str] | None = None,
    html: str | None = None,
    set_cookie: str | None = None,
) -> list[Technology]:
    """Return de-duplicated technology detections from passive evidence."""
    found: dict[str, Technology] = {}

    def record(name: str, version: str | None, confidence: float, evidence: str) -> None:
        existing = found.get(name)
        if existing is None or (version and not existing.version) or confidence > existing.confidence:
            version = version or (existing.version if existing else None)
            found[name] = Technology(name=name, version=version,
                                     confidence=max(confidence, existing.confidence if existing else 0.0),
                                     evidence=evidence[:120])

    hdrs = _headers_lower(headers or {})
    for name, header, pattern, vgroup in _HEADER_RULES:
        value = hdrs.get(header)
        if value is None:
            continue
        match = pattern.search(value)
        if match:
            version = match.group(vgroup) if vgroup and match.lastindex and match.lastindex >= vgroup else None
            record(name, version, 0.9, f"{header}: {value}")

    cookie_blob = set_cookie or hdrs.get("set-cookie", "")
    for name, pattern in _COOKIE_RULES:
        if pattern.search(cookie_blob):
            record(name, None, 0.75, "cookie name")

    if html:
        sample = html[:200_000]
        for name, pattern, vgroup in _HTML_RULES:
            match = pattern.search(sample)
            if match:
                version = match.group(vgroup) if vgroup and match.lastindex and match.lastindex >= vgroup else None
                record(name, version, 0.7, "html marker")
        gen = _GENERATOR_RE.search(sample)
        if gen:
            text = gen.group(1)
            name, _, version = text.partition(" ")
            record(name.strip() or text, version.strip() or None, 0.8, f"generator: {text[:60]}")

    return list(found.values())
