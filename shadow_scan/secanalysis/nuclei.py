"""Optional Nuclei integration through the existing tool-adapter model.

Conservative by construction: only safe template categories run (never DoS,
intrusive, brute-force, credential, or destructive templates), with a strict
timeout, bounded rate and a scope-controlled target list. Output is parsed from
Nuclei's JSONL into ShadowScan :class:`Finding` objects, which then flow through
the same deduplication/correlation as every other source.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator

from ..recon.tools.base import ToolAdapter, ToolResult
from .findings import make_evidence
from .models import Finding, ValidationState

# Conservative profiles -> Nuclei tag selections. Intrusive/destructive tags are excluded.
NUCLEI_PROFILES: dict[str, tuple[str, ...]] = {
    "passive": ("tech", "ssl", "dns"),
    "exposure": ("exposure", "exposures", "config", "backup"),
    "misconfig": ("misconfiguration", "misconfig", "headers", "cors"),
    "safe_web": ("tech", "exposure", "misconfiguration", "headers"),
}
# Tags that must never be included, even if a profile or user requests them.
_EXCLUDED_TAGS = ("dos", "intrusive", "fuzz", "fuzzing", "brute-force", "bruteforce",
                  "default-login", "sqli", "rce", "xss", "injection")
_EXCLUDED_SEVERITY = ("critical",)   # critical templates are often intrusive; require manual opt-in
_SEVERITY_PRIORITY = {"info": 15, "low": 30, "medium": 55, "high": 75, "unknown": 20}


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    version_args = ("-version",)

    def __init__(self, *args, profiles: Iterable[str] = ("passive", "exposure", "misconfig"),
                 rate_limit: int = 20, concurrency: int = 10, timeout_per_target: int = 5, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._profiles = tuple(profiles)
        self._rate_limit = rate_limit
        self._concurrency = concurrency
        self._timeout_per_target = timeout_per_target

    def selected_tags(self) -> list[str]:
        tags: list[str] = []
        for profile in self._profiles:
            for tag in NUCLEI_PROFILES.get(profile, ()):  # unknown profile contributes nothing
                if tag not in tags and tag not in _EXCLUDED_TAGS:
                    tags.append(tag)
        return tags

    def build_args(self, targets: Iterable[str]) -> list[str]:
        tags = self.selected_tags()
        args = [
            "nuclei", "-silent", "-jsonl", "-disable-update-check",
            "-rate-limit", str(self._rate_limit),
            "-concurrency", str(self._concurrency),
            "-timeout", str(self._timeout_per_target),
            "-exclude-tags", ",".join(_EXCLUDED_TAGS),
            "-exclude-severity", ",".join(_EXCLUDED_SEVERITY),
        ]
        if tags:
            args += ["-tags", ",".join(tags)]
        for target in targets:
            args += ["-target", target]
        return args

    def parse(self, result: ToolResult) -> Iterator[str]:
        # The base dedups strings; we yield raw JSONL lines and convert separately.
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                yield line


def parse_findings(jsonl_lines: Iterable[str]) -> list[Finding]:
    """Convert Nuclei JSONL output into ShadowScan findings, dropping unsafe hits."""
    findings: list[Finding] = []
    for line in jsonl_lines:
        try:
            doc = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(doc, dict):
            continue
        info = doc.get("info", {}) if isinstance(doc.get("info"), dict) else {}
        tags = info.get("tags", [])
        tag_list = tags if isinstance(tags, list) else [t.strip() for t in str(tags).split(",")]
        # Defense-in-depth: discard any result carrying an excluded tag.
        if any(t in _EXCLUDED_TAGS for t in tag_list):
            continue
        severity = str(info.get("severity", "unknown")).lower()
        if severity in _EXCLUDED_SEVERITY:
            continue
        host = doc.get("host") or doc.get("ip") or ""
        host = str(host).replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        matched = doc.get("matched-at") or doc.get("matched_at") or doc.get("host") or ""
        template = doc.get("template-id") or doc.get("templateID") or info.get("name") or "nuclei"
        findings.append(Finding(
            check_id=f"nuclei.{template}", asset=host, category="nuclei:" + (tag_list[0] if tag_list else "generic"),
            title=str(info.get("name", template))[:200],
            confidence=0.6, severity_hint=severity,
            endpoint=_path_of(str(matched)), review_priority=_SEVERITY_PRIORITY.get(severity, 20),
            validation_state=ValidationState.OBSERVED, source="nuclei",
            evidence=[make_evidence("response", "nuclei match",
                                    data={"template": str(template), "matched_at": str(matched)[:200],
                                          "tags": tag_list[:10], "severity": severity})],
        ))
    return findings


def _path_of(matched: str) -> str | None:
    if "://" in matched:
        rest = matched.split("://", 1)[1]
        slash = rest.find("/")
        return rest[slash:] if slash != -1 else "/"
    return matched or None
