"""Structured report generation (JSON / Markdown) and platform formatters.

Reports are built from stored structured evidence. They never fabricate impact
and always distinguish, per the report-safety rule:

  observed fact  |  automated hypothesis  |  non-destructive validation  |  manual confirmation

AI hypotheses are labeled advisory and never presented as confirmed
vulnerabilities. Evidence is redacted. No automatic submission to any platform.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..secanalysis.findings import redact

_VALIDATION_LABEL = {
    "observed": "Observed (passive)",
    "suspected": "Suspected (needs validation)",
    "validated_non_destructively": "Validated non-destructively (automated, read-only)",
    "manual_validation_required": "Manual validation required",
}


@dataclass(slots=True)
class FindingReport:
    title: str
    asset: str
    endpoint: str | None
    category: str
    confidence: float
    validation_state: str
    lifecycle: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    ai_hypotheses: list[dict[str, Any]] = field(default_factory=list)
    manual_package: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)
    timeline: list[dict[str, str]] = field(default_factory=list)

    def impact_statement(self) -> str:
        if self.lifecycle in ("confirmed", "reported"):
            return "Impact confirmed by manual researcher validation (see timeline)."
        return ("Impact NOT established automatically. Manual validation is required before "
                "any impact can be claimed. The items below are observations/hypotheses only.")


def _provenance_line(validation_state: str) -> str:
    return _VALIDATION_LABEL.get(validation_state, validation_state)


def render_finding_markdown(report: FindingReport, *, formatter: str = "generic") -> str:
    """Render a researcher-ready finding draft. ``formatter`` tweaks headers only."""
    h = _FORMATTER_HEADERS.get(formatter, _FORMATTER_HEADERS["generic"])
    lines: list[str] = [f"# {redact(report.title)}", ""]
    lines += [f"- **Asset:** {report.asset}",
              f"- **Endpoint:** {report.endpoint or 'n/a'}",
              f"- **Category:** {report.category}",
              f"- **Confidence:** {report.confidence:.2f}",
              f"- **Validation:** {_provenance_line(report.validation_state)}",
              f"- **Status:** {report.lifecycle}", ""]
    lines += [f"## {h['summary']}", "",
              "This report was assembled by ShadowScan from stored evidence. "
              "Automated hypotheses are advisory and are **not** confirmed vulnerabilities.", ""]
    lines += [f"## {h['evidence']}", ""]
    if report.evidence:
        for i, ev in enumerate(report.evidence, 1):
            lines.append(f"- `E{i}` [{ev.get('kind', 'evidence')}] {redact(str(ev.get('summary', '')))}")
    else:
        lines.append("- (no stored evidence)")
    lines += ["", f"## {h['repro']}", "",
              "> The following are suggested, non-destructive manual steps. "
              "ShadowScan does not perform state-changing tests automatically.", ""]
    if report.manual_package:
        pkg = report.manual_package
        lines.append(f"- Request shape: `{pkg.get('request_shape', 'n/a')}`")
        if pkg.get("required_auth_context"):
            lines.append(f"- Required auth context: {pkg['required_auth_context']}")
        for t in pkg.get("suggested_manual_tests", []):
            lines.append(f"- {t}")
    else:
        lines.append("- Reproduce the observation above and validate manually.")
    lines += ["", f"## {h['impact']}", "", report.impact_statement(), ""]
    if report.ai_hypotheses:
        lines += ["## AI Hypotheses (advisory — not confirmed)", ""]
        for hyp in report.ai_hypotheses:
            lines.append(f"- {redact(str(hyp.get('title', '')))} "
                         f"(confidence {hyp.get('confidence', 0)})")
    if report.notes:
        lines += ["", "## Researcher Notes", ""] + [f"- {redact(n)}" for n in report.notes]
    if report.timeline:
        lines += ["", "## Timeline", ""]
        for ev in report.timeline:
            lines.append(f"- {ev.get('created_at', '')}: {ev.get('event', '')} {ev.get('detail') or ''}".rstrip())
    lines += ["", "## References", "", "- (add program/platform references)", ""]
    return "\n".join(lines)


def render_finding_json(report: FindingReport) -> dict[str, Any]:
    return {
        "title": redact(report.title), "asset": report.asset, "endpoint": report.endpoint,
        "category": report.category, "confidence": round(report.confidence, 3),
        "validation": _provenance_line(report.validation_state), "status": report.lifecycle,
        "impact_statement": report.impact_statement(),
        "evidence": [{"id": f"E{i}", "kind": e.get("kind"), "summary": redact(str(e.get("summary", "")))}
                     for i, e in enumerate(report.evidence, 1)],
        "ai_hypotheses_advisory": [{"title": redact(str(h.get("title", ""))),
                                    "confidence": h.get("confidence"),
                                    "manual_tests": h.get("manual_tests", [])} for h in report.ai_hypotheses],
        "manual_package": report.manual_package,
        "notes": [redact(n) for n in report.notes],
        "timeline": report.timeline,
    }


_FORMATTER_HEADERS = {
    "generic": {"summary": "Summary", "evidence": "Evidence", "repro": "Steps to Reproduce", "impact": "Security Impact"},
    "hackerone": {"summary": "Summary", "evidence": "Evidence", "repro": "Steps To Reproduce", "impact": "Impact"},
    "bugcrowd": {"summary": "Description", "evidence": "Evidence", "repro": "Reproduction Steps", "impact": "Impact"},
}


@dataclass(slots=True)
class RunReport:
    program: str
    run_timestamp: str
    summary: dict[str, Any]
    top_items: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {"program": self.program, "run_timestamp": self.run_timestamp,
                "summary": self.summary, "top_items": self.top_items}

    def to_markdown(self) -> str:
        lines = [f"# ShadowScan run report — {self.program}", "", f"Run: {self.run_timestamp}", ""]
        for section, value in self.summary.items():
            lines.append(f"- **{section}:** {value}")
        if self.top_items:
            lines += ["", "## Top items", ""]
            for item in self.top_items:
                lines.append(f"- [{item.get('priority', 0):>3}] {item.get('title', '')} "
                             f"({item.get('asset', '')})")
        return "\n".join(lines)


def write_report(path, content: str | dict) -> None:
    import os
    from pathlib import Path
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = content if isinstance(content, str) else json.dumps(content, indent=2, ensure_ascii=False)
    fd, tmp = __import__("tempfile").mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            if not text.endswith("\n"):
                fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
