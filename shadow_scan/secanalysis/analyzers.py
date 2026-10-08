"""Asset-level security analyzers over existing recon evidence.

These are deterministic and mostly passive: they consume inventory ShadowScan
already has (DNS/CNAME history, OpenAPI specs, JS findings, discovered URLs) and
emit structured findings. They never claim a vulnerability — takeover is a
*candidate*, OpenAPI hints are *investigation signals*.
"""

from __future__ import annotations

import re

from ..recon.models import DnsRecord
from ..recon.openapi import OpenApiResult
from .classify import ParamClass, classify_parameter
from .findings import make_evidence
from .models import Finding, ValidationState

# --- subdomain-takeover candidate validation -------------------------------------------

# Well-known provider fingerprints: (provider, cname-suffix pattern, body error signature).
# A match is a *candidate* only; ShadowScan never registers or claims the resource.
_PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str], re.Pattern[str] | None], ...] = (
    ("GitHub Pages", re.compile(r"\.github\.io$", re.I), re.compile(r"There isn't a GitHub Pages site here", re.I)),
    ("Heroku", re.compile(r"\.herok(?:u)?app\.com$", re.I), re.compile(r"No such app|herokucdn", re.I)),
    ("AWS S3", re.compile(r"s3[.\-].*amazonaws\.com$", re.I), re.compile(r"NoSuchBucket", re.I)),
    ("Azure", re.compile(r"\.(?:azurewebsites|cloudapp|trafficmanager)\.net$", re.I), None),
    ("Fastly", re.compile(r"\.fastly\.net$", re.I), re.compile(r"Fastly error: unknown domain", re.I)),
    ("Shopify", re.compile(r"\.myshopify\.com$", re.I), re.compile(r"Sorry, this shop is currently unavailable", re.I)),
    ("Zendesk", re.compile(r"\.zendesk\.com$", re.I), re.compile(r"Help Center Closed", re.I)),
    ("Unbounce", re.compile(r"\.unbounce\.com$", re.I), re.compile(r"The requested URL was not found", re.I)),
    ("Readthedocs", re.compile(r"\.readthedocs\.io$", re.I), None),
)


def takeover_candidate(host: str, dns: DnsRecord, http_body_excerpt: str = "", http_status: int | None = None) -> Finding | None:
    """Return a takeover **candidate** finding, or None. Never 'confirmed' automatically."""
    cname = dns.terminal_cname
    if not cname:
        return None
    for provider, cname_re, body_re in _PROVIDER_PATTERNS:
        if not cname_re.search(cname):
            continue
        # Evidence: points at a provider AND (DNS doesn't resolve OR provider error body seen).
        dangling = not dns.resolves
        error_signature = bool(body_re and http_body_excerpt and body_re.search(http_body_excerpt))
        if not (dangling or error_signature):
            return None
        confidence = 0.75 if error_signature else 0.55
        evidence = [make_evidence("dns", "CNAME points to third-party provider",
                                  data={"cname": cname, "provider": provider, "dns_status": dns.status})]
        if error_signature:
            evidence.append(make_evidence("response", "provider error signature observed",
                                          data={"status": http_status, "excerpt": http_body_excerpt[:200]}))
        return Finding(
            check_id="takeover.candidate", asset=host, category="subdomain_takeover",
            title=f"Possible dangling {provider} resource (takeover candidate, unconfirmed)",
            confidence=confidence, severity_hint="medium", endpoint=None,
            review_priority=68 if error_signature else 55,
            validation_state=ValidationState.SUSPECTED, source="takeover",
            evidence=evidence,
        )
    return None


# --- OpenAPI security intelligence -----------------------------------------------------

_UNCOMMON_METHODS = {"TRACE", "CONNECT", "PATCH"}


def openapi_security_hints(host: str, spec: OpenApiResult, *, documents_auth: bool) -> list[Finding]:
    """Investigation signals from an OpenAPI document. Not runtime truth."""
    findings: list[Finding] = []
    admin_ops = [e for e in spec.endpoints if re.search(r"/(admin|internal|manage)\b", e.path, re.I)]
    upload_ops = [e for e in spec.endpoints if re.search(r"/(upload|import)\b", e.path, re.I)]
    id_params = [p for p in spec.parameters if classify_parameter(p.name) is ParamClass.OBJECT_IDENTIFIER]

    if not documents_auth and spec.endpoints:
        findings.append(Finding(
            check_id="openapi.no_auth_declared", asset=host, category="api_authorization",
            title="OpenAPI declares no authentication scheme",
            confidence=0.5, severity_hint="low", review_priority=35,
            validation_state=ValidationState.OBSERVED, source="openapi",
            evidence=[make_evidence("openapi", "no securitySchemes in spec",
                                    data={"endpoints": len(spec.endpoints)})],
        ))
    if admin_ops and id_params:
        findings.append(Finding(
            check_id="openapi.admin_object_access", asset=host, category="api_authorization",
            title="Administrative API operations with object-identifier parameters",
            confidence=0.55, severity_hint="medium",
            endpoint=admin_ops[0].path, parameter=id_params[0].name, review_priority=60,
            validation_state=ValidationState.OBSERVED, source="openapi",
            evidence=[make_evidence("openapi", "admin ops + id params",
                                    data={"admin_ops": [e.path for e in admin_ops[:5]],
                                          "id_params": [p.name for p in id_params[:5]]})],
        ))
    if spec.deprecated:
        findings.append(Finding(
            check_id="openapi.deprecated", asset=host, category="api_surface",
            title=f"Deprecated API operations documented ({len(spec.deprecated)})",
            confidence=0.6, severity_hint="info", review_priority=20,
            validation_state=ValidationState.OBSERVED, source="openapi",
            evidence=[make_evidence("openapi", "deprecated ops", data={"ops": spec.deprecated[:10]})],
        ))
    if upload_ops:
        findings.append(Finding(
            check_id="openapi.upload", asset=host, category="file_handling",
            title="Upload/import operations documented",
            confidence=0.5, severity_hint="low", endpoint=upload_ops[0].path, review_priority=30,
            validation_state=ValidationState.OBSERVED, source="openapi",
            evidence=[make_evidence("openapi", "upload ops", data={"ops": [e.path for e in upload_ops[:5]]})],
        ))
    return findings


# --- exposure (recon-derived) ----------------------------------------------------------

_EXPOSURE_SIGNATURES: tuple[tuple[str, re.Pattern[str], str, int], ...] = (
    ("env_file", re.compile(r"/\.env(\.|$)"), "medium", 55),
    ("git_dir", re.compile(r"/\.git(/|$)"), "medium", 55),
    ("source_map", re.compile(r"\.js\.map$"), "low", 35),
    ("backup_file", re.compile(r"\.(?:bak|old|swp|save|orig|tar\.gz|zip|sql)$", re.I), "low", 40),
    ("debug_endpoint", re.compile(r"/(?:actuator|debug|_debug|phpinfo|__internal)\b", re.I), "low", 45),
    ("metrics_endpoint", re.compile(r"/(?:metrics|prometheus)\b", re.I), "info", 25),
    ("config_endpoint", re.compile(r"/(?:config|configuration|settings)\.(?:json|yaml|yml|xml)$", re.I), "low", 40),
)


def exposure_from_url(host: str, url: str, path: str, status_code: int | None) -> Finding | None:
    """Flag a recon-discovered URL that looks like a sensitive exposure.

    Only fires for URLs ShadowScan already saw; this never guesses paths.
    """
    for kind, pattern, severity, priority in _EXPOSURE_SIGNATURES:
        if pattern.search(path):
            live = status_code is not None and 200 <= status_code < 300
            if status_code is not None and not live:
                return None   # discovered historically but not currently served
            return Finding(
                check_id=f"exposure.{kind}", asset=host, category="exposure",
                title=f"Potential exposure: {kind.replace('_', ' ')}",
                confidence=0.6 if live else 0.4, severity_hint=severity,
                endpoint=path, review_priority=priority,
                validation_state=ValidationState.OBSERVED, source="exposure",
                evidence=[make_evidence("response", "recon-discovered exposure path",
                                        data={"url": url, "status": status_code})],
            )
    return None


# --- GraphQL safe analysis -------------------------------------------------------------

def graphql_signals(host: str, endpoint_path: str, operations: list[str], introspection_confirmed: bool) -> list[Finding]:
    findings = [Finding(
        check_id="graphql.endpoint", asset=host, category="graphql",
        title="GraphQL endpoint candidate",
        confidence=0.6, severity_hint="info", endpoint=endpoint_path, review_priority=30,
        validation_state=ValidationState.OBSERVED, source="graphql",
        evidence=[make_evidence("js_source", "graphql endpoint/operations",
                                data={"operations": operations[:20]})],
    )]
    if introspection_confirmed:
        findings.append(Finding(
            check_id="graphql.introspection", asset=host, category="graphql",
            title="GraphQL introspection is enabled",
            confidence=0.8, severity_hint="low", endpoint=endpoint_path, review_priority=50,
            validation_state=ValidationState.VALIDATED_NON_DESTRUCTIVELY, source="graphql",
            evidence=[make_evidence("response", "introspection responded", data={})],
        ))
    return findings
