"""Deterministic review prioritization of detected changes.

``review_priority`` (0-100) answers *"how worthwhile is it for a human to look
at this change first?"*. It is **not** a vulnerability severity, a risk score
or CVSS.

``interesting`` marks state transitions that often deserve a researcher's
attention, such as a previously forbidden endpoint that now returns 200.
**Interesting does not mean vulnerable.** It means the transition may deserve
human review.

All rules live in this module and are plain, ordered conditionals. To change
a weight, edit :data:`PRIORITY`.
"""

from __future__ import annotations

from dataclasses import replace

from .models import Change, ChangeType

# Every weight in one place, ordered from most to least review-worthy.
PRIORITY: dict[str, int] = {
    "forbidden_to_success": 95,            # 403 -> 2xx
    "unauthorized_to_success": 90,         # 401 -> 2xx
    "missing_to_success": 85,              # 404/410 -> 2xx
    "newly_reachable_success": 80,         # unreachable -> reachable with 2xx
    "server_error_to_success": 70,         # 5xx -> 2xx
    "newly_reachable_other": 65,           # unreachable -> reachable with non-2xx
    "redirect_to_success": 65,             # 3xx -> 2xx
    "content_major": 60,                   # similarity < major threshold
    "success_to_auth_required": 55,        # 2xx -> 401/403
    "new_asset_reachable": 50,
    "dns_now_resolves": 45,                # dns_failure -> other network error
    "success_to_server_error": 40,         # 2xx -> 5xx
    "content_unmeasured": 40,              # binary / oversize: changed, magnitude unknown
    "redirect_changed_host": 40,           # redirect now points at a different host
    "status_other": 35,
    "stopped_responding": 35,              # reachable -> unreachable
    "redirect_changed": 30,
    "title_changed": 25,
    "success_to_missing": 25,              # 2xx -> 404/410
    "dns_lost": 20,                        # other network error -> dns_failure
    "content_minor": 15,
    "new_asset_unreachable": 15,
    "error_changed_other": 15,
    "server_header_changed": 10,
    "content_trivial": 5,                  # similarity >= trivial threshold
}


def _is_success(code: int | None) -> bool:
    return code is not None and 200 <= code < 300


def _is_redirect(code: int | None) -> bool:
    return code is not None and 300 <= code < 400


def _is_server_error(code: int | None) -> bool:
    return code is not None and code >= 500


def _assess_status(old: int | None, new: int | None) -> tuple[int, bool, str]:
    if _is_success(new):
        if old == 403:
            return PRIORITY["forbidden_to_success"], True, f"Previously forbidden endpoint (403) now returns HTTP {new}"
        if old == 401:
            return PRIORITY["unauthorized_to_success"], True, f"Previously authentication-protected endpoint (401) now returns HTTP {new}"
        if old in (404, 410):
            return PRIORITY["missing_to_success"], True, f"Previously missing endpoint ({old}) now returns HTTP {new}"
        if _is_server_error(old):
            return PRIORITY["server_error_to_success"], True, f"Previously failing endpoint ({old}) now returns HTTP {new}"
        if _is_redirect(old):
            return PRIORITY["redirect_to_success"], True, f"Endpoint that previously redirected ({old}) now serves content directly (HTTP {new})"
    if _is_success(old):
        if new in (401, 403):
            return PRIORITY["success_to_auth_required"], True, f"Endpoint now requires authorization ({old} -> {new}); access controls changed"
        if _is_server_error(new):
            return PRIORITY["success_to_server_error"], False, f"Endpoint now returns a server error ({old} -> {new})"
        if new in (404, 410):
            return PRIORITY["success_to_missing"], False, f"Endpoint content was removed ({old} -> {new})"
    return PRIORITY["status_other"], False, f"HTTP status changed ({old} -> {new})"


def assess(change: Change) -> Change:
    """Return ``change`` with ``interesting``, ``reason`` and ``review_priority`` set."""
    f = change.fields
    match change.change_type:
        case ChangeType.NEW_ASSET:
            if f.get("reachable"):
                priority, interesting, reason = PRIORITY["new_asset_reachable"], False, "First observation of this asset (HTTP response received)"
            else:
                priority, interesting, reason = PRIORITY["new_asset_unreachable"], False, "First observation of this asset (no HTTP response)"
        case ChangeType.STATUS_CHANGED:
            priority, interesting, reason = _assess_status(f.get("old_status"), f.get("new_status"))
        case ChangeType.AVAILABILITY_CHANGED:
            new_state = f["new"]
            if new_state["state"] == "reachable":
                code = new_state.get("status_code")
                key = "newly_reachable_success" if _is_success(code) else "newly_reachable_other"
                priority, interesting, reason = PRIORITY[key], True, f"Previously unreachable host now responds (HTTP {code})"
            else:
                priority, interesting, reason = (
                    PRIORITY["stopped_responding"], False, f"Host stopped responding ({new_state.get('error_type')})"
                )
        case ChangeType.ERROR_CHANGED:
            old_error, new_error = f.get("old_error"), f.get("new_error")
            if old_error == "dns_failure":
                priority, interesting, reason = (
                    PRIORITY["dns_now_resolves"], True,
                    f"Hostname now resolves in DNS but no HTTP service answers ({new_error})",
                )
            elif new_error == "dns_failure":
                priority, interesting, reason = PRIORITY["dns_lost"], False, "Hostname no longer resolves in DNS"
            else:
                priority, interesting, reason = (
                    PRIORITY["error_changed_other"], False, f"Failure mode changed ({old_error} -> {new_error})"
                )
        case ChangeType.REDIRECT_CHANGED:
            if f.get("host_changed"):
                priority, interesting, reason = PRIORITY["redirect_changed_host"], False, "Redirect now points to a different host"
            else:
                priority, interesting, reason = PRIORITY["redirect_changed"], False, "Redirect destination changed"
        case ChangeType.TITLE_CHANGED:
            priority, interesting, reason = PRIORITY["title_changed"], False, "Page title changed"
        case ChangeType.SERVER_HEADER_CHANGED:
            priority, interesting, reason = PRIORITY["server_header_changed"], False, "Server header changed"
        case ChangeType.CONTENT_CHANGED_MAJOR | ChangeType.CONTENT_CHANGED_MINOR:
            magnitude = f.get("magnitude")
            key = {
                "major": "content_major",
                "unmeasured": "content_unmeasured",
                "minor": "content_minor",
                "trivial": "content_trivial",
            }[magnitude]
            labels = {
                "major": "Major content change",
                "unmeasured": "Content changed (similarity not measurable for this response)",
                "minor": "Minor content change",
                "trivial": "Very small content change (likely dynamic noise)",
            }
            priority, interesting, reason = PRIORITY[key], False, labels[magnitude]
        case _:
            priority, interesting, reason = 0, False, None
    return replace(change, interesting=interesting, reason=reason, review_priority=priority)
