"""Application-oriented discovery projection built from static evidence.

This layer deliberately separates *presence* and *trust boundary* from
vulnerability claims. It is suitable for ordinary Android applications as well
as hybrid/game targets and keeps NOT_FOUND_LOCAL scoped to scanned artifacts.
"""
from __future__ import annotations

from copy import deepcopy

from modkit.reworkspace.trust import SURFACE_NAMES

_ORDER = (
    "authentication", "entitlement", "monetization", "feature_flags",
    "local_storage", "network", "crypto", "webview", "deep_link",
    "serialization", "debug", "defensive",
)

_REMEDIATION = {
    "authentication": "Keep session/auth decisions server-authoritative; avoid treating a local flag as the sole authority.",
    "entitlement": "Keep premium/subscription entitlement authoritative on a trusted backend or platform receipt flow.",
    "monetization": "Verify purchase state using trusted platform/server evidence; local purchase UI state is not authoritative proof.",
    "feature_flags": "Treat remotely managed flags as configuration, and protect security-sensitive behavior with independent authorization.",
    "local_storage": "Do not store security-critical authority only in mutable local storage; protect sensitive values and validate ownership.",
    "network": "Use authenticated transport and explicit trust boundaries; do not infer server state from local response caches alone.",
    "crypto": "Keep long-lived secrets out of reversible app constants; prefer Android Keystore for device-bound key material.",
    "webview": "Restrict JavaScript bridges and URL loading to trusted origins; validate every exposed bridge method.",
    "deep_link": "Validate scheme/host/path and authorization state before executing deep-link actions.",
    "serialization": "Treat deserialized input as untrusted and validate types, bounds, and required fields before use.",
    "debug": "Disable or strongly gate developer/debug surfaces in production builds.",
    "defensive": "Treat integrity signals as one layer of defense, not a sole authorization boundary.",
}


def build_application_discovery(report: dict) -> dict:
    trust = report.get("dexTrust") or {}
    surfaces = trust.get("surfaces") or {}
    cards = []
    confirmed = review = not_found = 0
    for domain in _ORDER:
        src = surfaces.get(domain) or {}
        total = int(src.get("totalMatches") or 0)
        app_matches = int(src.get("applicationMatches") or 0)
        if app_matches > 0:
            status = "CONFIRMED"
            confirmed += 1
        elif total > 0:
            status = "REVIEW"
            review += 1
        else:
            status = "NOT_FOUND_LOCAL"
            not_found += 1
        methods = []
        for row in (src.get("methods") or [])[:8]:
            if not isinstance(row, dict):
                continue
            methods.append({
                "label": row.get("label"),
                "artifact": row.get("artifact"),
                "evidenceRole": row.get("evidenceRole"),
                "trustBoundary": row.get("trustBoundary"),
                "localAuthority": row.get("localAuthority"),
            })
        cards.append({
            "domain": domain,
            "title": SURFACE_NAMES.get(domain, domain.replace("_", " ").title()),
            "status": status,
            "totalMatches": total,
            "applicationMatches": app_matches,
            "trustBoundary": src.get("trustBoundary", "unknown"),
            "localAuthority": src.get("localAuthority", "unknown"),
            "presenceConfidence": float(src.get("presenceConfidence") or 0.0),
            "behaviorConfidence": float(src.get("behaviorConfidence") or 0.0),
            "methods": methods,
            "remediation": _REMEDIATION.get(domain, "Review the trust boundary and keep security-sensitive authority outside mutable local state."),
            "evidenceNote": "Static DEX evidence only; presence is not a vulnerability and does not imply runtime execution.",
        })
    return {
        "schema": "modkit-application-discovery-1",
        "scope": "local-static",
        "statusSemantics": {
            "CONFIRMED": "Application-owned/bundled method evidence exists locally.",
            "REVIEW": "Only framework/third-party evidence exists locally.",
            "NOT_FOUND_LOCAL": "No matching evidence was found in the scanned local artifacts; this does not prove absence.",
        },
        "summary": {"confirmed": confirmed, "review": review, "notFoundLocal": not_found},
        "cards": cards,
        "dexTrust": deepcopy({k: trust.get(k) for k in ("schema", "methodsScanned", "errors")}),
    }
