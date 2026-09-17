"""Release evidence-quality normalization for the Evidence Graph catalogue.

This module does not invent confirmation. It collapses duplicate representations of the
same locator/surface, separates raw semantic discovery from method-bound evidence and
adds an explicit evidence tier used by UI/reporting. Stronger evidence wins display
fields while weaker duplicates remain represented by corroboratingSources/counts.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

SCHEMA = "modkit-evidence-quality-1.0"

_FRAMEWORK_HOST_PARTS = (
    "googleapis.com", "gstatic.com", "googleusercontent.com", "doubleclick.net",
    "firebaseio.com", "firebaseapp.com", "appsflyer.com", "adjust.com", "sentry.io",
    "facebook.com", "fbcdn.net", "unity3d.com", "unity.com", "akamaized.net",
    "cloudfront.net",
)


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _norm_space(value: Any) -> str:
    return re.sub(r"\s+", " ", _text(value)).strip().casefold()


def _norm_hex(value: Any) -> str:
    text = _text(value).casefold()
    if not text:
        return ""
    try:
        number = int(text, 0)
    except Exception:
        try:
            number = int(text, 16)
        except Exception:
            return text
    return f"0x{number:x}"


def normalize_endpoint(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    low = text.casefold()
    if low.startswith(("http://", "https://", "ws://", "wss://")):
        try:
            parsed = urlsplit(text)
            scheme = parsed.scheme.casefold()
            host = (parsed.hostname or "").casefold().rstrip(".")
            port = parsed.port
            default = (scheme in {"http", "ws"} and port == 80) or (scheme in {"https", "wss"} and port == 443)
            netloc = host + ((":" + str(port)) if port and not default else "")
            path = re.sub(r"/{2,}", "/", parsed.path or "/")
            if path != "/":
                path = path.rstrip("/")
            query_keys = sorted({part.split("=", 1)[0].casefold() for part in parsed.query.split("&") if part})
            query = "&".join(query_keys)
            return urlunsplit((scheme, netloc, path, query, ""))
        except Exception:
            return low.rstrip("/")
    if low.startswith("/"):
        return re.sub(r"/{2,}", "/", low).rstrip("/") or "/"
    return low.rstrip(".")


def _evidence(card: dict[str, Any]) -> dict[str, Any]:
    value = card.get("evidence")
    return value if isinstance(value, dict) else {}


def _method_identity(card: dict[str, Any]) -> str:
    ev = _evidence(card)
    mid = ev.get("metadataMethodId", ev.get("methodId", ev.get("id")))
    if mid not in (None, "") and str(mid).lstrip("-").isdigit():
        return "mid:" + str(mid)
    clazz = _text(ev.get("class") or ev.get("className") or ev.get("declaringClass") or ev.get("owner")).replace("/", ".").casefold()
    method = _text(ev.get("method") or ev.get("methodName") or ev.get("name")).casefold()
    signature = _text(ev.get("signature") or ev.get("descriptor") or ev.get("methodSignature")).casefold()
    if clazz and method:
        return "method:" + clazz + "::" + method + (":" + signature if signature else "")
    return ""


def _locator_identity(card: dict[str, Any]) -> str:
    loc = card.get("locator") if isinstance(card.get("locator"), dict) else {}
    rva = _norm_hex(loc.get("rva"))
    if rva:
        module = _norm_space(loc.get("library") or loc.get("module") or _evidence(card).get("library") or _evidence(card).get("module"))
        return "rva:" + module + ":" + rva
    artifact = _norm_space(loc.get("artifact"))
    code = loc.get("codeOffset")
    if artifact and code is not None:
        return "dex:" + artifact + ":" + str(code)
    entry = _norm_space(loc.get("entry"))
    symbol = _norm_space(loc.get("symbol"))
    if entry and symbol:
        return "script:" + entry + ":" + symbol
    return ""


def _surface_identity(card: dict[str, Any]) -> str:
    ev = _evidence(card)
    kind = _norm_space(ev.get("kind") or card.get("category"))
    value = ev.get("normalizedValue") or ev.get("value") or ev.get("endpoint") or ev.get("url")
    normalized = normalize_endpoint(value)
    if normalized:
        return "surface:" + kind + ":" + normalized
    return ""


def dedup_key(card: dict[str, Any]) -> str:
    control = _text(card.get("menuControlId"))
    if control:
        return "control:" + control
    for identity in (_locator_identity(card), _method_identity(card), _surface_identity(card)):
        if identity:
            return identity
    return "fallback:" + "|".join((
        _norm_space(card.get("source")), _norm_space(card.get("title")),
        _norm_space(card.get("category")), _norm_space(card.get("status")),
    ))


def _has_flow(card: dict[str, Any]) -> bool:
    ev = _evidence(card)
    for key in ("directInvokes", "invokes", "callers", "callees", "callReferences", "references", "xref", "xrefs"):
        value = ev.get(key)
        if isinstance(value, (list, dict)) and len(value) > 0:
            return True
    return bool(ev.get("flowConfirmed") or ev.get("dataFlowConfirmed"))


def _has_method_context(card: dict[str, Any]) -> bool:
    return bool(_method_identity(card) or _locator_identity(card))


def _explicit_issue(card: dict[str, Any]) -> bool:
    ev = _evidence(card)
    status = _norm_space(card.get("status"))
    return bool(
        ev.get("issueConfirmed") or ev.get("vulnerabilityConfirmed") or ev.get("exploitabilityConfirmed")
        or status in {"confirmed_issue", "vulnerability_confirmed"}
    )


def _runtime(card: dict[str, Any]) -> bool:
    ev = _evidence(card);status = _norm_space(card.get("status"))
    return "runtime" in status or bool(ev.get("runtimeConfirmed") or ev.get("runtimeObserved"))


def evidence_tier(card: dict[str, Any]) -> str:
    if _explicit_issue(card):
        return "CONFIRMED_ISSUE"
    if card.get("serverAudit"):
        if _runtime(card) and (_has_method_context(card) or _has_flow(card)):
            return "CONFIRMED_ISSUE"
        if _has_method_context(card) or _has_flow(card):
            return "CORRELATED_EVIDENCE"
        source = _text(card.get("source"))
        return "POTENTIAL_TRUST_BOUNDARY" if source == "SecuritySummary" else "DISCOVERED_SURFACE"
    if card.get("buildable") or card.get("actionable") or _runtime(card) or _has_method_context(card) or _has_flow(card):
        return "CORRELATED_EVIDENCE"
    return "DISCOVERED_SURFACE"


def _framework_endpoint(card: dict[str, Any]) -> bool:
    ev = _evidence(card)
    normalized = normalize_endpoint(ev.get("normalizedValue") or ev.get("value") or "")
    try:
        host = (urlsplit(normalized).hostname or "").casefold()
    except Exception:
        host = normalized.casefold()
    return any(host == part or host.endswith("." + part) for part in _FRAMEWORK_HOST_PARTS)


def _refine_card(card: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(card)
    tier = evidence_tier(out)
    out["evidenceTier"] = tier
    out["methodBoundEvidence"] = _has_method_context(out)
    out["flowCorrelated"] = _has_flow(out)
    out["controlCandidate"] = bool(out.get("buildable") or out.get("selectable") or out["methodBoundEvidence"]) and tier == "CORRELATED_EVIDENCE"
    if tier == "DISCOVERED_SURFACE":
        out["buildable"] = False
        out["selectable"] = False
        out["controlCandidate"] = False
        if _text(out.get("source")) == "SecuritySurface":
            out["priority"] = min(int(out.get("priority", 0) or 0), 44)
            out["important"] = False
            out["lowSignal"] = True
    if _framework_endpoint(out) and tier in {"DISCOVERED_SURFACE", "POTENTIAL_TRUST_BOUNDARY"}:
        out["networkRole"] = "FRAMEWORK_CDN_OR_TELEMETRY"
        out["priority"] = min(int(out.get("priority", 0) or 0), 36)
        out["important"] = False
        out["lowSignal"] = True
    elif out.get("serverAudit"):
        out["networkRole"] = "APP_OR_UNKNOWN_TRUST_SURFACE"
    return out


def _strength(card: dict[str, Any]) -> tuple[int, int, int]:
    tier_rank = {"DISCOVERED_SURFACE": 10, "POTENTIAL_TRUST_BOUNDARY": 20, "CORRELATED_EVIDENCE": 30, "CONFIRMED_ISSUE": 40}
    return (tier_rank.get(_text(card.get("evidenceTier")), 0), int(card.get("confirmationRank", 0) or 0), int(card.get("priority", 0) or 0))


def _merge(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    winner, other = (incoming, existing) if _strength(incoming) > _strength(existing) else (existing, incoming)
    out = deepcopy(winner)
    sources = set()
    for row in (existing, incoming):
        source = _text(row.get("source"))
        if source:
            sources.add(source)
        for value in row.get("corroboratingSources", []) if isinstance(row.get("corroboratingSources"), list) else []:
            if value:
                sources.add(str(value))
    out["corroboratingSources"] = sorted(sources)
    out["deduplicated"] = True
    out["duplicateCardCount"] = int(existing.get("duplicateCardCount", 1) or 1) + int(incoming.get("duplicateCardCount", 1) or 1)
    ev = out.get("evidence") if isinstance(out.get("evidence"), dict) else {}
    occurrence = 0
    for row in (existing, incoming):
        evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
        occurrence += int(evidence.get("occurrenceCount", 1) or 1)
    if isinstance(ev, dict):
        ev = deepcopy(ev);ev["mergedOccurrenceCount"] = occurrence;out["evidence"] = ev
    return out


def refine_catalog(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict):
        return report
    raw_cards = report.get("cards") if isinstance(report.get("cards"), list) else []
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for raw in raw_cards:
        if not isinstance(raw, dict):
            continue
        card = _refine_card(raw)
        key = dedup_key(card)
        if key in merged:
            merged[key] = _merge(merged[key], card)
        else:
            merged[key] = card;order.append(key)
    cards = list(merged.values())
    cards.sort(key=lambda c: (-int(c.get("priority", 0) or 0), _norm_space(c.get("category")), _norm_space(c.get("title"))))
    counts: dict[str, int] = {}
    tiers: dict[str, int] = {}
    for card in cards:
        status = _text(card.get("status")) or "UNKNOWN";counts[status] = counts.get(status, 0) + 1
        tier = _text(card.get("evidenceTier")) or "DISCOVERED_SURFACE";tiers[tier] = tiers.get(tier, 0) + 1
    report = dict(report)
    # Do not replace the caller's public catalogue schema here. Quality refinement
    # is an internal layer; changing the outer schema caused canonical and
    # cancellation-aware catalogue paths to become incompatible.
    report["cards"] = cards
    report["counts"] = counts
    report["total"] = len(cards)
    report["buildable"] = sum(1 for c in cards if c.get("buildable"))
    report["actionable"] = sum(1 for c in cards if c.get("actionable"))
    report["important"] = sum(1 for c in cards if c.get("important"))
    report["frameworkNoise"] = sum(1 for c in cards if c.get("ownership") == "FRAMEWORK")
    report["serverAudit"] = sum(1 for c in cards if c.get("serverAudit"))
    report["evidenceTiers"] = tiers
    report["rawCardCountBeforeDedup"] = len(raw_cards)
    report["deduplicatedCardCount"] = max(0, len(raw_cards) - len(cards))
    report["qualityPolicy"] = {
        "schema": SCHEMA,
        "rawStringsBecomeControls": False,
        "methodBoundEvidenceSeparated": True,
        "methodBoundCorrelatedMayEnterPreflight": True,
        "normalizedDedup": True,
        "frameworkCdnNoiseNormalized": True,
        "tiers": ["DISCOVERED_SURFACE", "POTENTIAL_TRUST_BOUNDARY", "CORRELATED_EVIDENCE", "CONFIRMED_ISSUE"],
    }
    return report