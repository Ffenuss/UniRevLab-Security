"""Fail-closed AutoMod planner over the unified Evidence Graph catalog.

The planner never modifies an APK and never upgrades a static keyword match into a
validated executable patch. It groups existing ModKit evidence by readiness and may
attach read-only procfs runtime observations to an existing native locator. Runtime
VA evidence is corroboration only: buildability still comes exclusively from the
validated local executable binding already present in the catalog.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = "modkit-automod-plan-1.1"

_BUILD = "READY_TO_BUILD"
_PREFLIGHT = "READY_FOR_PREFLIGHT"
_RUNTIME = "RUNTIME_NEEDED"
_REVIEW = "REVIEW"
_AUDIT = "AUDIT_ONLY"
_EXCLUDED = "EXCLUDED"

_EXCLUDED_OWNERSHIP = {"FRAMEWORK", "FRAMEWORK_NOISE", "BUNDLED_SDK", "SDK_NOISE", "ENGINE"}
_APP_OWNERSHIP = {"APP", "APP_OR_GAME"}
_AUDIT_WORDS = (
    "server", "backend", "network", "endpoint", "authentication", "oauth", "session",
    "billing", "purchase", "payment", "entitlement", "subscription", "license",
    "certificate", "pinning", "crypto", "credential", "access token", "refresh token",
)


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _audit_like(card: dict[str, Any]) -> bool:
    if card.get("serverAudit"):
        return True
    category = str(card.get("category") or "").casefold()
    title = str(card.get("title") or "").casefold()
    stage = str(card.get("verificationStage") or "").upper()
    status = str(card.get("status") or "").upper()
    if stage == "SERVER_AUDIT" or status == "SERVER_AUDIT":
        return True
    text = f"{category} {title}"
    return any(word in text for word in _AUDIT_WORDS)


def _locator_is_exact(card: dict[str, Any]) -> bool:
    locator = card.get("locator")
    if not isinstance(locator, dict) or not locator:
        return False
    if locator.get("rva") not in (None, "", 0, "0"):
        return True
    if locator.get("codeOffset") is not None and (locator.get("class") or locator.get("signature")):
        return True
    if locator.get("entry") and (locator.get("symbol") or locator.get("offset") is not None):
        return True
    return False


def _runtime_index(runtime_correlation: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Index only observations emitted by the read-only procfs correlator.

    A row is keyed by the stable catalog card id.  We deliberately do not match by
    title or guessed address: if the correlation cannot point back to the same card,
    AutoMod leaves it detached rather than broadening trust.
    """
    if not isinstance(runtime_correlation, dict):
        return {}
    rows = runtime_correlation.get("correlations")
    if not isinstance(rows, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        card_id = row.get("id")
        if card_id in (None, ""):
            continue
        if str(row.get("runtimeEvidence") or "") != "PROCFS_MODULE_LAYOUT":
            continue
        if bool(row.get("promotesBuildability")):
            continue
        out[str(card_id)] = row
    return out


def _runtime_view(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    return {
        "evidence": "PROCFS_MODULE_LAYOUT",
        "modulePath": row.get("modulePath"),
        "moduleBasename": row.get("moduleBasename"),
        "loadBaseHex": row.get("loadBaseHex"),
        "rvaHex": row.get("rvaHex"),
        "runtimeVaHex": row.get("runtimeVaHex"),
        "mapped": bool(row.get("mapped")),
        "mappingPerms": row.get("mappingPerms"),
        "matchMode": row.get("matchMode"),
        "promotesBuildability": False,
    }


def _classify(card: dict[str, Any]) -> tuple[str, str]:
    ownership = str(card.get("ownership") or "UNKNOWN").upper()
    stage = str(card.get("verificationStage") or "FOUND_STATIC").upper()
    status = str(card.get("status") or "").upper()

    if card.get("externalCorroborating"):
        return _EXCLUDED, "Внешняя corroboration-находка не становится patch-point без локального подтверждения."
    if ownership in _EXCLUDED_OWNERSHIP:
        return _EXCLUDED, "SDK/framework/runtime marker исключён из автоматической модификации."
    if _audit_like(card):
        return _AUDIT, "Server/payment/auth/network/trust evidence сохраняется только для аудита."

    app_owned = ownership in _APP_OWNERSHIP
    exact_locator = _locator_is_exact(card) or bool(card.get("actionable"))
    patch_ready = bool(card.get("buildable")) and stage == "PATCH_READY" and app_owned
    if patch_ready:
        return _BUILD, "Есть проверенный локальный executable binding; допустим signed build после обязательного preflight."
    if app_owned and exact_locator:
        return _PREFLIGHT, "Есть локальный точный locator; нужен smart prepare/preflight для validated executable binding."
    if app_owned and stage in {"RUNTIME_CONFIRMED", "FLOW_CONFIRMED", "LOCATOR_CONFIRMED"}:
        return _RUNTIME, "Evidence сильное, но ещё не доказан безопасный executable binding для автосборки."
    if app_owned and stage in {"APP_OWNED", "FOUND_STATIC"}:
        return _REVIEW, "App-owned статическая находка; требуется flow/runtime/locator подтверждение."
    if status.startswith("READY") and exact_locator:
        return _PREFLIGHT, "Есть точный локатор; перед сборкой требуется fail-closed preflight."
    return _REVIEW, "Находка полезна для ручной проверки, но её недостаточно для автоматической модификации."


def _candidate(card: dict[str, Any], runtime_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    stage, reason = _classify(card)
    runtime = _runtime_view(runtime_by_id.get(str(card.get("id"))))
    if runtime and runtime.get("mapped"):
        reason += " Runtime VA наблюдался в procfs layout; это corroboration и не заменяет executable binding/preflight."
    return {
        "id": card.get("id"),
        "title": card.get("title"),
        "category": card.get("category"),
        "source": card.get("source"),
        "stage": stage,
        "reason": reason,
        "sourceStatus": card.get("status"),
        "verificationStage": card.get("verificationStage"),
        "ownership": card.get("ownership"),
        "gameplayDomain": card.get("gameplayDomain"),
        "priority": int(card.get("priority") or 0),
        "buildable": bool(card.get("buildable")),
        "actionable": bool(card.get("actionable")),
        "serverAudit": bool(card.get("serverAudit")),
        "externalCorroborating": bool(card.get("externalCorroborating")),
        "locator": card.get("locator") if isinstance(card.get("locator"), dict) else None,
        "runtimeObserved": bool(runtime and runtime.get("mapped")),
        "runtimeObservation": runtime,
        "readyReason": card.get("readyReason"),
        "notReadyReason": card.get("notReadyReason"),
    }


def build_plan(catalog: dict[str, Any], runtime_correlation: dict[str, Any] | None = None) -> dict[str, Any]:
    cards = catalog.get("cards") if isinstance(catalog.get("cards"), list) else []
    runtime_by_id = _runtime_index(runtime_correlation)
    candidates = [_candidate(card, runtime_by_id) for card in cards if isinstance(card, dict)]
    order = {_BUILD: 0, _PREFLIGHT: 1, _RUNTIME: 2, _REVIEW: 3, _AUDIT: 4, _EXCLUDED: 5}
    candidates.sort(key=lambda row: (order.get(str(row.get("stage")), 99), -int(row.get("priority") or 0), str(row.get("title") or "").casefold()))
    counts = Counter(str(row.get("stage") or _REVIEW) for row in candidates)
    gameplay = Counter(str(row.get("gameplayDomain")) for row in candidates if row.get("gameplayDomain") and row.get("stage") not in {_AUDIT, _EXCLUDED})
    exact = sum(1 for row in candidates if isinstance(row.get("locator"), dict) and row.get("locator"))
    runtime_observed = sum(1 for row in candidates if row.get("runtimeObserved"))
    return {
        "schema": SCHEMA,
        "source": "simple-catalog.json",
        "runtimeSource": "runtime-correlation.json" if runtime_by_id else None,
        "failClosed": True,
        "modifiesTarget": False,
        "runtimeEvidencePromotesBuildability": False,
        "autoBuildRequiresValidatedExecutableBinding": True,
        "serverBypassGenerated": False,
        "counts": {stage: int(counts.get(stage, 0)) for stage in (_BUILD, _PREFLIGHT, _RUNTIME, _REVIEW, _AUDIT, _EXCLUDED)},
        "gameplayCounts": dict(sorted(gameplay.items())),
        "exactLocatorCount": exact,
        "runtimeObservedCount": runtime_observed,
        "readyToBuildCount": int(counts.get(_BUILD, 0)),
        "readyForPreflightCount": int(counts.get(_PREFLIGHT, 0)),
        "runtimeNeededCount": int(counts.get(_RUNTIME, 0)),
        "reviewCount": int(counts.get(_REVIEW, 0)),
        "auditOnlyCount": int(counts.get(_AUDIT, 0)),
        "excludedCount": int(counts.get(_EXCLUDED, 0)),
        "candidateCount": len(candidates),
        "candidates": candidates,
    }


def build_workspace_plan(workdir: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    catalog_path = root / "simple-catalog.json"
    catalog = _load(catalog_path)
    if not catalog:
        from modkit.mobile.simple_mode import build_catalog
        catalog = build_catalog(root, catalog_path)
    runtime_correlation = _load(root / "runtime-correlation.json")
    out = build_plan(catalog, runtime_correlation if runtime_correlation else None)
    destination = Path(output_path) if output_path else root / "automod-plan.json"
    destination.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
