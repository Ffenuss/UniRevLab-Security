"""Evidence-based target profile selection for ModKit UI and discovery routing."""
from __future__ import annotations

import json

_APP_SURFACES = {
    "authentication", "entitlement", "monetization", "feature_flags", "local_storage",
    "network", "crypto", "webview", "deep_link", "serialization", "debug", "defensive",
}


def _as_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def classify_apkset_scan(scan: dict, android_category_game: bool = False) -> dict:
    summary = scan.get("summary") or {}
    unity = _as_int(summary.get("unityMarkerCount"))
    dex = _as_int(summary.get("dexCount"))
    native = _as_int(summary.get("nativeCount"))
    game_score = 4 if android_category_game else 0
    reasons = []
    if android_category_game:
        reasons.append("Android ApplicationInfo.CATEGORY_GAME")
    if unity:
        # A generic SDK/string marker is not enough to call an ordinary app a game.
        # Strong game weight requires either PackageManager CATEGORY_GAME or a
        # structurally complete IL2CPP pair. This prevents analytics/media apps
        # with bundled engine strings from being mislabeled HYBRID.
        unity_weight = 3 if (android_category_game or bool(scan.get("fullIl2cppPair"))) else 1
        game_score += unity_weight
        reasons.append(f"Unity/engine markers: {unity} (weight {unity_weight})")
    app_score = 0
    if dex:
        app_score += 2
        reasons.append(f"DEX present: {dex}")
    if native:
        app_score += 1
    surfaces = ((scan.get("dexTrust") or {}).get("surfaces") or {})
    owned = [name for name, row in surfaces.items() if isinstance(row, dict) and _as_int(row.get("applicationMatches")) > 0]
    if owned:
        app_score += min(5, len(owned))
        reasons.append("application surfaces: " + ", ".join(sorted(owned)[:6]))
    if game_score >= 4 and app_score >= 4:
        profile = "HYBRID"
    elif game_score >= 3:
        profile = "GAME"
    elif app_score >= 2:
        profile = "APPLICATION"
    else:
        profile = "UNKNOWN"
    return {
        "schema": "modkit-target-profile-1",
        "profile": profile,
        "confidence": min(0.98, 0.55 + max(game_score, app_score) * 0.07),
        "gameScore": game_score,
        "applicationScore": app_score,
        "phase": "inventory",
        "reasons": reasons[:12],
    }


def classify_apkset_scan_json(scan_json: str, android_category_game: bool = False) -> str:
    return json.dumps(classify_apkset_scan(json.loads(scan_json), bool(android_category_game)), ensure_ascii=False, separators=(",", ":"))


def classify_report(report: dict) -> dict:
    game_score = 0
    app_score = 0
    reasons: list[str] = []

    findings = report.get("findings") or []
    categories = {str(x.get("category") or "") for x in findings if isinstance(x, dict)}
    if "gameplay_controls" in categories:
        game_score += 5
        reasons.append("gameplay control evidence")
    # Debug/overlay surfaces also exist in ordinary applications and therefore
    # are not game evidence by themselves. Gameplay/engine evidence below must
    # establish the game side of a HYBRID profile.

    unity = report.get("unity") or {}
    unity_markers = 0
    if isinstance(unity, dict):
        unity_markers += len(unity.get("bundles") or [])
        unity_markers += len(unity.get("addressables") or [])
        if unity.get("unity") or unity.get("engine"):
            unity_markers += 1
    if unity_markers:
        game_score += min(4, 2 + unity_markers)
        reasons.append("Unity content evidence")

    trust = (report.get("dexTrust") or {}).get("surfaces") or {}
    confirmed_app_surfaces = []
    for name in _APP_SURFACES:
        row = trust.get(name) or {}
        if _as_int(row.get("applicationMatches")) > 0:
            confirmed_app_surfaces.append(name)
    if confirmed_app_surfaces:
        app_score += min(8, 2 + len(confirmed_app_surfaces))
        reasons.append("application surfaces: " + ", ".join(sorted(confirmed_app_surfaces)[:6]))

    inventory = report.get("inventory") or {}
    if inventory.get("dex"):
        app_score += 2
        reasons.append("DEX application code present")
    if inventory.get("native"):
        app_score += 1

    if game_score >= 4 and app_score >= 5:
        profile = "HYBRID"
    elif game_score >= 4:
        profile = "GAME"
    elif app_score >= 3:
        profile = "APPLICATION"
    else:
        profile = "UNKNOWN"

    denom = max(1, max(game_score, app_score))
    margin = abs(game_score - app_score) / denom
    confidence = 0.62 + min(0.28, max(game_score, app_score) * 0.035) + min(0.08, margin * 0.08)
    return {
        "schema": "modkit-target-profile-1",
        "profile": profile,
        "confidence": round(min(0.98, confidence), 2),
        "gameScore": game_score,
        "applicationScore": app_score,
        "phase": "analysis",
        "reasons": reasons[:12],
    }
