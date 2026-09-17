"""File-backed IL2CPP method handoff for the release Evidence Graph.

Large IL2CPP targets keep the full method catalogue in JSONL so analysis.json stays
small enough for Android. This layer streams the bounded autopilot index and promotes
only exact, application-owned method identities into *preflight* cards. It never marks
a method buildable and never treats static evidence as runtime proof.

It also demotes a small set of proven framework/SDK false positives which otherwise
look like gameplay controls only because of substrings such as ``level`` or ``gold``.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Callable

SCHEMA = "modkit-filebacked-method-handoff-1.0"
_MAX_METHOD_CARDS = 256

_GAME_DOMAINS = {
    "health", "damage", "movement", "world", "progression", "economy", "resource",
    "level_xp", "currency", "mana", "stamina", "speed", "camera", "fov",
}
_APP_METHOD_WORDS = {
    "health", "hp", "damage", "dmg", "mana", "stamina", "energy", "speed",
    "timescale", "time", "fov", "camera", "money", "gold", "coin", "currency",
    "gem", "level", "xp", "experience", "critical", "crit", "weather",
    "invincible", "god", "noclip", "jump", "teleport",
}
_THIRD_PARTY_PREFIXES = (
    "unityengine", "unity.", "dg_tweening", "dg.tweening", "dotween", "tmpro",
    "spine", "cri", "fmod", "google", "firebase", "appsflyer", "adjust",
    "facebook", "system.", "microsoft.", "mono.", "newtonsoft", "cinemachine",
    "cysharp", "unitask", "messagepack", "besthttp", "litjson",
)
_SDK_MARKERS = (
    "crashsight", "bugly", "appsflyer", "adjust", "firebase", "sentry",
    "facebook", "alibaba", "netspeed", "networkdiagnosis",
)
_FRAMEWORK_MARKERS = (
    "goldfish", "/system/", "/vendor/", "/apex/", "/sys/", "/proc/",
)
_NATIVE_RUNTIME_PREFIXES = (
    "__cxa_", "__gnu_", "_unwind_", "pthread_", "malloc", "calloc", "realloc",
    "free", "memcpy", "memmove", "memset", "strlen", "strcmp", "operator new",
)


def _tick(gate: Callable[[], None] | None) -> None:
    if gate is not None:
        gate()


def _words(value: Any) -> set[str]:
    text = str(value or "")
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return set(re.findall(r"[a-z0-9]+", text.casefold()))


def _is_third_party_class(clazz: str) -> bool:
    low = str(clazz or "").casefold().replace("/", ".")
    return any(low.startswith(prefix) for prefix in _THIRD_PARTY_PREFIXES)


def _noise_kind(card: dict[str, Any]) -> str | None:
    ev = card.get("evidence") if isinstance(card.get("evidence"), dict) else {}
    loc = card.get("locator") if isinstance(card.get("locator"), dict) else {}
    pieces = [
        card.get("title"), card.get("description"), card.get("category"),
        ev.get("title"), ev.get("function"), ev.get("value"), ev.get("entry"),
        ev.get("library"), loc.get("library"), loc.get("entry"),
    ]
    low = " ".join(str(x or "") for x in pieces).casefold()
    if any(marker in low for marker in _FRAMEWORK_MARKERS):
        return "FRAMEWORK"
    if any(marker in low for marker in _SDK_MARKERS):
        return "BUNDLED_SDK"
    title = str(card.get("title") or "").casefold().strip()
    if title.startswith(_NATIVE_RUNTIME_PREFIXES):
        return "FRAMEWORK"
    if ("logger" in low or "log_level" in low or "log level" in low) and str(card.get("gameplayDomain") or "") == "level_xp":
        return "BUNDLED_SDK"
    return None


def _demote_false_positive(card: dict[str, Any]) -> bool:
    kind = _noise_kind(card)
    if not kind:
        return False
    if str(card.get("gameplayDomain") or "") not in _GAME_DOMAINS and not card.get("controlCandidate"):
        return False
    previous = card.get("gameplayDomain")
    card["ownership"] = kind
    card["important"] = False
    card["lowSignal"] = True
    card["controlCandidate"] = False
    card["selectable"] = False
    card["buildable"] = False
    card["priority"] = min(int(card.get("priority") or 0), 32)
    card["semanticNoiseReason"] = "framework-or-sdk-token-collision"
    if previous not in (None, ""):
        card["rejectedGameplayDomain"] = previous
        card["gameplayDomain"] = None
    return True


def _method_score(row: dict[str, Any]) -> int:
    label = str(row.get("label") or "")
    clazz = str(row.get("class") or "")
    name = str(row.get("name") or "")
    words = _words(f"{clazz} {name} {label}")
    score = 60
    role = str(row.get("methodRole") or "").casefold()
    if role == "setter":
        score += 18
    elif role in {"action", "command"}:
        score += 12
    if words & _APP_METHOD_WORDS:
        score += 12
    if int(row.get("callerCount") or 0) > 0:
        score += 4
    if int(row.get("calleeCount") or 0) > 0:
        score += 3
    if str(row.get("isStatic")).casefold() == "true" or row.get("isStatic") is True:
        score += 2
    return max(1, min(99, score))


def _eligible_method(row: dict[str, Any]) -> bool:
    if not isinstance(row, dict) or not row.get("applicationOwned"):
        return False
    rva = row.get("rva")
    mid = row.get("metadataMethodId")
    if not isinstance(rva, int) or rva <= 0 or not isinstance(mid, int) or mid < 0:
        return False
    if row.get("generic") or row.get("abstract"):
        return False
    clazz = str(row.get("class") or "")
    if not clazz or _is_third_party_class(clazz):
        return False
    domains = {str(x).casefold() for x in (row.get("semanticDomains") or row.get("domains") or [])}
    label_words = _words(f"{clazz} {row.get('name') or ''} {row.get('label') or ''}")
    if not (domains & _GAME_DOMAINS or label_words & _APP_METHOD_WORDS):
        return False
    name = str(row.get("name") or "").casefold()
    if name in {".ctor", ".cctor", "awake", "start", "update", "lateupdate", "movenext", "setstatemachine"}:
        return False
    role = str(row.get("methodRole") or "").casefold()
    if role in {"getter", "lifecycle"} and not label_words & {"fov", "health", "damage", "money", "gold", "speed", "timescale"}:
        return False
    return True


def _method_card(row: dict[str, Any]) -> dict[str, Any]:
    mid = int(row["metadataMethodId"])
    rva = int(row["rva"])
    clazz = str(row.get("class") or "")
    method = str(row.get("name") or "")
    label = str(row.get("label") or f"{clazz}::{method}")
    domains = [str(x) for x in (row.get("semanticDomains") or row.get("domains") or []) if x]
    domain = domains[0] if domains else None
    flow = int(row.get("callerCount") or 0) + int(row.get("calleeCount") or 0) > 0
    score = _method_score(row)
    return {
        "id": f"MethodCatalog:{mid}",
        "title": label,
        "category": "Gameplay/Method",
        "source": "IL2CPP Method Catalog",
        "status": "READY_METHOD_LOCATOR",
        "buildable": False,
        "selectable": False,
        "actionable": True,
        "locator": {
            "rva": rva,
            "rvaHex": f"0x{rva:x}",
            "metadataMethodId": mid,
            "methodId": mid,
            "class": clazz,
            "method": method,
            "methodName": method,
            "library": "libil2cpp.so",
        },
        "menuControlId": None,
        "description": (
            "Точный MethodDef + RVA из file-backed IL2CPP каталога. "
            "Это preflight locator: до executable binding требуется Deep Resolver/Menu preflight."
        ),
        "serverAudit": False,
        "ownership": "APP_OR_GAME",
        "evidence": {
            "id": f"method:{mid}",
            "kind": "IL2CPP_METHOD",
            "engineId": "il2cpp.filebacked-method-handoff",
            "metadataMethodId": mid,
            "methodId": mid,
            "class": clazz,
            "method": method,
            "methodName": method,
            "name": method,
            "label": label,
            "rva": rva,
            "rvaHex": f"0x{rva:x}",
            "applicationOwned": True,
            "methodRole": row.get("methodRole"),
            "semanticDomains": domains,
            "callerCount": int(row.get("callerCount") or 0),
            "calleeCount": int(row.get("calleeCount") or 0),
            "runtimeConfirmed": False,
            "runtimeTruth": "not-observed-by-static-analysis",
            "promotesBuildability": False,
        },
        "priority": score,
        "gameplayDomain": domain,
        "verificationStage": "LOCATOR_CONFIRMED",
        "confirmationRank": 55 if flow else 48,
        "readyReason": "MethodDef identity и executable RVA сохранены в file-backed каталоге.",
        "notReadyReason": "Нужны Deep Resolver/ABI/context и fail-closed Menu preflight.",
        "patchReady": False,
        "offlineCandidate": True,
        "lowSignal": False,
        "important": score >= 78,
        "evidenceTier": "CORRELATED_EVIDENCE",
        "methodBoundEvidence": True,
        "flowCorrelated": flow,
        "controlCandidate": True,
        "fileBackedMethod": True,
    }


def _repair_diagnostics(root: Path, selected_count: int) -> None:
    path = root / "re-analysis.json"
    analysis_path = root / "analysis.json"
    if not path.is_file() or not analysis_path.is_file():
        return
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
        analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    except Exception:
        return
    catalog = analysis.get("metadata_method_catalog") if isinstance(analysis, dict) else None
    if not isinstance(catalog, dict):
        return
    rows = int(catalog.get("rows") or 0)
    if rows <= 0:
        return
    diag = report.setdefault("pipelineDiagnostics", {})
    diag["fileBackedMethodCatalog"] = {
        "schema": "modkit-filebacked-method-diagnostics-1.0",
        "available": True,
        "rows": rows,
        "addressConfirmed": int(catalog.get("addressConfirmed") or 0),
        "directBlObserved": int(catalog.get("directBlObserved") or 0),
        "handoffCandidates": int(selected_count),
        "storage": catalog.get("storage") or "jsonl-file-backed",
        "file": catalog.get("file") or "analysis.methods.jsonl",
        "runtimeTruth": "not-observed-by-static-analysis",
    }
    # Keep the legacy embedded count untouched: zero means the compact JSON had no
    # inline rows. Expose the real effective count separately instead of fabricating
    # xref/context proof which was never computed.
    diag["il2cppEffectiveRows"] = rows
    diag["il2cppEffectiveRowsSource"] = "file-backed-method-catalog"
    tmp = path.with_name(path.name + ".handoff.part")
    try:
        tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)
    except Exception:
        tmp.unlink(missing_ok=True)


def enrich_catalog(report: dict[str, Any], workdir: str | Path,
                   gate: Callable[[], None] | None = None,
                   max_method_cards: int = _MAX_METHOD_CARDS) -> dict[str, Any]:
    if not isinstance(report, dict):
        return report
    root = Path(workdir)
    cards = report.get("cards") if isinstance(report.get("cards"), list) else []
    demoted = 0
    for card in cards:
        _tick(gate)
        if isinstance(card, dict) and _demote_false_positive(card):
            demoted += 1

    index_path = root / "analysis.autopilot-index.jsonl"
    candidates: list[dict[str, Any]] = []
    scanned = malformed = 0
    if index_path.is_file():
        try:
            with index_path.open("r", encoding="utf-8", errors="replace") as source:
                for line in source:
                    _tick(gate)
                    text = line.strip()
                    if not text:
                        continue
                    scanned += 1
                    try:
                        row = json.loads(text)
                    except json.JSONDecodeError:
                        malformed += 1
                        continue
                    if _eligible_method(row):
                        candidates.append(row)
        except OSError:
            candidates = []

    candidates.sort(key=lambda row: (-_method_score(row), int(row.get("metadataMethodId") or 0)))
    selected = candidates[:max(0, int(max_method_cards))]
    existing_ids = {str(c.get("id")) for c in cards if isinstance(c, dict)}
    added = 0
    for row in selected:
        card = _method_card(row)
        if card["id"] in existing_ids:
            continue
        cards.append(card)
        existing_ids.add(card["id"])
        added += 1

    report["cards"] = cards
    report["fileBackedMethodHandoff"] = {
        "schema": SCHEMA,
        "catalogPresent": index_path.is_file(),
        "rowsScanned": scanned,
        "eligibleRows": len(candidates),
        "methodCardsAdded": added,
        "falsePositiveCardsDemoted": demoted,
        "malformedRows": malformed,
        "maxMethodCards": int(max_method_cards),
        "buildabilityPromoted": False,
        "runtimeClaimed": False,
    }
    _repair_diagnostics(root, added)
    return report
