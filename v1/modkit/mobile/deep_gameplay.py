"""Semantic post-processing for gameplay evidence recovered by bundled deep backends.

The module increases recall for compact/camelCase names such as GetHP, MaxHP,
AddXP, RunSpeed and AddCoins without turning keyword matches into runtime proof.
It only promotes exact locators which already exist in static evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = "modkit-deep-gameplay-1.0"
ENGINE_ID = "semantic.gameplay"
MAX_FINDINGS = 3000

_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("health", (
        "health", "hp", "maxhp", "curhp", "currenthp", "playerhp", "hitpoint", "hitpoints",
        "life", "lives", "lifepoint", "lifepoints", "vitality", "hearts", "heal", "healing",
        "regen", "regeneration", "godmode", "immortal",
    )),
    ("damage", (
        "damage", "dmg", "attack", "attackpower", "attackdamage", "weaponpower", "weapon damage",
        "melee", "ranged", "critical", "crit", "critdamage", "defense", "defence", "armor", "armour",
        "resistance", "resist",
    )),
    ("speed", (
        "speed", "movespeed", "runspeed", "walkspeed", "sprintspeed", "attackspeed", "gamespeed",
        "timescale", "time scale", "velocitymultiplier", "movement speed",
    )),
    ("cooldown", (
        "cooldown", "cool down", "cd", "recharge", "recast", "skillcd", "abilitycd", "delay",
    )),
    ("currency", (
        "currency", "money", "cash", "coin", "coins", "gold", "silver", "credit", "credits",
        "gem", "gems", "diamond", "diamonds", "wallet", "balance", "funds", "token", "tokens",
    )),
    ("level_xp", (
        "level", "lvl", "lv", "xp", "exp", "experience", "playerlevel", "skillpoint", "skillpoints",
        "statpoint", "statpoints", "perkpoint", "perkpoints",
    )),
    ("inventory", (
        "inventory", "item", "items", "itemcount", "itemamount", "quantity", "stack", "stackcount",
        "ammo", "ammunition", "loot", "drop", "reward", "rewards",
    )),
    ("mana_energy", (
        "mana", "mp", "maxmana", "energy", "stamina", "maxstamina", "rage", "resource",
    )),
    ("movement", (
        "movement", "jump", "jumpheight", "gravity", "velocity", "teleport", "position",
        "coordinate", "coordinates", "noclip",
    )),
    ("camera", (
        "camera", "fov", "fieldofview", "field of view", "zoom", "viewdistance", "view distance",
    )),
)

_SHORT = {alias for _, aliases in _RULES for alias in aliases if len(re.sub(r"[^a-z0-9]", "", alias)) <= 3}
_COMPACT_PREFIXES = (
    "get", "set", "add", "grant", "apply", "reset", "update", "read", "write", "load", "save",
    "current", "max", "min", "base", "total", "player", "character", "local", "new", "old",
    "has", "is", "can", "use", "consume", "regen", "increase", "decrease", "modify",
)

# Semantic gameplay discovery must not bootstrap itself from an upstream label.
# These tokens identify infrastructure/diagnostic contexts in which words such as
# level, speed, balance and stack have non-gameplay meanings. They only suppress
# gameplay classification; the original evidence remains available to the generic
# RE/security reports.
_INFRA_CONTEXT = (
    "/system/", "/proc/", "/sys/", "/vendor/", "goldfish", "ranchu", "qemu",
    "crashsight", "appsflyer", "opentelemetry", "firebase", "adjust", "networkdiagnosis",
    "network_diagnosis", "netspeed", "androidx.", "androidx/", "kotlinx.", "kotlinx/",
)


class GameplayScanCancelled(RuntimeError):
    """Explicit cooperative cancellation for semantic correlation."""


def _cancelled(cb: Any | None) -> bool:
    if cb is None:
        return False
    checker = getattr(cb, "isCancelled", None)
    if callable(checker):
        return bool(checker())
    if callable(cb):
        return bool(cb())
    return False


def _check(cb: Any | None) -> None:
    if _cancelled(cb):
        raise GameplayScanCancelled("gameplay correlation cancelled")


def _id(*parts: object) -> str:
    return hashlib.sha256("!".join(str(x) for x in parts).encode("utf-8", "replace")).hexdigest()[:20]


def _words(value: object) -> tuple[set[str], str]:
    text = str(value or "")
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    low = text.casefold()
    tokens = set(re.findall(r"[a-z0-9]+", low))
    compact = re.sub(r"[^a-z0-9]", "", low)
    return tokens, compact


def _single_alias_hit(alias_compact: str, tokens: set[str], compact: str) -> bool:
    """Match a single semantic word only at a real semantic boundary."""
    if alias_compact in tokens or compact == alias_compact:
        return True
    return any(compact == prefix + alias_compact for prefix in _COMPACT_PREFIXES)


def classify(value: object) -> tuple[str, list[str]]:
    tokens, compact = _words(value)
    for domain, aliases in _RULES:
        matched: list[str] = []
        for alias in aliases:
            alias_tokens, alias_compact = _words(alias)
            if not alias_compact:
                continue
            if alias in _SHORT:
                hit = alias_compact in tokens
            elif len(alias_tokens) > 1:
                hit = alias_tokens.issubset(tokens) or compact == alias_compact
            else:
                hit = _single_alias_hit(alias_compact, tokens, compact)
            if hit:
                matched.append(alias)
        if matched:
            return domain, matched[:8]
    return "", []


def _semantic_text(row: dict[str, Any]) -> str:
    # Only classify semantic payload. Do not feed upstream category/kind/source/
    # entry labels back into the classifier: doing so can turn a previous broad
    # category guess into apparently independent gameplay evidence.
    values: list[object] = [
        row.get("title"), row.get("name"), row.get("function"), row.get("method"), row.get("symbol"),
        row.get("class"),
    ]
    for key in ("strings", "markers"):
        value = row.get(key)
        if isinstance(value, list):
            values.extend(value[:80])
    return " ".join(str(v) for v in values if v not in (None, ""))


def _artifact_context(row: dict[str, Any]) -> str:
    values = [row.get("entry"), row.get("path"), row.get("file"), row.get("source"), row.get("engineId")]
    return " ".join(str(v) for v in values if v not in (None, "")).casefold()


def _is_semantic_noise(row: dict[str, Any], text: str, domain: str, aliases: list[str]) -> bool:
    low = str(text or "").casefold()
    context = _artifact_context(row)
    combined = low + " " + context
    if any(marker in combined for marker in _INFRA_CONTEXT):
        return True

    words, _compact = _words(text)
    alias_set = {re.sub(r"[^a-z0-9]", "", a.casefold()) for a in aliases}
    if domain == "level_xp" and ("level" in alias_set or "lvl" in alias_set or "lv" in alias_set):
        if words & {"log", "logger", "logging", "trace", "crypto", "diagnostic", "severity"}:
            return True
    if domain == "speed":
        if words & {"network", "download", "upload", "bandwidth", "latency", "throughput", "netspeed"}:
            return True
    if domain == "inventory" and "stack" in alias_set:
        if words & {"trace", "stacktrace", "exception", "call", "frame"}:
            return True
    if domain == "currency":
        # Billing/attribution SDK vocabulary is monetization evidence, not proof
        # of a gameplay currency variable. Keep it in the security/trust surface.
        if words & {"billing", "purchase", "receipt", "payment", "iap", "price", "checkout", "revenue"}:
            return True
    return False


def _finding_from_native(lib: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    name = str(fn.get("name") or "").strip()
    domain, aliases = classify(name)
    if not name or not domain:
        return None
    rva = fn.get("rva")
    if not isinstance(rva, int) or rva <= 0:
        return None
    entry = str(lib.get("entry") or "")
    if _is_semantic_noise({"entry": entry, "engineId": "native.deep-embedded"}, name, domain, aliases):
        return None
    return {
        "id": "deep-semantic-native:" + _id(entry, rva, name, domain),
        "kind": "NATIVE_SEMANTIC_FUNCTION",
        "title": name,
        "category": "Gameplay/Native",
        "status": "FOUND_STATIC",
        "family": "native",
        "engineId": ENGINE_ID,
        "sourceEngineId": "native.deep-embedded",
        "entry": entry,
        "library": entry,
        "abi": lib.get("abi"),
        "function": name,
        "rva": rva,
        "size": fn.get("size"),
        "gameplayDomain": domain,
        "semanticAliases": aliases,
        "semanticConfidence": "HIGH" if any(len(re.sub(r"[^a-z0-9]", "", a)) >= 4 for a in aliases) else "MEDIUM",
        "ownershipKind": "APP_OR_GAME",
        "trustBoundary": "local",
        "patchReady": False,
        "runtimeConfirmed": False,
        "runtimeTruth": "not-observed-by-static-analysis",
        "evidenceRole": "deep-gameplay-native-symbol",
    }


def _findings_from_runtime_argument_flow(row: dict[str, Any]) -> list[dict[str, Any]]:
    source_kind = str(row.get("kind") or "")
    if source_kind not in {"IL2CPP_RUNTIME_ARGUMENT_FLOW", "IL2CPP_DLSYM_ARGUMENT_FLOW"}:
        return []
    flow = row.get("runtimeArgumentFlow") if isinstance(row.get("runtimeArgumentFlow"), dict) else {}
    identifier = str(flow.get("identifier") or "")
    domain = str(row.get("gameplayDomain") or flow.get("gameplayDomain") or "")
    if not domain and identifier:
        domain, _aliases = classify(identifier)
    if not domain:
        return []
    exact = bool(flow.get("exactManagedIdentityConfirmed"))
    return [{
        "id": "deep-il2cpp-argument-flow:" + _id(row.get("id"), domain),
        "kind": "IL2CPP_DLSYM_ARGUMENT_FLOW_EVIDENCE" if source_kind == "IL2CPP_DLSYM_ARGUMENT_FLOW"
                else "IL2CPP_RUNTIME_ARGUMENT_FLOW_EVIDENCE",
        "title": str(row.get("title") or "IL2CPP argument-register flow"),
        "category": "Gameplay/IL2CPP Runtime Lookup",
        "status": "CORRELATED_EVIDENCE",
        "family": "native",
        "engineId": ENGINE_ID,
        "sourceEngineId": row.get("engineId") or "native.deep-embedded",
        "sourceFindingId": row.get("id"),
        "entry": row.get("entry"),
        "library": row.get("library") or row.get("entry"),
        "abi": row.get("abi"),
        "sourceRva": row.get("sourceRva"),
        "sourceFunction": row.get("sourceFunction"),
        "callRva": row.get("callRva"),
        "gameplayDomain": domain,
        "semanticAliases": [identifier] if identifier else [],
        "semanticConfidence": "VERY_HIGH" if exact else "HIGH",
        "runtimeArgumentFlow": flow,
        "argumentFlowConfirmed": bool(flow.get("argumentFlowConfirmed")),
        "exactManagedIdentityConfirmed": exact,
        "ownershipKind": row.get("ownershipKind") or "APP_OR_GAME",
        "trustBoundary": row.get("trustBoundary") or "local",
        "patchReady": False,
        "automationExcluded": True,
        "runtimeConfirmed": False,
        "runtimeTruth": "not-observed-by-static-analysis",
        "evidenceRole": ("deep-gameplay-il2cpp-dlsym-pointer-argument-flow"
                         if source_kind == "IL2CPP_DLSYM_ARGUMENT_FLOW"
                         else "deep-gameplay-il2cpp-argument-register-flow"),
    }]


def _findings_from_runtime_lookup(row: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert same-function IL2CPP runtime lookup correlation into REVIEW evidence.

    The native backend only proves that lookup APIs and candidate managed
    identifiers are referenced by the same native function.  It does not prove
    exact argument flow, so these rows are explicitly automation-excluded.
    """
    if str(row.get("kind") or "") != "IL2CPP_RUNTIME_LOOKUP_CHAIN":
        return []
    lookup = row.get("runtimeLookup") if isinstance(row.get("runtimeLookup"), dict) else {}
    domains = {str(x) for x in (row.get("gameplayDomains") or []) if x}
    identifiers = lookup.get("candidateIdentifiers") if isinstance(lookup.get("candidateIdentifiers"), list) else []
    semantic_hits: dict[str, list[str]] = {}
    for ident in identifiers:
        if not isinstance(ident, dict):
            continue
        value = str(ident.get("value") or "")
        domain, aliases = classify(value)
        if domain:
            domains.add(domain)
            semantic_hits.setdefault(domain, [])
            for alias in aliases:
                if alias not in semantic_hits[domain]:
                    semantic_hits[domain].append(alias)
    out = []
    for domain in sorted(domains):
        out.append({
            "id": "deep-il2cpp-runtime-lookup:" + _id(row.get("id"), domain),
            "kind": "IL2CPP_RUNTIME_LOOKUP_CORRELATION",
            "title": str(row.get("title") or "IL2CPP runtime lookup"),
            "category": "Gameplay/IL2CPP Runtime Lookup",
            "status": "REVIEW",
            "family": "native",
            "engineId": ENGINE_ID,
            "sourceEngineId": row.get("engineId") or "native.deep-embedded",
            "sourceFindingId": row.get("id"),
            "entry": row.get("entry"),
            "library": row.get("library") or row.get("entry"),
            "abi": row.get("abi"),
            "sourceRva": row.get("sourceRva"),
            "sourceFunction": row.get("sourceFunction"),
            "gameplayDomain": domain,
            "semanticAliases": semantic_hits.get(domain, []),
            "semanticConfidence": lookup.get("confidence") or row.get("confidence") or "MEDIUM",
            "runtimeLookup": lookup,
            "ownershipKind": row.get("ownershipKind") or "APP_OR_GAME",
            "trustBoundary": row.get("trustBoundary") or "local",
            "patchReady": False,
            "automationExcluded": True,
            "runtimeConfirmed": False,
            "runtimeTruth": "not-observed-by-static-analysis",
            "evidenceRole": "deep-gameplay-il2cpp-runtime-lookup-review",
        })
    return out


def _finding_from_artifact(row: dict[str, Any]) -> dict[str, Any] | None:
    if str(row.get("kind") or "") == "IL2CPP_RUNTIME_LOOKUP_CHAIN":
        return None
    if row.get("gameplayDomain"):
        return None
    semantic_text = _semantic_text(row)
    domain, aliases = classify(semantic_text)
    if not domain or _is_semantic_noise(row, semantic_text, domain, aliases):
        return None
    title = str(row.get("title") or row.get("function") or row.get("name") or row.get("entry") or domain)
    entry = str(row.get("entry") or row.get("path") or row.get("file") or "")
    function = str(row.get("function") or row.get("functionName") or row.get("symbol") or "")
    kind = str(row.get("kind") or "SEMANTIC_ARTIFACT_MATCH")
    source_id = str(row.get("id") or _id(title, entry, function))
    status = "FOUND_STATIC"
    if kind == "SCRIPT_SYMBOL" and entry.casefold().endswith((".lua", ".luac", ".luae", ".js", ".mjs", ".cjs")) and function:
        status = "SCRIPT_CONTENT_SEARCH"
    out = {
        "id": "deep-semantic-artifact:" + _id(source_id, domain),
        "kind": "SEMANTIC_ARTIFACT_MATCH",
        "title": title,
        "category": "Gameplay/Script" if status == "SCRIPT_CONTENT_SEARCH" else "Gameplay/Artifact",
        "status": status,
        "family": row.get("family"),
        "engineId": ENGINE_ID,
        "sourceEngineId": row.get("engineId"),
        "sourceFindingId": row.get("id"),
        "entry": entry or None,
        "function": function or None,
        "line": row.get("line") or row.get("lineNumber"),
        "rva": row.get("rva") if isinstance(row.get("rva"), int) else None,
        "gameplayDomain": domain,
        "semanticAliases": aliases,
        "semanticConfidence": "HIGH" if any(len(re.sub(r"[^a-z0-9]", "", a)) >= 4 for a in aliases) else "MEDIUM",
        "ownershipKind": row.get("ownershipKind") or "APP_OR_GAME",
        "trustBoundary": row.get("trustBoundary") or "local",
        "patchReady": False,
        "runtimeConfirmed": False,
        "runtimeTruth": "not-observed-by-static-analysis",
        "evidenceRole": "deep-gameplay-semantic-corroboration",
    }
    return {k: v for k, v in out.items() if v is not None}


def analyze(artifact_report: dict[str, Any], native_report: dict[str, Any],
            cb: Any | None = None) -> dict[str, Any]:
    _check(cb)
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    existing_native: set[tuple[str, int]] = set()
    artifacts = artifact_report.get("artifacts", []) if isinstance(artifact_report, dict) else []
    for row_no, row in enumerate(artifacts if isinstance(artifacts, list) else []):
        if (row_no & 0xFF) == 0:
            _check(cb)
        if not isinstance(row, dict) or not row.get("gameplayDomain"):
            continue
        rva = row.get("rva")
        if not isinstance(rva, int):
            continue
        entry = str(row.get("library") or row.get("entry") or "")
        existing_native.add((entry, rva))

    def add(row: dict[str, Any] | None) -> None:
        if not row or len(findings) >= MAX_FINDINGS:
            return
        rid = str(row.get("id") or "")
        if not rid or rid in seen:
            return
        seen.add(rid)
        findings.append(row)

    checked = 0
    for lib in native_report.get("libraries", []) if isinstance(native_report, dict) else []:
        _check(cb)
        if not isinstance(lib, dict):
            continue
        entry = str(lib.get("entry") or "")
        for fn in lib.get("functions", []) if isinstance(lib.get("functions"), list) else []:
            checked += 1
            if (checked & 0xFF) == 0:
                _check(cb)
            if not isinstance(fn, dict):
                continue
            rva = fn.get("rva")
            if isinstance(rva, int) and (entry, rva) in existing_native:
                continue
            add(_finding_from_native(lib, fn))

    lookup_count = 0
    argument_flow_count = 0
    for row in native_report.get("findings", []) if isinstance(native_report, dict) else []:
        if not isinstance(row, dict):
            continue
        kind = str(row.get("kind") or "")
        if kind == "IL2CPP_RUNTIME_LOOKUP_CHAIN":
            lookup_count += 1
            if (lookup_count & 0x3F) == 0:
                _check(cb)
            for finding in _findings_from_runtime_lookup(row):
                add(finding)
        elif kind in {"IL2CPP_RUNTIME_ARGUMENT_FLOW", "IL2CPP_DLSYM_ARGUMENT_FLOW"}:
            argument_flow_count += 1
            if (argument_flow_count & 0x3F) == 0:
                _check(cb)
            for finding in _findings_from_runtime_argument_flow(row):
                add(finding)

    for row_no, row in enumerate(artifacts if isinstance(artifacts, list) else []):
        if (row_no & 0xFF) == 0:
            _check(cb)
        if isinstance(row, dict):
            add(_finding_from_artifact(row))

    _check(cb)
    coverage = Counter(str(row.get("gameplayDomain") or "") for row in findings if row.get("gameplayDomain"))
    locator_count = sum(1 for row in findings if isinstance(row.get("rva"), int) or (row.get("entry") and row.get("function")))
    return {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "bundled": True,
        "manualImportRequired": False,
        "passive": True,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "runtimeTruth": "not-observed-by-static-analysis",
        "findingCount": len(findings),
        "locatorCount": locator_count,
        "coverage": dict(sorted(coverage.items())),
        "runtimeLookupSourceCount": lookup_count,
        "runtimeLookupGameplayCount": sum(1 for row in findings if row.get("kind") == "IL2CPP_RUNTIME_LOOKUP_CORRELATION"),
        "runtimeArgumentFlowSourceCount": argument_flow_count,
        "runtimeArgumentFlowGameplayCount": sum(
            1 for row in findings if row.get("kind") in {
                "IL2CPP_RUNTIME_ARGUMENT_FLOW_EVIDENCE", "IL2CPP_DLSYM_ARGUMENT_FLOW_EVIDENCE"
            }
        ),
        "dlsymArgumentFlowGameplayCount": sum(
            1 for row in findings if row.get("kind") == "IL2CPP_DLSYM_ARGUMENT_FLOW_EVIDENCE"
        ),
        "exactManagedIdentityCount": sum(1 for row in findings if row.get("exactManagedIdentityConfirmed")),
        "findings": findings,
        "truncated": len(findings) >= MAX_FINDINGS,
    }


def scan_workspace(workdir: str | Path, artifact_report: dict[str, Any] | None = None,
                   native_report: dict[str, Any] | None = None,
                   output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    _check(cb)
    if artifact_report is None:
        path = root / "artifact-families.json"
        try:
            artifact_report = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        except Exception:
            artifact_report = {}
    if native_report is None:
        path = root / "native-deep.json"
        try:
            native_report = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        except Exception:
            native_report = {}
    out = analyze(artifact_report or {}, native_report or {}, cb)
    _check(cb)
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out