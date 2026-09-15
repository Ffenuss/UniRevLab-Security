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


def _id(*parts: object) -> str:
    return hashlib.sha256("!".join(str(x) for x in parts).encode("utf-8", "replace")).hexdigest()[:20]


def _words(value: object) -> tuple[set[str], str]:
    text = str(value or "")
    # Preserve acronym boundaries: GetHP -> Get HP, AddXP -> Add XP, MaxHealth -> Max Health.
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    low = text.casefold()
    tokens = set(re.findall(r"[a-z0-9]+", low))
    compact = re.sub(r"[^a-z0-9]", "", low)
    return tokens, compact


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
                hit = alias_tokens.issubset(tokens) or alias_compact in compact
            else:
                hit = alias_compact in tokens or alias_compact in compact
            if hit:
                matched.append(alias)
        if matched:
            return domain, matched[:8]
    return "", []


def _semantic_text(row: dict[str, Any]) -> str:
    values: list[object] = [
        row.get("title"), row.get("name"), row.get("function"), row.get("method"), row.get("symbol"),
        row.get("class"), row.get("category"), row.get("kind"), row.get("source"), row.get("entry"),
    ]
    for key in ("strings", "markers"):
        value = row.get(key)
        if isinstance(value, list):
            values.extend(value[:80])
    return " ".join(str(v) for v in values if v not in (None, ""))


def _finding_from_native(lib: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    name = str(fn.get("name") or "").strip()
    domain, aliases = classify(name)
    if not name or not domain:
        return None
    rva = fn.get("rva")
    if not isinstance(rva, int) or rva <= 0:
        return None
    entry = str(lib.get("entry") or "")
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


def _finding_from_artifact(row: dict[str, Any]) -> dict[str, Any] | None:
    if row.get("gameplayDomain"):
        return None
    domain, aliases = classify(_semantic_text(row))
    if not domain:
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


def analyze(artifact_report: dict[str, Any], native_report: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    existing_native: set[tuple[str, int]] = set()
    artifacts = artifact_report.get("artifacts", []) if isinstance(artifact_report, dict) else []
    for row in artifacts if isinstance(artifacts, list) else []:
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

    for lib in native_report.get("libraries", []) if isinstance(native_report, dict) else []:
        if not isinstance(lib, dict):
            continue
        entry = str(lib.get("entry") or "")
        for fn in lib.get("functions", []) if isinstance(lib.get("functions"), list) else []:
            if not isinstance(fn, dict):
                continue
            rva = fn.get("rva")
            if isinstance(rva, int) and (entry, rva) in existing_native:
                continue
            add(_finding_from_native(lib, fn))

    for row in artifacts if isinstance(artifacts, list) else []:
        if isinstance(row, dict):
            add(_finding_from_artifact(row))

    coverage = Counter(str(row.get("gameplayDomain") or "") for row in findings if row.get("gameplayDomain"))
    locator_count = sum(1 for row in findings if isinstance(row.get("rva"), int) or (row.get("entry") and row.get("function")))
    return {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "bundled": True,
        "manualImportRequired": False,
        "passive": True,
        "executesTargetCode": False,
        "runtimeTruth": "not-observed-by-static-analysis",
        "findingCount": len(findings),
        "locatorCount": locator_count,
        "coverage": dict(sorted(coverage.items())),
        "findings": findings,
        "truncated": len(findings) >= MAX_FINDINGS,
    }


def scan_workspace(workdir: str | Path, artifact_report: dict[str, Any] | None = None,
                   native_report: dict[str, Any] | None = None,
                   output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
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
    out = analyze(artifact_report or {}, native_report or {})
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
