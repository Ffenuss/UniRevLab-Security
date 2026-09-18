"""Embedded Defold Android archive/resource correlator.

The backend correlates the standard compiled archive family and extracts bounded
resource-path/string evidence from manifests/index/project artifacts. It never
claims original Lua/source recovery from compiled Defold archives.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-defold-deep-1.0"
ENGINE_ID = "defold.deep-embedded"
MAX_SAMPLE = 4 * 1024 * 1024
MAX_FINDINGS = 1200
ASCII = re.compile(rb"[\x20-\x7e]{5,}")
RESOURCE = re.compile(
    r"(?:/|res:)?[A-Za-z0-9_./-]+\.(?:collectionc|goc|scriptc|gui_scriptc|guic|"
    r"spritec|texturec|materialc|soundc|meshc|modelc|tilemapc|tilesourcec|"
    r"fontc|renderc|display_profilesc|particlefxc|labelc)"
)
SEMANTIC = (
    "health", "damage", "attack", "mana", "stamina", "energy", "currency",
    "coin", "gold", "gem", "level", "experience", "inventory", "speed",
    "cooldown", "player", "battle", "weapon", "ammo", "armor",
)


class DefoldScanCancelled(RuntimeError):
    pass


def _check(cb: Any | None) -> None:
    if cb is None:
        return
    checker = getattr(cb, "isCancelled", None)
    if callable(checker) and checker():
        raise DefoldScanCancelled("defold scan cancelled")


def _workspace_apks(root: Path) -> list[Path]:
    paths: list[Path] = []
    target = root / "installed-target.json"
    if target.is_file():
        try:
            obj = json.loads(target.read_text(encoding="utf-8"))
            for row in obj.get("splits", []) if isinstance(obj, dict) else []:
                if isinstance(row, dict):
                    p = Path(str(row.get("path") or ""))
                    if p.is_file() and p not in paths:
                        paths.append(p)
        except Exception:
            pass
    apk_dir = root / "installed-apks"
    if apk_dir.is_dir():
        for p in sorted(apk_dir.glob("*.apk")):
            if p not in paths:
                paths.append(p)
    game = root / "game.apk"
    if game.is_file() and game not in paths:
        paths.append(game)
    return paths


def _stable(prefix: str, *parts: str) -> str:
    return prefix + ":" + hashlib.sha256("!".join(parts).encode("utf-8", "replace")).hexdigest()[:20]


def _strings(data: bytes) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in ASCII.finditer(data):
        value = m.group().decode("utf-8", "replace").strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value[:300])
            if len(out) >= 1024:
                break
    return out


def _domains(value: str) -> list[str]:
    low = value.casefold()
    return sorted({word for word in SEMANTIC if word in low})


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    archive_groups: dict[tuple[str, str], dict[str, Any]] = {}
    native_libraries: list[dict[str, Any]] = []
    resource_paths: set[tuple[str, str, str]] = set()
    apk_count = 0

    def add(row: dict[str, Any]) -> None:
        if len(findings) < MAX_FINDINGS:
            findings.append(row)

    for raw in paths:
        _check(cb)
        apk = Path(raw)
        if not apk.is_file():
            continue
        apk_count += 1
        try:
            with zipfile.ZipFile(apk) as zf:
                for info in zf.infolist():
                    _check(cb)
                    if info.is_dir() or info.file_size <= 0:
                        continue
                    low = info.filename.casefold()
                    base = low.rsplit("/", 1)[-1]
                    if base == "libdmengine.so":
                        native_libraries.append({
                            "apk": apk.name, "entry": info.filename, "size": info.file_size,
                        })
                        add({
                            "id": _stable("defold-native", apk.name, info.filename),
                            "kind": "DEFOLD_NATIVE_ENGINE",
                            "title": f"Defold native engine: {Path(info.filename).name}",
                            "category": "Runtime/Defold",
                            "status": "FOUND_STATIC",
                            "engineId": ENGINE_ID,
                            "apk": apk.name, "entry": info.filename, "size": info.file_size,
                            "patchReady": False, "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "ENGINE", "trustBoundary": "local",
                            "evidenceRole": "defold-native-engine",
                        })
                        continue

                    member = None
                    if base.endswith(".arci"):
                        member = "index"
                    elif base.endswith(".arcd"):
                        member = "data"
                    elif base.endswith(".dmanifest"):
                        member = "manifest"
                    elif base.endswith(".projectc") or base == "game.projectc":
                        member = "project"
                    if not member:
                        continue

                    directory = info.filename.rsplit("/", 1)[0] if "/" in info.filename else ""
                    key = (apk.name, directory)
                    group = archive_groups.setdefault(key, {
                        "apk": apk.name, "directory": directory,
                        "index": None, "data": None, "manifest": None, "project": None,
                    })
                    group[member] = info.filename

                    if member == "data":
                        continue
                    try:
                        with zf.open(info, "r") as source:
                            sample = source.read(min(MAX_SAMPLE, info.file_size))
                    except Exception:
                        continue
                    for value in _strings(sample):
                        for match in RESOURCE.finditer(value):
                            resource_paths.add((apk.name, info.filename, match.group(0)))
                        domains = _domains(value)
                        if domains:
                            add({
                                "id": _stable("defold-semantic", apk.name, info.filename, value),
                                "kind": "DEFOLD_COMPILED_SEMANTIC_STRING",
                                "title": value[:180],
                                "category": "Gameplay/Defold",
                                "status": "FOUND_STATIC",
                                "engineId": ENGINE_ID,
                                "apk": apk.name, "entry": info.filename,
                                "semanticDomains": domains,
                                "patchReady": False, "automationExcluded": True,
                                "runtimeConfirmed": False,
                                "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                                "evidenceRole": "defold-compiled-string",
                            })
        except DefoldScanCancelled:
            raise
        except Exception:
            continue

    for (_apk, _dir), group in sorted(archive_groups.items()):
        present = [name for name in ("index", "data", "manifest", "project") if group.get(name)]
        add({
            "id": _stable("defold-archive", str(group["apk"]), str(group["directory"])),
            "kind": "DEFOLD_ARCHIVE_GROUP",
            "title": Path(str(group["directory"] or "Defold archive")).name or "Defold archive",
            "category": "Runtime/Defold Archive",
            "status": "CORRELATED_EVIDENCE",
            "engineId": ENGINE_ID,
            **group,
            "memberCount": len(present),
            "archivePairComplete": bool(group.get("index") and group.get("data")),
            "manifestPresent": bool(group.get("manifest")),
            "projectPresent": bool(group.get("project")),
            "patchReady": False, "automationExcluded": True,
            "runtimeConfirmed": False,
            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
            "evidenceRole": "defold-archive-topology",
        })

    for apk_name, entry, value in sorted(resource_paths):
        add({
            "id": _stable("defold-resource", apk_name, entry, value),
            "kind": "DEFOLD_RESOURCE_PATH",
            "title": value,
            "category": "Runtime/Defold Resource",
            "status": "FOUND_STATIC",
            "engineId": ENGINE_ID,
            "apk": apk_name, "entry": entry,
            "resourcePath": value,
            "semanticDomains": _domains(value),
            "patchReady": False, "automationExcluded": True,
            "runtimeConfirmed": False,
            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
            "evidenceRole": "defold-resource-path",
        })

    out = {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "passive": True,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "apkCount": apk_count,
        "archiveGroupCount": len(archive_groups),
        "resourcePathCount": len(resource_paths),
        "nativeLibraryCount": len(native_libraries),
        "nativeLibraries": native_libraries,
        "findingCount": len(findings),
        "findings": findings,
        "policy": {
            "archivePayloadFullyDecoded": False,
            "claimsOriginalLuaSource": False,
            "encryptedArchiveBypass": False,
        },
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path, cb)
