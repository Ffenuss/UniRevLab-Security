"""Embedded Unreal Engine cooked-artifact correlator.

The analyzer is passive and version-tolerant. It inventories PAK/IoStore container
topology, correlates uasset sidecars, extracts bounded name/reflection evidence and
semantic strings, and never claims Blueprint/native source reconstruction.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-unreal-deep-1.0"
ENGINE_ID = "unreal.deep-embedded"
MAX_ENTRY_SAMPLE = 2 * 1024 * 1024
MAX_NATIVE_SAMPLE = 8 * 1024 * 1024
MAX_FINDINGS = 1500
MAX_STRINGS = 512
ASCII = re.compile(rb"[\x20-\x7e]{5,}")
SEMANTIC = (
    "health", "damage", "attack", "mana", "stamina", "energy", "currency",
    "coin", "gold", "gem", "level", "experience", "inventory", "speed",
    "cooldown", "player", "character", "battle", "weapon", "ammo", "armor",
)
REFLECTION_MARKERS = (
    "/Script/", "BlueprintGeneratedClass", "WidgetBlueprintGeneratedClass",
    "Default__", "UClass", "UObject", "FName", "StaticClass", "ProcessEvent",
    "FindObject", "StaticFindObject", "StaticLoadObject",
)
PAK_MAGIC = 0x5A6F12E1


class UnrealScanCancelled(RuntimeError):
    pass


def _check(cb: Any | None) -> None:
    if cb is None:
        return
    checker = getattr(cb, "isCancelled", None)
    if callable(checker) and checker():
        raise UnrealScanCancelled("unreal scan cancelled")


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


def _read_sample(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    with zf.open(info, "r") as source:
        return source.read(min(limit, max(0, info.file_size)))


def _read_tail(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int = 512) -> bytes:
    # ZipExtFile is not seekable reliably on every runtime; for huge PAK files,
    # avoid reading the full entry and simply skip footer proof.
    if info.file_size > MAX_ENTRY_SAMPLE:
        return b""
    data = _read_sample(zf, info, MAX_ENTRY_SAMPLE)
    return data[-limit:]


def _strings(data: bytes) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in ASCII.finditer(data):
        value = match.group().decode("utf-8", "replace").strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value[:300])
            if len(out) >= MAX_STRINGS:
                break
    return out


def _domains(value: str) -> list[str]:
    low = value.casefold()
    return sorted({word for word in SEMANTIC if word in low})


def _stable(prefix: str, *parts: str) -> str:
    return prefix + ":" + hashlib.sha256("!".join(parts).encode("utf-8", "replace")).hexdigest()[:20]


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    containers: list[dict[str, Any]] = []
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    io_groups: dict[tuple[str, str], dict[str, Any]] = {}
    reflection: set[str] = set()
    apk_count = 0
    native_library_count = 0

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
                    suffix = Path(low).suffix
                    stem = str(Path(info.filename).with_suffix(""))
                    if suffix in {".uasset", ".uexp", ".ubulk"}:
                        key = (apk.name, stem)
                        group = groups.setdefault(key, {
                            "apk": apk.name, "base": stem, "uasset": None, "uexp": None, "ubulk": None,
                        })
                        group[suffix[1:]] = info.filename
                        try:
                            sample = _read_sample(zf, info, MAX_ENTRY_SAMPLE)
                        except Exception:
                            sample = b""
                        values = _strings(sample)
                        assets.append({
                            "apk": apk.name, "entry": info.filename, "kind": suffix[1:],
                            "size": info.file_size, "stringCount": len(values),
                        })
                        for value in values:
                            if any(marker.casefold() in value.casefold() for marker in REFLECTION_MARKERS):
                                reflection.add(value[:300])
                            domains = _domains(value)
                            if domains:
                                add({
                                    "id": _stable("unreal-semantic", apk.name, info.filename, value),
                                    "kind": "UNREAL_COOKED_SEMANTIC_STRING",
                                    "title": value[:180],
                                    "category": "Gameplay/Unreal Cooked Asset",
                                    "status": "FOUND_STATIC",
                                    "engineId": ENGINE_ID,
                                    "apk": apk.name, "entry": info.filename,
                                    "semanticDomains": domains,
                                    "patchReady": False, "automationExcluded": True,
                                    "runtimeConfirmed": False,
                                    "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                                    "evidenceRole": "unreal-cooked-string",
                                })
                    elif suffix in {".utoc", ".ucas"}:
                        base = str(Path(info.filename).with_suffix(""))
                        key = (apk.name, base)
                        row = io_groups.setdefault(key, {
                            "apk": apk.name, "base": base, "utoc": None, "ucas": None,
                        })
                        row[suffix[1:]] = info.filename
                    elif suffix == ".pak" or "pakchunk" in low:
                        tail = _read_tail(zf, info)
                        magic_offsets = []
                        magic = struct.pack("<I", PAK_MAGIC)
                        pos = tail.find(magic)
                        while pos >= 0:
                            magic_offsets.append(max(0, info.file_size - len(tail)) + pos)
                            pos = tail.find(magic, pos + 1)
                        containers.append({
                            "apk": apk.name, "entry": info.filename, "kind": "pak",
                            "size": info.file_size,
                            "pakFooterMagicObserved": bool(magic_offsets),
                            "pakMagicCandidateOffsets": magic_offsets[:8],
                            "footerSampled": bool(tail),
                        })
                    elif low.endswith(".so") and (
                        low.endswith("/libue4.so") or low.endswith("/libunreal.so")
                        or low.endswith("/libunrealengine.so")
                    ):
                        native_library_count += 1
                        try:
                            sample = _read_sample(zf, info, MAX_NATIVE_SAMPLE)
                        except Exception:
                            sample = b""
                        values = _strings(sample)
                        markers = sorted({
                            marker for marker in REFLECTION_MARKERS
                            if any(marker.casefold() in value.casefold() for value in values)
                        })
                        add({
                            "id": _stable("unreal-native", apk.name, info.filename),
                            "kind": "UNREAL_NATIVE_RUNTIME",
                            "title": f"Unreal native runtime: {Path(info.filename).name}",
                            "category": "Runtime/Unreal",
                            "status": "FOUND_STATIC",
                            "engineId": ENGINE_ID,
                            "apk": apk.name, "entry": info.filename,
                            "reflectionMarkers": markers,
                            "patchReady": False, "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "ENGINE", "trustBoundary": "local",
                            "evidenceRole": "unreal-native-runtime",
                        })

        except UnrealScanCancelled:
            raise
        except Exception:
            continue

    for (_apk, _base), group in sorted(groups.items()):
        members = [group.get("uasset"), group.get("uexp"), group.get("ubulk")]
        present = [x for x in members if x]
        add({
            "id": _stable("unreal-asset-group", str(group["apk"]), str(group["base"])),
            "kind": "UNREAL_COOKED_ASSET_GROUP",
            "title": Path(str(group["base"])).name,
            "category": "Runtime/Unreal Cooked Asset",
            "status": "CORRELATED_EVIDENCE",
            "engineId": ENGINE_ID,
            **group,
            "memberCount": len(present),
            "sidecarComplete": bool(group.get("uasset") and group.get("uexp")),
            "patchReady": False, "automationExcluded": True,
            "runtimeConfirmed": False,
            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
            "evidenceRole": "unreal-cooked-sidecar-topology",
        })

    for (_apk, _base), row in sorted(io_groups.items()):
        add({
            "id": _stable("unreal-iostore", str(row["apk"]), str(row["base"])),
            "kind": "UNREAL_IOSTORE_CONTAINER_PAIR",
            "title": Path(str(row["base"])).name,
            "category": "Runtime/Unreal IoStore",
            "status": "CORRELATED_EVIDENCE",
            "engineId": ENGINE_ID,
            **row,
            "pairComplete": bool(row.get("utoc") and row.get("ucas")),
            "patchReady": False, "automationExcluded": True,
            "runtimeConfirmed": False,
            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
            "evidenceRole": "unreal-iostore-topology",
        })

    for value in sorted(reflection)[:256]:
        add({
            "id": _stable("unreal-reflection", value),
            "kind": "UNREAL_REFLECTION_NAME",
            "title": value[:180],
            "category": "Runtime/Unreal Reflection",
            "status": "FOUND_STATIC",
            "engineId": ENGINE_ID,
            "reflectionName": value,
            "patchReady": False, "automationExcluded": True,
            "runtimeConfirmed": False,
            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
            "evidenceRole": "unreal-reflection-name",
        })

    out = {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "passive": True,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "apkCount": apk_count,
        "nativeLibraryCount": native_library_count,
        "cookedAssetCount": len(assets),
        "cookedAssetGroupCount": len(groups),
        "ioStorePairCount": len(io_groups),
        "containerCount": len(containers),
        "reflectionNameCount": len(reflection),
        "findingCount": len(findings),
        "containers": containers,
        "cookedAssets": assets,
        "findings": findings,
        "policy": {
            "claimsBlueprintSource": False,
            "claimsNativeSource": False,
            "pakIndexFullyParsed": False,
            "ioStoreIndexFullyParsed": False,
            "encryptedContainerBypass": False,
        },
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path, cb)
