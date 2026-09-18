"""Embedded .NET/Mono CLI metadata recovery for Android assemblies.

This backend is intentionally metadata-first: it parses the ECMA-335 metadata root,
stream directory and table row counts without executing managed code. It does not
claim C# source recovery or NativeAOT reconstruction.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-dotnet-metadata-1.0"
ENGINE_ID = "dotnet.metadata-embedded"
MAX_ASSEMBLY_BYTES = 64 * 1024 * 1024
MAX_STRINGS = 4096
MAX_FINDINGS = 1024

_TABLE_NAMES = {
    0: "Module", 1: "TypeRef", 2: "TypeDef", 3: "FieldPtr", 4: "Field",
    5: "MethodPtr", 6: "MethodDef", 7: "ParamPtr", 8: "Param",
    9: "InterfaceImpl", 10: "MemberRef", 11: "Constant", 12: "CustomAttribute",
    13: "FieldMarshal", 14: "DeclSecurity", 15: "ClassLayout", 16: "FieldLayout",
    17: "StandAloneSig", 18: "EventMap", 19: "EventPtr", 20: "Event",
    21: "PropertyMap", 22: "PropertyPtr", 23: "Property", 24: "MethodSemantics",
    25: "MethodImpl", 26: "ModuleRef", 27: "TypeSpec", 28: "ImplMap",
    29: "FieldRVA", 30: "ENCLog", 31: "ENCMap", 32: "Assembly",
    33: "AssemblyProcessor", 34: "AssemblyOS", 35: "AssemblyRef",
    36: "AssemblyRefProcessor", 37: "AssemblyRefOS", 38: "File",
    39: "ExportedType", 40: "ManifestResource", 41: "NestedClass",
    42: "GenericParam", 43: "MethodSpec", 44: "GenericParamConstraint",
}
_SEMANTIC_WORDS = (
    "health", "damage", "attack", "mana", "stamina", "energy", "currency",
    "coin", "gold", "gem", "diamond", "level", "experience", "inventory",
    "speed", "cooldown", "player", "battle", "hero", "purchase", "premium",
)


class DotNetScanCancelled(RuntimeError):
    pass


def _check(cb: Any | None) -> None:
    if cb is None:
        return
    checker = getattr(cb, "isCancelled", None)
    if callable(checker) and checker():
        raise DotNetScanCancelled("dotnet metadata scan cancelled")


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


def _aligned4(value: int) -> int:
    return (value + 3) & ~3


def _metadata_root(data: bytes) -> dict[str, Any] | None:
    root = data.find(b"BSJB")
    if root < 0 or root + 20 > len(data):
        return None
    try:
        signature, major, minor, _reserved, version_len = struct.unpack_from("<IHHII", data, root)
    except struct.error:
        return None
    if signature != 0x424A5342 or version_len > 4096:
        return None
    version_start = root + 16
    version_end = version_start + version_len
    if version_end > len(data):
        return None
    version = data[version_start:version_end].split(b"\0", 1)[0].decode("utf-8", "replace")
    pos = _aligned4(version_end)
    if pos + 4 > len(data):
        return None
    flags, stream_count = struct.unpack_from("<HH", data, pos)
    pos += 4
    if stream_count > 64:
        return None
    streams: dict[str, dict[str, int]] = {}
    for _ in range(stream_count):
        if pos + 8 > len(data):
            return None
        offset, size = struct.unpack_from("<II", data, pos)
        pos += 8
        name_end = data.find(b"\0", pos, min(len(data), pos + 64))
        if name_end < 0:
            return None
        name = data[pos:name_end].decode("ascii", "replace")
        pos = _aligned4(name_end + 1)
        absolute = root + offset
        if absolute < root or absolute + size > len(data):
            continue
        streams[name] = {"offset": absolute, "size": int(size), "relativeOffset": int(offset)}
    return {
        "rootOffset": root,
        "major": int(major),
        "minor": int(minor),
        "flags": int(flags),
        "runtimeVersion": version,
        "streams": streams,
    }


def _strings_heap(data: bytes, stream: dict[str, int] | None, limit: int = MAX_STRINGS) -> list[str]:
    if not stream:
        return []
    start = int(stream["offset"])
    end = min(len(data), start + int(stream["size"]))
    out: list[str] = []
    seen: set[str] = set()
    pos = start + 1 if start < end and data[start] == 0 else start
    while pos < end and len(out) < limit:
        stop = data.find(b"\0", pos, end)
        if stop < 0:
            break
        if stop > pos:
            raw = data[pos:stop]
            try:
                text = raw.decode("utf-8")
            except Exception:
                text = ""
            if text and text not in seen and all(ch.isprintable() or ch in "\t\r\n" for ch in text):
                seen.add(text)
                out.append(text[:500])
        pos = stop + 1
    return out


def _compressed_uint(data: bytes, pos: int, end: int) -> tuple[int, int] | None:
    if pos >= end:
        return None
    first = data[pos]
    if first & 0x80 == 0:
        return first, pos + 1
    if first & 0xC0 == 0x80:
        if pos + 2 > end:
            return None
        return ((first & 0x3F) << 8) | data[pos + 1], pos + 2
    if first & 0xE0 == 0xC0:
        if pos + 4 > end:
            return None
        return (
            ((first & 0x1F) << 24) | (data[pos + 1] << 16)
            | (data[pos + 2] << 8) | data[pos + 3],
            pos + 4,
        )
    return None


def _user_strings(data: bytes, stream: dict[str, int] | None, limit: int = 1024) -> list[str]:
    if not stream:
        return []
    start = int(stream["offset"])
    end = min(len(data), start + int(stream["size"]))
    pos = start + 1 if start < end and data[start] == 0 else start
    out: list[str] = []
    seen: set[str] = set()
    while pos < end and len(out) < limit:
        parsed = _compressed_uint(data, pos, end)
        if not parsed:
            break
        size, payload = parsed
        if size <= 0:
            pos = payload
            continue
        stop = payload + size
        if stop > end:
            break
        body = data[payload:stop]
        if len(body) >= 1:
            body = body[:-1]  # terminal special-character flag
        if len(body) % 2 == 0:
            try:
                text = body.decode("utf-16le", "strict").strip("\0")
            except Exception:
                text = ""
            if text and text not in seen:
                seen.add(text)
                out.append(text[:500])
        pos = stop
    return out


def _table_counts(data: bytes, stream: dict[str, int] | None) -> dict[str, int]:
    if not stream:
        return {}
    start = int(stream["offset"])
    end = min(len(data), start + int(stream["size"]))
    if start + 24 > end:
        return {}
    try:
        _reserved, major, minor, heap_sizes, _reserved2 = struct.unpack_from("<IBBBB", data, start)
        valid, _sorted = struct.unpack_from("<QQ", data, start + 8)
    except struct.error:
        return {}
    pos = start + 24
    counts: dict[str, int] = {}
    for table_id in range(64):
        if not (valid >> table_id) & 1:
            continue
        if pos + 4 > end:
            return counts
        count = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        counts[_TABLE_NAMES.get(table_id, f"Table{table_id}")] = int(count)
    counts["_metadataMajor"] = int(major)
    counts["_metadataMinor"] = int(minor)
    counts["_heapSizes"] = int(heap_sizes)
    return counts


def _flavor(entry: str, strings: list[str]) -> str:
    low_entry = entry.casefold()
    sample = " ".join(strings[:512]).casefold()
    if "assets/bin/data/managed/" in low_entry or "assembly-csharp" in low_entry or "unityengine" in sample:
        return "unity-mono"
    if low_entry.startswith("assemblies/") or "xamarin" in sample:
        return "xamarin-dotnet"
    if "microsoft.maui" in sample:
        return "maui-dotnet"
    return "managed-cli"


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    assemblies: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    apk_count = 0
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
                    low = info.filename.casefold()
                    if info.is_dir() or not low.endswith(".dll") or info.file_size <= 0:
                        continue
                    if info.file_size > MAX_ASSEMBLY_BYTES:
                        errors.append({"apk": apk.name, "entry": info.filename, "error": "assembly-too-large"})
                        continue
                    if not (
                        low.startswith("assemblies/") or "/managed/" in low
                        or "/assemblies/" in low or low.startswith("assets/bin/data/managed/")
                    ):
                        continue
                    try:
                        with zf.open(info, "r") as source:
                            data = source.read(MAX_ASSEMBLY_BYTES + 1)
                    except Exception as exc:
                        errors.append({"apk": apk.name, "entry": info.filename, "error": str(exc)})
                        continue
                    root = _metadata_root(data)
                    if not root:
                        assemblies.append({
                            "apk": apk.name, "entry": info.filename, "size": info.file_size,
                            "status": "OPAQUE_OR_NATIVE_IMAGE", "managedMetadata": False,
                        })
                        continue
                    streams = root["streams"]
                    strings = _strings_heap(data, streams.get("#Strings"))
                    user_strings = _user_strings(data, streams.get("#US"))
                    table_stream = streams.get("#~") or streams.get("#-")
                    counts = _table_counts(data, table_stream)
                    flavor = _flavor(info.filename, strings)
                    assembly = {
                        "apk": apk.name,
                        "entry": info.filename,
                        "size": info.file_size,
                        "runtimeVersion": root.get("runtimeVersion"),
                        "metadataRootOffset": root.get("rootOffset"),
                        "metadataStreams": sorted(streams),
                        "tableRowCounts": counts,
                        "stringCount": len(strings),
                        "userStringCount": len(user_strings),
                        "flavor": flavor,
                        "managedMetadata": True,
                    }
                    assemblies.append(assembly)
                    findings.append({
                        "id": "dotnet-assembly:" + hashlib.sha256(
                            f"{apk.name}!{info.filename}".encode()
                        ).hexdigest()[:20],
                        "kind": "DOTNET_MANAGED_METADATA",
                        "title": f".NET metadata: {Path(info.filename).name}",
                        "category": "Runtime/.NET",
                        "status": "FOUND_STATIC",
                        "engineId": ENGINE_ID,
                        **assembly,
                        "strings": strings[:256],
                        "userStrings": user_strings[:128],
                        "patchReady": False,
                        "automationExcluded": True,
                        "runtimeConfirmed": False,
                        "ownershipKind": "APP_OR_GAME",
                        "trustBoundary": "local",
                        "evidenceRole": "dotnet-cli-metadata",
                    })
                    for value in [*strings, *user_strings]:
                        low_value = value.casefold()
                        domains = sorted({word for word in _SEMANTIC_WORDS if word in low_value})
                        if not domains:
                            continue
                        findings.append({
                            "id": "dotnet-string:" + hashlib.sha256(
                                f"{apk.name}!{info.filename}!{value}".encode("utf-8", "replace")
                            ).hexdigest()[:20],
                            "kind": "DOTNET_METADATA_STRING",
                            "title": value[:180],
                            "category": "Gameplay/.NET Metadata",
                            "status": "FOUND_STATIC",
                            "engineId": ENGINE_ID,
                            "apk": apk.name,
                            "entry": info.filename,
                            "family": "dotnet",
                            "semanticDomains": domains,
                            "flavor": flavor,
                            "patchReady": False,
                            "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "APP_OR_GAME",
                            "trustBoundary": "local",
                            "evidenceRole": "dotnet-metadata-string",
                        })
                        if len(findings) >= MAX_FINDINGS:
                            break
                    if len(findings) >= MAX_FINDINGS:
                        break
        except DotNetScanCancelled:
            raise
        except Exception as exc:
            errors.append({"apk": apk.name, "entry": "", "error": str(exc)})

    out = {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "passive": True,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "apkCount": apk_count,
        "assemblyCount": len(assemblies),
        "managedAssemblyCount": sum(1 for row in assemblies if row.get("managedMetadata")),
        "findingCount": len(findings),
        "assemblies": assemblies,
        "findings": findings,
        "errors": errors,
        "policy": {
            "claimsOriginalSource": False,
            "nativeAotReconstructed": False,
            "cilInstructionsDecoded": False,
        },
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path, cb)
