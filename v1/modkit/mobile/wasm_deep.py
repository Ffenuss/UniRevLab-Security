"""Embedded WebAssembly structural parser for Android-packaged WASM modules.

Parses the standard module header and bounded section directory, including export
names. It does not execute modules and does not claim original source recovery.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-webassembly-deep-1.0"
ENGINE_ID = "webassembly.deep-embedded"
MAX_MODULE_BYTES = 64 * 1024 * 1024
MAX_FINDINGS = 1200
MAX_SECTIONS = 512
SEMANTIC = (
    "health", "damage", "attack", "mana", "stamina", "energy", "currency",
    "coin", "gold", "gem", "level", "experience", "inventory", "speed",
    "cooldown", "player", "battle", "weapon", "ammo", "armor",
)
SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "data_count", 13: "tag",
}


class WasmScanCancelled(RuntimeError):
    pass


def _check(cb: Any | None) -> None:
    if cb is None:
        return
    checker = getattr(cb, "isCancelled", None)
    if callable(checker) and checker():
        raise WasmScanCancelled("webassembly scan cancelled")


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


def _uleb(data: bytes, pos: int, end: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    for _ in range(5):
        if pos >= end:
            return None
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, pos
        shift += 7
    return None


def _name(data: bytes, pos: int, end: int) -> tuple[str, int] | None:
    parsed = _uleb(data, pos, end)
    if not parsed:
        return None
    size, pos = parsed
    stop = pos + size
    if stop > end:
        return None
    try:
        value = data[pos:stop].decode("utf-8", "strict")
    except Exception:
        value = data[pos:stop].decode("utf-8", "replace")
    return value, stop


def _vector_count(payload: bytes) -> int | None:
    parsed = _uleb(payload, 0, len(payload))
    return parsed[0] if parsed else None


def _exports(payload: bytes) -> list[dict[str, Any]]:
    parsed = _uleb(payload, 0, len(payload))
    if not parsed:
        return []
    count, pos = parsed
    out: list[dict[str, Any]] = []
    for _ in range(min(count, 4096)):
        named = _name(payload, pos, len(payload))
        if not named:
            break
        value, pos = named
        if pos >= len(payload):
            break
        kind = payload[pos]
        pos += 1
        idx = _uleb(payload, pos, len(payload))
        if not idx:
            break
        index, pos = idx
        out.append({
            "name": value[:500],
            "kind": {0: "function", 1: "table", 2: "memory", 3: "global", 4: "tag"}.get(kind, f"kind-{kind}"),
            "index": int(index),
        })
    return out


def _custom_name(payload: bytes) -> str | None:
    named = _name(payload, 0, len(payload))
    return named[0][:200] if named else None


def _domains(value: str) -> list[str]:
    low = value.casefold()
    return sorted({word for word in SEMANTIC if word in low})


def _parse(data: bytes) -> dict[str, Any] | None:
    if len(data) < 8 or data[:4] != b"\x00asm":
        return None
    version = struct.unpack_from("<I", data, 4)[0]
    pos = 8
    sections: list[dict[str, Any]] = []
    export_rows: list[dict[str, Any]] = []
    custom_names: list[str] = []
    malformed = False
    while pos < len(data) and len(sections) < MAX_SECTIONS:
        section_id = data[pos]
        pos += 1
        parsed = _uleb(data, pos, len(data))
        if not parsed:
            malformed = True
            break
        size, pos = parsed
        stop = pos + size
        if stop > len(data):
            malformed = True
            break
        payload = data[pos:stop]
        row: dict[str, Any] = {
            "id": int(section_id),
            "name": SECTION_NAMES.get(int(section_id), f"section-{section_id}"),
            "size": int(size),
            "offset": int(pos),
        }
        if section_id in {1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 13}:
            row["vectorCount"] = _vector_count(payload)
        if section_id == 0:
            custom = _custom_name(payload)
            if custom:
                row["customName"] = custom
                custom_names.append(custom)
        elif section_id == 7:
            rows = _exports(payload)
            export_rows.extend(rows)
            row["exportCountParsed"] = len(rows)
        sections.append(row)
        pos = stop
    return {
        "version": int(version),
        "sections": sections,
        "exports": export_rows,
        "customSections": custom_names,
        "malformed": malformed,
        "truncatedByLimit": len(sections) >= MAX_SECTIONS and pos < len(data),
    }


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    modules: list[dict[str, Any]] = []
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
                    if info.is_dir() or info.file_size < 8 or info.file_size > MAX_MODULE_BYTES:
                        continue
                    if not info.filename.casefold().endswith(".wasm"):
                        continue
                    try:
                        with zf.open(info, "r") as source:
                            data = source.read(MAX_MODULE_BYTES + 1)
                    except Exception:
                        continue
                    parsed = _parse(data)
                    if not parsed:
                        modules.append({
                            "apk": apk.name, "entry": info.filename, "size": info.file_size,
                            "validWasmHeader": False,
                        })
                        continue
                    module = {
                        "apk": apk.name, "entry": info.filename, "size": info.file_size,
                        "validWasmHeader": True,
                        **parsed,
                    }
                    modules.append(module)
                    add({
                        "id": _stable("wasm-module", apk.name, info.filename),
                        "kind": "WEBASSEMBLY_MODULE",
                        "title": f"WASM: {Path(info.filename).name}",
                        "category": "Runtime/WebAssembly",
                        "status": "CORRELATED_EVIDENCE" if not parsed["malformed"] else "REVIEW",
                        "engineId": ENGINE_ID,
                        **module,
                        "patchReady": False, "automationExcluded": True,
                        "runtimeConfirmed": False,
                        "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                        "evidenceRole": "wasm-section-directory",
                    })
                    for exported in parsed["exports"]:
                        domains = _domains(str(exported["name"]))
                        add({
                            "id": _stable("wasm-export", apk.name, info.filename, str(exported["name"]), str(exported["index"])),
                            "kind": "WEBASSEMBLY_EXPORT",
                            "title": str(exported["name"]),
                            "category": "Gameplay/WebAssembly" if domains else "Runtime/WebAssembly Export",
                            "status": "FOUND_STATIC",
                            "engineId": ENGINE_ID,
                            "apk": apk.name, "entry": info.filename,
                            "export": exported,
                            "semanticDomains": domains,
                            "patchReady": False, "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                            "evidenceRole": "wasm-export",
                        })
        except WasmScanCancelled:
            raise
        except Exception:
            continue

    out = {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "passive": True,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "apkCount": apk_count,
        "moduleCount": len(modules),
        "validModuleCount": sum(1 for row in modules if row.get("validWasmHeader")),
        "exportCount": sum(len(row.get("exports") or []) for row in modules),
        "modules": modules,
        "findingCount": len(findings),
        "findings": findings,
        "policy": {
            "executesModules": False,
            "claimsOriginalSource": False,
            "instructionBodiesDisassembled": False,
        },
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path, cb)
