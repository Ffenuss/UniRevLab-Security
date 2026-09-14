"""Built-in static discovery for non-DEX Android runtimes and script families.

This module never executes target code. It inventories recoverable Lua/JavaScript/Hermes/
Flutter/Cocos artifacts across a complete APK set and records an honest recovery level.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-artifact-families-1.1"
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 5000
PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")
LUA_FN = re.compile(r"(?:^|\s)(?:local\s+)?function\s+([A-Za-z_][\w.:]*)\s*\(", re.M)
JS_FN = re.compile(r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)")


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


def _sha(apk: str, entry: str, family: str, extra: str = "") -> str:
    return hashlib.sha256(f"{apk}!{entry}!{family}!{extra}".encode("utf-8", "replace")).hexdigest()[:20]


def _strings(data: bytes, limit: int = 120) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in PRINTABLE.finditer(data):
        text = m.group().decode("utf-8", "replace").strip()
        if text and text not in seen:
            seen.add(text); out.append(text[:300])
            if len(out) >= limit:
                break
    return out


def _lua_version(data: bytes) -> str | None:
    if not data.startswith(b"\x1bLua") or len(data) < 5:
        return None
    versions = {0x51: "5.1", 0x52: "5.2", 0x53: "5.3", 0x54: "5.4"}
    return versions.get(data[4], f"0x{data[4]:02x}")


def _classify(name: str, data: bytes) -> tuple[str | None, str, str, list[str]]:
    """Return family, representation, recovery level and markers."""
    low = name.lower()
    markers: list[str] = []
    if low.endswith(".lua"):
        return "lua", "source", "DECOMPILED_SOURCE", markers
    if low.endswith((".luac", ".luae")) or data.startswith(b"\x1bLua"):
        ver = _lua_version(data)
        if ver: markers.append("lua-bytecode-" + ver)
        return "lua", "bytecode", "DISASSEMBLED_METADATA", markers
    if low.endswith((".js", ".mjs", ".cjs")) or low.endswith("index.android.bundle") or ("/src/" in low and low.endswith(".bundle")):
        if b"__d(function" in data or b"react-native" in data.lower(): markers.append("react-native")
        return "javascript", "source-or-bundle", "DECOMPILED_SOURCE", markers
    if low.endswith((".hbc", ".hermes")) or ("hermes" in low and not low.endswith(".so")):
        return "hermes", "bytecode", "DISASSEMBLED_METADATA", markers
    if low.endswith("main.jsc") or low.endswith(".jsc"):
        return "javascript", "jsc-bytecode", "DISASSEMBLED_METADATA", ["javascriptcore-bytecode"]
    if "flutter_assets/" in low or low.endswith(("vm_snapshot_data", "isolate_snapshot_data", "kernel_blob.bin")):
        return "flutter", "snapshot-or-asset", "RECONSTRUCTED_METADATA", markers
    if low.endswith("libapp.so") and ("/lib/" in low or low.startswith("lib/")):
        return "flutter", "dart-aot-elf", "NATIVE_AOT", ["dart-aot-candidate"]
    if low.endswith("libflutter.so"):
        return "flutter", "flutter-engine", "NATIVE_ENGINE", markers
    if low.endswith(("libcocos2dcpp.so", "libcocos.so", "libcocos2d.so")):
        return "cocos", "native-engine", "NATIVE_ENGINE", markers
    if "cocos" in low or (low.endswith(("project.js", "settings.js")) and "assets/" in low):
        return "cocos", "engine-or-script", "RECONSTRUCTED_METADATA", markers
    return None, "", "", markers


def _source_symbols(family: str, data: bytes) -> list[dict[str, Any]]:
    if not data or len(data) > MAX_TEXT_BYTES:
        return []
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return []
    matches: list[tuple[str, int]] = []
    if family == "lua":
        matches = [(m.group(1), m.start(1)) for m in LUA_FN.finditer(text)]
    elif family == "javascript":
        for m in JS_FN.finditer(text):
            value = m.group(1) or m.group(2)
            if value:
                start = m.start(1) if m.group(1) else m.start(2)
                matches.append((value, start))
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, offset in matches:
        if name in seen:
            continue
        seen.add(name)
        line = text.count("\n", 0, offset) + 1
        out.append({"name": name, "line": line, "charOffset": offset})
        if len(out) >= 250:
            break
    return out


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    family_counts: dict[str, int] = {}
    recovery_counts: dict[str, int] = {}
    symbol_count = 0
    apk_count = 0
    for raw in paths:
        apk = Path(raw)
        if not apk.is_file():
            continue
        apk_count += 1
        try:
            with zipfile.ZipFile(apk) as z:
                for info in z.infolist():
                    if len(items) >= MAX_ITEMS:
                        break
                    if info.is_dir() or info.file_size <= 0 or info.file_size > MAX_ENTRY_BYTES:
                        continue
                    low = info.filename.lower()
                    likely = any(x in low for x in (".lua", ".js", ".jsc", ".hbc", "hermes", "flutter", "cocos", "snapshot", "libapp.so"))
                    if not likely:
                        continue
                    try:
                        data = z.read(info)
                    except Exception:
                        continue
                    family, representation, recovery, markers = _classify(info.filename, data)
                    if not family:
                        continue
                    symbol_locs = _source_symbols(family, data) if representation in ("source", "source-or-bundle") else []
                    symbols = [item["name"] for item in symbol_locs]
                    strings = _strings(data, 80) if recovery != "DECOMPILED_SOURCE" else []
                    row = {
                        "id": "artifact:" + family + ":" + _sha(apk.name, info.filename, family),
                        "kind": "ARTIFACT_FAMILY",
                        "title": f"{family}: {Path(info.filename).name}",
                        "category": "Runtime/Script",
                        "status": "FOUND_STATIC",
                        "family": family,
                        "representation": representation,
                        "recoveryLevel": recovery,
                        "apk": apk.name,
                        "entry": info.filename,
                        "size": info.file_size,
                        "markers": markers,
                        "symbols": symbols,
                        "symbolLocators": symbol_locs,
                        "strings": strings,
                        "serverAudit": False,
                        "trustBoundary": "local",
                        "patchReady": False,
                        "evidenceRole": "artifact-inventory",
                    }
                    items.append(row)
                    family_counts[family] = family_counts.get(family, 0) + 1
                    recovery_counts[recovery] = recovery_counts.get(recovery, 0) + 1
                    for symbol in symbol_locs:
                        if len(items) >= MAX_ITEMS:
                            break
                        name = str(symbol["name"])
                        line = int(symbol["line"])
                        items.append({
                            "id": "script:" + family + ":" + _sha(apk.name, info.filename, family, f"{name}:{line}"),
                            "kind": "SCRIPT_SYMBOL",
                            "title": name,
                            "category": "Gameplay/Script",
                            "status": "SCRIPT_CONTENT_SEARCH",
                            "family": family,
                            "representation": representation,
                            "recoveryLevel": recovery,
                            "apk": apk.name,
                            "entry": info.filename,
                            "function": name,
                            "line": line,
                            "charOffset": int(symbol["charOffset"]),
                            "serverAudit": False,
                            "trustBoundary": "local",
                            "patchReady": False,
                            "evidenceRole": "script-symbol",
                        })
                        symbol_count += 1
        except Exception:
            continue
    artifact_count = sum(family_counts.values())
    out = {
        "schema": SCHEMA,
        "passive": True,
        "executesTargetCode": False,
        "apkCount": apk_count,
        "total": len(items),
        "artifactCount": artifact_count,
        "symbolCount": symbol_count,
        "familyCounts": family_counts,
        "recoveryCounts": recovery_counts,
        "artifacts": items,
        "truncated": len(items) >= MAX_ITEMS,
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path)
