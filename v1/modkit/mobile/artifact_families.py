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
READ_CHUNK_BYTES = 1024 * 1024
PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")
LUA_FN = re.compile(r"(?:^|\s)(?:local\s+)?function\s+([A-Za-z_][\w.:]*)\s*\(", re.M)
JS_FN = re.compile(r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)")


class ArtifactScanCancelled(RuntimeError):
    """Explicit cooperative cancellation; partial inventory is never published."""


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
        raise ArtifactScanCancelled("artifact family scan cancelled")


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


def _strings(data: bytes, limit: int = 120, cb: Any | None = None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for no, m in enumerate(PRINTABLE.finditer(data)):
        if (no & 0xFF) == 0:
            _check(cb)
        text = m.group().decode("utf-8", "replace").strip()
        if text and text not in seen:
            seen.add(text); out.append(text[:300])
            if len(out) >= limit:
                break
    _check(cb)
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


def _source_symbols(family: str, data: bytes, cb: Any | None = None) -> list[dict[str, Any]]:
    if not data or len(data) > MAX_TEXT_BYTES:
        return []
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    line_no = 1
    line_scan_pos = 0
    regex = LUA_FN if family == "lua" else JS_FN if family == "javascript" else None
    if regex is None:
        return out
    for no, match in enumerate(regex.finditer(text)):
        if (no & 0x7F) == 0:
            _check(cb)
        if family == "lua":
            value = match.group(1)
            offset = match.start(1)
        else:
            value = match.group(1) or match.group(2)
            if not value:
                continue
            offset = match.start(1) if match.group(1) else match.start(2)
        if value in seen:
            continue
        # Regex matches arrive in source order. Count only the text since the
        # previous accepted symbol, so line mapping is linear rather than O(n²).
        line_no += text.count("\n", line_scan_pos, offset)
        line_scan_pos = offset
        seen.add(value)
        out.append({"name": value, "line": line_no, "charOffset": offset})
        if len(out) >= 250:
            break
    _check(cb)
    return out


def _read_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cb: Any | None = None) -> bytes:
    chunks: list[bytes] = []
    with zf.open(info, "r") as source:
        while True:
            _check(cb)
            chunk = source.read(READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
    _check(cb)
    return b"".join(chunks)


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    family_counts: dict[str, int] = {}
    recovery_counts: dict[str, int] = {}
    symbol_count = 0
    apk_count = 0
    for raw in paths:
        _check(cb)
        apk = Path(raw)
        if not apk.is_file():
            continue
        apk_count += 1
        try:
            with zipfile.ZipFile(apk) as z:
                for info in z.infolist():
                    _check(cb)
                    if len(items) >= MAX_ITEMS:
                        break
                    if info.is_dir() or info.file_size <= 0 or info.file_size > MAX_ENTRY_BYTES:
                        continue
                    low = info.filename.lower()
                    likely = any(x in low for x in (".lua", ".js", ".jsc", ".hbc", ".bundle", "hermes", "flutter", "cocos", "snapshot", "libapp.so"))
                    if not likely:
                        continue
                    try:
                        data = _read_entry(z, info, cb)
                    except ArtifactScanCancelled:
                        raise
                    except Exception:
                        if _cancelled(cb):
                            raise ArtifactScanCancelled("artifact family scan cancelled")
                        continue
                    family, representation, recovery, markers = _classify(info.filename, data)
                    if not family:
                        continue
                    symbol_locs = _source_symbols(family, data, cb) if representation in ("source", "source-or-bundle") else []
                    symbols = [item["name"] for item in symbol_locs]
                    strings = _strings(data, 80, cb) if recovery != "DECOMPILED_SOURCE" else []
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
                    for symbol_no, symbol in enumerate(symbol_locs):
                        if (symbol_no & 0x7F) == 0:
                            _check(cb)
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
        except ArtifactScanCancelled:
            raise
        except Exception:
            if _cancelled(cb):
                raise ArtifactScanCancelled("artifact family scan cancelled")
            continue
    _check(cb)
    artifact_count = sum(family_counts.values())
    out = {
        "schema": SCHEMA,
        "passive": True,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "apkCount": apk_count,
        "total": len(items),
        "artifactCount": artifact_count,
        "symbolCount": symbol_count,
        "familyCounts": family_counts,
        "recoveryCounts": recovery_counts,
        "artifacts": items,
        "truncated": len(items) >= MAX_ITEMS,
    }
    _check(cb)
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path, cb)
