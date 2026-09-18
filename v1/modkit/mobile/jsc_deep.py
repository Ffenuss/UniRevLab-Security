"""Embedded JavaScriptCore / React Native JSC artifact analyzer.

Source bundles are structurally indexed. Binary .jsc artifacts receive bounded
header/string evidence only because JavaScriptCore bytecode layouts are version
specific; the engine never claims source recovery from opaque bytecode.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-jsc-deep-1.0"
ENGINE_ID = "jsc.deep-embedded"
MAX_SAMPLE = 8 * 1024 * 1024
MAX_FINDINGS = 1500
ASCII = re.compile(rb"[\x20-\x7e]{5,}")
JS_FN = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(|"
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)"
)
SEMANTIC = (
    "health", "damage", "attack", "mana", "stamina", "energy", "currency",
    "coin", "gold", "gem", "level", "experience", "inventory", "speed",
    "cooldown", "player", "battle", "weapon", "ammo", "armor",
)


class JscScanCancelled(RuntimeError):
    pass


def _check(cb: Any | None) -> None:
    if cb is None:
        return
    checker = getattr(cb, "isCancelled", None)
    if callable(checker) and checker():
        raise JscScanCancelled("jsc scan cancelled")


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


def _domains(value: str) -> list[str]:
    low = value.casefold()
    return sorted({word for word in SEMANTIC if word in low})


def _ascii_strings(data: bytes, limit: int = 512) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in ASCII.finditer(data):
        value = match.group().decode("utf-8", "replace").strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value[:300])
            if len(out) >= limit:
                break
    return out


def _looks_like_source(data: bytes) -> bool:
    if not data:
        return False
    sample = data[: min(len(data), 512 * 1024)]
    printable = sum(1 for value in sample if value in b"\t\r\n" or 0x20 <= value <= 0x7E)
    ratio = printable / max(1, len(sample))
    lower = sample.lower()
    return ratio >= 0.80 and (
        b"function" in lower or b"__d(" in lower or b"react-native" in lower
        or b"const " in lower or b"var " in lower
    )


def _source_functions(data: bytes) -> list[dict[str, Any]]:
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in JS_FN.finditer(text):
        name = match.group(1) or match.group(2)
        if not name or name in seen:
            continue
        seen.add(name)
        out.append({
            "name": name,
            "charOffset": match.start(1) if match.group(1) else match.start(2),
        })
        if len(out) >= 512:
            break
    return out


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    native_libraries: list[dict[str, Any]] = []
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
                    if base in {"libjsc.so", "libjscexecutor.so"}:
                        native_libraries.append({
                            "apk": apk.name, "entry": info.filename, "size": info.file_size,
                        })
                        add({
                            "id": _stable("jsc-native", apk.name, info.filename),
                            "kind": "JSC_NATIVE_RUNTIME",
                            "title": f"JavaScriptCore runtime: {Path(info.filename).name}",
                            "category": "Runtime/JavaScriptCore",
                            "status": "FOUND_STATIC",
                            "engineId": ENGINE_ID,
                            "apk": apk.name, "entry": info.filename, "size": info.file_size,
                            "patchReady": False, "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "ENGINE", "trustBoundary": "local",
                            "evidenceRole": "jsc-native-runtime",
                        })
                        continue

                    candidate = (
                        low.endswith(".jsc") or low.endswith("index.android.bundle")
                        or (low.endswith(".js") and ("assets/" in low or "/src/" in low))
                    )
                    if not candidate:
                        continue
                    try:
                        with zf.open(info, "r") as source:
                            data = source.read(min(MAX_SAMPLE, info.file_size))
                    except Exception:
                        continue
                    source_like = _looks_like_source(data)
                    strings = _ascii_strings(data)
                    functions = _source_functions(data) if source_like else []
                    row = {
                        "apk": apk.name,
                        "entry": info.filename,
                        "size": info.file_size,
                        "sampleBytes": len(data),
                        "representation": "javascript-source-or-bundle" if source_like else "jsc-binary-bytecode",
                        "sourceLike": source_like,
                        "headerHex": data[:32].hex(),
                        "functionCount": len(functions),
                        "functions": functions,
                        "stringCount": len(strings),
                    }
                    artifacts.append(row)
                    add({
                        "id": _stable("jsc-artifact", apk.name, info.filename),
                        "kind": "JSC_ARTIFACT",
                        "title": f"JSC: {Path(info.filename).name}",
                        "category": "Runtime/JavaScriptCore",
                        "status": "SCRIPT_CONTENT_SEARCH" if source_like else "FOUND_STATIC",
                        "engineId": ENGINE_ID,
                        **row,
                        "patchReady": False, "automationExcluded": True,
                        "runtimeConfirmed": False,
                        "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                        "evidenceRole": "jsc-source-structure" if source_like else "jsc-bytecode-inventory",
                    })
                    for fn in functions:
                        domains = _domains(str(fn["name"]))
                        if domains:
                            add({
                                "id": _stable("jsc-function", apk.name, info.filename, str(fn["name"])),
                                "kind": "JSC_SOURCE_FUNCTION",
                                "title": str(fn["name"]),
                                "category": "Gameplay/JavaScriptCore",
                                "status": "SCRIPT_CONTENT_SEARCH",
                                "engineId": ENGINE_ID,
                                "apk": apk.name, "entry": info.filename,
                                "function": fn["name"], "charOffset": fn["charOffset"],
                                "semanticDomains": domains,
                                "patchReady": False, "automationExcluded": True,
                                "runtimeConfirmed": False,
                                "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                                "evidenceRole": "jsc-source-semantic",
                            })
                    for value in strings:
                        domains = _domains(value)
                        if not domains:
                            continue
                        add({
                            "id": _stable("jsc-string", apk.name, info.filename, value),
                            "kind": "JSC_SEMANTIC_STRING",
                            "title": value[:180],
                            "category": "Gameplay/JavaScriptCore",
                            "status": "FOUND_STATIC",
                            "engineId": ENGINE_ID,
                            "apk": apk.name, "entry": info.filename,
                            "semanticDomains": domains,
                            "representation": row["representation"],
                            "patchReady": False, "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                            "evidenceRole": "jsc-string-semantic",
                        })
        except JscScanCancelled:
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
        "artifactCount": len(artifacts),
        "sourceLikeCount": sum(1 for row in artifacts if row.get("sourceLike")),
        "binaryBytecodeCount": sum(1 for row in artifacts if not row.get("sourceLike")),
        "nativeLibraryCount": len(native_libraries),
        "nativeLibraries": native_libraries,
        "artifacts": artifacts,
        "findingCount": len(findings),
        "findings": findings,
        "policy": {
            "claimsSourceFromBinaryJsc": False,
            "versionSpecificBytecodeDecoded": False,
            "binaryJscPatchedAutomatically": False,
        },
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path, cb)
