"""Embedded Qt/QML structural analyzer.

Parses source QML into imports/components/properties/signals/functions and inventories
compiled QML/RCC artifacts without pretending to recover original QML from bytecode.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-qt-qml-deep-1.0"
ENGINE_ID = "qt.qml-deep-embedded"
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 1500

IMPORT_RE = re.compile(r"^\s*import\s+([^\r\n]+)", re.M)
COMPONENT_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9_.]*)\s*\{", re.M)
ID_RE = re.compile(r"^\s*id\s*:\s*([A-Za-z_][\w]*)", re.M)
PROPERTY_RE = re.compile(
    r"^\s*(?:readonly\s+|required\s+)?property\s+([A-Za-z_][\w<>.]*)\s+([A-Za-z_][\w]*)\s*(?::\s*([^\r\n]+))?",
    re.M,
)
SIGNAL_RE = re.compile(r"^\s*signal\s+([A-Za-z_][\w]*)\s*(?:\(([^)]*)\))?", re.M)
FUNCTION_RE = re.compile(r"^\s*function\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)", re.M)
SEMANTIC = (
    "health", "damage", "attack", "mana", "stamina", "energy", "currency",
    "coin", "gold", "gem", "level", "experience", "inventory", "speed",
    "cooldown", "player", "battle", "weapon", "ammo", "armor",
)


class QmlScanCancelled(RuntimeError):
    pass


def _check(cb: Any | None) -> None:
    if cb is None:
        return
    checker = getattr(cb, "isCancelled", None)
    if callable(checker) and checker():
        raise QmlScanCancelled("qml scan cancelled")


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


def _parse_qml(text: str) -> dict[str, Any]:
    imports = [m.group(1).strip() for m in IMPORT_RE.finditer(text)]
    components = [m.group(1) for m in COMPONENT_RE.finditer(text)]
    ids = [m.group(1) for m in ID_RE.finditer(text)]
    properties = [
        {
            "type": m.group(1),
            "name": m.group(2),
            "value": (m.group(3) or "").strip(),
        }
        for m in PROPERTY_RE.finditer(text)
    ]
    signals = [
        {"name": m.group(1), "args": (m.group(2) or "").strip()}
        for m in SIGNAL_RE.finditer(text)
    ]
    functions = [
        {"name": m.group(1), "args": m.group(2).strip()}
        for m in FUNCTION_RE.finditer(text)
    ]
    return {
        "imports": imports,
        "components": components,
        "ids": ids,
        "properties": properties,
        "signals": signals,
        "functions": functions,
    }


def scan_apk_paths(paths: Iterable[str | Path], output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    qml_sources: list[dict[str, Any]] = []
    compiled_qml: list[dict[str, Any]] = []
    rcc: list[dict[str, Any]] = []
    native_qt: list[dict[str, Any]] = []
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

                    if base.startswith(("libqt5", "libqt6")) and low.endswith(".so"):
                        native_qt.append({"apk": apk.name, "entry": info.filename, "size": info.file_size})
                        continue

                    if low.endswith(".rcc"):
                        try:
                            with zf.open(info, "r") as source:
                                head = source.read(32)
                        except Exception:
                            head = b""
                        row = {
                            "apk": apk.name, "entry": info.filename, "size": info.file_size,
                            "qresMagicObserved": head.startswith(b"qres"),
                        }
                        rcc.append(row)
                        add({
                            "id": _stable("qml-rcc", apk.name, info.filename),
                            "kind": "QT_RCC_CONTAINER",
                            "title": f"Qt RCC: {Path(info.filename).name}",
                            "category": "Runtime/Qt",
                            "status": "FOUND_STATIC" if row["qresMagicObserved"] else "REVIEW",
                            "engineId": ENGINE_ID,
                            **row,
                            "patchReady": False, "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                            "evidenceRole": "qt-rcc-header",
                        })
                        continue

                    if low.endswith((".qmlc", ".jsc")) and "/qml" in low:
                        compiled = {
                            "apk": apk.name, "entry": info.filename, "size": info.file_size,
                            "representation": "compiled-qml-or-js-cache",
                        }
                        compiled_qml.append(compiled)
                        add({
                            "id": _stable("qml-compiled", apk.name, info.filename),
                            "kind": "QML_COMPILED_ARTIFACT",
                            "title": Path(info.filename).name,
                            "category": "Runtime/Qt QML",
                            "status": "FOUND_STATIC",
                            "engineId": ENGINE_ID,
                            **compiled,
                            "patchReady": False, "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                            "evidenceRole": "qml-compiled-inventory",
                        })
                        continue

                    if not low.endswith(".qml") or info.file_size > MAX_TEXT_BYTES:
                        continue
                    try:
                        with zf.open(info, "r") as source:
                            text = source.read(MAX_TEXT_BYTES + 1).decode("utf-8", "replace")
                    except Exception:
                        continue
                    parsed = _parse_qml(text)
                    source_row = {
                        "apk": apk.name, "entry": info.filename, "size": info.file_size,
                        **parsed,
                    }
                    qml_sources.append(source_row)
                    add({
                        "id": _stable("qml-source", apk.name, info.filename),
                        "kind": "QML_SOURCE_STRUCTURE",
                        "title": f"QML: {Path(info.filename).name}",
                        "category": "Runtime/Qt QML",
                        "status": "SCRIPT_CONTENT_SEARCH",
                        "engineId": ENGINE_ID,
                        **source_row,
                        "patchReady": False, "automationExcluded": True,
                        "runtimeConfirmed": False,
                        "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                        "evidenceRole": "qml-source-structure",
                    })

                    semantic_rows: list[tuple[str, str, dict[str, Any]]] = []
                    for prop in parsed["properties"]:
                        semantic_rows.append(("property", str(prop["name"]), prop))
                    for fn in parsed["functions"]:
                        semantic_rows.append(("function", str(fn["name"]), fn))
                    for sig in parsed["signals"]:
                        semantic_rows.append(("signal", str(sig["name"]), sig))
                    for ident in parsed["ids"]:
                        semantic_rows.append(("id", str(ident), {"id": ident}))
                    for kind, name, evidence in semantic_rows:
                        domains = _domains(name)
                        if not domains:
                            continue
                        add({
                            "id": _stable("qml-semantic", apk.name, info.filename, kind, name),
                            "kind": "QML_SEMANTIC_MEMBER",
                            "title": name,
                            "category": "Gameplay/Qt QML",
                            "status": "SCRIPT_CONTENT_SEARCH",
                            "engineId": ENGINE_ID,
                            "apk": apk.name, "entry": info.filename,
                            "memberKind": kind, "member": evidence,
                            "semanticDomains": domains,
                            "patchReady": False, "automationExcluded": True,
                            "runtimeConfirmed": False,
                            "ownershipKind": "APP_OR_GAME", "trustBoundary": "local",
                            "evidenceRole": "qml-source-semantic",
                        })
        except QmlScanCancelled:
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
        "qmlSourceCount": len(qml_sources),
        "compiledQmlCount": len(compiled_qml),
        "rccCount": len(rcc),
        "nativeQtLibraryCount": len(native_qt),
        "qmlSources": qml_sources,
        "compiledQml": compiled_qml,
        "rcc": rcc,
        "nativeQtLibraries": native_qt,
        "findingCount": len(findings),
        "findings": findings,
        "policy": {
            "claimsSourceFromQmlc": False,
            "qmlBytecodeFullyDecoded": False,
            "rccPayloadFullyDecoded": False,
        },
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None,
                   cb: Any | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), output_path, cb)
