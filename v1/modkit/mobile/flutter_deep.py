"""Embedded Flutter/Dart AOT recovery.

This backend does not claim to reconstruct original Dart source. It correlates Flutter
snapshot/assets with the app-owned libapp.so ELF analysis produced by native_deep and
recovers package/route/class-like strings plus exact native function RVAs when symbols
survive AOT linking. Everything runs locally inside ModKit.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-flutter-deep-1.0"
ENGINE_ID = "flutter.aot-embedded"
MAX_ENTRY_BYTES = 96 * 1024 * 1024
MAX_FINDINGS = 1200
PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")


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
    installed = root / "installed-apks"
    if installed.is_dir():
        for path in sorted(installed.glob("*.apk")):
            if path not in paths:
                paths.append(path)
    game = root / "game.apk"
    if game.is_file() and game not in paths:
        paths.append(game)
    return paths


def _interesting(text: str) -> bool:
    low = text.casefold()
    if low.startswith(("package:", "dart:")):
        return True
    if any(token in low for token in (
        "widget", "stateful", "stateless", "navigator", "route", "provider", "bloc", "riverpod",
        "health", "damage", "currency", "diamond", "gold", "coin", "inventory", "cooldown",
        "premium", "subscription", "entitlement", "session", "token", "endpoint",
    )):
        return True
    return bool(re.match(r"^/[a-zA-Z0-9_./{}:-]{2,120}$", text))


def _scan_strings(data: bytes, limit: int = 300) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in PRINTABLE.finditer(data):
        text = match.group().decode("utf-8", "replace").strip()
        if not text or text in seen or not _interesting(text):
            continue
        seen.add(text)
        out.append(text[:320])
        if len(out) >= limit:
            break
    return out


def _load_native(native_report: str | Path | dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(native_report, dict):
        return native_report
    if native_report:
        path = Path(native_report)
        if path.is_file():
            try:
                obj = json.loads(path.read_text(encoding="utf-8"))
                return obj if isinstance(obj, dict) else {}
            except Exception:
                return {}
    return {}


def scan_apk_paths(paths: Iterable[str | Path], native_report: str | Path | dict[str, Any] | None = None,
                   output_path: str | Path | None = None) -> dict[str, Any]:
    native = _load_native(native_report)
    findings: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    apk_count = 0
    flutter_detected = False

    # Reuse exact app-owned function/call/xref work from the embedded native backend.
    for library in native.get("libraries", []) if isinstance(native, dict) else []:
        if not isinstance(library, dict) or not str(library.get("entry") or "").casefold().endswith("libapp.so"):
            continue
        flutter_detected = True
        artifacts.append({
            "kind": "DART_AOT_ELF",
            "apk": library.get("apk"),
            "entry": library.get("entry"),
            "abi": library.get("abi"),
            "functionSymbolCount": library.get("functionSymbolCount", 0),
            "directCallCount": library.get("directCallCount", 0),
            "addressXrefCount": library.get("addressXrefCount", 0),
            "recoveryLevel": "NATIVE_AOT",
        })
        for row in library.get("findings", []) or []:
            if not isinstance(row, dict):
                continue
            copied = dict(row)
            copied["id"] = "flutter:" + str(row.get("id") or hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()[:20])
            copied["family"] = "flutter"
            copied["engineId"] = ENGINE_ID
            copied["recoveryLevel"] = "NATIVE_AOT"
            copied["evidenceRole"] = "embedded-flutter-aot-native"
            findings.append(copied)
            if len(findings) >= MAX_FINDINGS:
                break

    for raw in paths:
        apk = Path(raw)
        if not apk.is_file():
            continue
        apk_count += 1
        try:
            with zipfile.ZipFile(apk) as zf:
                for info in zf.infolist():
                    if len(findings) >= MAX_FINDINGS:
                        break
                    low = info.filename.casefold()
                    flutter_entry = (
                        "flutter_assets/" in low
                        or low.endswith(("vm_snapshot_data", "isolate_snapshot_data", "kernel_blob.bin"))
                        or low.endswith("libapp.so")
                        or low.endswith("libflutter.so")
                    )
                    if not flutter_entry:
                        continue
                    flutter_detected = True
                    representation = "asset"
                    recovery = "RECONSTRUCTED_METADATA"
                    if low.endswith("libapp.so"):
                        representation = "dart-aot-elf"; recovery = "NATIVE_AOT"
                    elif low.endswith("libflutter.so"):
                        representation = "flutter-engine"; recovery = "NATIVE_ENGINE"
                    elif low.endswith(("vm_snapshot_data", "isolate_snapshot_data", "kernel_blob.bin")):
                        representation = "dart-snapshot"; recovery = "RECONSTRUCTED_METADATA"
                    artifacts.append({"kind": "FLUTTER_ARTIFACT", "apk": apk.name, "entry": info.filename,
                                      "size": info.file_size, "representation": representation,
                                      "recoveryLevel": recovery})
                    if info.file_size <= 0 or info.file_size > MAX_ENTRY_BYTES or low.endswith(("libapp.so", "libflutter.so")):
                        continue
                    try:
                        data = zf.read(info)
                    except Exception:
                        continue
                    for text in _scan_strings(data):
                        fid = hashlib.sha256(f"{apk.name}!{info.filename}!{text}".encode("utf-8", "replace")).hexdigest()[:20]
                        findings.append({
                            "id": "flutter-meta:" + fid,
                            "kind": "FLUTTER_AOT_METADATA",
                            "title": text[:180],
                            "category": "Flutter/Dart AOT",
                            "status": "FOUND_STATIC",
                            "family": "flutter",
                            "engineId": ENGINE_ID,
                            "apk": apk.name,
                            "entry": info.filename,
                            "representation": representation,
                            "recoveryLevel": recovery,
                            "ownershipKind": "APP_OR_GAME",
                            "trustBoundary": "local",
                            "patchReady": False,
                            "evidenceRole": "embedded-flutter-metadata",
                        })
                        if len(findings) >= MAX_FINDINGS:
                            break
        except Exception as exc:
            errors.append({"apk": apk.name, "error": str(exc)})

    out = {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "bundled": True,
        "manualImportRequired": False,
        "passive": True,
        "executesTargetCode": False,
        "originalDartSourceClaimed": False,
        "apkCount": apk_count,
        "detected": flutter_detected,
        "artifactCount": len(artifacts),
        "findingCount": len(findings),
        "artifacts": artifacts,
        "findings": findings,
        "errors": errors[:100],
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, native_report: str | Path | dict[str, Any] | None = None,
                   output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), native_report, output_path)
