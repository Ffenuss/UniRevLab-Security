"""Embedded Hermes HBC deep analysis for ModKit 1.1.

The Android package bundles the MIT HBC-Tool build 96 through Chaquopy. This module extracts
Hermes bytecode from the selected APK/split set and disassembles supported HBC versions entirely
inside ModKit. Target code is never executed and no network access is required on the device.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
from typing import Any, Iterable
import zipfile

SCHEMA = "modkit-hermes-deep-1.1"
ENGINE_ID = "hermes.deep-embedded"
BACKEND = "HBC-Tool/Kirlif build 96"
HERMES_MAGIC = 2240826417119764422
SUPPORTED_VERSIONS = {59, 62, 74, 76, *range(83, 97)}
MAX_ENTRY_BYTES = 96 * 1024 * 1024
MAX_FUNCTIONS = 20000
MAX_STRINGS = 5000


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


def _slug(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return clean[:80] or "bundle"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _header(data: bytes) -> tuple[int | None, int | None]:
    if len(data) < 12:
        return None, None
    try:
        magic, version = struct.unpack_from("<QI", data, 0)
        return magic, version
    except Exception:
        return None, None


def _is_candidate(name: str) -> bool:
    low = name.lower()
    return low.endswith((".hbc", ".hermes", ".bundle")) or low.endswith("index.android.bundle") or "hermes" in low


def scan_apk_paths(paths: Iterable[str | Path], workdir: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    engine_root = root / "hermes-deep"
    input_root = engine_root / "inputs"
    output_root = engine_root / "disassembly"
    input_root.mkdir(parents=True, exist_ok=True)
    output_root.mkdir(parents=True, exist_ok=True)

    bundles: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    try:
        from hbctool import hbc, hasm  # type: ignore
    except Exception as exc:
        out = {
            "schema": SCHEMA,
            "engineId": ENGINE_ID,
            "backend": BACKEND,
            "bundled": True,
            "available": False,
            "executesTargetCode": False,
            "bundleCount": 0,
            "findingCount": 0,
            "bundles": [],
            "findings": [],
            "errors": [{"error": f"bundled HBC parser failed to load: {exc}"}],
        }
        if output_path:
            Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        return out

    for raw in paths:
        apk = Path(raw)
        if not apk.is_file():
            continue
        try:
            with zipfile.ZipFile(apk) as z:
                for info in z.infolist():
                    if info.is_dir() or info.file_size <= 0 or info.file_size > MAX_ENTRY_BYTES or not _is_candidate(info.filename):
                        continue
                    try:
                        data = z.read(info)
                    except Exception as exc:
                        errors.append({"apk": apk.name, "entry": info.filename, "error": str(exc)})
                        continue
                    magic, version = _header(data)
                    if magic != HERMES_MAGIC:
                        continue
                    digest = _sha(data)
                    bundle_id = digest[:20]
                    record: dict[str, Any] = {
                        "id": f"hermes:{bundle_id}",
                        "apk": apk.name,
                        "entry": info.filename,
                        "size": len(data),
                        "sha256": digest,
                        "hbcVersion": version,
                        "supported": version in SUPPORTED_VERSIONS,
                        "backend": BACKEND,
                        "status": "HBC_FOUND",
                        "executesTargetCode": False,
                    }
                    if version not in SUPPORTED_VERSIONS:
                        record["status"] = "UNSUPPORTED_HBC_VERSION"
                        bundles.append(record)
                        continue

                    input_path = input_root / f"{_slug(apk.stem)}-{bundle_id}.hbc"
                    disasm_dir = output_root / f"{_slug(apk.stem)}-{bundle_id}"
                    try:
                        input_path.write_bytes(data)
                        if disasm_dir.exists():
                            shutil.rmtree(disasm_dir, ignore_errors=True)
                        with input_path.open("rb") as handle:
                            obj = hbc.load(handle)
                        hasm.dump(obj, str(disasm_dir), force=True)
                        header = obj.getHeader()
                        function_count = int(obj.getFunctionCount())
                        string_count = int(obj.getStringCount())
                        record.update({
                            "status": "DEEP_DISASSEMBLED",
                            "sourceHash": bytes(header.get("sourceHash", [])).hex() if isinstance(header, dict) else "",
                            "functionCount": function_count,
                            "stringCount": string_count,
                            "disassemblyDir": str(disasm_dir.relative_to(root)),
                            "metadataFile": str((disasm_dir / "metadata.json").relative_to(root)),
                            "stringsFile": str((disasm_dir / "string.json").relative_to(root)),
                            "instructionsFile": str((disasm_dir / "instruction.hasm").relative_to(root)),
                        })

                        for index in range(min(function_count, MAX_FUNCTIONS)):
                            try:
                                fn = obj.getFunction(index)
                                name = str(fn[0] or f"Function_{index}")
                                params = int(fn[1])
                                registers = int(fn[2])
                                symbols = int(fn[3])
                                instructions = len(fn[4]) if isinstance(fn[4], (list, tuple)) else 0
                            except Exception as exc:
                                errors.append({"apk": apk.name, "entry": info.filename, "error": f"function {index}: {exc}"})
                                continue
                            findings.append({
                                "id": f"hermes-fn:{bundle_id}:{index}",
                                "kind": "HERMES_FUNCTION",
                                "title": name,
                                "category": "Runtime/Hermes",
                                "status": "DEEP_DISASSEMBLED",
                                "engineId": ENGINE_ID,
                                "family": "hermes",
                                "representation": "hbc-disassembly",
                                "recoveryLevel": "DEEP_DISASSEMBLY",
                                "apk": apk.name,
                                "entry": info.filename,
                                "function": name,
                                "functionIndex": index,
                                "parameterCount": params,
                                "registerCount": registers,
                                "symbolCount": symbols,
                                "instructionCount": instructions,
                                "hbcVersion": version,
                                "ownershipKind": "APP_OR_GAME",
                                "trustBoundary": "local",
                                "serverAudit": False,
                                "patchReady": False,
                                "evidenceRole": "hermes-bytecode-function",
                            })

                        string_preview: list[dict[str, Any]] = []
                        for index in range(min(string_count, MAX_STRINGS)):
                            try:
                                value, string_header = obj.getString(index)
                                string_preview.append({
                                    "id": index,
                                    "value": str(value)[:1000],
                                    "isUTF16": bool(string_header[0] == 1) if string_header else False,
                                })
                            except Exception:
                                break
                        record["stringsPreview"] = string_preview
                    except Exception as exc:
                        record["status"] = "DEEP_DISASSEMBLY_FAILED"
                        record["error"] = str(exc)
                        errors.append({"apk": apk.name, "entry": info.filename, "error": str(exc)})
                    bundles.append(record)
        except Exception as exc:
            errors.append({"apk": apk.name, "entry": "", "error": str(exc)})

    out = {
        "schema": SCHEMA,
        "engineId": ENGINE_ID,
        "backend": BACKEND,
        "bundled": True,
        "available": True,
        "executesTargetCode": False,
        "supportedVersions": sorted(SUPPORTED_VERSIONS),
        "bundleCount": len(bundles),
        "findingCount": len(findings),
        "bundles": bundles,
        "findings": findings,
        "errors": errors,
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def scan_workspace(workdir: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    return scan_apk_paths(_workspace_apks(root), root, output_path)
