"""AutoMod Menu preparation with exact CodeGenModule count disambiguation.

The legacy engine's ``Elf.modules`` intentionally returns nothing when more than one
structurally plausible CodeGenModule record references an image name. For the AutoMod
prepare path we have stronger metadata: each managed image has a contiguous MethodDef
RID domain 1..N. This adapter temporarily narrows module resolution to candidates with
that exact N and then invokes the unchanged Deep Resolver -> Menu -> ELF preflight
pipeline. All existing ABI, semantic, instance-resolver and APK ELF gates remain in
force; this adapter only removes a false module ambiguity.

The patch of ``engine.Elf.modules`` exists only inside one locked call and is restored
in ``finally``. No target bytes are modified here. Adapter decisions are persisted as
provenance so a prepared menu can be audited without treating recovery as build proof.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from modkit.mobile import engine
from modkit.mobile.il2cpp_no_rva_native import _metadata_token_domains, _resolve_modules_expected

SCHEMA = "modkit-menu-native-recovery-adapter-1.0"
_LOCK = threading.RLock()


def _expected_counts(metadata_path: str | Path, cb=None) -> tuple[dict[str, int], dict[str, int]]:
    meta = engine.Metadata(metadata_path)
    try:
        return _metadata_token_domains(meta, cb)
    finally:
        meta.close()


def _fingerprint(role: str, path: str | Path, cb=None) -> dict[str, Any]:
    file = Path(path)
    engine.check(cb)
    if not file.is_file():
        raise FileNotFoundError(str(file))
    size = file.stat().st_size
    sha256 = engine.digest(file, cb)
    engine.check(cb)
    return {"role": role, "name": file.name, "size": size, "sha256": sha256}


def _write_audit(path: str | Path | None, audit: dict[str, Any]) -> None:
    if path is None:
        return
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name(destination.name + ".tmp")
    temp.write_text(json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(destination)


def _strict_modules_factory(original, expected_counts: dict[str, int], audit: dict[str, Any]):
    def strict_modules(self, image_names):
        wanted = {str(name) for name in image_names if str(name)}
        expected = {name: int(expected_counts[name]) for name in wanted if int(expected_counts.get(name, 0)) > 0}
        resolved: dict[str, tuple[int, int]] = {}
        stats: dict[str, Any] = {"requested": 0, "resolved": 0, "ambiguous": 0, "noString": 0, "noCandidate": 0, "modules": {}}
        if expected:
            resolved, stats = _resolve_modules_expected(self, expected, getattr(self, "cb", None))
        # Only images for which metadata could not prove a contiguous token domain
        # fall back to the original conservative resolver. We never let an original
        # ambiguous result override exact-count evidence.
        fallback_names = wanted - set(expected)
        fallback: dict[str, tuple[int, int]] = {}
        if fallback_names:
            fallback = original(self, fallback_names)
            for name, table in fallback.items():
                resolved.setdefault(name, table)
        call = {
            "requestedImages": sorted(wanted),
            "exactCountImages": sorted(expected),
            "exactCountResolved": int(stats.get("resolved") or 0),
            "exactCountAmbiguous": int(stats.get("ambiguous") or 0),
            "exactCountNoCandidate": int(stats.get("noCandidate") or 0),
            "fallbackImages": sorted(fallback_names),
            "fallbackResolvedImages": sorted(fallback),
            "returnedModules": sorted(resolved),
            "moduleResolution": stats.get("modules") if isinstance(stats.get("modules"), dict) else {},
        }
        audit["calls"] = int(audit.get("calls") or 0) + 1
        history = audit.setdefault("history", [])
        if isinstance(history, list):
            history.append(call)
        audit["last"] = call
        return resolved
    return strict_modules


def prepare(metadata_path: str | Path, library_path: str | Path, catalog_path: str | Path,
            deep_dir: str | Path, source_apk: str | Path, menu_json_path: str | Path,
            project_dir: str | Path, output_report: str | Path | None = None,
            output_preflight: str | Path | None = None, dump_dir: str | Path | None = None,
            title: str = "ModKit Autopilot Menu", max_deep: int = 24,
            target_controls: int = 12, cb=None, audit_path: str | Path | None = None):
    """Run the normal autopilot with stronger, fail-closed module disambiguation."""
    input_fingerprints = [
        _fingerprint("metadata", metadata_path, cb),
        _fingerprint("library", library_path, cb),
        _fingerprint("catalog", catalog_path, cb),
        _fingerprint("sourceApk", source_apk, cb),
    ]
    expected, non_contiguous = _expected_counts(metadata_path, cb)
    audit: dict[str, Any] = {
        "schema": SCHEMA,
        "mode": "EXACT_METADATA_TOKEN_DOMAIN_CODEGENMODULE_ADAPTER",
        "freshnessPolicy": "EXACT_INPUT_SHA256",
        "inputFingerprints": input_fingerprints,
        "outputFingerprints": [],
        "contiguousTokenDomains": len(expected),
        "nonContiguousTokenDomains": len(non_contiguous),
        "calls": 0,
        "history": [],
        "completed": False,
        "normalBindingRequired": True,
        "preflightRequired": True,
        "modifiesTarget": False,
        "addressRecoveryPromotesBuildability": False,
        "promotesBuildability": False,
        "inputs": {
            "metadata": Path(metadata_path).name,
            "library": Path(library_path).name,
            "catalog": Path(catalog_path).name,
            "sourceApk": Path(source_apk).name,
        },
    }
    original = engine.Elf.modules
    strict = _strict_modules_factory(original, expected, audit)
    with _LOCK:
        engine.Elf.modules = strict
        try:
            result = engine.menu_autopilot_prepare(
                str(metadata_path), str(library_path), str(catalog_path), str(deep_dir),
                str(source_apk), str(menu_json_path), str(project_dir),
                str(output_report) if output_report else None,
                str(output_preflight) if output_preflight else None,
                str(dump_dir) if dump_dir else None,
                str(title), int(max_deep), int(target_controls), cb,
            )
            audit["outputFingerprints"] = [_fingerprint("menuSpec", menu_json_path, cb)]
            audit["completed"] = True
            return result
        except Exception as exc:
            audit["errorType"] = type(exc).__name__
            audit["error"] = str(exc)
            raise
        finally:
            engine.Elf.modules = original
            _write_audit(audit_path, audit)


def prepare_workspace(workspace: str | Path, source_apk: str | Path, cb=None):
    root = Path(workspace)
    deep = root / "analysis-deep"
    deep.mkdir(parents=True, exist_ok=True)
    dump = root / "rodroid"
    return prepare(
        root / "metadata.bin",
        root / "library.so",
        root / "analysis.methods.jsonl",
        deep,
        source_apk,
        root / "menu-spec.json",
        root / "menu-project",
        root / "menu-autopilot.json",
        root / "menu-preflight.json",
        dump if dump.is_dir() else None,
        "ModKit Autopilot Menu",
        24,
        12,
        cb=cb,
        audit_path=root / "menu-native-recovery.json",
    )
