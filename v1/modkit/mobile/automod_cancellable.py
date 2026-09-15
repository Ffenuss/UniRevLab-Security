"""Cancellation-aware, finding-scoped release entry point for AutoMod planning.

Classification and fail-closed readiness semantics remain owned by :mod:`automod`.
This adapter only changes orchestration: expensive per-method evidence files are
streamed and retained only when they can correlate with current catalogue cards, and
all generated summaries/plan outputs are published atomically after cancellation
checks. Secondary IL2CPP evidence is reused only when exact input SHA-256 fingerprints
match; filesystem timestamps are never treated as proof of freshness here.
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

from modkit.mobile import automod as _base
from modkit.mobile import il2cpp_crosscheck_cancellable
from modkit.mobile import il2cpp_metadata_identity_cancellable
from modkit.mobile import simple_mode_cancellable

SCHEMA = _base.SCHEMA
_LOCK = threading.RLock()


class AutoModCancelled(RuntimeError):
    pass


def _cancelled(cb: Any | None) -> bool:
    if cb is None:
        return False
    checker = getattr(cb, "isCancelled", None)
    if callable(checker):
        return bool(checker())
    if callable(cb):
        return bool(cb())
    return False


class _Gate:
    def __init__(self, cb: Any | None, interval: int = 128):
        self.cb = cb
        self.interval = max(1, int(interval))
        self.count = 0

    def force(self) -> None:
        if _cancelled(self.cb):
            raise AutoModCancelled("AutoMod planning cancelled")

    def tick(self) -> None:
        self.count += 1
        if self.count % self.interval == 0:
            self.force()


class _FingerprintCache:
    def __init__(self):
        self._rows: dict[str, dict[str, Any]] = {}

    def file(self, path: Path, gate: _Gate) -> dict[str, Any]:
        key = str(path.resolve())
        cached = self._rows.get(key)
        if cached is not None:
            return dict(cached)
        gate.force()
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                gate.force()
                digest.update(chunk)
                size += len(chunk)
        gate.force()
        row = {"name": path.name, "size": size, "sha256": digest.hexdigest()}
        self._rows[key] = row
        return dict(row)

    def inputs(self, paths: list[Path], gate: _Gate) -> list[dict[str, Any]]:
        return [self.file(path, gate) for path in paths]


def _same_inputs(summary: dict[str, Any], fingerprints: list[dict[str, Any]]) -> bool:
    recorded = summary.get("inputFingerprints")
    return isinstance(recorded, list) and recorded == fingerprints


def _wanted(catalog: dict[str, Any], gate: _Gate):
    ids: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    names: set[str] = set()
    rvas: set[int] = set()
    cards = catalog.get("cards") if isinstance(catalog.get("cards"), list) else []
    for card in cards:
        gate.tick()
        if not isinstance(card, dict):
            continue
        locator = card.get("locator") if isinstance(card.get("locator"), dict) else {}
        method_id = _base._card_method_id(card)
        if method_id:
            ids.add(method_id)
        method = _base._norm_name(locator.get("method") or locator.get("methodName"))
        cls = _base._norm_class(locator.get("class") or locator.get("className"))
        if method:
            names.add(method)
        if method and cls:
            pairs.add((cls, method))
            short = cls.rsplit(".", 1)[-1]
            if short != cls:
                pairs.add((short, method))
        rva = _base._number(locator.get("rva"))
        if rva is not None and rva >= 0:
            rvas.add(rva)
    gate.force()
    return ids, pairs, names, rvas


def _filtered_jsonl(path: Path, kind: str, wanted, gate: _Gate) -> list[dict[str, Any]]:
    ids, pairs, names, rvas = wanted
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line in source:
            gate.tick()
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            keep = False
            if kind == "crosscheck":
                rva = _base._number(row.get("rva"))
                if rva is None:
                    rva = _base._number(row.get("rvaHex"))
                keep = rva is not None and rva in rvas
            elif kind == "identity":
                rid = row.get("id")
                method = _base._norm_name(row.get("methodName"))
                cls = _base._norm_class(row.get("class"))
                exact_id = rid not in (None, "") and str(rid) in ids
                exact_pair = bool(method and cls and ((cls, method) in pairs or (cls.rsplit(".", 1)[-1], method) in pairs))
                name_match = bool(method and method in names)
                keep = exact_id or exact_pair or name_match
            elif kind == "native":
                rid = row.get("metadataMethodId") if row.get("metadataMethodId") not in (None, "") else row.get("id")
                method = _base._norm_name(row.get("methodName"))
                cls = _base._norm_class(row.get("class"))
                keep = bool(
                    (rid not in (None, "") and str(rid) in ids)
                    or (method and cls and (cls, method) in pairs)
                )
            if keep:
                rows.append(row)
    gate.force()
    return rows


def _write_summary(path: Path, value: dict[str, Any], gate: _Gate) -> dict[str, Any]:
    part = path.with_name(path.name + ".part")
    part.unlink(missing_ok=True)
    try:
        part.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        gate.force()
        part.replace(path)
        return value
    except Exception:
        part.unlink(missing_ok=True)
        raise


def _ensure_crosscheck(root: Path, gate: _Gate, fingerprints: _FingerprintCache) -> dict[str, Any]:
    metadata, library, methods = root / "metadata.bin", root / "library.so", root / "analysis.methods.jsonl"
    output, rows = root / "il2cpp-crosscheck.json", root / "il2cpp-crosscheck.methods.jsonl"
    inputs = [metadata, library, methods]
    if not all(path.is_file() for path in inputs):
        return {}
    exact_inputs = fingerprints.inputs(inputs, gate)
    existing = _base._load(output)
    if existing.get("schema") == _base._IL2CPP_CROSSCHECK_SCHEMA and not existing.get("error") and rows.is_file() and _same_inputs(existing, exact_inputs):
        return existing
    if existing.get("error") and _same_inputs(existing, exact_inputs):
        return existing
    gate.force()
    try:
        result = il2cpp_crosscheck_cancellable.run_crosscheck(metadata, library, methods, output, rows, gate.cb)
        result["inputFingerprints"] = exact_inputs
        result["freshnessPolicy"] = "EXACT_INPUT_SHA256"
        return _write_summary(output, result, gate)
    except (AutoModCancelled, il2cpp_crosscheck_cancellable.CrosscheckCancelled):
        raise AutoModCancelled("AutoMod IL2CPP cross-check cancelled")
    except Exception as exc:
        error = {
            "schema": "modkit-il2cpp-crosscheck-error-1.0",
            "engine": "il2cpp.structural-crosscheck-embedded",
            "error": str(exc),
            "promotesBuildability": False,
            "confirmsMethodToRvaAssociation": False,
            "inputFingerprints": exact_inputs,
            "freshnessPolicy": "EXACT_INPUT_SHA256",
        }
        return _write_summary(output, error, gate)


def _ensure_identity(root: Path, gate: _Gate, fingerprints: _FingerprintCache) -> dict[str, Any]:
    metadata, methods = root / "metadata.bin", root / "analysis.methods.jsonl"
    output, rows = root / "il2cpp-metadata-identity.json", root / "il2cpp-metadata-identity.methods.jsonl"
    inputs = [metadata, methods]
    if not all(path.is_file() for path in inputs):
        return {}
    exact_inputs = fingerprints.inputs(inputs, gate)
    existing = _base._load(output)
    if existing.get("schema") == _base._METADATA_IDENTITY_SCHEMA and not existing.get("error") and rows.is_file() and _same_inputs(existing, exact_inputs):
        return existing
    if existing.get("error") and _same_inputs(existing, exact_inputs):
        return existing
    gate.force()
    try:
        result = il2cpp_metadata_identity_cancellable.build_workspace_identity(root, output, gate.cb)
        result["inputFingerprints"] = exact_inputs
        result["freshnessPolicy"] = "EXACT_INPUT_SHA256"
        return _write_summary(output, result, gate)
    except (AutoModCancelled, il2cpp_metadata_identity_cancellable.MetadataIdentityCancelled):
        raise AutoModCancelled("AutoMod metadata identity cancelled")
    except Exception as exc:
        error = {
            "schema": "modkit-il2cpp-metadata-identity-error-1.1",
            "engine": "il2cpp.metadata-identity-embedded",
            "error": str(exc),
            "addressResolver": False,
            "actionable": False,
            "promotesBuildability": False,
            "inputFingerprints": exact_inputs,
            "freshnessPolicy": "EXACT_INPUT_SHA256",
        }
        return _write_summary(output, error, gate)


def _ensure_native(root: Path, gate: _Gate, fingerprints: _FingerprintCache) -> dict[str, Any]:
    metadata, library, methods = root / "metadata.bin", root / "library.so", root / "analysis.methods.jsonl"
    output, rows = root / "il2cpp-no-rva-native.json", root / "il2cpp-no-rva-native.methods.jsonl"
    inputs = [metadata, library, methods]
    if not all(path.is_file() for path in inputs):
        return {}
    exact_inputs = fingerprints.inputs(inputs, gate)
    existing = _base._load(output)
    if existing.get("schema") == _base._NATIVE_RECOVERY_SCHEMA and not existing.get("error") and rows.is_file() and _same_inputs(existing, exact_inputs):
        return existing
    if existing.get("error") and _same_inputs(existing, exact_inputs):
        return existing
    gate.force()
    try:
        from modkit.mobile.il2cpp_no_rva_native import recover_workspace
        result = recover_workspace(root, output, gate.cb)
        result["inputFingerprints"] = exact_inputs
        result["freshnessPolicy"] = "EXACT_INPUT_SHA256"
        return _write_summary(output, result, gate)
    except Exception as exc:
        if _cancelled(gate.cb):
            raise AutoModCancelled("AutoMod native recovery cancelled") from exc
        error = {
            "schema": "modkit-il2cpp-no-rva-native-error-1.0",
            "engine": "il2cpp.codegenmodule-native-recovery",
            "error": str(exc),
            "addressResolver": True,
            "actionable": False,
            "buildable": False,
            "promotesBuildability": False,
            "inputFingerprints": exact_inputs,
            "freshnessPolicy": "EXACT_INPUT_SHA256",
        }
        return _write_summary(output, error, gate)


def build_workspace_plan(workdir: str | Path, output_path: str | Path | None = None,
                         cb: Any | None = None) -> dict[str, Any]:
    gate = _Gate(cb)
    gate.force()
    root = Path(workdir)
    catalog_path = root / "simple-catalog.json"
    catalog = _base._load(catalog_path)
    if not catalog:
        catalog = simple_mode_cancellable.build_catalog(root, catalog_path, cb)
    gate.force()
    runtime_correlation = _base._load(root / "runtime-correlation.json")
    fingerprints = _FingerprintCache()
    il2cpp_summary = _ensure_crosscheck(root, gate, fingerprints)
    identity_summary = _ensure_identity(root, gate, fingerprints)
    native_summary = _ensure_native(root, gate, fingerprints)
    wanted = _wanted(catalog, gate)
    il2cpp_rows = _filtered_jsonl(root / "il2cpp-crosscheck.methods.jsonl", "crosscheck", wanted, gate) if il2cpp_summary and not il2cpp_summary.get("error") else []
    identity_rows = _filtered_jsonl(root / "il2cpp-metadata-identity.methods.jsonl", "identity", wanted, gate) if identity_summary and not identity_summary.get("error") else []
    native_rows = _filtered_jsonl(root / "il2cpp-no-rva-native.methods.jsonl", "native", wanted, gate) if native_summary and not native_summary.get("error") else []

    with _LOCK:
        original_candidate = _base._candidate

        def wrapped_candidate(*args, **kwargs):
            gate.tick()
            return original_candidate(*args, **kwargs)

        _base._candidate = wrapped_candidate
        try:
            out = _base.build_plan(
                catalog,
                runtime_correlation if runtime_correlation else None,
                il2cpp_rows,
                identity_rows,
                native_rows,
            )
        finally:
            _base._candidate = original_candidate

    gate.force()
    if il2cpp_summary:
        out["il2cppCrosscheck"] = {
            "schema": il2cpp_summary.get("schema"), "engine": il2cpp_summary.get("engine"),
            "error": il2cpp_summary.get("error"), "counts": il2cpp_summary.get("counts"),
            "confirmsMethodToRvaAssociation": bool(il2cpp_summary.get("confirmsMethodToRvaAssociation")),
            "promotesBuildability": False,
            "freshnessPolicy": il2cpp_summary.get("freshnessPolicy"),
        }
    if identity_summary:
        out["il2cppMetadataIdentity"] = {
            "schema": identity_summary.get("schema"), "engine": identity_summary.get("engine"),
            "error": identity_summary.get("error"), "typeLayout": identity_summary.get("typeLayout"),
            "uniqueMethodTokenCount": int(identity_summary.get("uniqueMethodTokenCount") or 0),
            "counts": identity_summary.get("counts"), "addressResolver": False,
            "actionable": False, "promotesBuildability": False,
            "freshnessPolicy": identity_summary.get("freshnessPolicy"),
        }
    if native_summary:
        out["il2cppNativeRecovery"] = {
            "schema": native_summary.get("schema"), "engine": native_summary.get("engine"),
            "error": native_summary.get("error"), "resolvedModuleCount": int(native_summary.get("resolvedModuleCount") or 0),
            "counts": native_summary.get("counts"), "addressResolver": bool(native_summary.get("addressResolver")),
            "requiresUniqueExecutablePointer": bool(native_summary.get("requiresUniqueExecutablePointer")),
            "actionable": False, "buildable": False, "promotesBuildability": False,
            "mayEnterPreflight": True, "freshnessPolicy": native_summary.get("freshnessPolicy"),
        }
    out["memoryPolicy"] = {
        "perMethodEvidence": "STREAMED_FINDING_SCOPED_JSONL",
        "loadsFullMethodEvidenceIntoRam": False,
        "retainedCrosscheckRows": len(il2cpp_rows),
        "retainedIdentityRows": len(identity_rows),
        "retainedNativeRecoveryRows": len(native_rows),
        "schemaSemantics": "UNCHANGED_AUTOMOD_1_4",
        "cancelAware": cb is not None,
    }
    out["freshnessPolicy"] = {
        "secondaryIl2cppEvidence": "EXACT_INPUT_SHA256",
        "mtimeTrustedAsIdentity": False,
        "fingerprintsReusedWithinRun": True,
    }

    destination = Path(output_path) if output_path else root / "automod-plan.json"
    part = destination.with_name(destination.name + ".part")
    part.unlink(missing_ok=True)
    try:
        part.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        gate.force()
        part.replace(destination)
    except Exception:
        part.unlink(missing_ok=True)
        raise
    return out
