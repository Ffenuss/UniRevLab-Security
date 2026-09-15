"""Memory-bounded, cancellation-aware Connected Report 1.2 entry point.

The report semantics live in :mod:`connected_report_v12`. Large IL2CPP titles can
produce 100k+ per-method evidence rows, so the Android release path keeps those files
streamed and retains only rows which can actually correlate with current findings by
exact method id, exact fully-qualified class+method, permitted weak method-name
fallback, or exact RVA.

Cancellation is cooperative and fail-closed: heavy JSONL/catalogue scans check the
Android callback and final JSON/Markdown outputs are written through sibling ``.part``
files, then promoted only after one shared final cancellation gate. Standalone report
generation also verifies secondary IL2CPP evidence against exact input SHA-256 values
before any report correlation, so it never relies on mtime freshness alone.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Callable, Iterator

from modkit.mobile import connected_report as _base
from modkit.mobile import connected_report_v12 as _v12
from modkit.mobile import secondary_il2cpp_release as _secondary
from modkit.mobile.connected_report import _locator as _base_locator

SCHEMA = _v12.SCHEMA
_LOCK = threading.RLock()


class ReportCancelled(RuntimeError):
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
            raise ReportCancelled("Connected Report cancelled")

    def tick(self) -> None:
        self.count += 1
        if self.count % self.interval == 0:
            self.force()


def _iter_jsonl(path: str | Path, gate: _Gate | None = None) -> Iterator[dict[str, Any]]:
    source_path = Path(path)
    if not source_path.is_file():
        return
    try:
        with source_path.open("r", encoding="utf-8", errors="replace") as source:
            for line in source:
                if gate is not None:
                    gate.tick()
                text = line.strip()
                if not text:
                    continue
                try:
                    value = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    yield value
    except ReportCancelled:
        raise
    except OSError:
        return


def _wanted(workdir: str | Path, gate: _Gate | None = None) -> tuple[set[str], set[tuple[str, str]], set[str], set[str]]:
    root = Path(workdir)
    if gate is not None:
        gate.force()
    try:
        catalog = json.loads((root / "simple-catalog.json").read_text(encoding="utf-8"))
    except Exception:
        catalog = {}
    ids: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    names: set[str] = set()
    rvas: set[str] = set()
    cards = catalog.get("cards") if isinstance(catalog, dict) and isinstance(catalog.get("cards"), list) else []
    for card in cards:
        if gate is not None:
            gate.tick()
        if not isinstance(card, dict):
            continue
        loc = _base_locator(card)
        mid = loc.get("methodId")
        if mid not in (None, ""):
            ids.add(str(mid))
        cls = _v12._norm_class(loc.get("class"))
        method = _v12._norm_name(loc.get("method"))
        if cls and method:
            pairs.add((cls, method))
        if method:
            names.add(method)
        rva = _v12._norm_hex(loc.get("rva"))
        if rva:
            rvas.add(rva)
    if gate is not None:
        gate.force()
    return ids, pairs, names, rvas


def _filtered_reader(workdir: str | Path, gate: _Gate) -> tuple[Callable[[Path], Iterator[dict[str, Any]]], dict[str, int]]:
    ids, pairs, names, rvas = _wanted(workdir, gate)
    retained = {"crosscheck": 0, "identity": 0, "native": 0}

    def reader(path: Path) -> Iterator[dict[str, Any]]:
        filename = Path(path).name
        for row in _iter_jsonl(path, gate):
            keep = False
            if filename == "il2cpp-crosscheck.methods.jsonl":
                rva = _v12._norm_hex(row.get("rvaHex") if row.get("rvaHex") is not None else row.get("rva"))
                keep = bool(rva and rva in rvas)
                bucket = "crosscheck"
            elif filename == "il2cpp-metadata-identity.methods.jsonl":
                rid = row.get("id")
                cls = _v12._norm_class(row.get("class"))
                method = _v12._norm_name(row.get("methodName"))
                exact_id = rid not in (None, "") and str(rid) in ids
                exact_pair = bool(cls and method and (cls, method) in pairs)
                weak_name = bool(
                    method and method in names
                    and not bool(row.get("metadataQualifiedMethodPresent"))
                    and not bool(row.get("metadataTokenConfirmed"))
                    and not bool(row.get("metadataTokenConflict"))
                )
                keep = exact_id or exact_pair or weak_name
                bucket = "identity"
            elif filename == "il2cpp-no-rva-native.methods.jsonl":
                rid = row.get("metadataMethodId") if row.get("metadataMethodId") not in (None, "") else row.get("id")
                cls = _v12._norm_class(row.get("class"))
                method = _v12._norm_name(row.get("methodName"))
                keep = bool(
                    (rid not in (None, "") and str(rid) in ids)
                    or (cls and method and (cls, method) in pairs)
                )
                bucket = "native"
            else:
                keep = True
                bucket = ""
            if keep:
                if bucket:
                    retained[bucket] += 1
                yield row

    return reader, retained


def _method_index(
    path: Path,
    wanted_ids: set[int] | None,
    wanted_rvas: set[str] | None,
    wanted_names: set[str] | None,
    gate: _Gate,
    limit: int = 250000,
):
    by_id: dict[int, dict[str, Any]] = {}
    by_rva: dict[str, list[dict[str, Any]]] = {}
    by_name: dict[str, list[dict[str, Any]]] = {}
    catalog_rows = 0
    ids = wanted_ids or set()
    rvas = wanted_rvas or set()
    names = wanted_names or set()
    gate.force()
    if not path.is_file():
        return by_id, by_rva, by_name, catalog_rows
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for no, line in enumerate(stream):
            gate.tick()
            if no >= limit:
                break
            try:
                row = json.loads(line)
            except Exception:
                continue
            if not isinstance(row, dict):
                continue
            mid = row.get("id")
            if isinstance(mid, int):
                catalog_rows += 1
                if mid in ids:
                    by_id[mid] = row
            rva = _base._norm_hex(_base._first(row, "rva", "RVA", "address", "virtualAddress"))
            if rva and rva in rvas:
                bucket = by_rva.setdefault(rva, [])
                if len(bucket) < 25:
                    bucket.append(row)
            name = str(_base._first(row, "name", "method", "methodName", "label") or "").strip().casefold()
            if name and name in names:
                bucket = by_name.setdefault(name, [])
                if len(bucket) < 25:
                    bucket.append(row)
    gate.force()
    return by_id, by_rva, by_name, catalog_rows


def _stream_native_blockers(path: Path, findings: list[dict[str, Any]], gate: _Gate):
    wanted_ids, wanted_pairs = _v12._relevant_native_keys(findings)
    by_id: dict[str, dict[str, Any]] = {}
    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = {}
    if not path.is_file() or (not wanted_ids and not wanted_pairs):
        return by_id, by_pair
    try:
        with path.open("r", encoding="utf-8", errors="replace") as source:
            for line in source:
                gate.tick()
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(raw, dict):
                    continue
                safe = _v12._safe_native_blocker(raw)
                if safe is None:
                    continue
                mid_value = safe.get("metadataMethodId")
                mid = str(mid_value) if mid_value not in (None, "") else ""
                cls = _v12._norm_class(safe.get("class"))
                method = _v12._norm_name(safe.get("methodName"))
                if mid and mid in wanted_ids:
                    by_id[mid] = safe
                if cls and method and (cls, method) in wanted_pairs:
                    by_pair.setdefault((cls, method), []).append(safe)
    except ReportCancelled:
        raise
    except OSError:
        return {}, {}
    gate.force()
    return by_id, by_pair


def _exact_secondary_summary(secondary: dict[str, Any], key: str) -> dict[str, Any]:
    value = secondary.get(key)
    if not isinstance(value, dict) or not value:
        return {}
    out = dict(value)
    out["freshnessVerified"] = True
    out["sourceInputsAvailable"] = True
    out["freshnessPolicy"] = "EXACT_INPUT_SHA256"
    return out


def _part(path: str | Path | None) -> Path | None:
    if path is None:
        return None
    destination = Path(path)
    return destination.with_name(destination.name + ".part")


def build_connected_report(
    workdir: str | Path,
    output_json: str | Path | None = None,
    output_md: str | Path | None = None,
    cb: Any | None = None,
) -> dict[str, Any]:
    """Build Connected Report 1.2 with exact-fresh streamed evidence and cooperative cancel."""
    gate = _Gate(cb)
    gate.force()
    try:
        secondary = _secondary.ensure_workspace(workdir, cb)
    except Exception as exc:
        if _cancelled(cb):
            raise ReportCancelled("Connected Report cancelled while refreshing IL2CPP evidence") from exc
        raise
    gate.force()
    exact_crosscheck = _exact_secondary_summary(secondary, "crosscheck")
    exact_identity = _exact_secondary_summary(secondary, "metadataIdentity")
    exact_native = _exact_secondary_summary(secondary, "nativeRecovery")
    native_current = bool(exact_native) and not bool(exact_native.get("error"))
    reader, retained = _filtered_reader(workdir, gate)
    json_part = _part(output_json)
    md_part = _part(output_md)
    for temporary in (json_part, md_part):
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    with _LOCK:
        original_jsonl = _v12._jsonl
        original_method_index = _base._method_index
        original_locator = _base._locator
        original_stream_blockers = _v12._stream_native_blockers
        original_finding_rva = _v12._finding_rva
        original_crosscheck = _v12._ensure_il2cpp_crosscheck
        original_identity = _v12._ensure_metadata_identity
        original_native = _v12._ensure_native_recovery

        def wrapped_method_index(path, wanted_ids=None, wanted_rvas=None, wanted_names=None, limit=250000):
            return _method_index(path, wanted_ids, wanted_rvas, wanted_names, gate, limit)

        def wrapped_locator(card):
            gate.tick()
            return original_locator(card)

        def wrapped_stream_blockers(path, findings):
            gate.force()
            if not native_current:
                return {}, {}
            return _stream_native_blockers(path, findings, gate)

        def wrapped_finding_rva(finding):
            gate.tick()
            return original_finding_rva(finding)

        def wrapped_crosscheck(root):
            return dict(exact_crosscheck)

        def wrapped_identity(root):
            return dict(exact_identity)

        def wrapped_native(root):
            return dict(exact_native)

        _v12._jsonl = reader
        _base._method_index = wrapped_method_index
        _base._locator = wrapped_locator
        _v12._stream_native_blockers = wrapped_stream_blockers
        _v12._finding_rva = wrapped_finding_rva
        _v12._ensure_il2cpp_crosscheck = wrapped_crosscheck
        _v12._ensure_metadata_identity = wrapped_identity
        _v12._ensure_native_recovery = wrapped_native
        try:
            report = _v12.build_connected_report(workdir, json_part, md_part)
        except Exception:
            for temporary in (json_part, md_part):
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
            raise
        finally:
            _v12._jsonl = original_jsonl
            _base._method_index = original_method_index
            _base._locator = original_locator
            _v12._stream_native_blockers = original_stream_blockers
            _v12._finding_rva = original_finding_rva
            _v12._ensure_il2cpp_crosscheck = original_crosscheck
            _v12._ensure_metadata_identity = original_identity
            _v12._ensure_native_recovery = original_native

    gate.force()
    if isinstance(report, dict):
        report.setdefault("memoryPolicy", {})
        if isinstance(report["memoryPolicy"], dict):
            report["memoryPolicy"].update({
                "methodCatalog": "STREAMED_RELEVANT_ROWS_ONLY",
                "methodEvidence": "STREAMED_FINDING_SCOPED_JSONL",
                "loadsFullMethodCatalogIntoRam": False,
                "loadsFullMethodEvidenceIntoRam": False,
                "retainedCrosscheckRows": retained["crosscheck"],
                "retainedIdentityRows": retained["identity"],
                "retainedNativeRecoveryRows": retained["native"],
                "schemaSemantics": "UNCHANGED_CONNECTED_REPORT_1_2",
                "cancelAware": cb is not None,
                "atomicOutputPromotion": bool(output_json or output_md),
                "coordinatedFinalCancelGate": True,
                "multiFileTransactionAtomic": False,
            })
        report["freshnessPolicy"] = {
            "secondaryIl2cppEvidence": secondary.get("freshnessPolicy"),
            "mtimeTrustedAsIdentity": False,
            "standaloneReportRefreshesEvidence": True,
            "legacyMtimeFallbackUsed": False,
        }
        if json_part is not None:
            gate.force()
            json_part.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # One final cancellation decision governs the whole output pair. Do not check
    # again between the two short rename operations: a user cancel cannot leave a
    # new JSON report paired with an old Markdown report.
    gate.force()
    if json_part is not None and output_json is not None:
        json_part.replace(Path(output_json))
    if md_part is not None and output_md is not None:
        md_part.replace(Path(output_md))
    return report
