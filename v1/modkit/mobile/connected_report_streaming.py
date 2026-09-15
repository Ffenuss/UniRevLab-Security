"""Memory-bounded Connected Report 1.2 entry point.

The report semantics live in :mod:`connected_report_v12`. Large IL2CPP titles can
produce 100k+ per-method evidence rows, so the Android release path keeps those files
streamed and retains only rows which can actually correlate with current findings by
exact method id, exact fully-qualified class+method, permitted weak method-name
fallback, or exact RVA.

The temporary substitution is guarded by a process-local lock and always restored.
No target/evidence bytes are modified by this adapter beyond the normal report output
files written by ``build_connected_report`` itself.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Callable, Iterator

from modkit.mobile import connected_report_v12 as _v12
from modkit.mobile.connected_report import _locator as _base_locator

SCHEMA = _v12.SCHEMA
_LOCK = threading.RLock()


def _iter_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    source_path = Path(path)
    if not source_path.is_file():
        return
    try:
        with source_path.open("r", encoding="utf-8", errors="replace") as source:
            for line in source:
                text = line.strip()
                if not text:
                    continue
                try:
                    value = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    yield value
    except OSError:
        return


def _wanted(workdir: str | Path) -> tuple[set[str], set[tuple[str, str]], set[str], set[str]]:
    root = Path(workdir)
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
    return ids, pairs, names, rvas


def _filtered_reader(workdir: str | Path) -> tuple[Callable[[Path], Iterator[dict[str, Any]]], dict[str, int]]:
    ids, pairs, names, rvas = _wanted(workdir)
    retained = {"crosscheck": 0, "identity": 0, "native": 0}

    def reader(path: Path) -> Iterator[dict[str, Any]]:
        filename = Path(path).name
        for row in _iter_jsonl(path):
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


def build_connected_report(
    workdir: str | Path,
    output_json: str | Path | None = None,
    output_md: str | Path | None = None,
) -> dict[str, Any]:
    """Build Connected Report 1.2 with finding-scoped streamed per-method evidence."""
    reader, retained = _filtered_reader(workdir)
    with _LOCK:
        original = _v12._jsonl
        _v12._jsonl = reader
        try:
            report = _v12.build_connected_report(workdir, output_json, output_md)
        finally:
            _v12._jsonl = original
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
            })
        # v12 writes output_json before this adapter annotates the returned object.
        # Persist only the final small report object; evidence files remain streamed.
        if output_json:
            Path(output_json).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
