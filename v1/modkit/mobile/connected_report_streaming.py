"""Memory-bounded Connected Report 1.2 entry point.

The report semantics live in :mod:`connected_report_v12`.  That implementation's
index builders consume their JSONL inputs exactly once, but its historical `_jsonl`
helper first materialized every row into a Python list.  Large IL2CPP titles can have
100k+ method evidence rows, so the Android release path uses this adapter to provide
a lazy iterator while keeping the same schema, matching rules and fail-closed gates.

The temporary substitution is guarded by a process-local lock and always restored.
No target/evidence bytes are modified by this adapter beyond the normal report output
files written by ``build_connected_report`` itself.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Iterator

from modkit.mobile import connected_report_v12 as _v12

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


def build_connected_report(
    workdir: str | Path,
    output_json: str | Path | None = None,
    output_md: str | Path | None = None,
) -> dict[str, Any]:
    """Build the existing Connected Report 1.2 without list-materializing JSONL."""
    with _LOCK:
        original = _v12._jsonl
        _v12._jsonl = _iter_jsonl
        try:
            report = _v12.build_connected_report(workdir, output_json, output_md)
        finally:
            _v12._jsonl = original
    if isinstance(report, dict):
        report.setdefault("memoryPolicy", {})
        if isinstance(report["memoryPolicy"], dict):
            report["memoryPolicy"].update({
                "methodEvidence": "STREAMED_JSONL",
                "loadsFullMethodEvidenceIntoRam": False,
                "schemaSemantics": "UNCHANGED_CONNECTED_REPORT_1_2",
            })
        # v12 may already have written output_json before this adapter annotates the
        # returned object. Persist only the small final report object, never evidence.
        if output_json:
            Path(output_json).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
