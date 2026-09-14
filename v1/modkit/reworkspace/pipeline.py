"""Reusable stage/merge helpers for the bounded RE pipeline.

Kept separate from ``mobile.engine`` so staged report orchestration can evolve
without growing the Android bridge module further.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile


def write_json_stage(payload: dict, output_path: str | Path, prefix: str) -> str:
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".json", dir=str(Path(output_path).resolve().parent))
    os.close(fd)
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return path


def merge_unique_rows(dst: list, src: list) -> None:
    """Append JSON rows without duplicating exact staged evidence."""
    seen = set()
    for row in dst:
        try:
            seen.add(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        except Exception:
            pass
    for row in src:
        try:
            key = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except Exception:
            key = None
        if key is None or key not in seen:
            dst.append(row)
            if key is not None:
                seen.add(key)


def merge_findings(dst_report: dict, staged_findings: list) -> None:
    findings = dst_report.setdefault("findings", [])
    by_id = {str(x.get("id")): x for x in findings if x.get("id")}
    for incoming in staged_findings or []:
        fid = str(incoming.get("id") or "")
        if not fid or fid not in by_id:
            findings.append(incoming)
            if fid:
                by_id[fid] = incoming
            continue
        existing = by_id[fid]
        existing["confidence"] = max(float(existing.get("confidence") or 0.0), float(incoming.get("confidence") or 0.0))
        merge_unique_rows(existing.setdefault("evidence", []), incoming.get("evidence") or [])
        if incoming.get("rationale") and incoming.get("rationale") != existing.get("rationale"):
            old = str(existing.get("rationale") or "").strip()
            new = str(incoming.get("rationale") or "").strip()
            existing["rationale"] = (old + (" | " if old and new else "") + new)[:4000]


def merge_generic_stage(dst_report: dict, staged: dict) -> None:
    inv = dst_report.setdefault("inventory", {"dex": [], "native": [], "other": []})
    for key in ("dex", "native", "other"):
        merge_unique_rows(inv.setdefault(key, []), ((staged.get("inventory") or {}).get(key) or []))

    dst_rel = dst_report.setdefault("nativeRelations", {})
    src_rel = staged.get("nativeRelations") or {}
    for key, value in src_rel.items():
        if key == "schema":
            dst_rel.setdefault(key, value)
        elif isinstance(value, list):
            merge_unique_rows(dst_rel.setdefault(key, []), value)
        elif isinstance(value, dict):
            merged = dst_rel.setdefault(key, {})
            if isinstance(merged, dict):
                merged.update(value)
            else:
                dst_rel[key] = value
        elif key not in dst_rel:
            dst_rel[key] = value
    merge_findings(dst_report, staged.get("findings") or [])
