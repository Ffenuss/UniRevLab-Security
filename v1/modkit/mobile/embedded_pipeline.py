"""In-app orchestration for bundled ModKit analysis engines.

This is the Android-facing coordinator for analyzers which are physically shipped
with ModKit. It never depends on a user manually importing third-party output.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modkit.mobile import artifact_families, hermes_deep

SCHEMA = "modkit-embedded-analysis-1.0"


def _merge_hermes(static_report: dict[str, Any], deep_report: dict[str, Any]) -> None:
    artifacts = static_report.setdefault("artifacts", [])
    if not isinstance(artifacts, list):
        artifacts = []
        static_report["artifacts"] = artifacts

    existing = {str(row.get("id")) for row in artifacts if isinstance(row, dict)}
    added = 0
    for row in deep_report.get("findings", []) if isinstance(deep_report, dict) else []:
        if not isinstance(row, dict):
            continue
        rid = str(row.get("id") or "")
        if rid and rid in existing:
            continue
        merged = dict(row)
        merged.setdefault("kind", "SCRIPT_SYMBOL")
        merged.setdefault("category", "Runtime/Hermes")
        merged.setdefault("ownershipKind", "APP_OR_GAME")
        merged.setdefault("trustBoundary", "local")
        merged.setdefault("serverAudit", False)
        merged.setdefault("patchReady", False)
        artifacts.append(merged)
        if rid:
            existing.add(rid)
        added += 1

    static_report["deepHermes"] = {
        "engineId": deep_report.get("engineId") if isinstance(deep_report, dict) else "hermes.deep-embedded",
        "available": bool(deep_report.get("available")) if isinstance(deep_report, dict) else False,
        "bundleCount": int(deep_report.get("bundleCount") or 0) if isinstance(deep_report, dict) else 0,
        "findingCount": int(deep_report.get("findingCount") or 0) if isinstance(deep_report, dict) else 0,
        "mergedFindingCount": added,
    }
    static_report["total"] = len(artifacts)


def run_workspace(
    workdir: str | Path,
    artifact_output_path: str | Path | None = None,
    pipeline_output_path: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(workdir)
    artifact_path = Path(artifact_output_path) if artifact_output_path else root / "artifact-families.json"
    pipeline_path = Path(pipeline_output_path) if pipeline_output_path else root / "embedded-analysis.json"

    runs: list[dict[str, Any]] = []
    static_report: dict[str, Any]
    try:
        static_report = artifact_families.scan_workspace(root)
        runs.append({
            "engineId": "artifact-family-suite",
            "status": "SUCCESS",
            "artifactCount": int(static_report.get("artifactCount") or 0),
            "symbolCount": int(static_report.get("symbolCount") or 0),
        })
    except Exception as exc:
        static_report = {
            "schema": artifact_families.SCHEMA,
            "passive": True,
            "executesTargetCode": False,
            "apkCount": 0,
            "total": 0,
            "artifactCount": 0,
            "symbolCount": 0,
            "familyCounts": {},
            "recoveryCounts": {},
            "artifacts": [],
            "truncated": False,
        }
        runs.append({"engineId": "artifact-family-suite", "status": "FAILED", "error": str(exc)})

    try:
        deep = hermes_deep.scan_workspace(root, root / "hermes-deep.json")
        runs.append({
            "engineId": "hermes.deep-embedded",
            "status": "SUCCESS" if deep.get("available") else "UNAVAILABLE",
            "bundleCount": int(deep.get("bundleCount") or 0),
            "findingCount": int(deep.get("findingCount") or 0),
            "errorCount": len(deep.get("errors") or []),
        })
        _merge_hermes(static_report, deep)
    except Exception as exc:
        runs.append({"engineId": "hermes.deep-embedded", "status": "FAILED", "error": str(exc)})

    artifact_path.write_text(json.dumps(static_report, ensure_ascii=False, indent=2), encoding="utf-8")
    out = {
        "schema": SCHEMA,
        "mode": "IN_APP_AUTOMATIC",
        "manualImportRequired": False,
        "executesTargetCode": False,
        "runs": runs,
        "artifactReport": artifact_path.name,
        "successful": sum(1 for run in runs if run.get("status") == "SUCCESS"),
        "failed": sum(1 for run in runs if run.get("status") == "FAILED"),
    }
    pipeline_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
