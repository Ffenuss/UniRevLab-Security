"""In-app orchestration for bundled ModKit analysis engines.

This is the Android-facing coordinator for analyzers which are physically shipped
with ModKit. It never depends on a user manually importing third-party output.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modkit.mobile import artifact_families, cocos_deep, flutter_deep, hermes_deep, lua_deep, native_deep

SCHEMA = "modkit-embedded-analysis-1.3"


def _artifacts(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = report.setdefault("artifacts", [])
    if not isinstance(rows, list):
        rows = []
        report["artifacts"] = rows
    return rows


def _merge_findings(static_report: dict[str, Any], deep_report: dict[str, Any], *,
                    summary_key: str, default_engine: str, default_kind: str,
                    default_category: str) -> int:
    artifacts = _artifacts(static_report)
    existing = {str(row.get("id")) for row in artifacts if isinstance(row, dict) and row.get("id")}
    added = 0
    for row in deep_report.get("findings", []) if isinstance(deep_report, dict) else []:
        if not isinstance(row, dict):
            continue
        rid = str(row.get("id") or "")
        if rid and rid in existing:
            continue
        merged = dict(row)
        merged.setdefault("kind", default_kind)
        merged.setdefault("category", default_category)
        merged.setdefault("ownershipKind", "APP_OR_GAME")
        merged.setdefault("trustBoundary", "local")
        merged.setdefault("serverAudit", False)
        merged.setdefault("patchReady", False)
        artifacts.append(merged)
        if rid:
            existing.add(rid)
        added += 1

    static_report[summary_key] = {
        "engineId": deep_report.get("engineId", default_engine) if isinstance(deep_report, dict) else default_engine,
        "available": bool(deep_report.get("available", deep_report.get("detected", deep_report.get("analyzedLibraryCount", 0)))) if isinstance(deep_report, dict) else False,
        "findingCount": int(deep_report.get("findingCount") or 0) if isinstance(deep_report, dict) else 0,
        "mergedFindingCount": added,
        "manualImportRequired": bool(deep_report.get("manualImportRequired", False)) if isinstance(deep_report, dict) else False,
        "errorCount": len(deep_report.get("errors") or []) if isinstance(deep_report, dict) else 0,
    }
    static_report["total"] = len(artifacts)
    return added


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
        lua_report = lua_deep.scan_workspace(root, root / "lua-deep.json")
        runs.append({
            "engineId": lua_deep.ENGINE_ID,
            "status": "SUCCESS" if lua_report.get("available") else "UNAVAILABLE",
            "chunkCount": int(lua_report.get("chunkCount") or 0),
            "findingCount": int(lua_report.get("findingCount") or 0),
            "errorCount": len(lua_report.get("errors") or []),
        })
        _merge_findings(static_report, lua_report, summary_key="deepLua",
                        default_engine=lua_deep.ENGINE_ID, default_kind="LUA_BYTECODE",
                        default_category="Runtime/Lua")
    except Exception as exc:
        runs.append({"engineId": lua_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})

    try:
        deep = hermes_deep.scan_workspace(root, root / "hermes-deep.json")
        runs.append({
            "engineId": "hermes.deep-embedded",
            "status": "SUCCESS" if deep.get("available") else "UNAVAILABLE",
            "bundleCount": int(deep.get("bundleCount") or 0),
            "findingCount": int(deep.get("findingCount") or 0),
            "errorCount": len(deep.get("errors") or []),
        })
        _merge_findings(static_report, deep, summary_key="deepHermes",
                        default_engine="hermes.deep-embedded", default_kind="SCRIPT_SYMBOL",
                        default_category="Runtime/Hermes")
    except Exception as exc:
        runs.append({"engineId": "hermes.deep-embedded", "status": "FAILED", "error": str(exc)})

    native_report: dict[str, Any] = {}
    try:
        native_report = native_deep.scan_workspace(root, root / "native-deep.json")
        runs.append({
            "engineId": native_deep.ENGINE_ID,
            "status": "SUCCESS",
            "libraryCount": int(native_report.get("analyzedLibraryCount") or 0),
            "findingCount": int(native_report.get("findingCount") or 0),
            "errorCount": len(native_report.get("errors") or []),
        })
        _merge_findings(static_report, native_report, summary_key="deepNative",
                        default_engine=native_deep.ENGINE_ID, default_kind="NATIVE_EVIDENCE",
                        default_category="Native/ARM64")
    except Exception as exc:
        runs.append({"engineId": native_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})

    try:
        cocos_report = cocos_deep.scan_workspace(root, static_report, native_report, root / "cocos-deep.json")
        runs.append({
            "engineId": cocos_deep.ENGINE_ID,
            "status": "SUCCESS" if cocos_report.get("available") else "UNAVAILABLE",
            "scriptArtifactCount": int(cocos_report.get("scriptArtifactCount") or 0),
            "nativeLibraryCount": int(cocos_report.get("nativeLibraryCount") or 0),
            "correlationCount": int(cocos_report.get("correlationCount") or 0),
            "findingCount": int(cocos_report.get("findingCount") or 0),
        })
        _merge_findings(static_report, cocos_report, summary_key="deepCocos",
                        default_engine=cocos_deep.ENGINE_ID, default_kind="COCOS_EVIDENCE",
                        default_category="Runtime/Cocos")
    except Exception as exc:
        runs.append({"engineId": cocos_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})

    try:
        flutter_report = flutter_deep.scan_workspace(root, native_report, root / "flutter-deep.json")
        runs.append({
            "engineId": flutter_deep.ENGINE_ID,
            "status": "SUCCESS" if flutter_report.get("detected") else "UNAVAILABLE",
            "artifactCount": int(flutter_report.get("artifactCount") or 0),
            "findingCount": int(flutter_report.get("findingCount") or 0),
            "errorCount": len(flutter_report.get("errors") or []),
        })
        _merge_findings(static_report, flutter_report, summary_key="deepFlutter",
                        default_engine=flutter_deep.ENGINE_ID, default_kind="FLUTTER_AOT_EVIDENCE",
                        default_category="Flutter/Dart AOT")
    except Exception as exc:
        runs.append({"engineId": flutter_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})

    static_report["embeddedEnriched"] = True
    static_report["embeddedPipelineSchema"] = SCHEMA
    static_report["total"] = len(_artifacts(static_report))
    artifact_path.write_text(json.dumps(static_report, ensure_ascii=False, indent=2), encoding="utf-8")
    out = {
        "schema": SCHEMA,
        "mode": "IN_APP_AUTOMATIC",
        "manualImportRequired": False,
        "executesTargetCode": False,
        "runs": runs,
        "artifactReport": artifact_path.name,
        "luaReport": "lua-deep.json",
        "nativeReport": "native-deep.json",
        "cocosReport": "cocos-deep.json",
        "flutterReport": "flutter-deep.json",
        "successful": sum(1 for run in runs if run.get("status") == "SUCCESS"),
        "unavailable": sum(1 for run in runs if run.get("status") == "UNAVAILABLE"),
        "failed": sum(1 for run in runs if run.get("status") == "FAILED"),
    }
    pipeline_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
