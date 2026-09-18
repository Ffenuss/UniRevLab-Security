"""In-app orchestration for bundled ModKit analysis engines.

This is the Android-facing coordinator for analyzers which are physically shipped
with ModKit. It never depends on a user manually importing third-party output.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modkit.mobile import (
    arm32_deep, artifact_families, cocos_deep, deep_gameplay, deobfuscator, defold_deep, dotnet_deep, engine_router,
    flutter_deep, godot_deep, hermes_deep, jsc_deep, lua_deep, lua_deep_cancellable, native_deep,
    native_inventory, native_portable, qml_deep, runtime_profiler, unreal_deep, wasm_deep,
)

SCHEMA = "modkit-embedded-analysis-1.10"


class Cancelled(Exception):
    """Raised only for an explicit user cancellation request."""


def _check(cb=None, stage: str | None = None) -> None:
    if cb is None:
        return
    if cb.isCancelled():
        raise Cancelled("Операция отменена")
    if stage:
        cb.progress(stage)


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
        "available": bool(deep_report.get("available", deep_report.get("detected", deep_report.get("analyzedLibraryCount", deep_report.get("findingCount", 0))))) if isinstance(deep_report, dict) else False,
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
    cb=None,
) -> dict[str, Any]:
    root = Path(workdir)
    artifact_path = Path(artifact_output_path) if artifact_output_path else root / "artifact-families.json"
    pipeline_path = Path(pipeline_output_path) if pipeline_output_path else root / "embedded-analysis.json"

    runs: list[dict[str, Any]] = []
    static_report: dict[str, Any]
    profile_report: dict[str, Any] = {}
    router_report: dict[str, Any] = {}
    deob_report: dict[str, Any] = {}

    _check(cb, "Embedded 1/20 · runtime / engine profiler…")
    try:
        profile_report = runtime_profiler.scan_workspace(root, root / "runtime-profiler.json", cb)
        runs.append({
            "engineId": "runtime.profiler",
            "status": "SUCCESS",
            "profileCount": int(profile_report.get("profileCount") or 0),
            "detected": profile_report.get("detected") or [],
            "abis": profile_report.get("abis") or [],
        })
    except runtime_profiler.RuntimeProfileCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": "runtime.profiler", "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 2/20 · multi-runtime engine routing…")
    try:
        router_report = engine_router.route(profile_report, root / "engine-router.json")
        runs.append({
            "engineId": "runtime.engine-router",
            "status": "SUCCESS",
            "routeCount": int(router_report.get("routeCount") or 0),
            "selectedEngineCount": int(router_report.get("selectedEngineCount") or 0),
            "missingBackendCount": int(router_report.get("missingBackendCount") or 0),
        })
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": "runtime.engine-router", "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 3/20 · deobfuscation / protection profile…")
    try:
        deob_report = deobfuscator.scan_workspace(root, root / "deobfuscation.json", cb)
        runs.append({
            "engineId": deobfuscator.ENGINE_ID,
            "status": "SUCCESS",
            "findingCount": int(deob_report.get("findingCount") or 0),
            "normalizedIdentifierCount": int(deob_report.get("normalizedIdentifierCount") or 0),
        })
    except deobfuscator.DeobfuscationCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": deobfuscator.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 4/20 · artifact families…")
    try:
        static_report = artifact_families.scan_workspace(root, None, cb)
        runs.append({
            "engineId": "artifact-family-suite",
            "status": "SUCCESS",
            "artifactCount": int(static_report.get("artifactCount") or 0),
            "symbolCount": int(static_report.get("symbolCount") or 0),
        })
    except artifact_families.ArtifactScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
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
    _check(cb)

    if deob_report:
        _merge_findings(static_report, deob_report, summary_key="deobfuscation",
                        default_engine=deobfuscator.ENGINE_ID,
                        default_kind="PROTECTION_EVIDENCE",
                        default_category="Protection/Obfuscation")
    static_report["runtimeProfiler"] = {
        "schema": profile_report.get("schema"),
        "profileCount": int(profile_report.get("profileCount") or 0),
        "detected": profile_report.get("detected") or [],
        "abis": profile_report.get("abis") or [],
        "splitAware": bool(profile_report.get("splitAware")),
    }
    static_report["engineRouter"] = {
        "schema": router_report.get("schema"),
        "routeCount": int(router_report.get("routeCount") or 0),
        "coverageCounts": router_report.get("coverageCounts") or {},
        "selectedEngines": router_report.get("selectedEngines") or [],
        "missingBackends": router_report.get("missingBackends") or [],
    }

    _check(cb, "Embedded 5/20 · universal ELF / Android ABI inventory…")
    try:
        native_inventory_report = native_inventory.scan_workspace(root, root / "native-inventory.json", cb)
        runs.append({
            "engineId": native_inventory.ENGINE_ID,
            "status": "SUCCESS",
            "findingCount": int(native_inventory_report.get("findingCount") or 0),
            "archCounts": native_inventory_report.get("archCounts") or {},
            "abiCounts": native_inventory_report.get("abiCounts") or {},
        })
        _merge_findings(static_report, native_inventory_report, summary_key="nativeInventory",
                        default_engine=native_inventory.ENGINE_ID,
                        default_kind="ELF_UNIVERSAL_INVENTORY",
                        default_category="Native/Inventory")
    except native_inventory.NativeInventoryCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": native_inventory.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 6/20 · .NET / Mono CLI metadata…")
    try:
        dotnet_report = dotnet_deep.scan_workspace(root, root / "dotnet-deep.json", cb)
        runs.append({
            "engineId": dotnet_deep.ENGINE_ID,
            "status": "SUCCESS" if dotnet_report.get("assemblyCount") else "UNAVAILABLE",
            "assemblyCount": int(dotnet_report.get("assemblyCount") or 0),
            "managedAssemblyCount": int(dotnet_report.get("managedAssemblyCount") or 0),
            "findingCount": int(dotnet_report.get("findingCount") or 0),
            "errorCount": len(dotnet_report.get("errors") or []),
        })
        _merge_findings(static_report, dotnet_report, summary_key="deepDotNet",
                        default_engine=dotnet_deep.ENGINE_ID,
                        default_kind="DOTNET_MANAGED_METADATA",
                        default_category="Runtime/.NET")
    except dotnet_deep.DotNetScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": dotnet_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 7/20 · Unreal cooked assets / reflection…")
    try:
        unreal_report = unreal_deep.scan_workspace(root, root / "unreal-deep.json", cb)
        runs.append({
            "engineId": unreal_deep.ENGINE_ID,
            "status": "SUCCESS" if (
                unreal_report.get("containerCount") or unreal_report.get("cookedAssetCount")
                or unreal_report.get("nativeLibraryCount")
            ) else "UNAVAILABLE",
            "containerCount": int(unreal_report.get("containerCount") or 0),
            "cookedAssetCount": int(unreal_report.get("cookedAssetCount") or 0),
            "ioStorePairCount": int(unreal_report.get("ioStorePairCount") or 0),
            "reflectionNameCount": int(unreal_report.get("reflectionNameCount") or 0),
            "findingCount": int(unreal_report.get("findingCount") or 0),
        })
        _merge_findings(static_report, unreal_report, summary_key="deepUnreal",
                        default_engine=unreal_deep.ENGINE_ID,
                        default_kind="UNREAL_COOKED_EVIDENCE",
                        default_category="Runtime/Unreal")
    except unreal_deep.UnrealScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": unreal_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 8/20 · Godot PCK / scene graph…")
    try:
        godot_report = godot_deep.scan_workspace(root, root / "godot-deep.json", cb)
        runs.append({
            "engineId": godot_deep.ENGINE_ID,
            "status": "SUCCESS" if (
                godot_report.get("packCount") or godot_report.get("sceneCount")
                or godot_report.get("scriptCount")
            ) else "UNAVAILABLE",
            "packCount": int(godot_report.get("packCount") or 0),
            "sceneCount": int(godot_report.get("sceneCount") or 0),
            "scriptCount": int(godot_report.get("scriptCount") or 0),
            "findingCount": int(godot_report.get("findingCount") or 0),
        })
        _merge_findings(static_report, godot_report, summary_key="deepGodot",
                        default_engine=godot_deep.ENGINE_ID,
                        default_kind="GODOT_EVIDENCE",
                        default_category="Runtime/Godot")
    except godot_deep.GodotScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": godot_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 9/20 · Defold archive / resources…")
    try:
        defold_report = defold_deep.scan_workspace(root, root / "defold-deep.json", cb)
        runs.append({
            "engineId": defold_deep.ENGINE_ID,
            "status": "SUCCESS" if (
                defold_report.get("archiveGroupCount") or defold_report.get("nativeLibraryCount")
            ) else "UNAVAILABLE",
            "archiveGroupCount": int(defold_report.get("archiveGroupCount") or 0),
            "resourcePathCount": int(defold_report.get("resourcePathCount") or 0),
            "findingCount": int(defold_report.get("findingCount") or 0),
        })
        _merge_findings(static_report, defold_report, summary_key="deepDefold",
                        default_engine=defold_deep.ENGINE_ID,
                        default_kind="DEFOLD_EVIDENCE",
                        default_category="Runtime/Defold")
    except defold_deep.DefoldScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": defold_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 10/20 · Qt / QML structure…")
    try:
        qml_report = qml_deep.scan_workspace(root, root / "qml-deep.json", cb)
        runs.append({
            "engineId": qml_deep.ENGINE_ID,
            "status": "SUCCESS" if (
                qml_report.get("qmlSourceCount") or qml_report.get("compiledQmlCount")
                or qml_report.get("rccCount") or qml_report.get("nativeQtLibraryCount")
            ) else "UNAVAILABLE",
            "qmlSourceCount": int(qml_report.get("qmlSourceCount") or 0),
            "compiledQmlCount": int(qml_report.get("compiledQmlCount") or 0),
            "rccCount": int(qml_report.get("rccCount") or 0),
            "findingCount": int(qml_report.get("findingCount") or 0),
        })
        _merge_findings(static_report, qml_report, summary_key="deepQml",
                        default_engine=qml_deep.ENGINE_ID,
                        default_kind="QML_EVIDENCE",
                        default_category="Runtime/Qt QML")
    except qml_deep.QmlScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": qml_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 11/20 · JavaScriptCore / React Native…")
    try:
        jsc_report = jsc_deep.scan_workspace(root, root / "jsc-deep.json", cb)
        runs.append({
            "engineId": jsc_deep.ENGINE_ID,
            "status": "SUCCESS" if (
                jsc_report.get("artifactCount") or jsc_report.get("nativeLibraryCount")
            ) else "UNAVAILABLE",
            "artifactCount": int(jsc_report.get("artifactCount") or 0),
            "sourceLikeCount": int(jsc_report.get("sourceLikeCount") or 0),
            "binaryBytecodeCount": int(jsc_report.get("binaryBytecodeCount") or 0),
            "findingCount": int(jsc_report.get("findingCount") or 0),
        })
        _merge_findings(static_report, jsc_report, summary_key="deepJsc",
                        default_engine=jsc_deep.ENGINE_ID,
                        default_kind="JSC_EVIDENCE",
                        default_category="Runtime/JavaScriptCore")
    except jsc_deep.JscScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": jsc_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 12/20 · WebAssembly sections / exports…")
    try:
        wasm_report = wasm_deep.scan_workspace(root, root / "wasm-deep.json", cb)
        runs.append({
            "engineId": wasm_deep.ENGINE_ID,
            "status": "SUCCESS" if wasm_report.get("moduleCount") else "UNAVAILABLE",
            "moduleCount": int(wasm_report.get("moduleCount") or 0),
            "validModuleCount": int(wasm_report.get("validModuleCount") or 0),
            "exportCount": int(wasm_report.get("exportCount") or 0),
            "findingCount": int(wasm_report.get("findingCount") or 0),
        })
        _merge_findings(static_report, wasm_report, summary_key="deepWasm",
                        default_engine=wasm_deep.ENGINE_ID,
                        default_kind="WEBASSEMBLY_EVIDENCE",
                        default_category="Runtime/WebAssembly")
    except wasm_deep.WasmScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": wasm_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 13/20 · Lua bytecode…")
    try:
        lua_report = lua_deep_cancellable.scan_workspace(root, root / "lua-deep.json", cb)
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
    except lua_deep_cancellable.LuaScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": lua_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 14/20 · Hermes HBC…")
    try:
        deep = hermes_deep.scan_workspace(root, root / "hermes-deep.json", cb)
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
    except hermes_deep.HermesScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": "hermes.deep-embedded", "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 15/20 · portable ELF symbols / relocations…")
    try:
        portable_report = native_portable.scan_workspace(root, root / "native-portable.json", cb)
        runs.append({
            "engineId": native_portable.ENGINE_ID,
            "status": "SUCCESS" if portable_report.get("libraryCount") else "UNAVAILABLE",
            "libraryCount": int(portable_report.get("libraryCount") or 0),
            "archCounts": portable_report.get("archCounts") or {},
            "findingCount": int(portable_report.get("findingCount") or 0),
        })
        _merge_findings(static_report, portable_report, summary_key="portableNative",
                        default_engine=native_portable.ENGINE_ID,
                        default_kind="PORTABLE_ELF_EVIDENCE",
                        default_category="Native/Portable")
    except native_portable.PortableNativeCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": native_portable.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 16/20 · ARMv7 / Thumb control flow…")
    try:
        arm32_report = arm32_deep.scan_workspace(root, root / "arm32-deep.json", cb)
        runs.append({
            "engineId": arm32_deep.ENGINE_ID,
            "status": "SUCCESS" if arm32_report.get("availableLibraryCount") else "UNAVAILABLE",
            "libraryCount": int(arm32_report.get("libraryCount") or 0),
            "availableLibraryCount": int(arm32_report.get("availableLibraryCount") or 0),
            "functionCount": int(arm32_report.get("functionCount") or 0),
            "edgeCount": int(arm32_report.get("edgeCount") or 0),
            "findingCount": int(arm32_report.get("findingCount") or 0),
        })
        _merge_findings(static_report, arm32_report, summary_key="deepArm32",
                        default_engine=arm32_deep.ENGINE_ID,
                        default_kind="ARM32_CONTROL_FLOW_EDGE",
                        default_category="Native/ARM32 Control Flow")
    except arm32_deep.Arm32ScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": arm32_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    native_report: dict[str, Any] = {}
    _check(cb, "Embedded 17/20 · native ELF/ARM64…")
    try:
        native_report = native_deep.scan_workspace(root, root / "native-deep.json", cb)
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
    except native_deep.NativeScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": native_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 18/20 · Cocos correlation…")
    try:
        cocos_report = cocos_deep.scan_workspace(root, static_report, native_report, root / "cocos-deep.json", cb)
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
    except cocos_deep.CocosScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": cocos_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 19/20 · Flutter/Dart AOT…")
    try:
        flutter_report = flutter_deep.scan_workspace(root, native_report, root / "flutter-deep.json", cb)
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
    except flutter_deep.FlutterScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": flutter_deep.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    _check(cb, "Embedded 20/20 · gameplay semantic correlation…")
    try:
        gameplay_report = deep_gameplay.scan_workspace(root, static_report, native_report, root / "deep-gameplay.json", cb)
        runs.append({
            "engineId": deep_gameplay.ENGINE_ID,
            "status": "SUCCESS",
            "findingCount": int(gameplay_report.get("findingCount") or 0),
            "locatorCount": int(gameplay_report.get("locatorCount") or 0),
            "coverage": gameplay_report.get("coverage") or {},
        })
        _merge_findings(static_report, gameplay_report, summary_key="deepGameplay",
                        default_engine=deep_gameplay.ENGINE_ID, default_kind="SEMANTIC_GAMEPLAY_EVIDENCE",
                        default_category="Gameplay/Semantic")
    except deep_gameplay.GameplayScanCancelled as exc:
        raise Cancelled(str(exc)) from exc
    except Cancelled:
        raise
    except Exception as exc:
        runs.append({"engineId": deep_gameplay.ENGINE_ID, "status": "FAILED", "error": str(exc)})
    _check(cb)

    static_report["embeddedEnriched"] = True
    static_report["embeddedPipelineSchema"] = SCHEMA
    static_report["total"] = len(_artifacts(static_report))
    _check(cb)
    artifact_path.write_text(json.dumps(static_report, ensure_ascii=False, indent=2), encoding="utf-8")
    out = {
        "schema": SCHEMA,
        "mode": "IN_APP_AUTOMATIC",
        "manualImportRequired": False,
        "executesTargetCode": False,
        "cancelAware": cb is not None,
        "runs": runs,
        "artifactReport": artifact_path.name,
        "runtimeProfilerReport": "runtime-profiler.json",
        "engineRouterReport": "engine-router.json",
        "deobfuscationReport": "deobfuscation.json",
        "nativeInventoryReport": "native-inventory.json",
        "nativePortableReport": "native-portable.json",
        "arm32Report": "arm32-deep.json",
        "dotnetReport": "dotnet-deep.json",
        "unrealReport": "unreal-deep.json",
        "godotReport": "godot-deep.json",
        "defoldReport": "defold-deep.json",
        "qmlReport": "qml-deep.json",
        "jscReport": "jsc-deep.json",
        "wasmReport": "wasm-deep.json",
        "luaReport": "lua-deep.json",
        "nativeReport": "native-deep.json",
        "cocosReport": "cocos-deep.json",
        "flutterReport": "flutter-deep.json",
        "deepGameplayReport": "deep-gameplay.json",
        "successful": sum(1 for run in runs if run.get("status") == "SUCCESS"),
        "unavailable": sum(1 for run in runs if run.get("status") == "UNAVAILABLE"),
        "failed": sum(1 for run in runs if run.get("status") == "FAILED"),
    }
    _check(cb)
    pipeline_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
