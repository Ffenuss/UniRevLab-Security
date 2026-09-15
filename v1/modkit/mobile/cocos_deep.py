"""Static Cocos2d-x / Cocos Creator script-to-native correlation.

The backend correlates script symbols already recovered from APK assets with Cocos
native engine symbols and control-flow evidence produced by native.deep-embedded.
Name correlations are structural evidence only; they never manufacture a runtime
address for a script function or claim that an indirect call target was observed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

SCHEMA = "modkit-cocos-deep-1.0"
ENGINE_ID = "cocos.deep-embedded"
MAX_CORRELATIONS = 1200
MAX_BRIDGES = 800

_GENERIC = {"init", "start", "update", "main", "load", "create", "destroy", "ctor", "awake", "enable", "disable"}
_BRIDGE_MARKERS = ("jsb_", "register_all_", "scriptingcore", "tolua_", "luaopen_", "cocos2d", "_zn2se", "se::")
_SCRIPT_MARKERS = ("project.js", "settings.js", "main.js", "jsb-adapter", "/src/", "/scripts/", "cocos")


def _id(*parts: object) -> str:
    return hashlib.sha256("!".join(str(x) for x in parts).encode("utf-8", "replace")).hexdigest()[:20]


def _canon(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())


def _is_script(row: dict[str, Any], have_native_cocos: bool) -> bool:
    family = str(row.get("family") or "").casefold()
    entry = "/" + str(row.get("entry") or "").casefold()
    if family == "cocos":
        return True
    if family == "javascript":
        return any(marker in entry for marker in _SCRIPT_MARKERS) or entry.endswith(("/project.js", "/settings.js", "/main.jsc"))
    if family == "lua" and have_native_cocos:
        return "/lua/" in entry or entry.endswith((".lua", ".luac", ".luae"))
    return False


def _is_cocos_library(row: dict[str, Any]) -> bool:
    values = [row.get("entry"), row.get("soname"), *(row.get("needed") or [])]
    text = " ".join(str(v or "") for v in values).casefold()
    return "cocos" in text or "libcocos2dcpp.so" in text


def _bridge_function(name: object) -> bool:
    low = str(name or "").casefold()
    return any(marker in low for marker in _BRIDGE_MARKERS)


def _name_match(script_name: str, native_name: str) -> tuple[str, float] | None:
    token = _canon(script_name)
    native = _canon(native_name)
    if len(token) < 4 or token in _GENERIC or not native:
        return None
    if token == native:
        return "EXACT_CANONICAL_NAME", 0.98
    if token in native:
        bridge = _bridge_function(native_name)
        if bridge or len(token) >= 6:
            return ("BRIDGE_NAME_TOKEN" if bridge else "NAME_TOKEN"), (0.92 if bridge else 0.78)
    return None


def correlate(artifact_report: dict[str, Any], native_report: dict[str, Any]) -> dict[str, Any]:
    artifacts = [row for row in artifact_report.get("artifacts", []) if isinstance(row, dict)] if isinstance(artifact_report, dict) else []
    libraries = [row for row in native_report.get("libraries", []) if isinstance(row, dict)] if isinstance(native_report, dict) else []
    cocos_libs = [row for row in libraries if _is_cocos_library(row)]
    have_native = bool(cocos_libs)
    scripts = [row for row in artifacts if _is_script(row, have_native)]

    bridge_rows: list[dict[str, Any]] = []
    native_functions: list[tuple[dict[str, Any], dict[str, Any]]] = []
    edge_index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for lib in cocos_libs:
        entry = str(lib.get("entry") or "")
        for edge in lib.get("controlFlow", []) if isinstance(lib.get("controlFlow"), list) else []:
            if not isinstance(edge, dict):
                continue
            for key in ("sourceFunction", "targetFunction"):
                name = str(edge.get(key) or "")
                if name:
                    edge_index.setdefault((entry, name), []).append(edge)
        for fn in lib.get("functions", []) if isinstance(lib.get("functions"), list) else []:
            if not isinstance(fn, dict):
                continue
            native_functions.append((lib, fn))
            if _bridge_function(fn.get("name")) and len(bridge_rows) < MAX_BRIDGES:
                bridge_rows.append({
                    "library":entry,"function":fn.get("name"),"rva":fn.get("rva"),"size":fn.get("size"),
                    "status":"NATIVE_BRIDGE_SYMBOL","targetResolution":"EXACT_SYMBOL_RVA",
                })

    symbol_rows = [row for row in scripts if row.get("kind") == "SCRIPT_SYMBOL" and row.get("function")]
    correlations: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for script in symbol_rows:
        name = str(script.get("function") or script.get("title") or "")
        for lib, fn in native_functions:
            native_name = str(fn.get("name") or "")
            match = _name_match(name, native_name)
            if not match:
                continue
            rva = int(fn.get("rva") or 0)
            key = (str(script.get("id") or ""), str(lib.get("entry") or ""), rva)
            if key in seen:
                continue
            seen.add(key)
            kind, confidence = match
            entry = str(lib.get("entry") or "")
            correlations.append({
                "scriptId":script.get("id"),"scriptFunction":name,"scriptEntry":script.get("entry"),
                "scriptLine":script.get("line"),"scriptCharOffset":script.get("charOffset"),
                "nativeLibrary":entry,"nativeFunction":native_name,"nativeRva":rva,"nativeSize":fn.get("size"),
                "match":kind,"confidence":confidence,"status":"STRUCTURAL_CORRELATION",
                "targetResolution":"EXACT_NATIVE_SYMBOL_ONLY","runtimeTruth":"not-observed-by-static-analysis",
                "controlFlowEvidence":edge_index.get((entry, native_name), [])[:20],
            })
            if len(correlations) >= MAX_CORRELATIONS:
                break
        if len(correlations) >= MAX_CORRELATIONS:
            break

    script_markers = sum(1 for row in scripts if any(marker in ("/"+str(row.get("entry") or "").casefold()) for marker in _SCRIPT_MARKERS))
    detected = bool(cocos_libs or script_markers)
    if cocos_libs and scripts:
        confidence = "HIGH"
    elif cocos_libs or (script_markers >= 2):
        confidence = "MEDIUM"
    elif detected:
        confidence = "LOW"
    else:
        confidence = "NONE"

    findings: list[dict[str, Any]] = []
    if detected:
        findings.append({
            "id":"cocos-runtime:"+_id(len(cocos_libs),len(scripts),len(bridge_rows)),"kind":"COCOS_RUNTIME",
            "title":"Cocos runtime / script surface","category":"Runtime/Cocos","status":"FOUND_STATIC","family":"cocos",
            "engineId":ENGINE_ID,"nativeLibraryCount":len(cocos_libs),"scriptArtifactCount":len(scripts),
            "bridgeSymbolCount":len(bridge_rows),"correlationCount":len(correlations),"detectionConfidence":confidence,
            "ownershipKind":"APP_OR_GAME","trustBoundary":"local","patchReady":False,"structuralOnly":True,
            "evidenceRole":"embedded-cocos-runtime",
        })
    for bridge in bridge_rows[:300]:
        findings.append({
            "id":"cocos-bridge:"+_id(bridge.get("library"),bridge.get("function"),bridge.get("rva")),
            "kind":"COCOS_NATIVE_BRIDGE","title":str(bridge.get("function") or "Cocos bridge"),"category":"Runtime/Cocos",
            "status":"NATIVE_BRIDGE_SYMBOL","family":"cocos","engineId":ENGINE_ID,"library":bridge.get("library"),
            "function":bridge.get("function"),"rva":bridge.get("rva"),"targetResolution":"EXACT_SYMBOL_RVA",
            "ownershipKind":"APP_OR_GAME","trustBoundary":"local","patchReady":False,"structuralOnly":True,
            "evidenceRole":"embedded-cocos-native-bridge",
        })
    for corr in correlations:
        findings.append({
            "id":"cocos-link:"+_id(corr.get("scriptId"),corr.get("nativeLibrary"),corr.get("nativeRva")),
            "kind":"COCOS_SCRIPT_NATIVE_CORRELATION","title":f"{corr.get('scriptFunction')} ↔ {corr.get('nativeFunction')}",
            "category":"Gameplay/Cocos","status":"STRUCTURAL_CORRELATION","family":"cocos","engineId":ENGINE_ID,
            **corr,"ownershipKind":"APP_OR_GAME","trustBoundary":"local","patchReady":False,"structuralOnly":True,
            "evidenceRole":"embedded-cocos-script-native-correlation",
        })

    return {
        "schema":SCHEMA,"engineId":ENGINE_ID,"bundled":True,"manualImportRequired":False,"passive":True,
        "executesTargetCode":False,"available":detected,"detected":detected,"detectionConfidence":confidence,
        "nativeLibraryCount":len(cocos_libs),"scriptArtifactCount":len(scripts),"bridgeSymbolCount":len(bridge_rows),
        "correlationCount":len(correlations),"nativeLibraries":[str(row.get("entry") or "") for row in cocos_libs],
        "scriptEntries":sorted({str(row.get("entry") or "") for row in scripts if row.get("entry")})[:1000],
        "bridgeFunctions":bridge_rows,"correlations":correlations,"findingCount":len(findings),"findings":findings,
        "runtimeTruth":"not-observed-by-static-analysis",
    }


def scan_workspace(workdir: str | Path, artifact_report: dict[str, Any] | None = None,
                   native_report: dict[str, Any] | None = None, output_path: str | Path | None = None) -> dict[str, Any]:
    root = Path(workdir)
    if artifact_report is None:
        path = root / "artifact-families.json"
        artifact_report = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    if native_report is None:
        path = root / "native-deep.json"
        native_report = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    out = correlate(artifact_report, native_report)
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
