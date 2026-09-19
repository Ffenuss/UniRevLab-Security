"""Runtime-aware engine router.

Consumes runtime_profiler output and builds a deterministic multi-engine plan.
A target may route to several engines simultaneously. Missing specialized backends
are reported explicitly instead of being hidden behind a generic "supported" flag.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA = "modkit-engine-router-1.0"

_ROUTES: dict[str, dict[str, Any]] = {
    "android_dex": {
        "engines": ["apktool.android", "dex.structural", "jadx.android", "security.passive"],
        "coverage": "FULL_BUNDLED",
    },
    "native_elf": {
        "engines": ["elf.universal-inventory", "native.portable-embedded", "native.arm32-deep-embedded", "native.x86-deep-embedded", "elf.static", "native.deep-embedded", "security.passive"],
        "coverage": "FULL_BUNDLED",
    },
    "unity_il2cpp": {
        "engines": ["unity.discovery", "il2cpp.rodroid", "native.deep-embedded", "semantic.gameplay"],
        "coverage": "FULL_BUNDLED",
    },
    "unity_mono": {
        "engines": ["dotnet.static", "dotnet.metadata-embedded", "apktool.android", "dex.structural", "jadx.android", "security.passive"],
        "coverage": "PARTIAL_BUNDLED",
        "missing": ["managed CIL/assembly reconstruction for Unity Mono"],
    },
    "unreal": {
        "engines": ["unreal.static", "unreal.deep-embedded", "elf.static", "native.deep-embedded", "security.passive"],
        "coverage": "PARTIAL_BUNDLED",
        "missing": ["version-specific PAK/IoStore index deserialization", "full UObject/Blueprint semantic reconstruction"],
    },
    "flutter": {
        "engines": ["flutter.static", "flutter.aot-embedded", "native.deep-embedded", "security.passive"],
        "coverage": "FULL_BUNDLED",
    },
    "react_native_hermes": {
        "engines": ["hermes.static", "hermes.deep-embedded", "javascript.static", "dex.structural", "native.deep-embedded"],
        "coverage": "FULL_BUNDLED",
    },
    "react_native_jsc": {
        "engines": ["javascript.static", "jsc.deep-embedded", "dex.structural", "native.deep-embedded", "security.passive"],
        "coverage": "PARTIAL_BUNDLED",
        "missing": ["version-specific JavaScriptCore bytecode instruction decoder"],
    },
    "dotnet_android": {
        "engines": ["dotnet.static", "dotnet.metadata-embedded", "apktool.android", "dex.structural", "elf.static", "native.deep-embedded", "security.passive"],
        "coverage": "PARTIAL_BUNDLED",
        "missing": [".NET metadata/CIL/Mono/CoreCLR/NativeAOT reconstructor"],
    },
    "cordova": {
        "engines": ["javascript.static", "apktool.android", "dex.structural", "security.passive"],
        "coverage": "FULL_BUNDLED",
    },
    "capacitor": {
        "engines": ["javascript.static", "apktool.android", "dex.structural", "security.passive"],
        "coverage": "FULL_BUNDLED",
    },
    "cocos": {
        "engines": ["cocos.static", "cocos.deep-embedded", "javascript.static", "lua.static", "lua.bytecode-embedded", "native.deep-embedded"],
        "coverage": "FULL_BUNDLED",
    },
    "godot": {
        "engines": ["godot.static", "godot.deep-embedded", "elf.static", "native.deep-embedded", "security.passive"],
        "coverage": "PARTIAL_BUNDLED",
        "missing": ["binary/encrypted PCK file-table and binary resource semantic decoder"],
    },
    "defold": {
        "engines": ["defold.static", "defold.deep-embedded", "elf.static", "native.deep-embedded", "lua.static", "lua.bytecode-embedded"],
        "coverage": "PARTIAL_BUNDLED",
        "missing": ["compiled Defold archive payload decoder and original-source recovery"],
    },
    "qt_qml": {
        "engines": ["qt.qml-static", "qt.qml-deep-embedded", "elf.static", "native.deep-embedded", "apktool.android", "security.passive"],
        "coverage": "PARTIAL_BUNDLED",
        "missing": ["version-specific QML cache bytecode decoder and RCC payload extraction"],
    },
    "libgdx": {
        "engines": ["apktool.android", "dex.structural", "jadx.android", "elf.static", "native.deep-embedded"],
        "coverage": "FULL_BUNDLED",
    },
    "lua_runtime": {
        "engines": ["lua.static", "lua.bytecode-embedded", "native.deep-embedded"],
        "coverage": "FULL_BUNDLED",
    },
    "webview_hybrid": {
        "engines": ["javascript.static", "apktool.android", "dex.structural", "security.passive"],
        "coverage": "FULL_BUNDLED",
    },
    "webassembly": {
        "engines": ["webassembly.static", "webassembly.deep-embedded", "security.passive"],
        "coverage": "PARTIAL_BUNDLED",
        "missing": ["WebAssembly instruction-body disassembly/decompilation"],
    },
    "unknown": {
        "engines": ["apktool.android", "dex.structural", "jadx.android", "elf.static", "native.deep-embedded", "security.passive"],
        "coverage": "GENERIC_FALLBACK",
        "missing": ["specialized runtime decoder not identified"],
    },
}


def route(profile_report: dict[str, Any], output_path: str | Path | None = None) -> dict[str, Any]:
    profiles = profile_report.get("profiles") if isinstance(profile_report, dict) else []
    abis = {str(x) for x in (profile_report.get("abis") or [])} if isinstance(profile_report, dict) else set()
    routes: list[dict[str, Any]] = []
    selected: list[str] = []
    selected_set: set[str] = set()
    missing: list[str] = []

    for row in profiles if isinstance(profiles, list) else []:
        if not isinstance(row, dict):
            continue
        runtime_id = str(row.get("runtimeId") or "unknown")
        spec = dict(_ROUTES.get(runtime_id) or _ROUTES["unknown"])
        coverage = str(spec.get("coverage") or "GENERIC_FALLBACK")
        route_missing = [str(x) for x in (spec.get("missing") or [])]

        # native.deep-embedded currently has its deepest instruction/data-flow
        # implementation on AArch64. Other Android ABIs still receive ELF inventory.
        if runtime_id == "native_elf" and any(abi != "arm64-v8a" for abi in abis):
            coverage = "PARTIAL_BUNDLED"
            for abi in sorted(abi for abi in abis if abi != "arm64-v8a"):
                if abi == "armeabi-v7a":
                    route_missing.append(
                        "stripped binaries without usable unwind metadata, indirect branch/table target "
                        "recovery and interprocedural propagation beyond relocation-backed PLT veneers; "
                        "ELF symbols + ARM.exidx/.eh_frame_hdr exact function recovery, basic-block CFG, "
                        "cross-block identical-fact propagation, PC-relative literal flow, register/stack "
                        "arguments, portable relocations and dlsym result tracking are bundled"
                    )
                elif abi in {"x86", "x86_64"}:
                    route_missing.append(
                        f"stripped binaries without usable unwind metadata and without decoded direct-call/"
                        f"entry seeds, indirect jump-table target recovery and interprocedural propagation "
                        f"for {abi}; ELF symbols + .eh_frame_hdr exact recovery plus fail-closed Capstone "
                        "direct-call/ELF-entry seeding, basic-block CFG, cross-block identical-fact "
                        "propagation, register/stack argument flow, RIP/GOT relocation flow and dlsym "
                        "result tracking are bundled"
                    )
                else:
                    route_missing.append(
                        f"instruction-level CFG/data-flow backend for {abi}; "
                        "portable symbols/relocations are bundled"
                    )

        engines = [str(x) for x in spec.get("engines") or []]
        for engine_id in engines:
            if engine_id not in selected_set:
                selected_set.add(engine_id)
                selected.append(engine_id)
        for item in route_missing:
            if item not in missing:
                missing.append(item)

        routes.append({
            "id": "route:" + runtime_id,
            "runtimeId": runtime_id,
            "title": str(row.get("title") or runtime_id),
            "kind": "ENGINE_ROUTE",
            "category": "Engine/Router",
            "status": coverage,
            "coverage": coverage,
            "engines": engines,
            "missingBackends": route_missing,
            "evidence": row.get("evidence") or [],
            "patchReady": False,
            "automationExcluded": True,
            "ownershipKind": "ENGINE",
        })

    if not routes:
        spec = _ROUTES["unknown"]
        routes.append({
            "id": "route:unknown",
            "runtimeId": "unknown",
            "title": "Unknown / custom runtime fallback",
            "kind": "ENGINE_ROUTE",
            "category": "Engine/Router",
            "status": "GENERIC_FALLBACK",
            "coverage": "GENERIC_FALLBACK",
            "engines": list(spec["engines"]),
            "missingBackends": list(spec["missing"]),
            "patchReady": False,
            "automationExcluded": True,
            "ownershipKind": "ENGINE",
        })
        selected = list(spec["engines"])
        missing = list(spec["missing"])

    counts: dict[str, int] = {}
    for row in routes:
        key = str(row["coverage"])
        counts[key] = counts.get(key, 0) + 1

    out = {
        "schema": SCHEMA,
        "passive": True,
        "executesTargetCode": False,
        "runtimeProfileSchema": profile_report.get("schema") if isinstance(profile_report, dict) else None,
        "routeCount": len(routes),
        "coverageCounts": counts,
        "selectedEngineCount": len(selected),
        "selectedEngines": selected,
        "missingBackendCount": len(missing),
        "missingBackends": missing,
        "routes": routes,
    }
    if output_path:
        Path(output_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
