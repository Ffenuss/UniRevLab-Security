from __future__ import annotations

from pathlib import Path
import zipfile

from modkit.mobile import engine_router, runtime_profiler


def _apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_runtime_profiler_is_multi_label_for_mixed_android_stack(tmp_path: Path):
    apk = _apk(tmp_path / "base.apk", {
        "classes.dex": (
            b"dex\n035\x00"
            b"com/facebook/react HermesInternal Microsoft/Maui "
            b"com/getcapacitor android/webkit/WebView"
        ),
        "lib/arm64-v8a/libil2cpp.so": b"\x7fELF",
        "assets/bin/Data/Managed/Metadata/global-metadata.dat": b"meta",
        "assets/bin/Data/Managed/Assembly-CSharp.dll": b"MZ",
        "lib/arm64-v8a/libUE4.so": b"\x7fELF",
        "assets/pakchunk0-Android.pak": b"pak",
        "lib/arm64-v8a/libflutter.so": b"\x7fELF",
        "lib/arm64-v8a/libapp.so": b"\x7fELF",
        "assets/flutter_assets/AssetManifest.json": b"{}",
        "lib/arm64-v8a/libhermes.so": b"\x7fELF",
        "assemblies/App.dll": b"MZ",
        "assets/public/index.html": b"<html></html>",
        "lib/arm64-v8a/libcocos2dcpp.so": b"\x7fELF",
        "lib/arm64-v8a/libgodot_android.so": b"\x7fELF",
        "assets/game.pck": b"GDPC",
        "lib/arm64-v8a/libdmengine.so": b"\x7fELF",
        "assets/game.projectc": b"defold",
        "lib/arm64-v8a/libQt6Core.so": b"\x7fELF",
        "assets/qml/main.qml": b"Item {}",
        "lib/arm64-v8a/libgdx.so": b"\x7fELF",
        "assets/main.lua": b"return {}",
    })

    report = runtime_profiler.scan_apk_paths([apk])
    detected = set(report["detected"])
    assert {
        "android_dex", "native_elf", "unity_il2cpp", "unity_mono", "unreal",
        "flutter", "react_native_hermes", "dotnet_android", "capacitor",
        "webview_hybrid", "cocos", "godot", "defold", "qt_qml", "libgdx",
        "lua_runtime",
    }.issubset(detected)
    assert report["abis"] == ["arm64-v8a"]
    assert report["profileCount"] == len(report["profiles"])
    assert all(row["patchReady"] is False for row in report["profiles"])
    assert all(row["automationExcluded"] is True for row in report["profiles"])

    routed = engine_router.route(report)
    assert routed["routeCount"] == report["profileCount"]
    assert "apktool.android" in routed["selectedEngines"]
    assert "il2cpp.rodroid" in routed["selectedEngines"]
    assert "flutter.aot-embedded" in routed["selectedEngines"]
    assert "hermes.deep-embedded" in routed["selectedEngines"]
    assert "cocos.deep-embedded" in routed["selectedEngines"]

    routes = {row["runtimeId"]: row for row in routed["routes"]}
    assert routes["unity_il2cpp"]["coverage"] == "FULL_BUNDLED"
    assert routes["unreal"]["coverage"] == "PARTIAL_BUNDLED"
    assert "unreal.deep-embedded" in routes["unreal"]["engines"]
    assert routes["dotnet_android"]["coverage"] == "PARTIAL_BUNDLED"
    assert routes["godot"]["coverage"] == "PARTIAL_BUNDLED"
    assert "godot.deep-embedded" in routes["godot"]["engines"]
    assert routes["qt_qml"]["coverage"] == "PARTIAL_BUNDLED"
    assert routes["libgdx"]["coverage"] == "FULL_BUNDLED"


def test_router_marks_non_arm64_native_deep_backend_partial(tmp_path: Path):
    apk = _apk(tmp_path / "x86.apk", {
        "lib/x86_64/libgame.so": b"\x7fELF",
    })
    profile = runtime_profiler.scan_apk_paths([apk])
    assert profile["detected"] == ["native_elf"]
    assert profile["abis"] == ["x86_64"]

    routed = engine_router.route(profile)
    row = routed["routes"][0]
    assert row["runtimeId"] == "native_elf"
    assert row["coverage"] == "PARTIAL_BUNDLED"
    assert any("x86_64" in item for item in row["missingBackends"])


def test_unknown_package_gets_generic_fallback_not_empty_support(tmp_path: Path):
    apk = _apk(tmp_path / "unknown.apk", {
        "assets/custom.vm": b"opaque custom runtime",
    })
    profile = runtime_profiler.scan_apk_paths([apk])
    assert profile["detected"] == ["unknown"]
    route = engine_router.route(profile)
    assert route["routes"][0]["coverage"] == "GENERIC_FALLBACK"
    assert route["missingBackendCount"] >= 1
    assert "security.passive" in route["selectedEngines"]


def test_embedded_pipeline_publishes_universal_reports():
    root = Path(__file__).resolve().parents[1]
    source = (root / "modkit/mobile/embedded_pipeline.py").read_text(encoding="utf-8")
    assert 'root / "runtime-profiler.json"' in source
    assert 'root / "engine-router.json"' in source
    assert 'root / "deobfuscation.json"' in source
    assert '"Embedded 14/14 · gameplay semantic correlation…"' in source
