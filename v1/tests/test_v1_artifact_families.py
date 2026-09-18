from __future__ import annotations

from pathlib import Path
import zipfile

from modkit.engines import catalog
from modkit.mobile.artifact_families import scan_apk_paths


def _apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return path


def test_artifact_family_scanner_is_split_aware_and_honest(tmp_path: Path):
    base = _apk(tmp_path / "base.apk", {
        "assets/main.lua": b"-- player\nfunction Player.takeDamage(x) return x end\n",
        "assets/index.android.bundle": b"// bundle\nfunction setHealth(v){ return v; } // react-native\n",
        "assets/flutter_assets/vm_snapshot_data": b"snapshot-readable-marker",
        "lib/arm64-v8a/libapp.so": b"ELF dart_aot PlayerHealth damage currency",
    })
    split = _apk(tmp_path / "split_config.arm64_v8a.apk", {
        "assets/game.luac": b"\x1bLua\x53compiled-health-damage",
        "assets/main.hbc": b"Hermes bytecode health damage currency",
        "lib/arm64-v8a/libcocos2dcpp.so": b"ELF cocos gameplay",
    })
    report = scan_apk_paths([base, split])
    assert report["apkCount"] == 2
    assert report["familyCounts"]["lua"] >= 2
    assert report["familyCounts"]["javascript"] >= 1
    assert report["familyCounts"]["hermes"] >= 1
    assert report["familyCounts"]["flutter"] >= 2
    assert report["familyCounts"]["cocos"] >= 1
    artifact_rows = [row for row in report["artifacts"] if row["kind"] == "ARTIFACT_FAMILY"]
    by_entry = {row["entry"]: row for row in artifact_rows}
    assert by_entry["assets/main.lua"]["recoveryLevel"] == "DECOMPILED_SOURCE"
    assert by_entry["assets/game.luac"]["recoveryLevel"] == "DISASSEMBLED_METADATA"
    assert by_entry["lib/arm64-v8a/libapp.so"]["recoveryLevel"] == "NATIVE_AOT"
    assert by_entry["lib/arm64-v8a/libcocos2dcpp.so"]["recoveryLevel"] == "NATIVE_ENGINE"
    symbols = [row for row in report["artifacts"] if row["kind"] == "SCRIPT_SYMBOL"]
    damage = next(row for row in symbols if row["title"] == "Player.takeDamage")
    health = next(row for row in symbols if row["title"] == "setHealth")
    assert damage["status"] == "SCRIPT_CONTENT_SEARCH" and damage["entry"] == "assets/main.lua" and damage["line"] == 2
    assert health["entry"] == "assets/index.android.bundle" and health["line"] == 2
    assert report["symbolCount"] >= 2
    assert report["artifactCount"] == sum(report["familyCounts"].values())
    assert report["executesTargetCode"] is False


def test_registry_promotes_mobile_static_engines_but_not_heavy_desktop_tools():
    data = catalog()
    rows = {row["engine_id"]: row for row in data["engines"]}
    for engine_id in ("lua.static", "javascript.static", "hermes.static", "flutter.static", "cocos.static"):
        assert rows[engine_id]["bundled"] is True
    for engine_id in ("ghidra.bridge", "rizin.bridge", "cpp2il.bridge", "frida.local-bridge"):
        assert rows[engine_id]["bundled"] is False


def test_security_workspace_contract_records_artifact_family_report():
    source = Path("modkit/mobile/security_scan.py").read_text(encoding="utf-8")
    assert 'root / "artifact-families.json"' in source
    assert "artifact_families.scan_apk_paths" in source
    assert 'out["artifactFamilies"]' in source


def test_artifact_family_scanner_inventories_cross_platform_runtime_assets(tmp_path: Path):
    apk = _apk(tmp_path / "multi-runtime.apk", {
        "assemblies/App.dll": b"MZ managed assembly",
        "assets/pakchunk0-Android.pak": b"PAK" * 128,
        "assets/Hero.uasset": b"UE4 asset",
        "assets/game.pck": b"GDPC",
        "assets/player.gd": b"extends Node\nfunc take_damage(v):\n    return v\n",
        "assets/scene.tscn": b"[gd_scene]\n",
        "assets/game.arcd": b"defold archive",
        "assets/qml/Main.qml": b"Item { function setHealth(v) { return v } }",
        "assets/qml/cache.qmlc": b"QMLC bytecode",
        "assets/module.wasm": b"\x00asm\x01\x00\x00\x00",
    })
    report = scan_apk_paths([apk])
    counts = report["familyCounts"]
    assert counts["dotnet"] >= 1
    assert counts["unreal"] >= 2
    assert counts["godot"] >= 3
    assert counts["defold"] >= 1
    assert counts["qt_qml"] >= 2
    assert counts["webassembly"] >= 1

    artifacts = [row for row in report["artifacts"] if row["kind"] == "ARTIFACT_FAMILY"]
    by_entry = {row["entry"]: row for row in artifacts}
    assert by_entry["assemblies/App.dll"]["recoveryLevel"] == "MANAGED_ASSEMBLY"
    assert by_entry["assets/pakchunk0-Android.pak"]["recoveryLevel"] == "CONTAINER_INVENTORY"
    assert by_entry["assets/player.gd"]["representation"] == "gdscript-source"
    assert by_entry["assets/qml/Main.qml"]["representation"] == "qml-source"
    assert by_entry["assets/module.wasm"]["representation"] == "wasm-bytecode"

    symbols = [row for row in report["artifacts"] if row["kind"] == "SCRIPT_SYMBOL"]
    assert any(row["title"] == "take_damage" and row["family"] == "godot" for row in symbols)
    assert any(row["title"] == "setHealth" and row["family"] == "qt_qml" for row in symbols)
