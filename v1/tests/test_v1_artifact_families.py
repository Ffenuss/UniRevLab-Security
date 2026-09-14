from __future__ import annotations

from pathlib import Path
import json
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
        "assets/main.lua": b"function Player.takeDamage(x) return x end\n",
        "assets/index.android.bundle": b"function setHealth(v){ return v; } // react-native\n",
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
    by_entry = {row["entry"]: row for row in report["artifacts"]}
    assert by_entry["assets/main.lua"]["recoveryLevel"] == "DECOMPILED_SOURCE"
    assert by_entry["assets/game.luac"]["recoveryLevel"] == "DISASSEMBLED_METADATA"
    assert by_entry["lib/arm64-v8a/libapp.so"]["recoveryLevel"] == "NATIVE_AOT"
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
