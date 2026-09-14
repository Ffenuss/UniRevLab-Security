from __future__ import annotations

import json
from pathlib import Path
import zipfile

from modkit.mobile import embedded_pipeline, flutter_deep, native_deep, security_scan
from modkit.selftest.fixtures import so_blob


def _flutter_apk(root: Path) -> Path:
    apk = root / "game.apk"
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr("lib/arm64-v8a/libapp.so", so_blob())
        z.writestr(
            "assets/flutter_assets/isolate_snapshot_data",
            b"package:demo/player.dart\x00HealthWidget\x00/store\x00Navigator\x00premium\x00",
        )
        z.writestr("assets/flutter_assets/AssetManifest.json", b'{"assets/hero.png":["assets/hero.png"]}')
    return apk


def test_embedded_native_scans_arm64_without_external_engine(tmp_path: Path):
    _flutter_apk(tmp_path)
    out = native_deep.scan_workspace(tmp_path, tmp_path / "native-deep.json")
    assert out["schema"] == "modkit-native-deep-1.0"
    assert out["engineId"] == "native.deep-embedded"
    assert out["bundled"] is True
    assert out["manualImportRequired"] is False
    assert out["executesTargetCode"] is False
    assert out["analyzedLibraryCount"] == 1
    lib = out["libraries"][0]
    assert lib["entry"] == "lib/arm64-v8a/libapp.so"
    assert lib["architecture"] == "aarch64"
    assert lib["status"] == "ANALYZED"


def test_embedded_flutter_correlates_snapshot_and_native_aot(tmp_path: Path):
    _flutter_apk(tmp_path)
    native = native_deep.scan_workspace(tmp_path, tmp_path / "native-deep.json")
    out = flutter_deep.scan_workspace(tmp_path, native, tmp_path / "flutter-deep.json")
    assert out["schema"] == "modkit-flutter-deep-1.0"
    assert out["engineId"] == "flutter.aot-embedded"
    assert out["bundled"] is True
    assert out["manualImportRequired"] is False
    assert out["originalDartSourceClaimed"] is False
    assert out["detected"] is True
    assert any(row.get("kind") == "DART_AOT_ELF" for row in out["artifacts"])
    titles = {str(row.get("title")) for row in out["findings"]}
    assert "package:demo/player.dart" in titles
    assert "HealthWidget" in titles


def test_embedded_pipeline_merges_deep_evidence_and_security_preserves_it(tmp_path: Path):
    _flutter_apk(tmp_path)
    result = embedded_pipeline.run_workspace(
        tmp_path,
        tmp_path / "artifact-families.json",
        tmp_path / "embedded-analysis.json",
    )
    assert result["manualImportRequired"] is False
    run_ids = {row.get("engineId") for row in result["runs"]}
    assert "native.deep-embedded" in run_ids
    assert "flutter.aot-embedded" in run_ids

    artifacts = json.loads((tmp_path / "artifact-families.json").read_text(encoding="utf-8"))
    assert artifacts["embeddedEnriched"] is True
    assert artifacts["deepNative"]["engineId"] == "native.deep-embedded"
    assert artifacts["deepFlutter"]["engineId"] == "flutter.aot-embedded"
    before_ids = {row.get("id") for row in artifacts["artifacts"] if isinstance(row, dict)}

    security = security_scan.scan_workspace(tmp_path, tmp_path / "security-surfaces.json")
    assert security["artifactFamilies"]["reusedEnrichedReport"] is True
    after = json.loads((tmp_path / "artifact-families.json").read_text(encoding="utf-8"))
    after_ids = {row.get("id") for row in after["artifacts"] if isinstance(row, dict)}
    assert after_ids == before_ids
    assert after["deepNative"]["engineId"] == "native.deep-embedded"
    assert after["deepFlutter"]["engineId"] == "flutter.aot-embedded"
