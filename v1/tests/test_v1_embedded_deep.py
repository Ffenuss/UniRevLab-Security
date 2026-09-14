from __future__ import annotations

import json
from pathlib import Path
import zipfile

from modkit.arch import arm64
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


def _control_flow_apk(root: Path) -> Path:
    blob = bytearray(so_blob())
    # Fixture dynsym exposes functions at RVA 0x208 and 0x210. Make the first a
    # direct tail branch into the second, then make the second perform a classic
    # object -> table -> slot -> BLR indirect call. Target of BLR stays unknown.
    blob[0x208:0x20C] = arm64.b(0x210 - 0x208)
    blob[0x210:0x214] = arm64.ldr_imm(8, 0, 0, 8)
    blob[0x214:0x218] = arm64.ldr_imm(8, 8, 0x20, 8)
    blob[0x218:0x21C] = arm64.blr(8)
    blob[0x21C:0x220] = arm64.ret()
    apk = root / "game.apk"
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr("lib/arm64-v8a/libgame.so", bytes(blob))
    return apk


def test_embedded_native_scans_arm64_without_external_engine(tmp_path: Path):
    _flutter_apk(tmp_path)
    out = native_deep.scan_workspace(tmp_path, tmp_path / "native-deep.json")
    assert out["schema"] == "modkit-native-deep-1.1"
    assert out["engineId"] == "native.deep-embedded"
    assert out["bundled"] is True
    assert out["manualImportRequired"] is False
    assert out["executesTargetCode"] is False
    assert out["analyzedLibraryCount"] == 1
    lib = out["libraries"][0]
    assert lib["entry"] == "lib/arm64-v8a/libapp.so"
    assert lib["architecture"] == "aarch64"
    assert lib["status"] == "ANALYZED"


def test_embedded_native_recovers_tail_edge_and_structural_indirect_slot(tmp_path: Path):
    _control_flow_apk(tmp_path)
    out = native_deep.scan_workspace(tmp_path, tmp_path / "native-deep.json")
    lib = out["libraries"][0]
    rows = lib["controlFlow"]
    tail = next(row for row in rows if row["kind"] == "arm64-direct-b-tail")
    assert tail["sourceRva"] == 0x208
    assert tail["targetRva"] == 0x210
    assert tail["targetResolution"] == "EXACT_STATIC"

    indirect = next(row for row in rows if row["kind"] == "arm64-indirect-slot-blr")
    assert indirect["sourceRva"] == 0x210
    assert indirect["callRva"] == 0x218
    assert indirect["slotOffset"] == 0x20
    assert indirect["receiverRegister"] == 0
    assert indirect["tableLoadOffset"] == 0
    assert indirect["targetRva"] is None
    assert indirect["targetResolution"] == "STRUCTURAL_SLOT_ONLY"
    assert indirect["virtualDispatchCandidate"] is True
    assert lib["exactTailThunkCount"] >= 1
    assert lib["indirectSlotCallCount"] >= 1


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
