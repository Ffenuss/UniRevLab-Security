from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_analysis_storage_surfaces_all_embedded_deep_reports():
    storage = read("android/app/src/main/java/dev/modkit/mobile/AnalysisStorageActivity.java")
    for name in (
        "lua-deep.json",
        "hermes-deep.json",
        "native-deep.json",
        "cocos-deep.json",
        "flutter-deep.json",
        "automatic-evidence.json",
        "connected-report.json",
        "connected-report.md",
    ):
        assert name in storage
    assert "Cocos script↔native" in storage
    assert "Lua bytecode" in storage
    assert "DeepEvidenceActivity.class" in storage


def test_deep_evidence_screen_is_private_and_keeps_static_runtime_distinction():
    manifest = read("android/app/src/main/AndroidManifest.xml")
    activity = read("android/app/src/main/java/dev/modkit/mobile/DeepEvidenceActivity.java")
    assert '.DeepEvidenceActivity" android:exported="false"' in manifest
    for name in ("lua-deep.json", "hermes-deep.json", "native-deep.json", "cocos-deep.json", "flutter-deep.json"):
        assert name in activity
    assert "Exact RVA" in activity
    assert "runtime-наблюдение" in activity
    assert "indirect slots" in activity
    assert "original Dart source не заявляется" in activity


def test_report_center_exposes_connected_1_2_deep_coverage_and_streaming_export():
    center = read("android/app/src/main/java/dev/modkit/mobile/ReportCenterActivity.java")
    assert "connected-report 1.2" in center
    assert 'getModule("modkit.mobile.connected_report_streaming")' in center
    assert 'optInt("deepEnginesAvailable",0)' in center
    assert "deep backend'ов" in center
    assert "ExportProgress" in center
    assert "EvidenceBundleExporter.export" in center


def test_connected_report_keeps_base_coverage_and_v12_corroboration_schema():
    base = read("modkit/mobile/connected_report.py")
    v12 = read("modkit/mobile/connected_report_v12.py")
    streaming = read("modkit/mobile/connected_report_streaming.py")
    assert 'SCHEMA = "modkit-connected-report-1.1"' in base
    assert 'SCHEMA = "modkit-connected-report-1.2"' in v12
    assert '"engineCoverage": coverage' in base
    assert '"artifactGuide": evidence_guide' in base
    assert '"runtimeTruth"' in base
    assert '"lua-deep.json"' in base
    assert '"cocos-deep.json"' in base
    assert "_iter_jsonl" in streaming
    assert '"loadsFullMethodEvidenceIntoRam": False' in streaming
