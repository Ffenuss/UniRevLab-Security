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


def test_report_center_exposes_deep_coverage_in_export_status():
    center = read("android/app/src/main/java/dev/modkit/mobile/ReportCenterActivity.java")
    assert "connected-report 1.1" in center
    assert 'optInt("deepEnginesAvailable",0)' in center
    assert "deep backend'ов с evidence" in center
    assert "EvidenceBundleExporter.export" in center


def test_connected_report_has_structured_engine_coverage_and_artifact_guide():
    report = read("modkit/mobile/connected_report.py")
    assert 'SCHEMA = "modkit-connected-report-1.1"' in report
    assert '"engineCoverage": coverage' in report
    assert '"artifactGuide": evidence_guide' in report
    assert '"runtimeTruth"' in report
    assert '"lua-deep.json"' in report
    assert '"cocos-deep.json"' in report
