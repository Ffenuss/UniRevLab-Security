from __future__ import annotations

import json
from pathlib import Path

from modkit.mobile.connected_report_v12 import build_connected_report

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_connected_report_v12_attaches_runtime_and_il2cpp_without_promoting_buildability(tmp_path: Path):
    (tmp_path / "analysis.methods.jsonl").write_text(
        json.dumps({"id": 7, "name": "SetHealth", "rva": "0x1234", "class": "Player"}) + "\n",
        encoding="utf-8",
    )
    _write_json(
        tmp_path / "simple-catalog.json",
        {
            "total": 1,
            "important": 1,
            "buildable": 0,
            "actionable": 1,
            "serverAudit": 0,
            "cards": [{
                "id": "health-card",
                "title": "SetHealth",
                "status": "LOCATOR_CONFIRMED",
                "verificationStage": "LOCATOR_CONFIRMED",
                "ownership": "APP_OR_GAME",
                "buildable": False,
                "actionable": True,
                "locator": {"methodId": 7, "rva": "0x1234", "library": "libil2cpp.so"},
            }],
        },
    )
    _write_json(tmp_path / "analysis.summary.json", {"targetProfile": "GAME"})
    _write_json(tmp_path / "embedded-analysis.json", {"schema": "modkit-embedded-analysis-test", "runs": []})
    _write_json(tmp_path / "artifact-families.json", {})
    _write_json(tmp_path / "security-surfaces.json", {})
    _write_json(tmp_path / "apktool-analysis.json", {})
    _write_json(
        tmp_path / "runtime-correlation.json",
        {
            "schema": "modkit-runtime-correlation-1.0",
            "mode": "READ_ONLY_PROCFS_CORRELATION",
            "correlationCount": 1,
            "mappedRuntimeVaCount": 1,
            "correlations": [{
                "id": "health-card",
                "runtimeEvidence": "PROCFS_MODULE_LAYOUT",
                "rvaHex": "0x1234",
                "runtimeVaHex": "0x70001234",
                "loadBaseHex": "0x70000000",
                "modulePath": "/data/app/game/lib/arm64/libil2cpp.so",
                "moduleBasename": "libil2cpp.so",
                "mapped": True,
                "mappingPerms": "r-xp",
                "matchMode": "EXACT_LIBRARY_BASENAME",
                "promotesBuildability": False,
            }],
        },
    )
    _write_json(
        tmp_path / "il2cpp-crosscheck.json",
        {
            "schema": "modkit-il2cpp-crosscheck-1.0",
            "engine": "il2cpp.structural-crosscheck-embedded",
            "counts": {"structuralBothPresent": 1},
            "confirmsMethodToRvaAssociation": False,
            "promotesBuildability": False,
        },
    )
    (tmp_path / "il2cpp-crosscheck.methods.jsonl").write_text(
        json.dumps({
            "id": 7,
            "methodName": "SetHealth",
            "rva": 0x1234,
            "rvaHex": "0x1234",
            "metadataMethodNamePresent": True,
            "executableElfRangePresent": True,
            "elfRangeMode": "DIRECT_ELF_VADDR",
            "segmentIndex": 1,
            "status": "STRUCTURAL_BOTH_PRESENT",
            "associationConfirmed": False,
            "promotesBuildability": False,
        }) + "\n",
        encoding="utf-8",
    )

    out_json = tmp_path / "connected-report.json"
    out_md = tmp_path / "connected-report.md"
    report = build_connected_report(tmp_path, out_json, out_md)

    assert report["schema"] == "modkit-connected-report-1.2"
    assert report["findingCount"] == 1
    finding = report["findings"][0]
    assert finding["methodLinkStatus"] == "EXACT_METHOD_ID"
    assert finding["buildable"] is False
    assert finding["runtimeObserved"] is True
    assert finding["runtimeObservation"]["runtimeVaHex"] == "0x70001234"
    assert finding["runtimeObservation"]["promotesBuildability"] is False
    assert finding["il2cppStructuralObserved"] is True
    assert finding["il2cppStructural"]["status"] == "STRUCTURAL_BOTH_PRESENT"
    assert finding["il2cppStructural"]["associationConfirmed"] is False
    assert finding["il2cppStructural"]["promotesBuildability"] is False
    assert report["runtimeObservedFindings"] == 1
    assert report["il2cppStructuralFindings"] == 1
    assert report["il2cppStructuralBothFindings"] == 1
    assert report["corroboration"]["runtime"]["promotesBuildability"] is False
    assert report["corroboration"]["il2cppStructural"]["confirmsMethodToRvaAssociation"] is False
    assert report["corroboration"]["il2cppStructural"]["promotesBuildability"] is False

    guide = {row["file"]: row for row in report["artifactGuide"]}
    assert guide["runtime-correlation.json"]["available"] is True
    assert guide["il2cpp-crosscheck.json"]["available"] is True
    assert guide["il2cpp-crosscheck.methods.jsonl"]["available"] is True

    markdown = out_md.read_text(encoding="utf-8")
    assert "## Runtime / IL2CPP corroboration" in markdown
    assert "Runtime-observed findings: 1" in markdown
    assert "IL2CPP structural findings: 1" in markdown
    assert "associationConfirmed=false" in markdown
    assert out_json.is_file()


def test_connected_report_runtime_rva_fallback_requires_unique_observation(tmp_path: Path):
    (tmp_path / "analysis.methods.jsonl").write_text(
        json.dumps({"id": 1, "name": "Foo", "rva": "0x2000"}) + "\n", encoding="utf-8"
    )
    _write_json(tmp_path / "simple-catalog.json", {"cards": [{"id": "different-id", "title": "Foo", "buildable": False, "locator": {"rva": "0x2000"}}]})
    _write_json(tmp_path / "runtime-correlation.json", {
        "correlations": [
            {"id": "a", "runtimeEvidence": "PROCFS_MODULE_LAYOUT", "rvaHex": "0x2000", "runtimeVaHex": "0x70002000", "mapped": True, "promotesBuildability": False},
            {"id": "b", "runtimeEvidence": "PROCFS_MODULE_LAYOUT", "rvaHex": "0x2000", "runtimeVaHex": "0x80002000", "mapped": True, "promotesBuildability": False},
        ]
    })
    report = build_connected_report(tmp_path)
    assert report["findings"][0].get("runtimeObservation") is None
    assert report["runtimeObservedFindings"] == 0


def test_android_report_center_uses_enriched_connected_report_and_evidence_bundle():
    activity = (ROOT / "android/app/src/main/java/dev/modkit/mobile/ReportCenterActivity.java").read_text(encoding="utf-8")
    exporter = (ROOT / "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java").read_text(encoding="utf-8")
    assert 'getModule("modkit.mobile.connected_report_v12")' in activity
    assert "connected-report 1.2" in activity
    assert "runtimeObservedFindings" in activity
    assert "il2cppStructuralFindings" in activity
    assert "EvidenceBundleExporter.export" in activity
    assert '".jsonl"' in exporter
