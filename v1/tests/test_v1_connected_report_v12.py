from __future__ import annotations

import json
import os
from pathlib import Path

from modkit.mobile.connected_report_v12 import build_connected_report, _fresh, _ensure_metadata_identity

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
    assert report["corroboration"]["il2cppStructural"]["freshnessVerified"] is False

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


def test_connected_report_attaches_exact_no_rva_metadata_identity_without_address_promotion(tmp_path: Path):
    (tmp_path / "analysis.methods.jsonl").write_text(
        json.dumps({"id": 42, "class": "Game.Player", "name": "SetHealth", "rva": None}) + "\n",
        encoding="utf-8",
    )
    _write_json(tmp_path / "simple-catalog.json", {
        "cards": [{
            "id": "health-no-rva",
            "title": "SetHealth",
            "buildable": False,
            "actionable": False,
            "locator": {"methodId": 42, "class": "Game.Player", "method": "SetHealth"},
        }]
    })
    _write_json(tmp_path / "il2cpp-metadata-identity.json", {
        "schema": "modkit-il2cpp-metadata-identity-1.0",
        "engine": "il2cpp.metadata-identity-embedded",
        "typeLayout": "COMPACT_TYPEDEF_88",
        "counts": {"qualifiedMethodConfirmedNoRva": 1},
        "addressResolver": False,
        "promotesBuildability": False,
    })
    (tmp_path / "il2cpp-metadata-identity.methods.jsonl").write_text(
        json.dumps({
            "id": 42,
            "class": "Game.Player",
            "methodName": "SetHealth",
            "status": "METADATA_QUALIFIED_METHOD_CONFIRMED_NO_RVA",
            "metadataMethodNamePresent": True,
            "metadataQualifiedMethodPresent": True,
            "addressConfirmed": False,
            "rva": None,
            "actionable": False,
            "buildable": False,
            "promotesBuildability": False,
        }) + "\n",
        encoding="utf-8",
    )
    out_md = tmp_path / "connected-report.md"
    report = build_connected_report(tmp_path, tmp_path / "connected-report.json", out_md)
    finding = report["findings"][0]
    assert finding["buildable"] is False
    assert finding["actionable"] is False
    assert finding["metadataIdentityConfirmed"] is True
    assert finding["metadataIdentity"]["status"] == "METADATA_QUALIFIED_METHOD_CONFIRMED_NO_RVA"
    assert finding["metadataIdentity"]["addressConfirmed"] is False
    assert finding["metadataIdentity"]["rva"] is None
    assert finding["metadataIdentity"]["actionable"] is False
    assert finding["metadataIdentity"]["buildable"] is False
    assert finding["metadataIdentity"]["promotesBuildability"] is False
    assert report["metadataIdentityConfirmedFindings"] == 1
    assert report["metadataQualifiedIdentityFindings"] == 1
    assert report["metadataTokenIdentityFindings"] == 0
    assert report["corroboration"]["il2cppMetadataIdentity"]["addressResolver"] is False
    assert report["corroboration"]["il2cppMetadataIdentity"]["promotesBuildability"] is False
    assert report["corroboration"]["il2cppMetadataIdentity"]["freshnessVerified"] is False
    assert "No-RVA metadata identity confirmed: 1" in out_md.read_text(encoding="utf-8")


def test_connected_report_attaches_unique_token_identity_without_rva_or_promotion(tmp_path: Path):
    (tmp_path / "analysis.methods.jsonl").write_text(
        json.dumps({"id": 77, "class": "Game.Player", "name": "SetHealth", "token": "0x0600002a", "rva": None}) + "\n",
        encoding="utf-8",
    )
    _write_json(tmp_path / "simple-catalog.json", {"cards": [{
        "id": "token-health",
        "title": "SetHealth",
        "buildable": False,
        "actionable": False,
        "locator": {"methodId": 77, "class": "Game.Player", "method": "SetHealth", "rva": None},
    }]})
    _write_json(tmp_path / "il2cpp-metadata-identity.json", {
        "schema": "modkit-il2cpp-metadata-identity-1.1",
        "engine": "il2cpp.metadata-identity-embedded",
        "uniqueMethodTokenCount": 4,
        "counts": {"tokenMethodConfirmedNoRva": 1, "tokenConflictNoRva": 0},
        "addressResolver": False,
        "promotesBuildability": False,
    })
    (tmp_path / "il2cpp-metadata-identity.methods.jsonl").write_text(json.dumps({
        "id": 77,
        "class": "Game.Player",
        "methodName": "SetHealth",
        "status": "METADATA_TOKEN_METHOD_CONFIRMED_NO_RVA",
        "metadataMethodNamePresent": True,
        "metadataQualifiedMethodPresent": True,
        "metadataToken": "0x0600002a",
        "metadataTokenConfirmed": True,
        "metadataTokenConflict": False,
        "metadataResolvedClass": "Game.Player",
        "metadataResolvedMethodName": "SetHealth",
        "addressConfirmed": False,
        "rva": None,
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }) + "\n", encoding="utf-8")

    report = build_connected_report(tmp_path)
    finding = report["findings"][0]
    assert finding["metadataIdentityConfirmed"] is True
    assert finding["metadataIdentity"]["metadataToken"] == "0x0600002a"
    assert finding["metadataIdentity"]["metadataTokenConfirmed"] is True
    assert finding["metadataIdentity"]["rva"] is None
    assert finding["actionable"] is False
    assert finding["buildable"] is False
    assert report["metadataIdentityConfirmedFindings"] == 1
    assert report["metadataTokenIdentityFindings"] == 1
    assert report["metadataTokenConflictFindings"] == 0
    assert report["corroboration"]["il2cppMetadataIdentity"]["uniqueMethodTokenCount"] == 4


def test_connected_report_token_conflict_is_visible_but_never_confirmation(tmp_path: Path):
    (tmp_path / "analysis.methods.jsonl").write_text(
        json.dumps({"id": 88, "class": "Game.Player", "name": "SetHealth", "token": "0x0600002b", "rva": None}) + "\n",
        encoding="utf-8",
    )
    _write_json(tmp_path / "simple-catalog.json", {"cards": [{
        "id": "conflict-health",
        "title": "SetHealth",
        "buildable": False,
        "actionable": False,
        "locator": {"methodId": 88, "class": "Game.Player", "method": "SetHealth", "rva": None},
    }]})
    _write_json(tmp_path / "il2cpp-metadata-identity.json", {
        "schema": "modkit-il2cpp-metadata-identity-1.1",
        "engine": "il2cpp.metadata-identity-embedded",
        "counts": {"tokenMethodConfirmedNoRva": 0, "tokenConflictNoRva": 1},
        "addressResolver": False,
        "promotesBuildability": False,
    })
    (tmp_path / "il2cpp-metadata-identity.methods.jsonl").write_text(json.dumps({
        "id": 88,
        "class": "Game.Player",
        "methodName": "SetHealth",
        "status": "METADATA_TOKEN_CONFLICT_NO_RVA",
        "metadataToken": "0x0600002b",
        "metadataTokenConfirmed": False,
        "metadataTokenConflict": True,
        "metadataResolvedClass": "Game.Enemy",
        "metadataResolvedMethodName": "SetHealth",
        "addressConfirmed": False,
        "rva": None,
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }) + "\n", encoding="utf-8")

    report = build_connected_report(tmp_path)
    finding = report["findings"][0]
    assert finding["metadataIdentityConfirmed"] is False
    assert finding.get("metadataIdentity") is None
    assert finding["metadataIdentityConflict"]["status"] == "METADATA_TOKEN_CONFLICT_NO_RVA"
    assert finding["metadataIdentityConflict"]["metadataTokenConflict"] is True
    assert finding["metadataIdentityConflict"]["actionable"] is False
    assert finding["metadataIdentityConflict"]["buildable"] is False
    assert finding["actionable"] is False
    assert finding["buildable"] is False
    assert report["metadataIdentityConfirmedFindings"] == 0
    assert report["metadataTokenIdentityFindings"] == 0
    assert report["metadataTokenConflictFindings"] == 1
    assert report["metadataTokenConflictRows"] == 1


def test_connected_report_freshness_guard_invalidates_outputs_after_method_catalog_changes(tmp_path: Path):
    metadata = tmp_path / "metadata.bin"
    methods = tmp_path / "analysis.methods.jsonl"
    summary = tmp_path / "il2cpp-metadata-identity.json"
    rows = tmp_path / "il2cpp-metadata-identity.methods.jsonl"
    metadata.write_bytes(b"metadata")
    methods.write_text("old\n", encoding="utf-8")
    summary.write_text("{}", encoding="utf-8")
    rows.write_text("{}\n", encoding="utf-8")
    newest_output = max(summary.stat().st_mtime_ns, rows.stat().st_mtime_ns)
    old_input = min(metadata.stat().st_mtime_ns, methods.stat().st_mtime_ns)
    if old_input > newest_output:
        os.utime(metadata, ns=(newest_output - 1_000_000, newest_output - 1_000_000))
        os.utime(methods, ns=(newest_output - 1_000_000, newest_output - 1_000_000))
    assert _fresh([summary, rows], [metadata, methods]) is True
    future = max(summary.stat().st_mtime_ns, rows.stat().st_mtime_ns) + 10_000_000
    os.utime(methods, ns=(future, future))
    assert _fresh([summary, rows], [metadata, methods]) is False


def test_connected_report_rebuilds_fresh_but_old_metadata_identity_schema(tmp_path: Path, monkeypatch):
    metadata = tmp_path / "metadata.bin"
    methods = tmp_path / "analysis.methods.jsonl"
    summary = tmp_path / "il2cpp-metadata-identity.json"
    rows = tmp_path / "il2cpp-metadata-identity.methods.jsonl"
    metadata.write_bytes(b"raw-metadata")
    methods.write_text("{}\n", encoding="utf-8")
    _write_json(summary, {"schema": "modkit-il2cpp-metadata-identity-1.0", "engine": "old"})
    rows.write_text("{}\n", encoding="utf-8")
    newer = max(summary.stat().st_mtime_ns, rows.stat().st_mtime_ns)
    older = newer - 10_000_000
    os.utime(metadata, ns=(older, older))
    os.utime(methods, ns=(older, older))
    assert _fresh([summary, rows], [metadata, methods]) is True

    called = {"value": False}
    import modkit.mobile.il2cpp_metadata_identity as identity_module

    def fake_build(workspace, output_path):
        called["value"] = True
        Path(workspace, "il2cpp-metadata-identity.methods.jsonl").write_text("{}\n", encoding="utf-8")
        value = {"schema": "modkit-il2cpp-metadata-identity-1.1", "engine": "new", "counts": {}}
        Path(output_path).write_text(json.dumps(value), encoding="utf-8")
        return value

    monkeypatch.setattr(identity_module, "build_workspace_identity", fake_build)
    result = _ensure_metadata_identity(tmp_path)
    assert called["value"] is True
    assert result["schema"] == "modkit-il2cpp-metadata-identity-1.1"
    assert result["freshnessVerified"] is True
    assert result["sourceInputsAvailable"] is True


def test_android_report_center_uses_enriched_connected_report_and_evidence_bundle():
    activity = (ROOT / "android/app/src/main/java/dev/modkit/mobile/ReportCenterActivity.java").read_text(encoding="utf-8")
    exporter = (ROOT / "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java").read_text(encoding="utf-8")
    automatic = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java").read_text(encoding="utf-8")
    assert 'getModule("modkit.mobile.connected_report_v12")' in activity
    assert "connected-report 1.2" in activity
    assert "runtimeObservedFindings" in activity
    assert "il2cppStructuralFindings" in activity
    assert "metadataTokenIdentityFindings" in activity
    assert "metadataTokenConflictFindings" in activity
    assert "token conflicts" in activity
    assert "EvidenceBundleExporter.export" in activity
    assert '".jsonl"' in exporter
    assert 'getModule("modkit.mobile.connected_report_v12")' in automatic
    assert 'app.file("connected-report.json")' in automatic
    assert 'app.file("connected-report.md")' in automatic
    assert '"metadataTokenNoRva"' in automatic
    assert '"metadataTokenConflicts"' in automatic
