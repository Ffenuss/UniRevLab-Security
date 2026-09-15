import json
from pathlib import Path

from modkit.mobile.connected_report_v13 import build_connected_report


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_connected_report_v13_attaches_no_rva_metadata_identity_fail_closed(tmp_path: Path):
    (tmp_path / "analysis.methods.jsonl").write_text(
        json.dumps({"id": 77, "name": "SetHealth", "class": "Game.Player", "rva": None}) + "\n",
        encoding="utf-8",
    )
    _write_json(
        tmp_path / "simple-catalog.json",
        {
            "total": 1,
            "important": 1,
            "buildable": 0,
            "actionable": 0,
            "serverAudit": 0,
            "cards": [{
                "id": "health-no-rva",
                "title": "SetHealth",
                "status": "APP_OWNED",
                "verificationStage": "APP_OWNED",
                "ownership": "APP_OR_GAME",
                "buildable": False,
                "actionable": False,
                "locator": {"methodId": 77, "class": "Game.Player", "method": "SetHealth", "rva": None},
            }],
        },
    )
    _write_json(tmp_path / "analysis.summary.json", {"targetProfile": "GAME"})
    _write_json(tmp_path / "embedded-analysis.json", {"schema": "test", "runs": []})
    _write_json(tmp_path / "artifact-families.json", {})
    _write_json(tmp_path / "security-surfaces.json", {})
    _write_json(tmp_path / "apktool-analysis.json", {})
    _write_json(
        tmp_path / "il2cpp-metadata-identity.json",
        {
            "schema": "modkit-il2cpp-metadata-identity-1.0",
            "engine": "il2cpp.metadata-identity-embedded",
            "typeLayout": "COMPACT_TYPEDEF_88",
            "counts": {"qualifiedMethodConfirmedNoRva": 1},
            "addressResolver": False,
            "actionable": False,
            "promotesBuildability": False,
        },
    )
    (tmp_path / "il2cpp-metadata-identity.methods.jsonl").write_text(
        json.dumps({
            "id": 77,
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

    out_json = tmp_path / "connected-report.json"
    out_md = tmp_path / "connected-report.md"
    report = build_connected_report(tmp_path, out_json, out_md)

    assert report["schema"] == "modkit-connected-report-1.3"
    assert report["metadataIdentityFindings"] == 1
    assert report["metadataQualifiedNoRvaFindings"] == 1
    finding = report["findings"][0]
    assert finding["metadataIdentityObserved"] is True
    assert finding["metadataIdentity"]["metadataQualifiedMethodPresent"] is True
    assert finding["metadataIdentity"]["addressConfirmed"] is False
    assert finding["metadataIdentity"]["rva"] is None
    assert finding["metadataIdentity"]["actionable"] is False
    assert finding["metadataIdentity"]["buildable"] is False
    assert finding["actionable"] is False
    assert finding["buildable"] is False
    corroboration = report["corroboration"]["il2cppMetadataIdentity"]
    assert corroboration["addressResolver"] is False
    assert corroboration["actionable"] is False
    assert corroboration["promotesBuildability"] is False

    guide = {row["file"]: row for row in report["artifactGuide"]}
    assert guide["il2cpp-metadata-identity.json"]["available"] is True
    assert guide["il2cpp-metadata-identity.methods.jsonl"]["available"] is True
    markdown = out_md.read_text(encoding="utf-8")
    assert "## IL2CPP metadata identity without RVA" in markdown
    assert "Exact Class::Method confirmations without RVA: 1" in markdown
    assert "RVA=unresolved" in markdown
    assert out_json.is_file()


def test_connected_report_v13_does_not_guess_ambiguous_name_only_identity(tmp_path: Path):
    (tmp_path / "analysis.methods.jsonl").write_text(
        json.dumps({"id": 1, "name": "SetHealth", "rva": None}) + "\n", encoding="utf-8"
    )
    _write_json(tmp_path / "simple-catalog.json", {
        "cards": [{"id": "health", "title": "SetHealth", "buildable": False, "actionable": False, "locator": {"rva": None}}]
    })
    (tmp_path / "il2cpp-metadata-identity.methods.jsonl").write_text(
        json.dumps({"id": 10, "class": "A.Player", "methodName": "SetHealth", "status": "METADATA_METHOD_NAME_PRESENT_NO_RVA", "addressConfirmed": False, "actionable": False, "buildable": False, "promotesBuildability": False}) + "\n" +
        json.dumps({"id": 11, "class": "B.Player", "methodName": "SetHealth", "status": "METADATA_METHOD_NAME_PRESENT_NO_RVA", "addressConfirmed": False, "actionable": False, "buildable": False, "promotesBuildability": False}) + "\n",
        encoding="utf-8",
    )
    _write_json(tmp_path / "il2cpp-metadata-identity.json", {"schema": "modkit-il2cpp-metadata-identity-1.0", "engine": "il2cpp.metadata-identity-embedded"})
    report = build_connected_report(tmp_path)
    assert report["metadataIdentityFindings"] == 0
    assert report["findings"][0]["metadataIdentityObserved"] is False
    assert "metadataIdentity" not in report["findings"][0]
