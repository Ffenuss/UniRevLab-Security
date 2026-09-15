import json
from pathlib import Path

from modkit.mobile.connected_report_v12 import build_connected_report


def _write_json(path: Path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def _success(method_id=77, cls="Game.Player", method="SetHealth"):
    return {
        "id": method_id,
        "metadataMethodId": method_id,
        "metadataToken": "0x0600002a",
        "image": "Assembly-CSharp.dll",
        "class": cls,
        "methodName": method,
        "status": "NATIVE_RVA_RECOVERED_EXACT_CODEGENMODULE",
        "rva": 0x345678,
        "rvaHex": "0x345678",
        "addressConfirmed": True,
        "associationConfirmed": True,
        "uniqueExecutablePointer": True,
        "moduleResolution": "EXACT_EXPECTED_METHOD_COUNT",
        "promotesBuildability": False,
        "actionable": False,
        "buildable": False,
    }


def _blocker(method_id=77, cls="Other.Player", method="SetHealth"):
    return {
        "id": method_id,
        "metadataMethodId": method_id,
        "metadataToken": "0x0600002a",
        "image": "Assembly-CSharp.dll",
        "class": cls,
        "methodName": method,
        "status": "NATIVE_RVA_IDENTITY_CONFLICT",
        "blockers": ["declaring-type-mismatch"],
        "metadataResolvedClass": "Game.Player",
        "metadataResolvedMethodName": method,
        "rva": None,
        "addressConfirmed": False,
        "associationConfirmed": False,
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }


def _native_summary():
    return {
        "schema": "modkit-il2cpp-no-rva-native-1.0",
        "engine": "il2cpp.codegenmodule-native-recovery",
        "addressResolver": True,
        "requiresUniqueExecutablePointer": True,
        "failureRowsFile": "il2cpp-no-rva-native.failures.jsonl",
        "failuresAreFileBacked": True,
        "statusCounts": {"NATIVE_RVA_IDENTITY_CONFLICT": 1},
        "promotesBuildability": False,
    }


def test_connected_report_rejects_method_id_recovery_when_declaring_class_conflicts_and_explains_blocker(tmp_path: Path):
    (tmp_path / "analysis.methods.jsonl").write_text("", encoding="utf-8")
    _write_json(tmp_path / "simple-catalog.json", {"cards": [{
        "id": "hp",
        "title": "SetHealth",
        "actionable": False,
        "buildable": False,
        "locator": {"methodId": 77, "class": "Other.Player", "method": "SetHealth", "rva": None},
    }]})
    _write_json(tmp_path / "il2cpp-no-rva-native.json", _native_summary())
    (tmp_path / "il2cpp-no-rva-native.methods.jsonl").write_text(json.dumps(_success()) + "\n", encoding="utf-8")
    (tmp_path / "il2cpp-no-rva-native.failures.jsonl").write_text(json.dumps(_blocker()) + "\n", encoding="utf-8")

    out_md = tmp_path / "connected-report.md"
    report = build_connected_report(tmp_path, tmp_path / "connected-report.json", out_md)
    finding = report["findings"][0]

    assert finding.get("nativeRvaRecovery") is None
    assert finding.get("recoveredLocator") is None
    assert finding["nativeRvaRecovered"] is False
    assert finding["nativeRvaBlocker"]["status"] == "NATIVE_RVA_IDENTITY_CONFLICT"
    assert finding["nativeRvaBlocker"]["blockers"] == ["declaring-type-mismatch"]
    assert finding["actionable"] is False
    assert finding["buildable"] is False
    assert report["nativeRvaRecoveredFindings"] == 0
    assert report["nativeRvaBlockedFindings"] == 1
    assert report["nativeRvaBlockerStatusCounts"] == {"NATIVE_RVA_IDENTITY_CONFLICT": 1}
    assert "IL2CPP native recovery: BLOCKED" in out_md.read_text(encoding="utf-8")


def test_connected_report_never_uses_short_declaring_class_for_recovered_rva(tmp_path: Path):
    (tmp_path / "analysis.methods.jsonl").write_text("", encoding="utf-8")
    _write_json(tmp_path / "simple-catalog.json", {"cards": [{
        "id": "hp",
        "title": "SetHealth",
        "actionable": False,
        "buildable": False,
        "locator": {"class": "Player", "method": "SetHealth", "rva": None},
    }]})
    _write_json(tmp_path / "il2cpp-no-rva-native.json", _native_summary())
    (tmp_path / "il2cpp-no-rva-native.methods.jsonl").write_text(json.dumps(_success()) + "\n", encoding="utf-8")
    (tmp_path / "il2cpp-no-rva-native.failures.jsonl").write_text("", encoding="utf-8")

    report = build_connected_report(tmp_path)
    finding = report["findings"][0]
    assert finding.get("nativeRvaRecovery") is None
    assert finding.get("recoveredLocator") is None
    assert report["nativeRvaRecoveredFindings"] == 0


def test_connected_report_exposes_file_backed_failure_provenance_without_loading_it_as_native_successes(tmp_path: Path):
    (tmp_path / "analysis.methods.jsonl").write_text("", encoding="utf-8")
    _write_json(tmp_path / "simple-catalog.json", {"cards": []})
    _write_json(tmp_path / "il2cpp-no-rva-native.json", _native_summary())
    (tmp_path / "il2cpp-no-rva-native.methods.jsonl").write_text("", encoding="utf-8")
    (tmp_path / "il2cpp-no-rva-native.failures.jsonl").write_text(json.dumps(_blocker()) + "\n", encoding="utf-8")

    report = build_connected_report(tmp_path)
    native = report["corroboration"]["il2cppNativeRvaRecovery"]
    guide = {row["file"]: row for row in report["artifactGuide"]}
    assert native["failureRowsFile"] == "il2cpp-no-rva-native.failures.jsonl"
    assert native["failuresAreFileBacked"] is True
    assert native["statusCounts"] == {"NATIVE_RVA_IDENTITY_CONFLICT": 1}
    assert guide["il2cpp-no-rva-native.failures.jsonl"]["available"] is True
