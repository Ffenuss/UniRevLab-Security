import json
from pathlib import Path

from modkit.mobile.connected_report_v12 import build_connected_report

ROOT = Path(__file__).resolve().parents[1]


def _json(path: Path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def test_connected_report_attaches_exact_native_recovery_without_promoting_buildability(tmp_path: Path):
    (tmp_path / "analysis.methods.jsonl").write_text(
        json.dumps({"id": 77, "class": "Game.Player", "name": "SetHealth", "rva": None}) + "\n",
        encoding="utf-8",
    )
    _json(tmp_path / "simple-catalog.json", {"cards": [{
        "id": "hp",
        "title": "SetHealth",
        "ownership": "APP_OR_GAME",
        "actionable": False,
        "buildable": False,
        "locator": {"methodId": 77, "class": "Game.Player", "method": "SetHealth", "rva": None},
    }]})
    _json(tmp_path / "il2cpp-no-rva-native.json", {
        "schema": "modkit-il2cpp-no-rva-native-1.0",
        "engine": "il2cpp.codegenmodule-native-recovery",
        "metadataVersion": 29,
        "resolvedModuleCount": 1,
        "counts": {"recoveredExact": 1},
        "addressResolver": True,
        "requiresUniqueExecutablePointer": True,
        "promotesBuildability": False,
    })
    (tmp_path / "il2cpp-no-rva-native.methods.jsonl").write_text(json.dumps({
        "id": 77,
        "metadataMethodId": 77,
        "metadataToken": "0x0600002a",
        "image": "Assembly-CSharp.dll",
        "class": "Game.Player",
        "methodName": "SetHealth",
        "status": "NATIVE_RVA_RECOVERED_EXACT_CODEGENMODULE",
        "rva": 0x345678,
        "rvaHex": "0x345678",
        "addressConfirmed": True,
        "associationConfirmed": True,
        "uniqueExecutablePointer": True,
        "moduleResolution": "EXACT_EXPECTED_METHOD_COUNT",
        "identityProof": "metadataMethodId+token+image+declaringType+methodName",
        "actionable": False,
        "buildable": False,
        "promotesBuildability": False,
    }) + "\n", encoding="utf-8")

    out_md = tmp_path / "connected-report.md"
    report = build_connected_report(tmp_path, tmp_path / "connected-report.json", out_md)
    finding = report["findings"][0]
    assert finding["nativeRvaRecovered"] is True
    assert finding["nativeRvaRecovery"]["rva"] == 0x345678
    assert finding["nativeRvaRecovery"]["addressConfirmed"] is True
    assert finding["nativeRvaRecovery"]["associationConfirmed"] is True
    assert finding["recoveredLocator"]["source"] == "EXACT_CODEGENMODULE_RECOVERY"
    assert finding["recoveredLocator"]["mayEnterPreflight"] is True
    assert finding["actionable"] is False
    assert finding["buildable"] is False
    assert report["nativeRvaRecoveredFindings"] == 1
    assert report["summary"]["nativeRvaRecoveredFindings"] == 1
    native = report["corroboration"]["il2cppNativeRvaRecovery"]
    assert native["addressResolver"] is True
    assert native["requiresUniqueExecutablePointer"] is True
    assert native["mayEnterPreflight"] is True
    assert native["promotesBuildability"] is False
    guide = {row["file"]: row for row in report["artifactGuide"]}
    assert guide["il2cpp-no-rva-native.json"]["available"] is True
    assert guide["il2cpp-no-rva-native.methods.jsonl"]["available"] is True
    assert "Exact native RVA recovered: 1" in out_md.read_text(encoding="utf-8")


def test_connected_report_rejects_non_unique_or_unconfirmed_native_recovery(tmp_path: Path):
    (tmp_path / "analysis.methods.jsonl").write_text(json.dumps({"id": 88, "name": "Foo", "rva": None}) + "\n", encoding="utf-8")
    _json(tmp_path / "simple-catalog.json", {"cards": [{"id": "foo", "title": "Foo", "buildable": False, "locator": {"methodId": 88, "class": "Game.X", "method": "Foo"}}]})
    _json(tmp_path / "il2cpp-no-rva-native.json", {"schema": "modkit-il2cpp-no-rva-native-1.0", "engine": "il2cpp.codegenmodule-native-recovery", "addressResolver": True, "promotesBuildability": False})
    (tmp_path / "il2cpp-no-rva-native.methods.jsonl").write_text(json.dumps({
        "id": 88, "metadataMethodId": 88, "class": "Game.X", "methodName": "Foo",
        "status": "NATIVE_RVA_RECOVERED_EXACT_CODEGENMODULE", "rva": 0x1234,
        "addressConfirmed": True, "associationConfirmed": True,
        "uniqueExecutablePointer": False, "promotesBuildability": False,
    }) + "\n", encoding="utf-8")
    report = build_connected_report(tmp_path)
    finding = report["findings"][0]
    assert finding.get("nativeRvaRecovery") is None
    assert finding.get("recoveredLocator") is None
    assert report["nativeRvaRecoveredFindings"] == 0
    assert finding["buildable"] is False


def test_automod_surface_shows_recovered_rva_separately_from_metadata_identity():
    activity = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModActivity.java").read_text(encoding="utf-8")
    assert "nativeRecoveredLocatorCount" in activity
    assert "nativeRvaRecovery" in activity
    assert "recovered RVA" in activity
    assert "exact recovery" in activity
    assert "binding/preflight" in activity
