import json
import zipfile

from modkit.menu import MenuControl, MenuSpec
from modkit.menu.callable_preflight import augment_preflight, verify_numeric_callable
from modkit.selftest import fixtures


def _numeric_control(rva=0x1040):
    return MenuControl(
        id="time_scale",
        title="IGameTime::set_timeScale",
        type="label",
        binding=None,
        target_so="libil2cpp.so",
        is_static=True,
        value_type="System.Single",
        suggested_type="slider_float",
        evidence_rva=rva,
        evidence_source="Assembly-CSharp.dll",
        evidence_kind="il2cpp-metadata-callable",
        evidence_location=f"RVA 0x{rva:x}",
        evidence_confidence=0.98,
        evidence_status="structural-confirmed",
        suggested_binding="number_setter",
        evidence_is_static=True,
        evidence_signature="void IGameTime__set_timeScale(float value, const MethodInfo* method)",
        call_abi="il2cpp",
        semantic_verified=True,
        semantic_status="verified-static-xref",
        context_verified=True,
        context_status="corroborated-static-context",
        method_verification={
            "addressConfirmed": True,
            "abiConfirmed": True,
            "executableReady": True,
        },
    )


def _apk(tmp_path):
    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    return apk


def test_verified_numeric_callable_does_not_invent_range_or_binding(tmp_path):
    apk = _apk(tmp_path)
    control = _numeric_control()

    report = verify_numeric_callable(control, apk)

    assert report["verified"] is True
    assert report["parameterPolicyRequired"] is True
    assert report["bindingCreated"] is False
    assert report["policyInferred"] is False
    assert report["suggestedType"] == "slider_float"
    assert report["elfVerification"]["rva"] == 0x1040
    assert control.binding is None
    assert control.type == "label"
    assert control.min_value is None and control.max_value is None


def test_numeric_callable_bad_rva_remains_unverified(tmp_path):
    apk = _apk(tmp_path)
    report = verify_numeric_callable(_numeric_control(0x7FFFFFFF), apk)

    assert report["verified"] is False
    assert report["blocker"] == "elf-preflight-block"
    assert any(row.get("severity") == "BLOCK" for row in report["issues"])


def test_augment_preflight_separates_callable_probe_and_modification_readiness(tmp_path):
    apk = _apk(tmp_path)
    control = _numeric_control()
    menu = MenuSpec("AFK", controls=[control]).json()
    menu_path = tmp_path / "menu-spec.json"
    menu_path.write_text(json.dumps(menu), encoding="utf-8")
    preflight_path = tmp_path / "menu-preflight.json"
    preflight_path.write_text(json.dumps({
        "schema": "modkit-menu-preflight-1.1",
        "counts": {
            "total": 1,
            "bound": 0,
            "probeReadOnly": 0,
            "evidenceOnly": 1,
            "unresolved": 0,
            "actionableReview": 1,
            "informationalReview": 0,
        },
        "controls": [{"id": "time_scale", "state": "evidence-only"}],
        "issues": [],
        "blocked": False,
        "readyForPayload": False,
        "readyForAutoBuild": False,
    }), encoding="utf-8")

    out = augment_preflight(menu_path, preflight_path, apk)

    assert out["counts"]["callableVerified"] == 1
    assert out["counts"]["callableVerifiedRangePending"] == 1
    assert out["controls"][0]["state"] == "callable-verified-range-pending"
    assert out["controls"][0]["callableVerified"] is True
    assert out["parameterPolicyPending"] == 1
    assert out["readyForModificationPayload"] is False
    assert out["readyForProbePayload"] is False
    assert out["readyForPayload"] is False
    assert out["readyForAutoBuild"] is False
    assert any(row.get("code") == "CALLABLE_VERIFIED_RANGE_PENDING" for row in out["issues"])

    persisted_menu = json.loads(menu_path.read_text(encoding="utf-8"))
    persisted_control = persisted_menu["controls"][0]
    assert persisted_control["binding"] is None
    assert persisted_control["type"] == "label"
    assert persisted_control["min_value"] is None
    assert persisted_control["max_value"] is None
