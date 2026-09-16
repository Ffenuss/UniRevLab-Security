import json
from pathlib import Path

import pytest

from modkit.mobile.menu_native_recovery import _phase7_allowed_rvas, _validate_phase7_menu

ROOT = Path(__file__).resolve().parents[1]


def _plan():
    return {
        "schema": "modkit-automod-plan-1.4",
        "phase7Policy": {
            "schema": "modkit-automod-phase7-policy-1.0",
            "refinedCatalogRequiresControlCandidate": True,
        },
        "executableControlCount": 2,
        "candidates": [
            {
                "id": "direct",
                "executableControl": True,
                "stage": "READY_FOR_PREFLIGHT",
                "locator": {"rva": 0x1000},
            },
            {
                "id": "recovered",
                "executableControl": True,
                "stage": "READY_FOR_PREFLIGHT",
                "locator": {"methodId": 77, "rva": None},
                "resolvedLocator": {"rva": 0x2000, "source": "EXACT_CODEGENMODULE_RECOVERY"},
            },
            {
                "id": "runtime-only",
                "executableControl": False,
                "runtimeProbe": True,
                "stage": "RUNTIME_NEEDED",
                "locator": {"rva": 0x9000},
            },
        ],
    }


def test_phase7_allowlist_excludes_runtime_and_review_evidence():
    assert _phase7_allowed_rvas(_plan()) == {0x1000, 0x2000}


def test_phase7_menu_validation_accepts_only_current_plan_controls(tmp_path):
    (tmp_path / "menu-native-recovery.json").write_text(
        json.dumps({"completed": True, "phase7PlanRequired": True}), encoding="utf-8"
    )
    (tmp_path / "menu-spec.json").write_text(
        json.dumps({
            "controls": [
                {"id": "hp", "title": "HP", "type": "toggle", "binding": "bool_setter", "rva": 0x1000},
                {"id": "speed", "title": "Speed", "type": "slider_float", "binding": "number_setter", "rva": 0x2000, "finding_id": "deep.method.77"},
                {"id": "watch", "title": "Runtime watch", "type": "label", "rva": 0x9000, "probe_kind": "watch"},
            ]
        }),
        encoding="utf-8",
    )
    gate = _validate_phase7_menu(tmp_path, _plan(), {0x1000, 0x2000})
    assert gate["validated"] is True
    assert gate["validatedMenuControlCount"] == 2
    assert gate["rejectedControlCount"] == 0
    assert gate["methodIdentityRequiredForBoundRva"] is True
    assert gate["identityBoundRvaCount"] == 1
    assert gate["allowedMethodIdsByRva"]["0x2000"] == [77]
    stored = json.loads((tmp_path / "menu-native-recovery.json").read_text(encoding="utf-8"))
    assert stored["completed"] is True
    assert stored["phase7Gate"]["validated"] is True
    assert stored["phase7Gate"]["runtimeEvidencePromotesBuildability"] is False
    assert stored["phase7Gate"]["reviewEvidencePromotesBuildability"] is False


def test_phase7_menu_validation_rejects_same_rva_with_wrong_method_identity(tmp_path):
    (tmp_path / "menu-native-recovery.json").write_text(
        json.dumps({"completed": True, "phase7PlanRequired": True}), encoding="utf-8"
    )
    (tmp_path / "menu-spec.json").write_text(
        json.dumps({
            "controls": [
                {"id": "wrong", "type": "toggle", "binding": "bool_setter", "rva": 0x2000, "finding_id": "deep.method.78"},
            ]
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="outside current Evidence Graph allowlist"):
        _validate_phase7_menu(tmp_path, _plan(), {0x1000, 0x2000})
    stored = json.loads((tmp_path / "menu-native-recovery.json").read_text(encoding="utf-8"))
    rejected = stored["phase7Gate"]["rejected"]
    assert rejected[0]["reason"] == "method-identity-mismatch"
    assert rejected[0]["metadataMethodId"] == 78
    assert rejected[0]["expectedMetadataMethodIds"] == [77]


def test_phase7_menu_validation_fails_closed_on_legacy_bypass_control(tmp_path):
    (tmp_path / "menu-native-recovery.json").write_text(
        json.dumps({"completed": True, "phase7PlanRequired": True}), encoding="utf-8"
    )
    (tmp_path / "menu-spec.json").write_text(
        json.dumps({
            "controls": [
                {"id": "hp", "type": "toggle", "binding": "bool_setter", "rva": 0x1000},
                {"id": "legacy", "type": "toggle", "binding": "bool_setter", "rva": 0x9000},
            ]
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="outside current Evidence Graph allowlist"):
        _validate_phase7_menu(tmp_path, _plan(), {0x1000, 0x2000})
    stored = json.loads((tmp_path / "menu-native-recovery.json").read_text(encoding="utf-8"))
    assert stored["completed"] is False
    assert stored["phase7Gate"]["validated"] is False
    assert stored["phase7Gate"]["rejectedControlCount"] == 1
    assert stored["phase7Gate"]["rejected"][0]["rva"] == 0x9000
    assert stored["phase7Gate"]["rejected"][0]["reason"] == "rva-not-allowed"


def test_android_automod_surface_separates_lanes_and_requires_phase7_audit():
    activity = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModActivity.java").read_text(encoding="utf-8")
    verifier = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModAuditVerifier.java").read_text(encoding="utf-8")
    prepare = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModPrepareService.java").read_text(encoding="utf-8")
    recovery = (ROOT / "modkit/mobile/menu_native_recovery.py").read_text(encoding="utf-8")

    assert "controlsList" in activity
    assert "runtimeList" in activity
    assert "reviewList" in activity
    assert 'optInt("executableControlCount"' in activity
    assert 'optBoolean("refinedCatalogRequiresControlCandidate")' in activity
    assert "exactPrepareAuditReady()" in activity

    assert 'audit.optBoolean("phase7PlanRequired")' in verifier
    assert 'audit.optJSONObject("phase7Gate")' in verifier
    assert '"modkit-automod-phase7-prepare-gate-1.0"' in verifier
    assert 'phase7.optBoolean("methodIdentityRequiredForBoundRva")' in verifier
    assert 'phase7.optInt("rejectedControlCount",-1)!=0' in verifier
    assert 'fingerprint(rows,"phase7Plan")' in verifier
    assert 'fingerprint(rows,"simpleCatalog")' in verifier
    assert 'verify(rows,"phase7Plan",app.file("automod-plan.json"),gate)' in verifier
    assert 'verify(rows,"simpleCatalog",app.file("simple-catalog.json"),gate)' in verifier
    assert '"EXACT_PLAN_AND_CATALOG_SHA256"' in verifier
    assert 'AutoModAuditVerifier.bindPhase7Inputs' in prepare

    assert "automod_cancellable.build_workspace_plan" in recovery
    assert "_phase7_allowed_bindings(plan)" in recovery
    assert "_validate_phase7_menu(root, plan, allowed_rvas, cb, allowed_methods_by_rva)" in recovery


def test_legacy_menu_builder_cannot_launch_signed_il2cpp_build_or_leave_stale_audit():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/MenuBuilderActivity.java").read_text(encoding="utf-8")

    assert 'if(il2cpp){startActivity(new Intent(this,AutoModActivity.class));return;}' in source
    assert 'if(!il2cpp&&!app.file("menu-spec.json").isFile()' in source
    assert 'private boolean signedBuildOp(String op)' in source
    assert 'private boolean mutatesPreparedMenu(String op)' in source
    assert 'private void invalidateAutoModPreparedState()' in source
    assert '"menu-native-recovery.json"' in source
    assert 'if(mutatesPreparedMenu(op))invalidateAutoModPreparedState()' in source
    assert 'Io.writeUtf8(app.file("menu-spec.json"),o.toString(2));invalidateAutoModPreparedState();' in source
    for op in (
        "menu_build_apk",
        "menu_auto_build_apk",
        "menu_auto_build_apk_deep",
        "menu_autopilot_build_apk",
        "menu_probe_build_apk",
        "menu_smart_build_apk",
    ):
        assert f'"{op}".equals(op)' in source
    assert 'if(hasIl2cppPath()&&signedBuildOp(op))' in source
    assert 'toast("Подписанная IL2CPP-сборка выполняется только через AutoMod Phase 7")' in source
    assert 'button("Проверить готовность через AutoMod"' in source
    assert 'button("Собрать подписанный APK / APK-set через AutoMod"' in source
