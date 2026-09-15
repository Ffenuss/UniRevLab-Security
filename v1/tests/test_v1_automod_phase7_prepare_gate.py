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
                {"id": "speed", "title": "Speed", "type": "slider_float", "binding": "number_setter", "rva": 0x2000},
                {"id": "watch", "title": "Runtime watch", "type": "label", "rva": 0x9000, "probe_kind": "watch"},
            ]
        }),
        encoding="utf-8",
    )
    gate = _validate_phase7_menu(tmp_path, _plan(), {0x1000, 0x2000})
    assert gate["validated"] is True
    assert gate["validatedMenuControlCount"] == 2
    assert gate["rejectedControlCount"] == 0
    stored = json.loads((tmp_path / "menu-native-recovery.json").read_text(encoding="utf-8"))
    assert stored["completed"] is True
    assert stored["phase7Gate"]["validated"] is True
    assert stored["phase7Gate"]["runtimeEvidencePromotesBuildability"] is False
    assert stored["phase7Gate"]["reviewEvidencePromotesBuildability"] is False


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


def test_android_automod_surface_separates_lanes_and_requires_phase7_audit():
    activity = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModActivity.java").read_text(encoding="utf-8")
    verifier = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModAuditVerifier.java").read_text(encoding="utf-8")
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
    assert 'phase7.optInt("rejectedControlCount",-1)!=0' in verifier

    assert "automod_cancellable.build_workspace_plan" in recovery
    assert "_phase7_allowed_rvas(plan)" in recovery
    assert "_validate_phase7_menu(root, plan, allowed_rvas, cb)" in recovery
