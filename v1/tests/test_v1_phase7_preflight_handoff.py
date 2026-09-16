import hashlib
import json
from pathlib import Path

import pytest

from modkit.menu.phase7_guard import Phase7PreflightError, verify_preflight_workspace


def _fp(role: str, path: Path):
    data = path.read_bytes()
    return {"role": role, "name": path.name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _workspace(tmp_path: Path):
    files = {
        "metadata": tmp_path / "metadata.bin",
        "library": tmp_path / "library.so",
        "catalog": tmp_path / "analysis.methods.jsonl",
        "sourceApk": tmp_path / "game.apk",
        "phase7Plan": tmp_path / "automod-plan.json",
        "simpleCatalog": tmp_path / "simple-catalog.json",
        "menuSpec": tmp_path / "menu-spec.json",
    }
    for i, (role, path) in enumerate(files.items()):
        path.write_bytes((role + ":" + str(i)).encode("utf-8"))
    audit = {
        "completed": True,
        "phase7PlanRequired": True,
        "freshnessPolicy": "EXACT_INPUT_SHA256",
        "phase7FreshnessPolicy": "EXACT_PLAN_AND_CATALOG_SHA256",
        "inputFingerprints": [_fp(role, files[role]) for role in (
            "metadata", "library", "catalog", "sourceApk", "phase7Plan", "simpleCatalog"
        )],
        "outputFingerprints": [_fp("menuSpec", files["menuSpec"])],
        "phase7Gate": {
            "schema": "modkit-automod-phase7-prepare-gate-1.0",
            "validated": True,
            "methodIdentityRequiredForBoundRva": True,
            "rejectedControlCount": 0,
            "validatedMenuControlCount": 2,
            "identityBoundRvaCount": 1,
            "runtimeEvidencePromotesBuildability": False,
            "reviewEvidencePromotesBuildability": False,
        },
    }
    (tmp_path / "menu-native-recovery.json").write_text(json.dumps(audit), encoding="utf-8")
    return files


def test_phase7_preflight_guard_rechecks_every_bound_input(tmp_path):
    files = _workspace(tmp_path)
    result = verify_preflight_workspace(files["sourceApk"])
    assert result["required"] is True
    assert result["verified"] is True
    assert result["validatedMenuControlCount"] == 2
    assert result["identityBoundRvaCount"] == 1


@pytest.mark.parametrize("role", ["menuSpec", "sourceApk", "phase7Plan", "simpleCatalog", "catalog", "library", "metadata"])
def test_phase7_preflight_guard_blocks_handoff_tampering(tmp_path, role):
    files = _workspace(tmp_path)
    files[role].write_bytes(files[role].read_bytes() + b"-changed")
    with pytest.raises(Phase7PreflightError, match="changed"):
        verify_preflight_workspace(files["sourceApk"])


def test_phase7_guard_is_opt_in_for_legacy_workspaces(tmp_path):
    source = tmp_path / "game.apk"
    source.write_bytes(b"legacy")
    assert verify_preflight_workspace(source) == {"required": False, "verified": False}


def test_menu_package_wraps_both_preflight_and_payload_generation():
    source = Path("modkit/menu/__init__.py").read_text(encoding="utf-8")
    assert "review_preflight as _builder_review_preflight" in source
    assert "write_patch_payload as _builder_write_patch_payload" in source
    assert source.count("verify_preflight_workspace(source_apk)") == 2
    assert "return _builder_review_preflight(spec, source_apk)" in source
    assert "return _builder_write_patch_payload(" in source
