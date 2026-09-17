import hashlib
import json

from modkit.mobile.menu_native_recovery import _bind_phase7_freshness


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_python_prepare_binds_plan_catalog_menu_and_preflight_sha(tmp_path):
    files = {
        "automod-plan.json": b'{"schema":"modkit-automod-plan-1.4"}',
        "simple-catalog.json": b'{"schema":"modkit-simple-catalog-test"}',
        "menu-spec.json": b'{"schema":"modkit-menu-1.1"}',
        "menu-preflight.json": b'{"schema":"modkit-menu-preflight-test"}',
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)

    audit = {
        "schema": "modkit-menu-native-recovery-adapter-1.0",
        "completed": True,
        "inputFingerprints": [
            {"role": "metadata", "name": "metadata.bin", "size": 1, "sha256": "a" * 64},
            {"role": "phase7Plan", "name": "stale.json", "size": 0, "sha256": "0" * 64},
        ],
        "outputFingerprints": [
            {"role": "menuSpec", "name": "stale-menu.json", "size": 0, "sha256": "0" * 64},
        ],
        "phase7Gate": {
            "schema": "modkit-automod-phase7-prepare-gate-1.0",
            "validated": True,
            "rejectedControlCount": 0,
        },
    }
    (tmp_path / "menu-native-recovery.json").write_text(json.dumps(audit), encoding="utf-8")

    out = _bind_phase7_freshness(tmp_path)
    inputs = {row["role"]: row for row in out["inputFingerprints"]}
    outputs = {row["role"]: row for row in out["outputFingerprints"]}

    assert out["phase7FreshnessPolicy"] == "EXACT_PLAN_AND_CATALOG_SHA256"
    assert inputs["phase7Plan"]["sha256"] == _sha(tmp_path / "automod-plan.json")
    assert inputs["simpleCatalog"]["sha256"] == _sha(tmp_path / "simple-catalog.json")
    assert outputs["menuSpec"]["sha256"] == _sha(tmp_path / "menu-spec.json")
    assert outputs["menuPreflight"]["sha256"] == _sha(tmp_path / "menu-preflight.json")
    assert outputs["menuSpec"]["name"] == "menu-spec.json"
    assert len([row for row in out["inputFingerprints"] if row.get("role") == "phase7Plan"]) == 1
    assert len([row for row in out["outputFingerprints"] if row.get("role") == "menuSpec"]) == 1

    persisted = json.loads((tmp_path / "menu-native-recovery.json").read_text(encoding="utf-8"))
    assert persisted["phase7FreshnessPolicy"] == "EXACT_PLAN_AND_CATALOG_SHA256"
    assert {row["role"] for row in persisted["outputFingerprints"]} >= {"menuSpec", "menuPreflight"}


def test_python_phase7_freshness_fails_closed_without_validated_gate(tmp_path):
    (tmp_path / "menu-native-recovery.json").write_text(json.dumps({
        "completed": True,
        "inputFingerprints": [],
        "outputFingerprints": [],
        "phase7Gate": {"validated": False, "rejectedControlCount": 0},
    }), encoding="utf-8")

    try:
        _bind_phase7_freshness(tmp_path)
    except ValueError as exc:
        assert "identity gate" in str(exc)
    else:
        raise AssertionError("unvalidated Phase 7 gate must fail closed")
