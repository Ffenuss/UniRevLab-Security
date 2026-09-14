import json
from pathlib import Path

from modkit.mobile.simple_cache import plan_workspace, record_workspace
from modkit.mobile.simple_mode import build_catalog


def test_simple_cache_reuses_hash_and_invalidates_changed_target(tmp_path):
    apk = tmp_path / "game.apk"
    apk.write_bytes(b"APK-one")
    manifest = tmp_path / "simple-cache.json"
    first = json.loads(plan_workspace(tmp_path, manifest))
    assert first["unchanged"] is False and first["targetCount"] == 1
    record_workspace(tmp_path, manifest, json.dumps(first))
    second = json.loads(plan_workspace(tmp_path, manifest))
    assert second["unchanged"] is True and second["reusedHashCount"] == 1
    apk.write_bytes(b"APK-two-changed")
    third = json.loads(plan_workspace(tmp_path, manifest))
    assert third["unchanged"] is False and "game.apk" in third["changedFiles"]


def test_confirmation_ladder_and_gameplay_domain(tmp_path):
    (tmp_path / "analysis.gameplay-coverage.json").write_text(json.dumps({
        "findings": [
            {"title":"Player maxHealth","status":"CONFIRMED","category":"stats","trustBoundary":"local","artifact":"classes2.dex","class":"game.PlayerStats","method":"getMaxHealth","codeOffset":321},
            {"title":"androidx.room.RawQuery::observedEntities","status":"CONFIRMED","artifact":"classes.dex","class":"androidx.room.RawQuery","method":"observedEntities","codeOffset":42,"evidenceRole":"framework/third-party"},
            {"title":"Authentication / Session","status":"FOUND_STATIC","category":"authentication","trustBoundary":"server","class":"game.Auth"},
        ]
    }), encoding="utf-8")
    out = build_catalog(tmp_path)
    hp = next(c for c in out["cards"] if c["title"] == "Player maxHealth")
    assert hp["status"] == "READY_DEX"
    assert hp["verificationStage"] == "LOCATOR_CONFIRMED"
    assert hp["gameplayDomain"] == "health" and hp["offlineCandidate"]
    fw = next(c for c in out["cards"] if c["title"].startswith("androidx.room.RawQuery"))
    assert fw["verificationStage"] == "FRAMEWORK_NOISE"
    auth = next(c for c in out["cards"] if c["title"] == "Authentication / Session")
    assert auth["verificationStage"] == "SERVER_AUDIT" and not auth["patchReady"]


def test_menu_binding_is_patch_ready(tmp_path):
    (tmp_path / "menu-spec.json").write_text(json.dumps({"controls":[{
        "id":"hp","title":"Health multiplier","category":"health","type":"slider_float","binding":"native","rva":4096,"library":"libil2cpp.so"
    }]}), encoding="utf-8")
    out = build_catalog(tmp_path)
    card = next(c for c in out["cards"] if c.get("menuControlId") == "hp")
    assert card["verificationStage"] == "PATCH_READY" and card["patchReady"] and card["buildable"]
