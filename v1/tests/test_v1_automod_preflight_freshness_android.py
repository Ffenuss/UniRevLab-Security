from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_automod_plan_and_prepare_invalidate_stale_build_gate():
    activity = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModActivity.java").read_text(encoding="utf-8")
    service = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoModPrepareService.java").read_text(encoding="utf-8")
    worker = (ROOT / "android/app/src/main/java/dev/modkit/mobile/WorkerService.java").read_text(encoding="utf-8")

    assert "invalidatePreparedState();" in activity
    assert '"menu-spec.json","menu-preflight.json","menu-validation.json","menu-auto-confirm.json","menu-autopilot.json"' in activity
    assert "invalidatePreparedState();" in service
    assert '"menu-spec.json","menu-preflight.json","menu-validation.json","menu-auto-confirm.json","menu-autopilot.json"' in service

    # The picker/UI guard is not the final security boundary. Build must re-run
    # menu_review_preflight against the current menu-spec and owning APK.
    assert 'private JSONObject menuPreflightReport()' in worker
    assert 'callAttr("menu_review_preflight"' in worker
    assert 'private void menuBuildApk(Uri uri)' in worker
    assert 'JSONObject preflight=menuPreflightReport();' in worker
    assert 'if(!preflight.optBoolean("readyForPayload"))' in worker
