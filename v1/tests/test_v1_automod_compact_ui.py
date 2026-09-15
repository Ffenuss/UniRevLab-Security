from pathlib import Path


def _source() -> str:
    return Path(
        "android/app/src/main/java/dev/modkit/mobile/AutoModActivity.java"
    ).read_text(encoding="utf-8")


def test_manual_automod_refresh_uses_release_adapter_and_cancel_callback():
    source = _source()

    assert 'getModule("modkit.mobile.automod_cancellable")' in source
    assert 'new PlanningProgress()' in source
    assert 'Thread.currentThread().isInterrupted()' in source
    assert 'callAttr("build_workspace_plan"' in source
    assert 'getModule("modkit.mobile.automod").callAttr' not in source


def test_patch_lab_keeps_all_actions_in_compact_rows():
    source = _source()

    assert 'row.setOrientation(LinearLayout.HORIZONTAL)' in source
    for label in (
        "Обновить план",
        "Exact prepare",
        "Preflight",
        "Собрать APK",
        "Runtime",
        "Controls",
        "Patch Pack",
    ):
        assert f'"{label}"' in source

    assert "ProcessLabActivity.class" in source
    assert "MenuBuilderActivity.class" in source
    assert "PatchPackActivity.class" in source
    assert 'startWorker("menu_preflight",null)' in source
    assert 'startForegroundService(new Intent(this,AutoModPrepareService.class))' in source


def test_patch_lab_build_remains_fail_closed():
    source = _source()

    assert 'exactPrepareAuditReady()' in source
    assert 'pf.optBoolean("readyForAutoBuild")' in source
    verifier = Path("android/app/src/main/java/dev/modkit/mobile/AutoModAuditVerifier.java").read_text(encoding="utf-8")
    assert 'audit.optBoolean("promotesBuildability")||audit.optBoolean("addressRecoveryPromotesBuildability")' in verifier
    assert '"EXACT_INPUT_SHA256".equals(audit.optString("freshnessPolicy"))' in verifier
    assert 'build.setEnabled(idle&&prepareCount>0&&preflightReady&&exactPrepareAuditReady())' in source


def test_candidate_cards_are_compact_but_full_details_remain_accessible():
    source = _source()

    assert 'shown<16' in source
    assert "нажмите для деталей" in source
    assert "new AlertDialog.Builder(this)" in source
    assert ".setMessage(row.toString())" in source
    assert 'row.optString("reason","")' in source


def test_planning_serializes_prepare_preflight_and_build_actions():
    source = _source()

    assert 'if(planning){toast("Дождитесь обновления AutoMod-плана")' in source
    assert 'planning=true;refresh.setEnabled(false);prepare.setEnabled(false);check.setEnabled(false);build.setEnabled(false)' in source
    assert 'finally{planning=false;runOnUiThread(this::render);}' in source
    assert 'boolean idle=!app.busy.get()&&!planning' in source
    assert 'if(!planning)status.setText(app.status==null?"":app.status)' in source
