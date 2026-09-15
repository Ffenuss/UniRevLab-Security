from pathlib import Path


ANDROID = Path("android/app/src/main/java/dev/modkit/mobile")


def _read(name: str) -> str:
    return (ANDROID / name).read_text(encoding="utf-8")


def test_rerun_invalidates_old_final_manifest_before_reconstruction():
    source = _read("FullAnalysisService.java")

    assert 'pipelineState("RUNNING","RECONSTRUCTION",false,false,null);' in source
    assert 'File temp=app.file("automatic-evidence.json.part")' in source
    assert 'Files.move(temp.toPath(),dest.toPath(),StandardCopyOption.REPLACE_EXISTING)' in source


def test_full_rerun_invalidates_prepared_automod_epoch_before_target_work():
    source = _read("FullAnalysisService.java")

    required = (
        "automod-plan.json",
        "automod-plan.json.part",
        "menu-spec.json",
        "menu-preflight.json",
        "menu-validation.json",
        "menu-auto-confirm.json",
        "menu-autopilot.json",
        "menu-native-recovery.json",
    )
    helper = source.split("private void invalidatePreparedAutoModState()", 1)[1].split("/** Chaquopy", 1)[0]
    for name in required:
        assert f'"{name}"' in helper

    invalidate = source.index("invalidatePreparedAutoModState();preparedStateInvalidated=true;")
    resolve = source.index("DecompilerEngine.resolveTargetInputs(app)")
    inventory = source.index('stage(1,4,"Inventory:')
    assert invalidate < resolve < inventory


def test_failed_epoch_invalidation_blocks_evidence_handoff():
    source = _read("FullAnalysisService.java")

    assert "boolean preparedStateInvalidated=false;" in source
    assert 'if(!preparedStateInvalidated){chain=false;handoffFailure="AUTOMOD_PREPARED_STATE_INVALIDATION_FAILED:' in source
    assert 'preparedStateInvalidated?"HANDOFF":"RECONSTRUCTION"' in source


def test_pre_evidence_cancel_and_handoff_failure_are_terminal_states():
    source = _read("FullAnalysisService.java")

    assert 'pipelineState("CANCELLED","RECONSTRUCTION",false,true,"USER_CANCELLED")' in source
    assert 'pipelineState("FAILED",preparedStateInvalidated?"HANDOFF":"RECONSTRUCTION",false,false' in source
    assert 'EVIDENCE_HANDOFF_NOT_STARTED' in source


def test_evidence_service_persists_live_phase_before_heavy_pipeline():
    source = _read("AutomaticEvidenceService.java")

    start = source.index('.put("status","RUNNING").put("phase","EVIDENCE")')
    persisted = source.index('writeJson("automatic-evidence.json",manifest)', start)
    pipeline = source.index('runPipeline(manifest)', persisted)
    assert start < persisted < pipeline
    assert '.put("phase","FINISHED")' in source


def test_process_death_only_converts_running_manifest_to_system_interrupted():
    source = _read("App.java")

    assert 'if(!"RUNNING".equals(value.optString("status")))return;' in source
    assert '.put("status","FAILED").put("phase","FINISHED")' in source
    assert '.put("interruptedBySystem",true)' in source
    assert '.put("error","SYSTEM_INTERRUPTED")' in source
    assert 'markInterruptedPipeline();' in source


def test_target_switch_clears_pipeline_status_temp():
    source = _read("TargetPreparationService.java")

    assert '"automatic-evidence.json.part"' in source
