from pathlib import Path


ANDROID = Path("android/app/src/main/java/dev/modkit/mobile")


def _read(name: str) -> str:
    return (ANDROID / name).read_text(encoding="utf-8")


def test_rerun_invalidates_old_final_manifest_before_reconstruction():
    source = _read("FullAnalysisService.java")

    assert 'pipelineState("RUNNING","RECONSTRUCTION",false,false,null);' in source
    assert 'writeAtomicJson("automatic-evidence.json",state)' in source


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
        "menu-native-recovery.json.tmp",
    )
    helper = source.split("private void invalidatePreparedAutoModState()", 1)[1].split("private void invalidateEmbeddedRunOutputs()", 1)[0]
    for name in required:
        assert f'"{name}"' in helper

    invalidate = source.index("invalidatePreparedAutoModState();preparedStateInvalidated=true;")
    resolve = source.index("DecompilerEngine.resolveTargetInputs(app)")
    inventory = source.index('stage(1,4,"Inventory:')
    assert invalidate < resolve < inventory


def test_embedded_outputs_are_invalidated_before_same_target_rerun_backend_executes():
    source = _read("FullAnalysisService.java")
    helper = source.split("private void invalidateEmbeddedRunOutputs()", 1)[1].split("/** Chaquopy", 1)[0]
    for name in (
        "artifact-families.json",
        "embedded-analysis.json",
        "lua-deep.json",
        "hermes-deep.json",
        "native-deep.json",
        "cocos-deep.json",
        "flutter-deep.json",
        "deep-gameplay.json",
    ):
        assert f'"{name}"' in helper
    stage = source.index('stage(4,4,"Lua/JS/Hermes deep')
    invalidate = source.index("invalidateEmbeddedRunOutputs();", stage)
    backend = source.index('getModule("modkit.mobile.embedded_pipeline")', invalidate)
    assert stage < invalidate < backend


def test_failed_epoch_invalidation_is_terminal_reconstruction_failure():
    source = _read("FullAnalysisService.java")

    assert "boolean preparedStateInvalidated=false;" in source
    assert 'reconstructionFailure="AUTOMOD_PREPARED_STATE_INVALIDATION_FAILED:' in source
    assert 'pipelineState("FAILED","RECONSTRUCTION",false,false,reconstructionFailure)' in source


def test_unexpected_reconstruction_error_never_hands_off_evidence_graph():
    source = _read("FullAnalysisService.java")

    outer_catch = source.index("}catch(Exception e){", source.index("invalidatePreparedAutoModState();preparedStateInvalidated=true;"))
    outer_finally = source.index("}finally{", outer_catch)
    catch_block = source[outer_catch:outer_finally]
    assert "chain=false;" in catch_block
    assert 'reconstructionFailure="RECONSTRUCTION_FAILED:' in catch_block
    assert "Evidence Graph не будет запущен на неполной реконструкции" in catch_block

    handoff_gate = source.index("if(chain&&!app.cancelled.get())")
    evidence_start = source.index("startForegroundService(new Intent(this,AutomaticEvidenceService.class))", handoff_gate)
    assert handoff_gate < evidence_start


def test_pre_evidence_cancel_reconstruction_failure_and_handoff_failure_are_terminal_states():
    source = _read("FullAnalysisService.java")

    assert 'pipelineState("CANCELLED","RECONSTRUCTION",false,true,"USER_CANCELLED")' in source
    assert 'pipelineState("FAILED","RECONSTRUCTION",false,false,reconstructionFailure)' in source
    assert 'pipelineState("FAILED","HANDOFF",false,false' in source
    assert 'EVIDENCE_HANDOFF_NOT_STARTED' in source


def test_evidence_service_persists_live_phase_before_heavy_pipeline():
    source = _read("AutomaticEvidenceService.java")

    start = source.index('.put("status","RUNNING").put("phase","EVIDENCE")')
    persisted = source.index('writeJson("automatic-evidence.json",manifest)', start)
    pipeline = source.index('runPipeline(manifest)', persisted)
    assert start < persisted < pipeline
    assert '.put("phase","FINISHED")' in source


def test_process_death_only_converts_running_manifest_to_system_interrupted_atomically():
    source = _read("App.java")

    assert 'File part=file("automatic-evidence.json.part")' in source
    assert 'if(!"RUNNING".equals(value.optString("status")))return;' in source
    assert '.put("status","FAILED").put("phase","FINISHED")' in source
    assert '.put("interruptedBySystem",true)' in source
    assert '.put("error","SYSTEM_INTERRUPTED")' in source
    assert 'Files.write(part.toPath(),value.toString(2).getBytes(StandardCharsets.UTF_8))' in source
    assert 'Files.move(part.toPath(),manifest.toPath(),StandardCopyOption.REPLACE_EXISTING)' in source
    assert 'Files.deleteIfExists(part.toPath())' in source
    assert 'markInterruptedPipeline();' in source


def test_target_switch_clears_pipeline_status_temp():
    source = _read("TargetPreparationService.java")

    assert '"automatic-evidence.json.part"' in source
