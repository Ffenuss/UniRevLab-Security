from pathlib import Path


ANDROID = Path("android/app/src/main/java/dev/modkit/mobile")


def _read(name: str) -> str:
    return (ANDROID / name).read_text(encoding="utf-8")


def test_rerun_publishes_running_manifest_before_worker_and_reconstruction():
    source = _read("FullAnalysisService.java")

    helper = source.split("private void writePipelineState", 1)[1].split("private boolean bestEffortPipelineState", 1)[0]
    assert '.put("status",status).put("phase",phase)' in helper
    assert 'writeAtomicJson("automatic-evidence.json",state)' in helper

    started = source.index("startedAt=System.currentTimeMillis();")
    publish = source.index('writePipelineState("RUNNING","RECONSTRUCTION",false,false,null);', started)
    worker = source.index("new Thread(()->", publish)
    prepared = source.index("invalidatePreparedAutoModState();", worker)
    resolve = source.index("DecompilerEngine.resolveTargetInputs(app)", prepared)
    inventory = source.index('stage(1,4,"Inventory:', resolve)
    assert started < publish < worker < prepared < resolve < inventory


def test_running_manifest_write_failure_blocks_worker_and_all_reconstruction_backends():
    source = _read("FullAnalysisService.java")

    publish = source.index('writePipelineState("RUNNING","RECONSTRUCTION",false,false,null);')
    failure_start = source.index("}catch(Exception startError){", publish)
    worker = source.index("new Thread(()->", failure_start)
    failure = source[failure_start:worker]

    assert 'Files.deleteIfExists(app.file("automatic-evidence.json.part").toPath())' in failure
    assert 'Files.deleteIfExists(app.file("automatic-evidence.json").toPath())' in failure
    assert 'putBoolean("running",false)' in failure
    assert "не удалось опубликовать RUNNING manifest" in failure
    assert "wake.release()" in failure
    assert "app.busy.set(false)" in failure
    assert "stopForeground(true)" in failure
    assert "stopSelf()" in failure
    assert "return START_NOT_STICKY" in failure

    resolve = source.index("DecompilerEngine.resolveTargetInputs(app)", worker)
    inventory = source.index('stage(1,4,"Inventory:', resolve)
    assert publish < failure_start < worker < resolve < inventory
    assert "boolean pipelineStarted=true;" in source[worker:resolve]


def test_full_rerun_invalidates_prepared_automod_and_per_run_evidence_before_target_work():
    source = _read("FullAnalysisService.java")

    prepared_helper = source.split("private void invalidatePreparedAutoModState()", 1)[1].split("private void invalidatePerRunEvidenceState()", 1)[0]
    for name in (
        "automod-plan.json",
        "automod-plan.json.part",
        "menu-spec.json",
        "menu-preflight.json",
        "menu-validation.json",
        "menu-auto-confirm.json",
        "menu-autopilot.json",
        "menu-native-recovery.json",
        "menu-native-recovery.json.tmp",
    ):
        assert f'"{name}"' in prepared_helper

    run_helper = source.split("private void invalidatePerRunEvidenceState()", 1)[1].split("private void deleteRunTree", 1)[0]
    for name in (
        "simple-catalog.json",
        "simple-catalog.json.part",
        "simple-progress.json",
        "simple-progress.json.part",
        "il2cpp-no-rva-native.json",
        "il2cpp-no-rva-native.json.part",
        "il2cpp-no-rva-native.methods.jsonl",
        "il2cpp-no-rva-native.methods.jsonl.part",
        "il2cpp-no-rva-native.failures.jsonl",
        "il2cpp-no-rva-native.failures.jsonl.part",
        "menu-result.json",
        "menu-auto-prepare.json",
        "menu-auto-prepare-deep.json",
        "menu-probe-prepare.json",
        "menu-spec.simple-source.json",
        "menu-payload-report.json",
        "menu-apk-report.json",
        "connected-report.json",
        "connected-report.json.part",
        "connected-report.md",
        "connected-report.md.part",
    ):
        assert f'"{name}"' in run_helper

    prepared = source.index("invalidatePreparedAutoModState();")
    per_run = source.index("invalidatePerRunEvidenceState();", prepared)
    invalidated = source.index("runStateInvalidated=true;", per_run)
    resolve = source.index("DecompilerEngine.resolveTargetInputs(app)", invalidated)
    inventory = source.index('stage(1,4,"Inventory:')
    assert prepared < per_run < invalidated < resolve < inventory


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


def test_fresh_evidence_core_outputs_are_invalidated_before_il2cpp_and_re_backends():
    source = _read("AutomaticEvidenceService.java")
    helper = source.split("private void invalidateFreshCoreOutputs()", 1)[1].split("private void invalidatePerRunDerivedOutputs()", 1)[0]
    for name in (
        "analysis.json",
        "analysis.summary.json",
        "analysis.summary.json.part",
        "analysis.methods.jsonl",
        "analysis.evidence-graph.jsonl",
        "analysis.gameplay-coverage.json",
        "analysis-deep",
        "re-analysis.json",
        "re-analysis.ui.json",
        "re-analysis.menu.json",
        "rodroid",
    ):
        assert f'"{name}"' in helper

    fresh_gate = source.index("if(!coreCacheHit){")
    invalidate = source.index("invalidateFreshCoreOutputs();", fresh_gate)
    il2cpp = source.index("runIl2cpp(reTarget)", invalidate)
    re_backend = source.index("runReAnalysis(reTarget)", il2cpp)
    assert fresh_gate < invalidate < il2cpp < re_backend


def test_per_run_derived_outputs_are_invalidated_before_evidence_backends_can_fail():
    source = _read("AutomaticEvidenceService.java")
    helper = source.split("private void invalidatePerRunDerivedOutputs()", 1)[1].split("private void runPipeline", 1)[0]
    for name in (
        "simple-catalog.json",
        "simple-catalog.json.part",
        "simple-progress.json",
        "simple-progress.json.part",
        "il2cpp-no-rva-native.json",
        "il2cpp-no-rva-native.json.part",
        "il2cpp-no-rva-native.methods.jsonl",
        "il2cpp-no-rva-native.methods.jsonl.part",
        "il2cpp-no-rva-native.failures.jsonl",
        "il2cpp-no-rva-native.failures.jsonl.part",
        "automod-plan.json",
        "automod-plan.json.part",
        "connected-report.json",
        "connected-report.json.part",
        "connected-report.md",
        "connected-report.md.part",
    ):
        assert f'"{name}"' in helper

    run = source.index("private void runPipeline(JSONObject manifest)")
    invalidate = source.index("invalidatePerRunDerivedOutputs();", run)
    python = source.index("Python.start(new AndroidPlatform(this))", invalidate)
    stage1 = source.index('stage(1,6,"target digest + APK/split cache plan")', python)
    assert run < invalidate < python < stage1
    stage6 = source.index('stage(6,6,"no-RVA native recovery + AutoMod + connected report + cache")')
    assert "invalidatePerRunDerivedOutputs();" not in source[stage6:]


def test_evidence_wakelock_covers_long_release_pipeline():
    source = _read("AutomaticEvidenceService.java")
    acquire = source.index('newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"ModKit:auto-evidence")')
    assert "wake.acquire(2L*60L*60L*1000L);" in source[acquire:acquire + 300]
    assert "if(wake!=null&&wake.isHeld())wake.release();" in source


def test_evidence_handoff_preserves_full_run_epoch_start_and_clears_terminal_fields():
    source = _read("AutomaticEvidenceService.java")
    helper = source.split("private JSONObject initialManifest()", 1)[1].split("@Override public int onStartCommand", 1)[0]
    assert 'readJson("automatic-evidence.json")' in helper
    assert '"RUNNING".equals(previous.optString("status"))' in helper
    assert 'previous.optLong("startedAtMs",0L)>0L' in helper
    assert "return previous;" in helper
    assert "return new JSONObject();" in helper
    assert 'JSONObject manifest=initialManifest();' in source
    assert 'long inheritedStartedAt=manifest.optLong("startedAtMs",0L);' in source
    assert 'startedAt=inheritedStartedAt>0L?inheritedStartedAt:System.currentTimeMillis();' in source
    assert '.put("startedAtMs",startedAt)' in source
    assert '.remove("finishedAtMs")' in source
    assert 'manifest.remove("error")' in source


def test_core_cache_hit_requires_re_analysis_and_complete_il2cpp_artifacts_when_pair_exists():
    source = _read("AutomaticEvidenceService.java")
    assert 'boolean hasIl2cppPair=app.file("metadata.bin").isFile()&&app.file("library.so").isFile();' in source
    assert 'boolean haveReAnalysis=app.file("re-analysis.json").isFile();' in source
    assert 'boolean haveIl2cppAnalysis=!hasIl2cppPair||(app.file("analysis.json").isFile()&&app.file("analysis.summary.json").isFile()&&app.file("analysis.methods.jsonl").isFile()&&app.file("analysis.gameplay-coverage.json").isFile());' in source
    for required in ("analysis.json", "analysis.summary.json", "analysis.methods.jsonl", "analysis.gameplay-coverage.json"):
        assert f'app.file("{required}").isFile()' in source
    assert 'boolean coreCacheReady=haveReAnalysis&&haveIl2cppAnalysis;' in source
    assert 'boolean coreCacheHit=unchanged&&coreCacheReady;' in source
    assert '.put("cacheHit",coreCacheHit)' in source
    assert 'if(!coreCacheHit)' in source
    assert '(coreCacheHit?" · cache hit":" · fresh core")' in source


def test_non_il2cpp_cache_hit_remains_not_applicable_not_fake_il2cpp_cache_hit():
    source = _read("AutomaticEvidenceService.java")
    assert 'engines.put("il2cpp",hasIl2cppPair?new JSONObject().put("status","CACHE_HIT"):new JSONObject().put("status","NOT_APPLICABLE").put("reason","complete IL2CPP pair not found"));' in source
    assert 'engines.put("re",new JSONObject().put("status","CACHE_HIT"));' in source


def test_failed_run_epoch_invalidation_is_terminal_reconstruction_failure():
    source = _read("FullAnalysisService.java")

    assert "boolean runStateInvalidated=false;" in source
    assert 'reconstructionFailure="RUN_EPOCH_INVALIDATION_FAILED:' in source
    assert 'bestEffortPipelineState("FAILED","RECONSTRUCTION",false,false,reconstructionFailure)' in source


def test_unexpected_reconstruction_error_never_hands_off_evidence_graph():
    source = _read("FullAnalysisService.java")

    invalidated = source.index("runStateInvalidated=true;")
    outer_catch = source.index("}catch(Exception e){", invalidated)
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

    assert 'bestEffortPipelineState("CANCELLED","RECONSTRUCTION",false,true,"USER_CANCELLED")' in source
    assert 'bestEffortPipelineState("FAILED","RECONSTRUCTION",false,false,reconstructionFailure)' in source
    assert 'bestEffortPipelineState("FAILED","HANDOFF",false,false' in source
    assert 'EVIDENCE_HANDOFF_NOT_STARTED' in source


def test_terminal_manifest_write_is_best_effort_only_after_running_manifest_was_published():
    source = _read("FullAnalysisService.java")

    helper = source.split("private boolean bestEffortPipelineState", 1)[1].split("private void invalidatePreparedAutoModState", 1)[0]
    assert "try{writePipelineState" in helper
    terminal = source.split("if(!handedOff){", 1)[1].split("getSharedPreferences", 1)[0]
    assert "if(pipelineStarted)" in terminal
    assert "bestEffortPipelineState" in terminal
    assert 'Files.deleteIfExists(app.file("automatic-evidence.json").toPath())' in terminal
    assert 'Files.deleteIfExists(app.file("automatic-evidence.json.part").toPath())' in terminal


def test_evidence_service_persists_live_phase_before_heavy_pipeline():
    source = _read("AutomaticEvidenceService.java")

    start = source.index('.put("status","RUNNING").put("phase","EVIDENCE")')
    persisted = source.index('writeJson("automatic-evidence.json",manifest)', start)
    pipeline = source.index('runPipeline(manifest)', persisted)
    assert start < persisted < pipeline
    assert '.put("phase","FINISHED")' in source


def test_process_death_recovers_running_manifest_or_orphan_atomic_part_fail_closed():
    source = _read("App.java")
    helper = source.split("private boolean markInterruptedPipeline()", 1)[1].split("private void deleteInterruptedTargetTree", 1)[0]

    assert 'File part=file("automatic-evidence.json.part"),manifest=file("automatic-evidence.json")' in helper
    assert "boolean interruptedPublication=part.isFile();" in helper
    assert "if(interruptedPublication)" in helper
    assert "Files.readAllBytes(part.toPath())" in helper
    assert 'if(!interruptedPublication&&!"RUNNING".equals(value.optString("status")))return false;' in helper
    assert '.put("status","FAILED").put("phase","FINISHED")' in helper
    assert '.put("interruptedBySystem",true)' in helper
    assert '.put("error","SYSTEM_INTERRUPTED")' in helper
    assert 'Files.write(part.toPath(),value.toString(2).getBytes(StandardCharsets.UTF_8))' in helper
    assert 'Files.move(part.toPath(),manifest.toPath(),StandardCopyOption.REPLACE_EXISTING)' in helper
    assert "Files.deleteIfExists(manifest.toPath())" in helper

    on_create = source.split("@Override public void onCreate()", 1)[1]
    assert "boolean pipelineInterrupted=false;" in on_create
    assert "pipelineInterrupted=markInterruptedPipeline();" in on_create
    assert "if(wasRunning||pipelineInterrupted)" in on_create
    assert "if(wasRunning||targetPreparing||pipelineInterrupted)" in on_create


def test_target_switch_clears_pipeline_status_temp():
    source = _read("TargetPreparationService.java")

    assert '"automatic-evidence.json.part"' in source
