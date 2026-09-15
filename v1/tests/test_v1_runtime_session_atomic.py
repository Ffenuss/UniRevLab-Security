from pathlib import Path


SOURCE = Path("android/app/src/main/java/dev/modkit/mobile/ProcessLabActivity.java")
TARGET_PREP = Path("android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java")
FULL = Path("android/app/src/main/java/dev/modkit/mobile/FullAnalysisService.java")


def test_runtime_session_is_published_via_generic_part_then_replace_helper():
    source = SOURCE.read_text(encoding="utf-8")
    helper = source.split("private void writeAtomicJson", 1)[1].split("private void writeRuntimeSession", 1)[0]
    assert 'app.file(name+".part")' in helper
    assert "Files.deleteIfExists(part.toPath())" in helper
    write = helper.index("Files.write(part.toPath()")
    move = helper.index("Files.move(part.toPath(),destination.toPath(),StandardCopyOption.REPLACE_EXISTING)")
    assert write < move
    assert "catch(Exception e){Files.deleteIfExists(part.toPath());throw e;}" in helper
    assert 'writeAtomicJson("runtime-session.json",snapshot)' in source
    assert "writeRuntimeSession(snapshot);" in source


def test_runtime_correlation_uses_backend_temp_then_validated_atomic_publish():
    source = SOURCE.read_text(encoding="utf-8")
    method = source.split("private JSONObject persistAndCorrelate", 1)[1].split("private void recomputeCorrelation", 1)[0]
    assert 'app.file("runtime-correlation.json.build")' in method
    assert 'app.file("runtime-correlation.json.part")' in method
    assert 'build_workspace_correlation", getFilesDir().getPath(), app.file("runtime-session.json").getPath(), backendTemp.getPath()' in method
    assert "new JSONObject(module.callAttr" in method
    assert 'writeAtomicJson("runtime-correlation.json",linked)' in method
    assert "Files.deleteIfExists(destination.toPath())" in method
    assert 'writeAtomicJson("runtime-correlation.json",error)' in method


def test_failed_manual_runtime_snapshot_removes_created_saf_document():
    source = SOURCE.read_text(encoding="utf-8")
    assert "DocumentsContract.deleteDocument" in source
    assert "deleteCreatedDocument(uri); showError" in source


def test_target_switch_clears_runtime_session_and_correlation_orphans():
    source = TARGET_PREP.read_text(encoding="utf-8")
    cleanup = source.split("private void clearTargetDependentOutputs()", 1)[1].split("private void cleanupFailedPreparation()", 1)[0]
    for name in (
        "runtime-session.json",
        "runtime-session.json.part",
        "runtime-correlation.json",
        "runtime-correlation.json.part",
        "runtime-correlation.json.build",
    ):
        assert f'"{name}"' in cleanup


def test_full_rerun_invalidates_ephemeral_runtime_session_before_static_backends():
    source = FULL.read_text(encoding="utf-8")
    helper = source.split("private void invalidatePerRunEvidenceState()", 1)[1].split("private void deleteRunTree", 1)[0]
    for name in (
        "runtime-session.json",
        "runtime-session.json.part",
        "runtime-correlation.json",
        "runtime-correlation.json.part",
        "runtime-correlation.json.build",
    ):
        assert f'"{name}"' in helper

    invalidate = source.index("invalidatePerRunEvidenceState();")
    resolve = source.index("DecompilerEngine.resolveTargetInputs(app)", invalidate)
    inventory = source.index('stage(1,4,"Inventory:', resolve)
    assert invalidate < resolve < inventory
