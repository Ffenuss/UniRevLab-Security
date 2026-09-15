from pathlib import Path


SOURCE = Path("android/app/src/main/java/dev/modkit/mobile/ProcessLabActivity.java")
TARGET_PREP = Path("android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java")


def test_runtime_session_is_published_via_part_then_replace():
    source = SOURCE.read_text(encoding="utf-8")
    helper = source.split("private void writeRuntimeSession", 1)[1].split("private JSONObject persistAndCorrelate", 1)[0]
    assert 'app.file("runtime-session.json.part")' in helper
    assert "Files.deleteIfExists(part.toPath())" in helper
    write = helper.index("Files.write(part.toPath()")
    move = helper.index("Files.move(part.toPath(),destination.toPath(),StandardCopyOption.REPLACE_EXISTING)")
    assert write < move
    assert "catch(Exception e){Files.deleteIfExists(part.toPath());throw e;}" in helper
    assert "writeRuntimeSession(snapshot);" in source


def test_failed_manual_runtime_snapshot_removes_created_saf_document():
    source = SOURCE.read_text(encoding="utf-8")
    assert "DocumentsContract.deleteDocument" in source
    assert "deleteCreatedDocument(uri); showError" in source


def test_target_switch_clears_orphan_runtime_session_part():
    source = TARGET_PREP.read_text(encoding="utf-8")
    cleanup = source.split("private void clearTargetDependentOutputs()", 1)[1].split("private void cleanupFailedPreparation()", 1)[0]
    assert '"runtime-session.json"' in cleanup
    assert '"runtime-session.json.part"' in cleanup
    assert '"runtime-correlation.json"' in cleanup
