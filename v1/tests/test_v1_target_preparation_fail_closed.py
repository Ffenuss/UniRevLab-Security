from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java"


def test_installed_target_is_invalidated_before_package_lookup_can_fail():
    source = SOURCE.read_text(encoding="utf-8")
    method = source.split("private void prepareInstalled", 1)[1].split("@SuppressWarnings", 1)[0]
    assert method.index("clearTargetDependentOutputs();") < method.index("getApplicationInfo(packageName,0)")


def test_failed_or_cancelled_target_cannot_leave_ready_stale_artifacts():
    source = SOURCE.read_text(encoding="utf-8")
    catch = source.index("catch(Exception e){AnalysisJournal.exception")
    cleanup_call = source.index("try{cleanupFailedPreparation();}", catch)
    # The terminal user-visible status is emitted through the service progress()
    # wrapper after fail-closed cleanup succeeds. The old test looked for a direct
    # app.progress() call which is no longer the service contract.
    terminal_progress = source.index("progress(app.cancelled.get()?", cleanup_call)
    finally_block = source.index("}finally{", terminal_progress)
    assert catch < cleanup_call < terminal_progress < finally_block
    cleanup = source.split("private void cleanupFailedPreparation", 1)[1].split("private void checkCancelled", 1)[0]
    for name in ("installed-target.json", "installed-apks", "game.apk", "game.apk.part"):
        assert name in cleanup
    assert '.remove("installed.package").remove("game.apk")' in cleanup


def test_target_copy_and_hash_loops_are_cooperatively_cancellable():
    source = SOURCE.read_text(encoding="utf-8")
    copy = source.split("private void copy", 1)[1].split("private String sha256", 1)[0]
    digest = source.split("private String sha256", 1)[1].split("private static void deleteTree", 1)[0]
    assert "checkCancelled();" in copy
    assert "checkCancelled();" in digest


def test_target_reset_clears_visible_target_preferences_immediately():
    source = SOURCE.read_text(encoding="utf-8")
    reset = source.split("private void clearTargetDependentOutputs", 1)[1].split("private void cleanupFailedPreparation", 1)[0]
    assert '.remove("installed.package")' in reset
    assert '.remove("game.apk")' in reset
