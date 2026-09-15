from pathlib import Path


SERVICE = Path("android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java")
APP = Path("android/app/src/main/java/dev/modkit/mobile/App.java")


def test_target_preparation_persists_in_progress_marker_before_worker_and_clears_in_finally():
    source = SERVICE.read_text(encoding="utf-8")

    helper = source.split("private boolean persistPreparationState", 1)[1].split("@Override public int onStartCommand", 1)[0]
    assert 'putBoolean("running",running)' in helper
    assert 'putBoolean("target.preparing",running)' in helper
    assert ".commit()" in helper
    assert ".apply()" not in helper

    start = source.index("if(!persistPreparationState(true))")
    worker = source.index('new Thread(()->', start)
    final = source.index("persistPreparationState(false)", worker)
    assert start < worker < final


def test_target_copy_fails_closed_when_durable_recovery_marker_cannot_be_committed():
    source = SERVICE.read_text(encoding="utf-8")
    failure = source.split("if(!persistPreparationState(true))", 1)[1].split('new Thread(()->', 1)[0]

    assert "recovery marker" in failure
    assert "wake.release()" in failure
    assert "app.busy.set(false)" in failure
    assert "stopForeground(true)" in failure
    assert "stopSelf()" in failure
    assert "return START_NOT_STICKY" in failure


def test_app_process_restart_cleans_partial_target_and_current_evidence_fail_closed():
    source = APP.read_text(encoding="utf-8")
    helper = source.split("private void cleanupInterruptedTargetPreparation()", 1)[1].split("@Override public void onCreate()", 1)[0]

    for name in (
        "installed-target.json",
        "installed-apks",
        "game.apk",
        "game.apk.part",
        "metadata.bin",
        "library.so",
        "automatic-evidence.json",
        "analysis.summary.json",
        "simple-catalog.json",
        "automod-plan.json",
        "connected-report.json",
        "hermes-deep",
        "runtime-correlation.json",
        "il2cpp-crosscheck.json",
        "il2cpp-metadata-identity.json",
        "il2cpp-no-rva-native.json",
        "patchpack-report.json",
        "workspace-report.json",
        "target-signed.apk",
        "target-signed-set",
    ):
        assert f'"{name}"' in helper

    assert 'remove("installed.package")' in helper
    assert 'remove("game.apk")' in helper
    assert 'remove("selections")' in helper

    on_create = source.split("@Override public void onCreate()", 1)[1]
    detect = on_create.index('getBoolean("target.preparing",false)')
    cleanup = on_create.index("cleanupInterruptedTargetPreparation();", detect)
    restore = on_create.index('new Thread(() ->', cleanup)
    assert detect < cleanup < restore
    assert 'putBoolean("target.preparing",false)' in on_create
    assert "Частичный APK/APK-set очищен" in on_create


def test_interrupted_target_cleanup_preserves_historical_project_tree_signing_identity_and_user_patchpack():
    source = APP.read_text(encoding="utf-8")
    helper = source.split("private void cleanupInterruptedTargetPreparation()", 1)[1].split("@Override public void onCreate()", 1)[0]

    assert 'file("projects")' not in helper
    assert "SigningKeyManager" not in helper
    assert '"patchpack.zip"' not in helper
