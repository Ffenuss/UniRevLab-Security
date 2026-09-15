from pathlib import Path


SERVICE = Path("android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java")
APP = Path("android/app/src/main/java/dev/modkit/mobile/App.java")


def test_target_preparation_persists_in_progress_marker_until_service_finally():
    source = SERVICE.read_text(encoding="utf-8")

    start = source.index('putBoolean("running",true).putBoolean("target.preparing",true).apply()')
    worker = source.index('new Thread(()->', start)
    final = source.index('putBoolean("running",false).putBoolean("target.preparing",false).apply()', worker)
    assert start < worker < final


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
