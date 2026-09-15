from pathlib import Path


def test_target_reset_clears_atomic_output_orphans_and_progress():
    source = Path("android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java").read_text(encoding="utf-8")

    required = (
        '"automod-plan.json.part"',
        '"connected-report.json.part"',
        '"connected-report.md.part"',
        '"il2cpp-crosscheck.json.part"',
        '"il2cpp-crosscheck.methods.jsonl.part"',
        '"il2cpp-metadata-identity.json.part"',
        '"il2cpp-metadata-identity.methods.jsonl.part"',
        '"installed-apk-set.zip.tmp"',
        '"simple-progress.json"',
        '"automatic-evidence.json"',
    )
    for name in required:
        assert name in source

    # A failed preparation must not leave the temporary APK-set archive behind.
    cleanup = source.split("private void cleanupFailedPreparation()", 1)[1]
    assert '"installed-apk-set.zip.tmp"' in cleanup
