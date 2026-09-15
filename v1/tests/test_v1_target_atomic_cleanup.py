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
        '"il2cpp-no-rva-native.json.part"',
        '"installed-apk-set.zip.tmp"',
        '"simple-progress.json"',
        '"simple-progress.json.part"',
        '"automatic-evidence.json"',
        '"automatic-evidence.json.part"',
    )
    for name in required:
        assert name in source

    # A failed preparation must not leave the temporary APK-set archive behind.
    cleanup = source.split("private void cleanupFailedPreparation()", 1)[1]
    assert '"installed-apk-set.zip.tmp"' in cleanup


def test_evidence_service_json_promotion_uses_sibling_part_file():
    source = Path("android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java").read_text(encoding="utf-8")

    assert 'part=app.file(name+".part")' in source
    assert 'Files.deleteIfExists(part.toPath())' in source
    assert 'Files.write(part.toPath()' in source
    assert 'Files.move(part.toPath(),destination.toPath(),StandardCopyOption.REPLACE_EXISTING)' in source
