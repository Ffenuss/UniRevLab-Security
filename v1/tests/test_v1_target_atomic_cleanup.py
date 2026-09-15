from pathlib import Path


ANDROID = Path("android/app/src/main/java/dev/modkit/mobile")


def test_target_reset_clears_atomic_output_orphans_and_progress():
    source = (ANDROID / "TargetPreparationService.java").read_text(encoding="utf-8")

    required = (
        '"full-reconstruction.json.part"',
        '"apktool-analysis.json.part"',
        '"automod-plan.json.part"',
        '"connected-report.json.part"',
        '"connected-report.md.part"',
        '"il2cpp-crosscheck.json.part"',
        '"il2cpp-crosscheck.methods.jsonl.part"',
        '"il2cpp-metadata-identity.json.part"',
        '"il2cpp-metadata-identity.methods.jsonl.part"',
        '"il2cpp-no-rva-native.json.part"',
        '"installed-apk-set.zip.tmp"',
        '"installed-target.json.part"',
        '"simple-progress.json"',
        '"simple-progress.json.part"',
        '"automatic-evidence.json"',
        '"automatic-evidence.json.part"',
    )
    for name in required:
        assert name in source

    cleanup = source.split("private void cleanupFailedPreparation()", 1)[1]
    assert '"installed-apk-set.zip.tmp"' in cleanup
    assert '"installed-target.json.part"' in cleanup


def test_target_preparation_publishes_installed_manifest_atomically():
    source = (ANDROID / "TargetPreparationService.java").read_text(encoding="utf-8")

    helper = source.split("private void writeAtomicJson", 1)[1].split("private void prepareInstalled", 1)[0]
    assert 'app.file(name+".part")' in helper
    write = helper.index("Files.write(temp.toPath()")
    move = helper.index("Files.move(temp.toPath(),dest.toPath(),StandardCopyOption.REPLACE_EXISTING)")
    assert write < move
    assert 'writeAtomicJson("installed-target.json",target)' in source


def test_full_reconstruction_status_target_and_backend_manifests_use_atomic_json():
    source = (ANDROID / "FullAnalysisService.java").read_text(encoding="utf-8")

    helper = source.split("private void writeAtomicJson", 1)[1].split("private void stage", 1)[0]
    assert 'app.file(name+".part")' in helper
    assert "Files.deleteIfExists(temp.toPath())" in helper
    assert "StandardCopyOption.REPLACE_EXISTING" in helper
    assert 'writeAtomicJson("simple-progress.json",row)' in source
    assert 'writeAtomicJson("automatic-evidence.json",state)' in source
    assert 'writeAtomicJson("installed-target.json",normalized)' in source
    assert source.count('writeAtomicJson("full-reconstruction.json",state)') == 2
    assert 'writeAtomicJson("apktool-analysis.json",apktool)' in source
    assert 'writeAtomicJson("apktool-analysis.json",error)' in source


def test_evidence_service_json_promotion_uses_sibling_part_file():
    source = (ANDROID / "AutomaticEvidenceService.java").read_text(encoding="utf-8")

    assert 'part=app.file(name+".part")' in source
    assert 'Files.deleteIfExists(part.toPath())' in source
    assert 'Files.write(part.toPath()' in source
    assert 'Files.move(part.toPath(),destination.toPath(),StandardCopyOption.REPLACE_EXISTING)' in source
