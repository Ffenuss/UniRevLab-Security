from pathlib import Path


def test_bundle_manifest_surfaces_pipeline_health():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java"
    ).read_text(encoding="utf-8")

    assert '"automatic-evidence.json"' in source
    for field in (
        "pipelineStatus",
        "pipelineComplete",
        "pipelineDegraded",
        "pipelineDegradedReasons",
        "pipelineError",
    ):
        assert f'"{field}"' in source


def test_bundle_keeps_evidence_hashing_and_excludes_raw_target_binaries():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java"
    ).read_text(encoding="utf-8")

    assert '".json"' in source
    assert 'sha256(file)' in source
    assert '.put("rawTargetBinariesIncluded", false)' in source
    assert '"hashes.sha256"' in source
