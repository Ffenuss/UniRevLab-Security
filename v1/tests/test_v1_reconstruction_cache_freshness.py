from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_jadx_cache_requires_output_size_and_sha256():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/FullAnalysisService.java").read_text(encoding="utf-8")
    assert 'old.optString("outputSha256","")' in source
    assert 'old.optLong("outputSize",-1L)' in source
    assert 'expectedSize==decompiled.length()' in source
    assert 'expectedSha.equals(fileSha256(decompiled))' in source
    assert 'decompiled.getName().equals(old.optString("output"))' in source


def test_jadx_manifest_becomes_complete_only_after_export_fingerprint():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/FullAnalysisService.java").read_text(encoding="utf-8")
    fingerprint = source.index('String outputSha=fileSha256(zip)')
    sha_field = source.index('put("outputSha256",outputSha)', fingerprint)
    complete = source.index('put("complete",dec.complete)', sha_field)
    partial = source.index('put("partial",!dec.complete)', complete)
    assert fingerprint < sha_field < complete < partial


def test_reconstruction_hashing_remains_cancellable_and_old_manifests_fail_closed():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/FullAnalysisService.java").read_text(encoding="utf-8")
    assert 'private String fileSha256(File file)' in source
    assert 'if(app.cancelled.get())throw new java.io.InterruptedIOException("cancelled")' in source
    assert 'catch(java.io.InterruptedIOException cancelled){throw cancelled;}' in source
    # Missing outputSha256/outputSize never enters the verified cache-hit branch.
    assert 'expectedSize>=0L' in source and '!expectedSha.isEmpty()' in source
