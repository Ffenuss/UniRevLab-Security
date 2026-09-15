import os
from pathlib import Path

from modkit.mobile import automod_cancellable


class _NeverCancel:
    def isCancelled(self):
        return False


def test_secondary_evidence_fingerprint_detects_same_size_same_mtime_byte_change(tmp_path):
    source = tmp_path / "analysis.methods.jsonl"
    source.write_bytes(b"AAAA")
    original = source.stat()

    gate = automod_cancellable._Gate(_NeverCancel())
    first = automod_cancellable._FingerprintCache().inputs([source], gate)

    source.write_bytes(b"BBBB")
    os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
    second = automod_cancellable._FingerprintCache().inputs([source], gate)

    assert first[0]["size"] == second[0]["size"] == 4
    assert source.stat().st_mtime_ns == original.st_mtime_ns
    assert first[0]["sha256"] != second[0]["sha256"]
    assert not automod_cancellable._same_inputs({"inputFingerprints": first}, second)


def test_old_secondary_summary_without_hashes_fails_closed(tmp_path):
    source = tmp_path / "metadata.bin"
    source.write_bytes(b"metadata")
    current = automod_cancellable._FingerprintCache().inputs(
        [source], automod_cancellable._Gate(_NeverCancel())
    )

    assert not automod_cancellable._same_inputs({}, current)
    assert not automod_cancellable._same_inputs({"inputFingerprints": []}, current)


def test_android_no_rva_stage_uses_shared_exact_freshness_route():
    source = Path("android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java").read_text(encoding="utf-8")

    assert 'getModule("modkit.mobile.il2cpp_no_rva_native_release")' in source
    assert 'getModule("modkit.mobile.il2cpp_no_rva_native");' not in source
