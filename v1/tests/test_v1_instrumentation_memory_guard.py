from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_instrumentation_memory_access_is_session_bound_and_fail_closed():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/RootMemoryInstrumentation.java").read_text(encoding="utf-8")
    assert "MAX_READ_BYTES = 4096" in source
    assert "MAX_WRITE_BYTES = 256" in source
    assert "startTicks" in source
    assert "stale process lease" in source
    assert '"dd if=/proc/" + pid + "/mem' in source
    assert '" | dd of=/proc/" + pid + "/mem' in source
    assert "compare-before-write failed" in source
    assert "mapping is not writable" in source
    assert "write verification failed; rollback attempted" in source
    assert "rollback blocked because current bytes no longer match" in source
    assert '"rollbackPolicy", "ONLY_IF_CURRENT_BYTES_MATCH_REPLACEMENT"' in source


def test_instrumentation_memory_writes_require_expected_original_bytes():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/RootMemoryInstrumentation.java").read_text(encoding="utf-8")
    assert "guardedWrite(ProcessLease lease, long address, byte[] expectedOriginal, byte[] replacement)" in source
    assert "expectedOriginal.length != replacement.length" in source
    assert "Arrays.equals(current, expectedOriginal)" in source
    assert "Arrays.equals(verified, replacement)" in source
    assert "requireRegion(lease, address, replacement.length, true)" in source
