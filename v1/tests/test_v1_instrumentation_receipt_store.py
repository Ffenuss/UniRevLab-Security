from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "android/app/src/main/java/dev/modkit/mobile/InstrumentationReceiptStore.java"


def text():
    return SOURCE.read_text(encoding="utf-8")


def test_pending_write_receipt_is_atomic_bounded_and_user_confirmed_only():
    source = text()
    assert 'SCHEMA = "modkit-instrumentation-pending-write-1.0"' in source
    assert '"USER_CONFIRMED_ROLLBACK_ONLY"' in source
    assert 'new File(destination.getPath() + ".part")' in source
    assert "StandardCopyOption.REPLACE_EXISTING" in source
    assert "raw.length > 64 * 1024" in source
    assert "Files.deleteIfExists(new File(destination.getPath() + \".part\").toPath())" in source


def test_recovered_receipt_preserves_fail_closed_rollback_guards():
    source = text()
    assert '"modkit-instrumentation-write-1.0"' in source
    assert '"modkit-instrumentation-lease-1.0"' in source
    assert '"ONLY_IF_CURRENT_BYTES_MATCH_REPLACEMENT"' in source
    assert "MAX_WRITE_BYTES" in source
    assert "unverified write receipt cannot be recovered" in source
    assert "stored rollback region is not readable+writable" in source
    assert "stored write range is outside stored region" in source
    assert "new RootMemoryInstrumentation.ProcessLease" in source
    assert "new RootMemoryInstrumentation.WriteReceipt" in source


def test_loading_pending_receipt_never_performs_memory_write_or_automatic_rollback():
    source = text()
    load_body = source[source.index("static PendingWrite load"):source.index("static void clear")]
    assert "RootMemoryInstrumentation.rollback" not in load_body
    assert "guardedWrite" not in load_body
    assert "writeRaw" not in load_body
