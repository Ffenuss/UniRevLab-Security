from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "android/app/src/main/java/dev/modkit/mobile/ProcessLabActivity.java"


def text():
    return SOURCE.read_text(encoding="utf-8")


def test_process_lab_keeps_runtime_session_read_only_and_requires_explicit_instrumentation_arm():
    source = text()
    assert "Подключить read-only session" in source
    assert "private void armInstrumentation()" in source
    assert "RootMemoryInstrumentation.captureLease(current.process.pid, current.process.uid)" in source
    assert "Включить Instrumentation v1 для session" in source
    assert "armInstrumentationButton = button" in source
    # Attaching the observation session must not itself arm or mutate target memory.
    attach_body = source[source.index("private void attach()"):source.index("private void writeAtomicJson")]
    assert "captureLease" not in attach_body
    assert "guardedWrite" not in attach_body


def test_process_lab_reads_through_live_module_rva_resolution_before_enabling_write():
    source = text()
    assert "RootModuleAddressResolver.resolve(lease, selector, rva, length, false)" in source
    assert "RootModuleAddressResolver.read(resolved)" in source
    assert "expectedInput.setText(bytesToHex(bytes))" in source
    assert "lastReadBytes = bytes.clone()" in source
    assert "lastReadBytes.length <= RootMemoryInstrumentation.MAX_WRITE_BYTES" in source


def test_process_lab_guarded_write_is_explicit_confirmed_verified_and_reversible():
    source = text()
    assert 'setTitle("Подтвердить guarded write")' in source
    assert "Arrays.equals(expected, lastReadBytes)" in source
    assert "RootModuleAddressResolver.guardedWrite(target, expected, replacement)" in source
    assert "WRITE VERIFIED · rollback доступен" in source
    assert 'setTitle("Rollback последней записи")' in source
    assert "RootMemoryInstrumentation.rollback(receipt)" in source
    assert "ROLLBACK VERIFIED" in source


def test_pending_write_cannot_be_silently_lost_on_process_switch_or_disconnect():
    source = text()
    select_body = source[source.index("private void selectProcess"):source.index("private void attach()")]
    assert "if (lastWrite != null)" in select_body
    assert "Сначала выполните rollback" in select_body
    detach_body = source[source.index("private void detach()"):source.index("private void detachNow()")]
    assert "if (lastWrite != null)" in detach_body
    assert "Отключить без rollback" in detach_body


def test_instrumentation_actions_are_bounded_and_audited():
    source = text()
    assert "MAX_INSTRUMENTATION_AUDIT_EVENTS = 64" in source
    assert '"modkit-instrumentation-audit-1.0"' in source
    for event in (
        "LEASE_ARMED", "LEASE_FAILED", "READ_VERIFIED", "READ_FAILED",
        "WRITE_VERIFIED", "WRITE_FAILED", "ROLLBACK_VERIFIED", "ROLLBACK_FAILED",
    ):
        assert event in source
    assert "instrumentation-audit.json" in source
    assert "RootMemoryInstrumentation.MAX_READ_BYTES" in source
    assert "RootMemoryInstrumentation.MAX_WRITE_BYTES" in source
