from pathlib import Path


SOURCE = Path("modkit/mobile/connected_report_streaming.py")
SECONDARY = Path("modkit/mobile/secondary_il2cpp_release.py")
AUTOMOD = Path("modkit/mobile/automod_cancellable.py")


def test_release_connected_report_uses_shared_exact_sha_secondary_gate():
    source = SOURCE.read_text(encoding="utf-8")
    secondary = SECONDARY.read_text(encoding="utf-8")
    automod = AUTOMOD.read_text(encoding="utf-8")

    assert "root = Path(workdir)" in source
    assert "_secondary.ensure_workspace(root, cb)" in source
    assert '"freshnessPolicy": "EXACT_INPUT_SHA256"' in secondary
    assert '"mtimeTrustedAsIdentity": False' in secondary
    assert "hashlib.sha256()" in automod
    assert "def _same_inputs" in automod
    assert 'recorded == fingerprints' in automod


def test_exact_secondary_summaries_fail_closed_when_current_inputs_are_unavailable():
    source = SOURCE.read_text(encoding="utf-8")
    helper = source.split("def _exact_secondary_summary", 1)[1].split("def _part", 1)[0]

    assert "if not isinstance(value, dict) or not value:" in helper
    assert "return {}" in helper
    assert 'out["freshnessVerified"] = True' in helper
    assert 'out["sourceInputsAvailable"] = True' in helper
    assert 'out["freshnessPolicy"] = "EXACT_INPUT_SHA256"' in helper

    for key in ("crosscheck", "metadataIdentity", "nativeRecovery"):
        assert f'_exact_secondary_summary(secondary, "{key}")' in source


def test_v12_legacy_mtime_ensure_functions_are_replaced_and_restored_around_build():
    source = SOURCE.read_text(encoding="utf-8")

    assert "original_crosscheck = _v12._ensure_il2cpp_crosscheck" in source
    assert "original_identity = _v12._ensure_metadata_identity" in source
    assert "original_native = _v12._ensure_native_recovery" in source
    assert "_v12._ensure_il2cpp_crosscheck = wrapped_crosscheck" in source
    assert "_v12._ensure_metadata_identity = wrapped_identity" in source
    assert "_v12._ensure_native_recovery = wrapped_native" in source
    assert "_v12._ensure_il2cpp_crosscheck = original_crosscheck" in source
    assert "_v12._ensure_metadata_identity = original_identity" in source
    assert "_v12._ensure_native_recovery = original_native" in source

    patch = source.index("_v12._ensure_il2cpp_crosscheck = wrapped_crosscheck")
    build = source.index("report = _v12.build_connected_report", patch)
    restore = source.index("_v12._ensure_il2cpp_crosscheck = original_crosscheck", build)
    assert patch < build < restore


def test_native_failure_rows_require_current_exact_summary_and_declared_file_backing():
    source = SOURCE.read_text(encoding="utf-8")

    assert 'failures_path = root / "il2cpp-no-rva-native.failures.jsonl"' in source
    gate = source.split("native_blockers_current = bool(", 1)[1].split("reader, retained", 1)[0]
    assert 'not exact_native.get("error")' in gate
    assert 'exact_native.get("freshnessPolicy") == "EXACT_INPUT_SHA256"' in gate
    assert 'bool(exact_native.get("failuresAreFileBacked"))' in gate
    assert 'exact_native.get("failureRowsFile") == failures_path.name' in gate
    assert "failures_path.is_file()" in gate

    wrapper = source.split("def wrapped_stream_blockers", 1)[1].split("def wrapped_finding_rva", 1)[0]
    assert "if not native_blockers_current or Path(path).name != failures_path.name:" in wrapper
    assert "return {}, {}" in wrapper
    assert "return _stream_native_blockers(failures_path, findings, gate)" in wrapper


def test_report_declares_no_legacy_mtime_fallback_and_native_blocker_freshness():
    source = SOURCE.read_text(encoding="utf-8")
    assert '"legacyMtimeFallbackUsed": False' in source
    assert '"mtimeTrustedAsIdentity": False' in source
    assert '"nativeBlockerRowsExactCurrent": native_blockers_current' in source
