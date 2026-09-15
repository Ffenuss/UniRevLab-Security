from pathlib import Path


SOURCE = Path("modkit/mobile/connected_report_streaming.py")
SECONDARY = Path("modkit/mobile/secondary_il2cpp_release.py")
AUTOMOD = Path("modkit/mobile/automod_cancellable.py")


def test_release_connected_report_uses_shared_exact_sha_secondary_gate():
    source = SOURCE.read_text(encoding="utf-8")
    secondary = SECONDARY.read_text(encoding="utf-8")
    automod = AUTOMOD.read_text(encoding="utf-8")

    assert "_secondary.ensure_workspace(workdir, cb)" in source
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

    for name in (
        "_ensure_il2cpp_crosscheck",
        "_ensure_metadata_identity",
        "_ensure_native_recovery",
    ):
        assert f"original_" in source
        assert f"_v12.{name}" in source

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


def test_native_failure_rows_are_not_streamed_without_current_exact_native_summary():
    source = SOURCE.read_text(encoding="utf-8")

    assert 'native_current = bool(exact_native) and not bool(exact_native.get("error"))' in source
    wrapper = source.split("def wrapped_stream_blockers", 1)[1].split("def wrapped_finding_rva", 1)[0]
    assert "if not native_current:" in wrapper
    assert "return {}, {}" in wrapper
    assert "return _stream_native_blockers(path, findings, gate)" in wrapper


def test_report_declares_no_legacy_mtime_fallback_in_release_wrapper():
    source = SOURCE.read_text(encoding="utf-8")
    assert '"legacyMtimeFallbackUsed": False' in source
    assert '"mtimeTrustedAsIdentity": False' in source
