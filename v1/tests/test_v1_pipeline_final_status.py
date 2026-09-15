from pathlib import Path


def _source() -> str:
    return Path(
        "android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java"
    ).read_text(encoding="utf-8")


def test_manifest_has_distinct_success_partial_failed_cancelled_states():
    source = _source()

    assert '.put("status","RUNNING")' in source
    assert 'app.cancelled.get()?"CANCELLED":"FAILED"' in source
    assert '.put("complete",false)' in source
    assert 'manifest.put("degraded",degraded)' in source
    assert '.put("status",degraded?"PARTIAL":"SUCCESS")' in source


def test_partial_reasons_cover_reconstruction_and_release_backends():
    source = _source()

    required = (
        "JADX_RECONSTRUCTION_MISSING",
        "JADX_RECONSTRUCTION_PARTIAL",
        "JADX_DECODE_ERRORS",
        "APKTOOL_SUMMARY_MISSING",
        "APKTOOL_PARTIAL",
        "EMBEDDED_SUMMARY_MISSING",
        "EMBEDDED_PARTIAL",
        "IL2CPP_PARTIAL",
        "RE_ANALYSIS_PARTIAL",
        "NO_RVA_NATIVE_PARTIAL",
        "AUTOMOD_PARTIAL",
        "CONNECTED_REPORT_PARTIAL",
    )
    for reason in required:
        assert f'"{reason}"' in source


def test_apktool_hard_failure_and_jadx_decode_errors_are_not_success():
    source = _source()

    assert 'reconstruction.optInt("errors")>0' in source
    assert '"FAILED".equals(apktoolSummary.optString("status"))' in source
    assert 'hasError(apktoolSummary)' in source
    assert 'apktoolSummary.optInt("failed")>0' in source


def test_secondary_release_errors_propagate_to_partial_status():
    source = _source()

    assert 'recoveryError.isEmpty()?"SUCCESS":"PARTIAL"' in source
    assert 'hasError(autoPlan.optJSONObject("il2cppCrosscheck"))' in source
    assert 'hasError(autoPlan.optJSONObject("il2cppMetadataIdentity"))' in source
    assert 'hasError(autoPlan.optJSONObject("il2cppNativeRecovery"))' in source
    assert '"PARTIAL".equals(reportStatus.optString("status"))' in source
