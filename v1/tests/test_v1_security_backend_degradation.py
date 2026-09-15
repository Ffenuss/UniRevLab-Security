from pathlib import Path


SERVICE = Path("android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java")


def _source() -> str:
    return SERVICE.read_text(encoding="utf-8")


def test_security_backend_failure_is_partial_not_terminal():
    source = _source()

    stage4 = source.index('stage(4,6,securityCacheHit?')
    stage5 = source.index('stage(5,6,"Evidence Graph:', stage4)
    block = source[stage4:stage5]

    assert "try{" in block
    assert 'if(app.cancelled.get())check();' in block
    assert '.put("status","PARTIAL")' in block
    assert "продолжаю Evidence Graph/AutoMod/report" in block
    assert 'manifest.put("security"' in block


def test_security_cache_reuses_only_readable_non_error_result():
    source = _source()

    assert 'JSONObject cachedSecurity=unchanged?readJson("security-surfaces.json"):null' in source
    assert 'boolean securityCacheHit=cachedSecurity!=null&&!hasError(cachedSecurity)' in source
    assert 'if(!securityCacheHit){PyObject sec=Python.getInstance().getModule("modkit.mobile.security_scan")' in source


def test_security_partial_marks_final_pipeline_degraded():
    source = _source()

    assert '"PARTIAL".equals(securityStatus.optString("status"))' in source
    assert 'degradedReasons.put("SECURITY_PARTIAL")' in source
    assert 'manifest.put("degraded",degraded)' in source
    assert 'degraded?"PARTIAL":"SUCCESS"' in source
