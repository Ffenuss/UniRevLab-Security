from pathlib import Path


SERVICE = Path("android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java")


def _source() -> str:
    return SERVICE.read_text(encoding="utf-8")


def test_cache_record_failure_invalidates_old_cache_and_continues_partial():
    source = _source()

    start = source.index('cache.callAttr("record_workspace"')
    end = source.index("JSONArray degradedReasons", start)
    block = source[start:end]

    assert 'if(app.cancelled.get())check();' in block
    assert 'Files.deleteIfExists(app.file("simple-cache.json").toPath())' in block
    assert '.put("cacheRecorded",false)' in block
    assert '.put("status","PARTIAL")' in block
    assert "stale cache инвалидирован" in block


def test_cache_invalidation_failure_is_terminal_not_silently_partial():
    source = _source()

    assert 'throw new IOException("Cache write failed and stale cache invalidation failed:' in source
    assert "invalidationError" in source


def test_cache_write_partial_marks_pipeline_degraded():
    source = _source()

    assert 'JSONObject cacheStatus=manifest.optJSONObject("cacheStatus")' in source
    assert 'degradedReasons.put("CACHE_WRITE_PARTIAL")' in source
    assert 'degraded?"PARTIAL":"SUCCESS"' in source


def test_core_analyzer_partial_still_requires_cache_invalidation():
    source = _source()

    blocked = source.index('put("cacheBlockedReason","core analyzer partial or incomplete")')
    delete = source.rfind('Files.deleteIfExists(app.file("simple-cache.json").toPath())', 0, blocked)
    assert delete >= 0
    assert delete < blocked
