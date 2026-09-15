from pathlib import Path


SOURCE = Path("android/app/src/main/java/dev/modkit/mobile/DeepEvidenceActivity.java")


def test_missing_deep_evidence_fields_render_as_unknown_not_zero():
    source = SOURCE.read_text(encoding="utf-8")
    helper = source.split("private String value(JSONObject o,String key)", 1)[1].split("private String countIfReport", 1)[0]
    assert '!o.has(key)' in helper
    assert 'o.isNull(key)' in helper
    assert 'return "—"' in helper
    assert '?"0"' not in helper
    assert 'настоящий 0 остаётся нулём' in source


def test_missing_reports_do_not_turn_derived_counters_into_fake_zeroes():
    source = SOURCE.read_text(encoding="utf-8")
    assert 'private String countIfReport(JSONObject report,long value){return report==null?"—":String.valueOf(value);}' in source
    assert 'countIfReport(lua,decoded)' in source
    assert 'countIfReport(lua,opaque)' in source
    assert 'countIfReport(nativeReport,direct)' in source
    assert 'countIfReport(nativeReport,tail)' in source
    assert 'countIfReport(nativeReport,indirect)' in source


def test_backend_error_is_not_rendered_as_not_detected():
    source = SOURCE.read_text(encoding="utf-8")
    state = source.split("private String state(JSONObject value)", 1)[1].split("private String value", 1)[0]
    error = state.index('!value.optString("error","").isEmpty()')
    detected = state.index('value.optBoolean("available")', error)
    not_detected = state.index('return "не обнаружено"', detected)
    assert error < detected < not_detected
    assert 'return "backend partial/error"' in state
