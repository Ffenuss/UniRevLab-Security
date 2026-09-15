from pathlib import Path


SOURCE = Path("android/app/src/main/java/dev/modkit/mobile/DeepEvidenceActivity.java")


def test_missing_deep_evidence_fields_render_as_unknown_not_zero():
    source = SOURCE.read_text(encoding="utf-8")
    helper = source.split("private String value(JSONObject o,String key)", 1)[1].split("private String rva", 1)[0]
    assert '!o.has(key)' in helper
    assert 'o.isNull(key)' in helper
    assert 'return "—"' in helper
    assert '?"0"' not in helper
    assert 'настоящий 0 остаётся нулём' in source
