from pathlib import Path


SOURCE = Path("android/app/src/main/java/dev/modkit/mobile/ReWorkspaceActivity.java")


def test_missing_re_confidence_is_unknown_not_zero():
    source = SOURCE.read_text(encoding="utf-8")
    helper = source.split("private String confidence(JSONObject finding)", 1)[1].split("private void addLinesCard", 1)[0]
    assert '!finding.has("confidence")' in helper
    assert 'finding.isNull("confidence")' in helper
    assert 'return "—"' in helper
    assert 'confidence(f)' in source
    assert 'f.optDouble("confidence")' not in source.split("private void refresh()", 1)[1]


def test_re_workspace_has_no_historical_dev18_dev19_user_instruction():
    source = SOURCE.read_text(encoding="utf-8")
    assert "dev18" not in source
    assert "dev19" not in source
    assert "текущей версии ModKit" in source
