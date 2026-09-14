from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def test_dev39_human_catalogue_filters_and_json_evidence_survive_new_shell():
    model=(ROOT/'modkit/mobile/simple_mode.py').read_text(encoding='utf-8')
    ui=(ROOT/'android/app/src/main/java/dev/modkit/mobile/AutoAnalysisActivity.java').read_text(encoding='utf-8')
    for token in ('PATCH_READY','gameplayDomain','serverAudit','FRAMEWORK_NOISE','SDK_NOISE'):
        assert token in model
    assert 'important=cat.optInt("important")' in ui
    assert 'cat.optJSONArray("cards")' in ui
    assert 'c.toString()' in ui

def test_dev39_dex_boundary_fix_is_present():
    dex=(ROOT/'modkit/reworkspace/dex.py').read_text(encoding='utf-8')
    assert 'for method_count in (direct, virtual)' in dex
    assert 'contaminates directInvokes' in dex

def test_dev39_security_scan_remains_passive():
    sec=(ROOT/'modkit/mobile/security_scan.py').read_text(encoding='utf-8')
    assert 'activeConnectionAttempted' in sec and 'credentialValueExtraction' in sec and 'keyValueExtraction' in sec
    assert 'socket.socket' not in sec and 'requests.' not in sec and 'urllib.request' not in sec

def test_dev39_guards_survive_v1_release_identity():
    g=(ROOT/'android/app/build.gradle').read_text(encoding='utf-8'); p=(ROOT/'pyproject.toml').read_text(encoding='utf-8')
    assert 'versionCode 46' in g and "versionName '1.0.0'" in g and 'version = "1.0.0"' in p
