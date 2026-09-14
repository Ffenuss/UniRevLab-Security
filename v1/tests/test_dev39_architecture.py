from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def test_dev39_human_simple_mode_filters_and_json_on_demand():
    ui=(ROOT/'android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java').read_text(encoding='utf-8')
    for token in ('Важное','READY','Gameplay','Crypto/Keys','Технические доказательства JSON'):
        assert token in ui
    assert 'serverAudit' in ui
    assert 'frameworkNoise' in ui and 'bundledSdk' in ui

def test_dev39_dex_boundary_fix_is_present():
    dex=(ROOT/'modkit/reworkspace/dex.py').read_text(encoding='utf-8')
    assert 'for method_count in (direct, virtual)' in dex
    assert 'contaminates directInvokes' in dex

def test_dev39_security_scan_remains_passive():
    sec=(ROOT/'modkit/mobile/security_scan.py').read_text(encoding='utf-8')
    assert 'activeConnectionAttempted' in sec and 'credentialValueExtraction' in sec and 'keyValueExtraction' in sec
    assert 'socket.socket' not in sec and 'requests.' not in sec and 'urllib.request' not in sec

def test_dev39_version():
    g=(ROOT/'android/app/build.gradle').read_text(encoding='utf-8'); p=(ROOT/'pyproject.toml').read_text(encoding='utf-8')
    assert 'versionCode 45' in g and '0.9.0-dev40' in g and '0.9.0.dev40' in p
