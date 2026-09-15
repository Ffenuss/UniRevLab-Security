from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def test_dev37_analysis_and_file_workspace_are_wired_without_legacy_shell():
    home=(ROOT/'android/app/src/main/java/dev/modkit/mobile/HomeActivity.java').read_text(encoding='utf-8')
    full=(ROOT/'android/app/src/main/java/dev/modkit/mobile/FullModeActivity.java').read_text(encoding='utf-8')
    compat=(ROOT/'android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java').read_text(encoding='utf-8')
    manifest=(ROOT/'android/app/src/main/AndroidManifest.xml').read_text(encoding='utf-8')
    worker=(ROOT/'android/app/src/main/java/dev/modkit/mobile/WorkerService.java').read_text(encoding='utf-8')
    assert 'AutoAnalysisActivity.class' in home
    assert 'FullModeActivity.class' in home
    assert 'FileWorkspaceActivity.class' in full
    assert 'extends AutoAnalysisActivity' in compat
    assert 'startActivity(' not in compat and 'finish();' not in compat
    assert '.AutoAnalysisActivity' in manifest and '.FileWorkspaceActivity' in manifest
    # Historical operation IDs remain compatibility contracts for manual tools only.
    assert 'simple_prepare' in worker and 'simple_build' in worker
    assert 'workspace_inspect' in worker and 'workspace_build' in worker


def test_dev37_server_findings_fail_closed():
    simple=(ROOT/'modkit/mobile/simple_mode.py').read_text(encoding='utf-8')
    assert 'serverBypassGenerated' in simple
    assert 'audit+local-simulation-only' in simple
    assert 'not _contains_server(c)' in simple


def test_dev37_generic_workspace_patch_is_explicit_manifest_only():
    core=(ROOT/'modkit/patchpack/core.py').read_text(encoding='utf-8')
    assert 'modkit-workspace-patch-1.0' in core
    assert 'WORKSPACE_TARGET_INVALID' in core
    assert 'workspaceManifest' in core


def test_dev37_cocos_runtime_detection_is_part_of_installed_scan():
    apkset=(ROOT/'modkit/mobile/apkset.py').read_text(encoding='utf-8')
    simple=(ROOT/'modkit/mobile/simple_mode.py').read_text(encoding='utf-8')
    for marker in ('libcocos2dcpp.so','jsb-adapter','.luac','.jsc'):
        assert marker in apkset or marker in simple
