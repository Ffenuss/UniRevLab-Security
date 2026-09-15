from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_deep_script_outputs_are_cleared_when_target_changes():
    prep = (ROOT / "android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java").read_text(encoding="utf-8")
    assert '"lua-deep.json"' in prep
    assert '"cocos-deep.json"' in prep
    assert '"deep-gameplay.json"' in prep
    assert '"artifact-families.json"' in prep
    assert '"embedded-analysis.json"' in prep


def test_embedded_pipeline_runs_lua_cocos_and_semantic_gameplay_without_manual_import():
    pipeline = (ROOT / "modkit/mobile/embedded_pipeline.py").read_text(encoding="utf-8")
    assert "lua_deep_cancellable.scan_workspace" in pipeline
    assert "cocos_deep.scan_workspace" in pipeline
    assert "deep_gameplay.scan_workspace" in pipeline
    assert '"luaReport": "lua-deep.json"' in pipeline
    assert '"cocosReport": "cocos-deep.json"' in pipeline
    assert '"deepGameplayReport": "deep-gameplay.json"' in pipeline
    assert '"manualImportRequired": False' in pipeline
