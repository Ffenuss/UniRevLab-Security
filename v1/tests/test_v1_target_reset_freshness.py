from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_new_target_clears_file_backed_indexes_cache_and_exact_recovery_state():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java").read_text(encoding="utf-8")
    required = (
        "installed-target.json",
        "game.apk",
        "metadata.bin",
        "library.so",
        "analysis.methods.jsonl",
        "analysis.methods.jsonl.idx",
        "analysis.methods.jsonl.rva.idx",
        "analysis.methods.jsonl.pages.idx",
        "analysis.methods.meta.json",
        "analysis.resolver-index.json",
        "analysis.autopilot-index.jsonl",
        "analysis.evidence-graph.jsonl.idx",
        "analysis.evidence-graph.meta.json",
        "simple-cache.json",
        "il2cpp-crosscheck.json",
        "il2cpp-metadata-identity.json",
        "il2cpp-no-rva-native.json",
        "il2cpp-no-rva-native.methods.jsonl",
        "il2cpp-no-rva-native.failures.jsonl",
        "automod-plan.json",
        "menu-spec.json",
        "menu-preflight.json",
        "menu-autopilot.json",
        "connected-report.json",
        "connected-report.md",
    )
    for name in required:
        assert f'"{name}"' in source
    assert "app.result=null" in source
    assert '.remove("active.project")' in source
    assert '.remove("selections")' in source


def test_target_reset_fails_closed_if_old_artifact_cannot_be_deleted():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java").read_text(encoding="utf-8")
    assert "private void clearTargetDependentOutputs()throws IOException" in source
    assert "private static void deleteTree(File file)throws IOException" in source
    assert 'if(!file.delete()&&file.exists())throw new IOException("Не удалось очистить старый target artifact: "+file.getName())' in source


def test_target_selection_service_remains_preparation_only():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java").read_text(encoding="utf-8")
    assert "FullAnalysisService.class" not in source
    assert 'put("preparedOnly",true)' in source
    assert 'put("analysisPerformed",false)' in source
