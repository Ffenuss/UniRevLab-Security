from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_full_reconstruction_persists_stage_remaining_and_elapsed():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/FullAnalysisService.java").read_text(encoding="utf-8")
    compact = "".join(source.split())
    assert 'put("phase","RECONSTRUCTION")' in compact
    assert 'put("stage",index)' in compact
    assert 'put("totalStages",total)' in compact
    assert 'put("remainingStages",Math.max(0,total-index))' in compact
    assert 'put("elapsedMs",elapsed)' in compact
    assert 'app.file("simple-progress.json")' in source
    assert 'stage(1,4,"Inventory:' in source
    assert 'stage(2,4,"JADX:' in source
    assert 'stage(3,4,"Apktool ' in source
    assert 'stage(4,4,"Lua/JS/Hermes deep' in source


def test_auto_analysis_renders_elapsed_without_fake_eta():
    source = (ROOT / "android/app/src/main/java/dev/modkit/mobile/AutoAnalysisActivity.java").read_text(encoding="utf-8")
    assert 'p.optLong("elapsedMs")' in source
    assert 'p.optInt("remainingStages")' in source
    assert 'phase(p)' in source
    assert 'прошло:' in source
    assert 'ETA' not in source
    assert 'осталось стадий:' in source
