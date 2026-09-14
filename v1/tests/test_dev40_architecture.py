from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


def test_dev40_cache_behavior_survives_v1():
    gradle=(ROOT/"android/app/build.gradle").read_text(encoding="utf-8")
    assert "versionCode 46" in gradle and "1.0.0" in gradle
    cache=(ROOT/"modkit/mobile/simple_cache.py").read_text(encoding="utf-8")
    assert "reuseOnlyWhenTargetDigestMatches" in cache and "cacheDoesNotRelaxValidation" in cache


def test_dev40_simple_mode_filters_progress_cancel_and_handoff():
    ui=(ROOT/"android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java").read_text(encoding="utf-8")
    for token in ("Patch Ready","HP / Health","Damage","Cooldown","Currency","Level / XP","Inventory","Movement","Authentication","Framework noise"):
        assert token in ui
    for token in ("Отменить анализ","simple-progress.json","Открыть в Decompiler","Открыть в Native","Deep Resolve / RE Workspace"):
        assert token in ui


def test_dev40_worker_is_staged_cached_and_cancel_aware():
    worker=(ROOT/"android/app/src/main/java/dev/modkit/mobile/WorkerService.java").read_text(encoding="utf-8")
    assert "simpleStage(1,6" in worker and "simpleStage(6,6" in worker
    assert "plan_workspace" in worker and "record_workspace" in worker
    assert "simpleCheckCancelled" in worker and "passive Network/API" in worker


def test_dev40_confirmation_ladder_is_distinct_from_locator_status():
    sm=(ROOT/"modkit/mobile/simple_mode.py").read_text(encoding="utf-8")
    for token in ("FOUND_STATIC","APP_OWNED","FLOW_CONFIRMED","LOCATOR_CONFIRMED","RUNTIME_CONFIRMED","PATCH_READY","SERVER_AUDIT","SDK_NOISE","FRAMEWORK_NOISE"):
        assert token in sm
    assert 'card["verificationStage"]' in sm and 'card["gameplayDomain"]' in sm
