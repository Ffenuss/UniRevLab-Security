from pathlib import Path


SOURCE = Path("android/app/src/main/java/dev/modkit/mobile/App.java")


def test_interrupted_startup_never_restores_old_analysis_summary_into_current_ui_result():
    source = SOURCE.read_text(encoding="utf-8")
    on_create = source.split("@Override public void onCreate()", 1)[1]

    assert "boolean interruptedState=wasRunning||targetPreparing||pipelineInterrupted;" in on_create
    assert "final boolean restorePreviousResult=!interruptedState;" in on_create

    thread = on_create.split('new Thread(() ->', 1)[1]
    gate = thread.index("if(!restorePreviousResult){result=null;revision++;return;}")
    summary = thread.index('File f = file("analysis.summary.json")')
    restore = thread.index("result = new JSONObject", summary)
    assert gate < summary < restore


def test_interrupted_result_suppression_preserves_cache_files_for_sha_verified_future_reuse():
    source = SOURCE.read_text(encoding="utf-8")
    on_create = source.split("@Override public void onCreate()", 1)[1]

    # Interruption suppresses in-memory/UI restoration only. Full target-preparation
    # interruption has its own stronger cleanup path, but a normal interrupted
    # analysis keeps core files so simple_cache can validate them by exact SHA later.
    interrupted_branch = on_create.split("boolean interruptedState=", 1)[1].split('new Thread(() ->', 1)[0]
    assert 'deleteInterruptedTargetTree(file("analysis.summary.json"))' not in interrupted_branch
    assert "restorePreviousResult=!interruptedState" in on_create
