from pathlib import Path


def test_evidence_service_never_demotes_user_cancel_to_partial():
    source = Path("android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java").read_text(encoding="utf-8")

    # IL2CPP, RE, no-RVA recovery, AutoMod and Connected Report all have local
    # partial-error recovery. A user cancellation must escape through the common
    # cancelled path before any of those blocks records PARTIAL or continues.
    assert source.count("catch(Throwable e){if(app.cancelled.get())check();") >= 5
    assert 'progress(app.cancelled.get()?"Автоанализ отменён."' in source


def test_process_restart_clears_persisted_running_state():
    source = Path("android/app/src/main/java/dev/modkit/mobile/App.java").read_text(encoding="utf-8")

    assert 'getSharedPreferences("state",0).getBoolean("running",false)' in source
    assert 'Предыдущая операция прервана системой. Можно запустить её заново.' in source
    assert 'putBoolean("running",false)' in source
