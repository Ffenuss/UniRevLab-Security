from pathlib import Path


ANDROID = Path("android/app/src/main/java/dev/modkit/mobile")
MANIFEST = Path("android/app/src/main/AndroidManifest.xml")


def test_manifest_keeps_wakelock_permission_for_long_analysis():
    manifest = MANIFEST.read_text(encoding="utf-8")
    assert 'android.permission.WAKE_LOCK' in manifest


def test_reconstruction_holds_and_releases_partial_wakelock():
    source = (ANDROID / "FullAnalysisService.java").read_text(encoding="utf-8")
    assert "PowerManager.WakeLock wake" in source
    assert "PowerManager.PARTIAL_WAKE_LOCK" in source
    assert '"ModKit:full-analysis"' in source
    acquire = source.index("wake.acquire(")
    thread = source.index('new Thread(()->{', acquire)
    release = source.index("if(wake!=null&&wake.isHeld())wake.release()", thread)
    stop = source.index("stopForeground(true);stopSelf();", release)
    assert acquire < thread < release < stop


def test_evidence_phase_keeps_its_own_wakelock_and_releases_it():
    source = (ANDROID / "AutomaticEvidenceService.java").read_text(encoding="utf-8")
    assert "PowerManager.PARTIAL_WAKE_LOCK" in source
    assert '"ModKit:auto-evidence"' in source
    acquire = source.index("wake.acquire(")
    release = source.index("if(wake!=null&&wake.isHeld())wake.release()", acquire)
    assert acquire < release
