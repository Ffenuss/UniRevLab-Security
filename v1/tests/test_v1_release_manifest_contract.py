from pathlib import Path


MANIFEST = Path("android/app/src/main/AndroidManifest.xml")
BUILD = Path("android/app/build.gradle")


def test_release_manifest_keeps_single_launcher_and_private_pipeline_services():
    source = MANIFEST.read_text(encoding="utf-8")

    assert source.count('android.intent.category.LAUNCHER') == 2  # launcher activity + package visibility query
    assert '<activity android:name=".HomeActivity" android:exported="true">' in source
    for activity in (
        "AutoAnalysisActivity",
        "FullModeActivity",
        "TargetSelectionActivity",
        "AutoModActivity",
        "ReportCenterActivity",
    ):
        assert f'<activity android:name=".{activity}" android:exported="false"' in source

    for service in (
        "TargetPreparationService",
        "FullAnalysisService",
        "AutomaticEvidenceService",
        "AutoModPrepareService",
        "AutoModBuildGuardService",
        "WorkerService",
    ):
        assert f'<service android:name=".{service}" android:exported="false" android:foregroundServiceType="dataSync"/>' in source


def test_release_manifest_does_not_request_network_permission():
    source = MANIFEST.read_text(encoding="utf-8")

    assert "android.permission.INTERNET" not in source
    assert "android.permission.FOREGROUND_SERVICE" in source
    assert "android.permission.WAKE_LOCK" in source


def test_dev_release_version_stays_unpromoted_until_canonical_ci_is_green():
    source = BUILD.read_text(encoding="utf-8")

    assert "versionCode 47" in source
    assert "versionName '1.1.0-dev1'" in source
    assert "compileSdk 34" in source
    assert "targetSdk 34" in source
    assert "ndkVersion '26.1.10909125'" in source
    assert "org.apktool:apktool-lib:2.12.1" in source
