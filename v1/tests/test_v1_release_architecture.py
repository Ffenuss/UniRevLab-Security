from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_release_version_is_consistent():
    gradle = read("android/app/build.gradle")
    package = read("pyproject.toml")
    init = read("modkit/__init__.py")
    assert "versionCode 46" in gradle
    assert "versionName '1.0.0'" in gradle
    assert 'version = "1.0.0"' in package
    assert '__version__ = "1.0.0"' in init


def test_release_home_and_runtime_lab_are_private_except_launcher():
    manifest = read("android/app/src/main/AndroidManifest.xml")
    assert '.HomeActivity" android:exported="true"' in manifest
    for activity in ("MainActivity", "ProcessLabActivity", "EngineCatalogActivity", "ReportCenterActivity"):
        assert f'.{activity}" android:exported="false"' in manifest


def test_core_app_keeps_no_internet_permission():
    manifest = read("android/app/src/main/AndroidManifest.xml")
    assert "android.permission.INTERNET" not in manifest


def test_root_lab_is_explicit_read_only_by_default():
    activity = read("android/app/src/main/java/dev/modkit/mobile/ProcessLabActivity.java")
    engine = read("android/app/src/main/java/dev/modkit/mobile/RootProcessEngine.java")
    root = read("android/app/src/main/java/dev/modkit/mobile/RootAccess.java")
    assert "Проверить root" in activity
    assert "RootAccess.probe()" in activity
    assert "READ_ONLY_OBSERVATION" in engine
    assert 'runSu("id"' in root
    assert "uid == 0" in root
    for forbidden in ("/proc/" + '" + pid + "/mem', "kill -", "am force-stop"):
        assert forbidden not in engine


def test_full_evidence_export_and_engine_catalog_exist():
    exporter = read("android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java")
    assert "modkit-evidence-bundle-1.0" in exporter
    assert "engine-catalog.json" in exporter
    assert "hashes.sha256" in exporter
    assert "rawTargetBinariesIncluded" in exporter
