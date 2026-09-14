from __future__ import annotations

import json
from pathlib import Path

from modkit.engines.bridges import normalize_file

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_release_version_is_consistent():
    gradle = read("android/app/build.gradle")
    package = read("pyproject.toml")
    init = read("modkit/__init__.py")
    assert "versionCode 47" in gradle
    assert "versionName '1.1.0-dev1'" in gradle
    assert 'version = "1.1.0.dev1"' in package
    assert '__version__ = "1.1.0.dev1"' in init


def test_release_home_and_runtime_lab_are_private_except_launcher():
    manifest = read("android/app/src/main/AndroidManifest.xml")
    assert '.HomeActivity" android:exported="true"' in manifest
    for activity in ("AutoAnalysisActivity", "FullModeActivity", "TargetSelectionActivity", "AnalysisStorageActivity", "MainActivity", "SimpleModeActivity", "ProcessLabActivity", "ReportCenterActivity"):
        assert f'.{activity}" android:exported="false"' in manifest
    assert "EngineCatalogActivity" not in manifest
    assert "EngineBridgeActivity" not in manifest
    assert '.TargetPreparationService" android:exported="false"' in manifest
    assert '.FullAnalysisService" android:exported="false"' in manifest
    assert '.AutomaticEvidenceService" android:exported="false"' in manifest


def test_home_has_only_release_routes_not_legacy_shell():
    home = read("android/app/src/main/java/dev/modkit/mobile/HomeActivity.java")
    assert "AutoAnalysisActivity.class" in home
    assert "FullModeActivity.class" in home
    assert "ReportCenterActivity.class" in home
    for forbidden in ("MainActivity.class", "SimpleModeActivity.class", "EngineCatalogActivity.class", "DecompilerActivity.class", "ReWorkspaceActivity.class", "NativeWorkspaceActivity.class"):
        assert forbidden not in home


def test_legacy_entry_points_are_redirects_only():
    main = read("android/app/src/main/java/dev/modkit/mobile/MainActivity.java")
    simple = read("android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java")
    assert "FullModeActivity.class" in main
    assert "AutoAnalysisActivity.class" in simple
    for forbidden in ("section(", "RecyclerView", "Для глупых", "Discovery / Methods"):
        assert forbidden not in main + simple


def test_target_selection_prepares_only_and_full_analysis_runs_once():
    auto = read("android/app/src/main/java/dev/modkit/mobile/AutoAnalysisActivity.java")
    selector = read("android/app/src/main/java/dev/modkit/mobile/TargetSelectionActivity.java")
    prep = read("android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java")
    service = read("android/app/src/main/java/dev/modkit/mobile/FullAnalysisService.java")
    evidence = read("android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java")
    assert "TargetSelectionActivity.class" in auto
    assert "FullAnalysisService.class" in auto
    assert "TargetPreparationService.class" in selector
    assert 'putExtra("kind","installed")' in selector
    assert 'putExtra("kind","apk")' in selector
    assert 'analysisPerformed",false' in prep
    assert "WorkerService.class" not in selector
    assert "DecompilerEngine.resolveTargetInputs" in service
    assert 'getModule("modkit.mobile.apkset")' in service
    assert 'callAttr("inspect_apk_paths"' in service
    assert 'getModule("modkit.mobile.package_target")' in service
    assert "exportAllZip(app.cancelled)" in service
    assert "ApktoolEngine.analyze(this,inputs,app.cancelled)" in service
    assert 'getModule("modkit.mobile.embedded_pipeline")' in service
    assert "AutomaticEvidenceService.class" in service
    assert "WorkerService.class" not in service
    assert "simple_prepare" not in service
    assert 'put("legacyWorkerUsed",false)' in evidence.replace(" ", "")
    assert 'callAttr("re_analyze_apk"' in evidence
    assert 'getModule("modkit.mobile.security_scan")' in evidence
    assert 'callAttr("build_catalog"' in evidence
    assert "WorkerService.class" not in evidence
    assert '"automatic-evidence.json"' in prep
    assert '"installed-apk-set.zip"' in prep


def test_long_running_chain_persists_interruption_marker():
    app = read("android/app/src/main/java/dev/modkit/mobile/App.java")
    prep = read("android/app/src/main/java/dev/modkit/mobile/TargetPreparationService.java")
    full = read("android/app/src/main/java/dev/modkit/mobile/FullAnalysisService.java")
    evidence = read("android/app/src/main/java/dev/modkit/mobile/AutomaticEvidenceService.java")
    for source in (prep, full, evidence):
        compact = "".join(source.split())
        assert 'putBoolean("running",true)' in compact
        assert 'putBoolean("running",false)' in compact
    assert 'getBoolean("running",false)' in app
    assert "Предыдущая операция прервана системой" in app
    assert "handedOff" in full
    assert "AutomaticEvidenceService.class" in full


def test_full_analysis_runs_embedded_apktool_and_script_backends_without_import():
    service = read("android/app/src/main/java/dev/modkit/mobile/FullAnalysisService.java")
    gradle = read("android/app/build.gradle")
    settings = read("android/settings.gradle")
    apktool = read("android/app/src/main/java/dev/modkit/mobile/ApktoolEngine.java")
    embedded = read("modkit/mobile/embedded_pipeline.py")
    hermes = read("modkit/mobile/hermes_deep.py")
    assert "org.apktool:apktool-lib:2.12.1" in gradle
    assert "jitpack.io" not in settings.casefold()
    assert 'APKTOOL_VERSION = "2.12.1"' in apktool
    assert "new Config()" in apktool and "new ExtFile(input)" in apktool
    assert "docopt-ng==0.8.1" in gradle
    assert "Kirlif/HBC-Tool/releases/download/96/hbctool-0.1.5-96-py3-none-any.whl" in gradle
    assert "options '--no-deps'" in gradle
    assert "ApktoolEngine.analyze(this,inputs,app.cancelled)" in service
    assert 'getModule("modkit.mobile.embedded_pipeline")' in service
    assert '"manualImportRequired": False' in embedded
    assert "hermes_deep.scan_workspace" in embedded
    assert 'ENGINE_ID = "apktool.android"' in apktool
    assert '"hermes.deep-embedded"' in hermes


def test_connected_report_links_findings_to_methods():
    report = read("modkit/mobile/connected_report.py")
    center = read("android/app/src/main/java/dev/modkit/mobile/ReportCenterActivity.java")
    assert "EXACT_METHOD_ID" in report and "EXACT_RVA" in report and "EXACT_NAME" in report
    assert '"manualImportRequired": False' in report
    assert 'getModule("modkit.mobile.connected_report")' in center
    assert "EvidenceBundleExporter.export" in center


def test_external_bridge_normalizes_as_optional_corroboration(tmp_path: Path):
    source = tmp_path / "ghidra.json"
    source.write_text(json.dumps({"functions": [{"name": "Player_takeDamage", "address": "0x1234", "size": 48}]}), encoding="utf-8")
    out = normalize_file("ghidra", source)
    assert out["engineId"] == "ghidra.bridge"
    assert out["status"] == "IMPORTED_EVIDENCE"
    assert out["trusted"] is False


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
    compact = "".join(engine.split())
    assert 'put("writesTargetMemory",false)' in compact
    assert 'put("injectsCode",false)' in compact


def test_full_evidence_export_and_engine_catalog_exist_in_bundle():
    exporter = read("android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java")
    assert "modkit-evidence-bundle-1.0" in exporter
    assert "engine-catalog.json" in exporter
    assert "hashes.sha256" in exporter


def test_canonical_ci_never_reconstructs_dev_patch_chain():
    workflow = (ROOT.parent / ".github/workflows/modkit-v1-ci.yml").read_text(encoding="utf-8")
    assert "working-directory: v1" in workflow
    assert "packages: platform-tools" in workflow
    assert ".dev40" not in workflow and "apply-dev" not in workflow
    assert "assembleDebug" in workflow and "lintDebug" in workflow
    assert "zipalign" in workflow and "apksigner" in workflow
