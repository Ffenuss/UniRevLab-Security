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
    assert "versionCode 46" in gradle
    assert "versionName '1.0.0'" in gradle
    assert 'version = "1.0.0"' in package
    assert '__version__ = "1.0.0"' in init


def test_release_home_and_runtime_lab_are_private_except_launcher():
    manifest = read("android/app/src/main/AndroidManifest.xml")
    assert '.HomeActivity" android:exported="true"' in manifest
    for activity in ("MainActivity", "ProcessLabActivity", "EngineCatalogActivity", "EngineBridgeActivity", "ReportCenterActivity"):
        assert f'.{activity}" android:exported="false"' in manifest
    assert '.FullAnalysisService" android:exported="false"' in manifest


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
    assert 'put("writesTargetMemory", false)' in engine
    assert 'put("injectsCode", false)' in engine
    for forbidden in ("/proc/" + '" + pid + "/mem', "kill -", "am force-stop"):
        assert forbidden not in engine


def test_simple_mode_runs_full_reconstruction_before_evidence_pipeline():
    ui = read("android/app/src/main/java/dev/modkit/mobile/SimpleModeActivity.java")
    service = read("android/app/src/main/java/dev/modkit/mobile/FullAnalysisService.java")
    assert "startFullAnalysis()" in ui
    assert "FullAnalysisService.class" in ui
    assert "DecompilerEngine.resolveTargetInputs" in service
    assert "exportAllZip(app.cancelled)" in service
    assert '"full-reconstruction.json"' in service
    assert '"artifact-families.json"' in service
    assert 'putExtra("op","simple_prepare")' in service


def test_external_bridge_normalizes_without_executing_imported_code(tmp_path: Path):
    source = tmp_path / "ghidra.json"
    source.write_text(json.dumps({"functions": [{"name": "Player_takeDamage", "address": "0x1234", "size": 48}]}), encoding="utf-8")
    out = normalize_file("ghidra", source)
    assert out["engineId"] == "ghidra.bridge"
    assert out["recordCount"] >= 1
    assert out["executesImportedCode"] is False
    assert out["status"] == "IMPORTED_EVIDENCE"


def test_full_evidence_export_and_engine_catalog_exist():
    exporter = read("android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java")
    assert "modkit-evidence-bundle-1.0" in exporter
    assert "engine-catalog.json" in exporter
    assert "hashes.sha256" in exporter
    assert "rawTargetBinariesIncluded" in exporter
    assert '".json"' in exporter


def test_canonical_ci_never_reconstructs_dev_patch_chain():
    workflow = (ROOT.parent / ".github/workflows/modkit-v1-ci.yml").read_text(encoding="utf-8")
    assert "working-directory: v1" in workflow
    assert ".dev40" not in workflow and "apply-dev" not in workflow
    assert "assembleDebug" in workflow and "lintDebug" in workflow
    assert "zipalign" in workflow and "apksigner" in workflow
