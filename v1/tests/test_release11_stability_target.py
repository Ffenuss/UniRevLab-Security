from __future__ import annotations

import json
from pathlib import Path
import zipfile

from modkit.mobile import unityscan


ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android" / "app" / "src" / "main" / "java" / "dev" / "modkit" / "mobile"


def _apk(path: Path, extra: dict[str, bytes] | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"manifest")
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return path


def test_unityscan_apkset_scans_every_member(tmp_path: Path):
    base = _apk(tmp_path / "base.apk", {"assets/bin/Data/globalgamemanagers": b"x"})
    split = _apk(tmp_path / "split_config.arm64_v8a.apk", {"lib/arm64-v8a/libil2cpp.so": b"ELF"})
    report = tmp_path / "unity.json"

    result = unityscan.inspect_apk_paths(json.dumps([str(base), str(split)]), report)

    assert result["schema"] == "modkit-unity-apkset-1.0"
    assert result["apkCount"] == 2
    assert len(result["members"]) == 2
    assert {Path(row["apk"]).name for row in result["members"]} == {base.name, split.name}
    assert json.loads(report.read_text(encoding="utf-8"))["apkCount"] == 2


def test_full_analysis_uses_bounded_jadx_and_oom_boundaries():
    source = (JAVA / "FullAnalysisService.java").read_text(encoding="utf-8")
    bounded = (JAVA / "BoundedJadxExporter.java").read_text(encoding="utf-8")
    manifest = (ROOT / "android" / "app" / "src" / "main" / "AndroidManifest.xml").read_text(encoding="utf-8")

    assert "BoundedJadxExporter.export" in source
    assert "catch(Throwable e)" in source
    assert "JADX_FATAL_OOM" in source
    assert "JADX_OOM" in bounded
    assert "jadx.close()" in bounded
    assert 'android:largeHeap="true"' in manifest


def test_diagnostics_survive_missing_pipeline_manifest():
    exporter = (JAVA / "EvidenceBundleExporter.java").read_text(encoding="utf-8")
    journal = (JAVA / "AnalysisJournal.java").read_text(encoding="utf-8")
    app = (JAVA / "App.java").read_text(encoding="utf-8")

    assert "PIPELINE_MANIFEST_MISSING" in exporter
    assert "syntheticDiagnostic" in exporter
    assert "session-diagnostics.jsonl" in journal
    assert "UNCAUGHT_EXCEPTION" in app


def test_manual_re_is_bound_to_canonical_target_resolver():
    activity = (JAVA / "ReWorkspaceActivity.java").read_text(encoding="utf-8")
    service = (JAVA / "ReAnalysisService.java").read_text(encoding="utf-8")
    resolver = (JAVA / "TargetResolver.java").read_text(encoding="utf-8")
    manifest = (ROOT / "android" / "app" / "src" / "main" / "AndroidManifest.xml").read_text(encoding="utf-8")

    assert "ReAnalysisService.class" in activity
    assert "TargetResolver.resolve(app)" in service
    assert 'getModule("modkit.mobile.apkset")' in service
    assert 'getModule("modkit.mobile.unityscan")' in service
    assert "prepareAnalysisContainer" in service
    assert "class TargetResolver" in resolver
    assert '.ReAnalysisService' in manifest


def test_target_picker_is_async_single_instance_and_archive_aware():
    picker = (JAVA / "TargetSelectionActivity.java").read_text(encoding="utf-8")
    importer = (JAVA / "TargetArchiveImporter.java").read_text(encoding="utf-8")
    classifier = (JAVA / "InstalledAppClassifier.java").read_text(encoding="utf-8")

    assert "newSingleThreadExecutor" in picker
    assert "pickerLoading" in picker
    assert "installedDialog!=null&&installedDialog.isShowing()" in picker
    assert "*/*" in picker
    assert "application/zip" in picker
    assert "TargetArchiveImporter.importSelected" in (JAVA / "TargetPreparationService.java").read_text(encoding="utf-8")
    assert 'endsWith(".apk")' in importer
    assert "CATEGORY_GAME" in classifier
    assert "libunity.so" in classifier
