from pathlib import Path


def test_bundle_manifest_surfaces_pipeline_health():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java"
    ).read_text(encoding="utf-8")

    assert '"automatic-evidence.json"' in source
    for field in (
        "pipelineStatus",
        "pipelineComplete",
        "pipelineDegraded",
        "pipelineDegradedReasons",
        "pipelineError",
    ):
        assert f'"{field}"' in source


def test_bundle_keeps_evidence_hashing_and_excludes_raw_target_binaries():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java"
    ).read_text(encoding="utf-8")

    assert '".json"' in source
    assert 'sha256(file)' in source
    assert '.put("rawTargetBinariesIncluded", false)' in source
    assert '"hashes.sha256"' in source


def test_bundle_export_fails_closed_while_analysis_is_running():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java"
    ).read_text(encoding="utf-8")

    assert 'static void ensureExportable(Context context)' in source
    assert 'app.busy.get()' in source
    assert '"RUNNING".equals(pipeline.optString("status"))' in source
    assert 'ensureExportable(context);' in source
    assert "Анализ ещё выполняется" in source


def test_report_center_preflights_before_building_connected_report():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/ReportCenterActivity.java"
    ).read_text(encoding="utf-8")

    preflight = source.index("EvidenceBundleExporter.ensureExportable(this)")
    connected = source.index("JSONObject connected=buildConnected()")
    export = source.index("EvidenceBundleExporter.export(this,uri)")
    assert preflight < connected < export
    assert 'manifest.optString("pipelineStatus","UNKNOWN")' in source
