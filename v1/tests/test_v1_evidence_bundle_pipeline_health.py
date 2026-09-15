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


def test_bundle_export_requires_terminal_pipeline_state_and_blocks_running_or_missing_manifest():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java"
    ).read_text(encoding="utf-8")

    assert 'static void ensureExportable(Context context)' in source
    assert 'app.busy.get()' in source
    assert '"RUNNING".equals(pipeline.optString("status"))' in source
    assert 'if (pipeline == null)' in source
    assert "Нет завершённого pipeline manifest" in source
    for status in ("SUCCESS", "PARTIAL", "FAILED", "CANCELLED"):
        assert f'"{status}".equals(status)' in source
    assert "Pipeline state не является terminal" in source
    assert 'ensureExportable(context);' in source


def test_bundle_streaming_loops_are_interruptible():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java"
    ).read_text(encoding="utf-8")

    assert "Thread.currentThread().isInterrupted()" in source
    assert "InterruptedIOException" in source
    assert "collectInto(root, child, out, depth + 1)" in source
    assert "while ((n = in.read(buf)) != -1) { checkInterrupted(); zip.write(buf, 0, n); }" in source
    assert "while ((n = in.read(buf)) != -1) { checkInterrupted(); digest.update(buf, 0, n); }" in source


def test_failed_bundle_export_clears_partial_destination():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java"
    ).read_text(encoding="utf-8")

    assert "catch (Exception error)" in source
    assert "clearFailedOutput(context, output);" in source
    assert 'openOutputStream(output, "wt")' in source
    assert "throw error;" in source


def test_report_center_preflights_before_building_connected_report():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/ReportCenterActivity.java"
    ).read_text(encoding="utf-8")

    preflight = source.index("EvidenceBundleExporter.ensureExportable(this)")
    connected = source.index("JSONObject connected=buildConnected()")
    export = source.index("EvidenceBundleExporter.export(this,uri)")
    assert preflight < connected < export
    assert 'manifest.optString("pipelineStatus","UNKNOWN")' in source


def test_report_center_propagates_cancel_and_removes_failed_saf_destination():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/ReportCenterActivity.java"
    ).read_text(encoding="utf-8")

    assert "Отменить экспорт" in source
    assert "job.cancel(true)" in source
    assert "exportCancelled.get()||Thread.currentThread().isInterrupted()" in source
    assert 'callAttr("build_connected_report"' in source
    assert "new ExportProgress()" in source
    assert "DocumentsContract.deleteDocument(getContentResolver(),uri)" in source
    assert "deleteFailedDestination(uri);" in source
    assert "Экспорт отменён." in source
    assert "worker.shutdownNow()" in source
