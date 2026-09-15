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
        "diagnosticFreshOnly",
        "staleEvidenceFilesExcluded",
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
    assert 'private static JSONObject terminalPipeline(Context context)' in source
    assert 'app.busy.get()' in source
    assert '"RUNNING".equals(pipeline.optString("status"))' in source
    assert 'if (pipeline == null)' in source
    assert "Нет завершённого pipeline manifest" in source
    for status in ("SUCCESS", "PARTIAL", "FAILED", "CANCELLED"):
        assert f'"{status}".equals(status)' in source
    assert "Pipeline state не является terminal" in source


def test_failed_or_cancelled_bundle_excludes_evidence_older_than_current_epoch():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java"
    ).read_text(encoding="utf-8")

    assert "private static boolean diagnosticFreshOnly(JSONObject pipeline)" in source
    assert 'return "FAILED".equals(status) || "CANCELLED".equals(status);' in source
    assert "private static boolean belongsToFailureEpoch(File file, JSONObject pipeline)" in source
    assert 'pipeline.optLong("startedAtMs", -1L)' in source
    assert "file.lastModified() >= startedAt" in source
    assert "boolean freshOnly = diagnosticFreshOnly(initialPipeline);" in source
    assert "if (freshOnly && !belongsToFailureEpoch(file, initialPipeline)) { staleExcluded[0]++; continue; }" in source
    assert "FAILED/CANCELLED diagnostic bundle contains only evidence modified in the current pipeline epoch" in source


def test_connected_report_synthesis_only_runs_for_success_or_partial_pipeline():
    exporter = Path(
        "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java"
    ).read_text(encoding="utf-8")
    report = Path(
        "android/app/src/main/java/dev/modkit/mobile/ReportCenterActivity.java"
    ).read_text(encoding="utf-8")

    helper = exporter.split("static boolean shouldBuildConnectedReport", 1)[1].split("static JSONObject export", 1)[0]
    assert 'return "SUCCESS".equals(status) || "PARTIAL".equals(status);' in helper
    assert "boolean buildConnected=EvidenceBundleExporter.shouldBuildConnectedReport(this);" in report
    assert "JSONObject connected=buildConnected?buildConnected():null;" in report
    assert "if(connected==null)" in report
    assert "diagnostic bundle" in report
    assert "staleEvidenceFilesExcluded" in report


def test_bundle_export_is_bound_to_one_pipeline_epoch():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/EvidenceBundleExporter.java"
    ).read_text(encoding="utf-8")

    assert "private static String pipelineEpoch(JSONObject pipeline)" in source
    assert "static String exportEpoch(Context context)" in source
    assert "JSONObject initialPipeline = terminalPipeline(context);" in source
    assert "String initialEpoch = pipelineEpoch(initialPipeline);" in source
    assert "String finalEpoch = exportEpoch(context);" in source
    assert "if (!initialEpoch.equals(finalEpoch))" in source
    assert "if (!initialEpoch.equals(exportEpoch(context)))" in source
    assert "epoch consistency" in source


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


def test_report_center_binds_report_preparation_to_same_pipeline_epoch_before_export():
    source = Path(
        "android/app/src/main/java/dev/modkit/mobile/ReportCenterActivity.java"
    ).read_text(encoding="utf-8")

    first_epoch = source.index("String epoch=EvidenceBundleExporter.exportEpoch(this)")
    gate = source.index("EvidenceBundleExporter.shouldBuildConnectedReport(this)", first_epoch)
    connected = source.index("JSONObject connected=buildConnected?buildConnected():null", gate)
    second_epoch = source.index("EvidenceBundleExporter.exportEpoch(this)", connected)
    export = source.index("EvidenceBundleExporter.export(this,uri)", second_epoch)
    assert first_epoch < gate < connected < second_epoch < export
    assert "Pipeline изменился во время подготовки отчёта" in source
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
