#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    if new in text:
        print(f"already patched: {rel}")
        return
    if old not in text:
        raise SystemExit(f"patch state mismatch: {rel}\nmissing block:\n{old[:800]}")
    write(rel, text.replace(old, new, 1))
    print(f"patched: {rel}")


# -----------------------------------------------------------------------------
# Full report export used to build one giant String and then allocate a second
# full-size UTF-8 ByteArray before writing. Real DEX/xref reports can be large
# enough for that peak to fail on Android, leaving the SAF document at 0 bytes.
# Convert the deterministic writer helpers from StringBuilder-only receivers to
# Appendable so the same serializer can stream directly to a buffered Writer.
# -----------------------------------------------------------------------------
report_rel = "app/src/main/java/org/unirevlab/security/analysis/ReportJsonExporter.kt"
report = read(report_rel)
if "fun write(report: StaticAnalysisReport, out: Appendable)" not in report:
    old_head = "    fun export(report: StaticAnalysisReport): String = buildString {\n"
    new_head = '''    fun export(report: StaticAnalysisReport): String = buildString { appendReport(report) }\n\n    /** Stream the deterministic report without materializing the whole JSON in memory. */\n    fun write(report: StaticAnalysisReport, out: Appendable) {\n        out.appendReport(report)\n    }\n\n    private fun Appendable.appendReport(report: StaticAnalysisReport) {\n'''
    if old_head not in report:
        raise SystemExit("ReportJsonExporter export entrypoint changed")
    report = report.replace(old_head, new_head, 1)
    report = report.replace("private fun StringBuilder.", "private fun Appendable.")

    # StringBuilder has append overloads for primitives; java.lang.Appendable does not.
    # These small overloads preserve the existing serializer source while streaming.
    marker = "object ReportJsonExporter {\n"
    primitive_helpers = '''object ReportJsonExporter {\n    private fun Appendable.append(value: Int): Appendable = append(value.toString())\n    private fun Appendable.append(value: Long): Appendable = append(value.toString())\n    private fun Appendable.append(value: Float): Appendable = append(value.toString())\n    private fun Appendable.append(value: Double): Appendable = append(value.toString())\n    private fun Appendable.append(value: Boolean): Appendable = append(value.toString())\n\n'''
    if marker not in report:
        raise SystemExit("ReportJsonExporter object marker missing")
    report = report.replace(marker, primitive_helpers, 1)
    write(report_rel, report)
    print(f"patched: {report_rel}")
else:
    print(f"already patched: {report_rel}")


# -----------------------------------------------------------------------------
# Android SAF export: serialize into a cache temp file first, then copy to the
# chosen destination. This keeps peak RAM bounded and prevents a serializer
# failure from silently leaving a corrupt partial report. If export fails, try
# to delete the just-created empty SAF document and surface the error in UI.
# -----------------------------------------------------------------------------
main_rel = "app/src/main/java/org/unirevlab/security/MainActivity.kt"
main = read(main_rel)
if "unirevlab-report-export-" not in main:
    old_import = "import kotlinx.coroutines.withContext\n"
    new_import = "import kotlinx.coroutines.withContext\nimport java.io.File\n"
    if old_import not in main:
        raise SystemExit("MainActivity import marker missing")
    main = main.replace(old_import, new_import, 1)

    old_block = '''                val result = runCatching {\n                    withContext(Dispatchers.IO) {\n                        context.contentResolver.openOutputStream(uri, "wt").use { output ->\n                            requireNotNull(output) { "Не удалось открыть файл отчёта" }\n                            output.write(ReportJsonExporter.export(current).toByteArray(Charsets.UTF_8))\n                        }\n                    }\n                }\n                error = result.exceptionOrNull()?.message\n'''
    new_block = '''                val result = runCatching {\n                    withContext(Dispatchers.IO) {\n                        val temp = File.createTempFile("unirevlab-report-export-", ".json", context.cacheDir)\n                        try {\n                            temp.bufferedWriter(Charsets.UTF_8, 128 * 1024).use { writer ->\n                                ReportJsonExporter.write(current, writer)\n                            }\n                            require(temp.length() > 2L) { "Сериализованный отчёт пуст" }\n                            context.contentResolver.openOutputStream(uri, "wt").use { output ->\n                                requireNotNull(output) { "Не удалось открыть файл отчёта" }\n                                temp.inputStream().buffered(128 * 1024).use { input ->\n                                    input.copyTo(output, 128 * 1024)\n                                }\n                                output.flush()\n                            }\n                        } finally {\n                            temp.delete()\n                        }\n                    }\n                }\n                result.exceptionOrNull()?.let {\n                    runCatching { context.contentResolver.delete(uri, null, null) }\n                }\n                error = result.exceptionOrNull()?.message\n'''
    if old_block not in main:
        raise SystemExit("MainActivity report export block changed")
    main = main.replace(old_block, new_block, 1)
    write(main_rel, main)
    print(f"patched: {main_rel}")
else:
    print(f"already patched: {main_rel}")


# -----------------------------------------------------------------------------
# Regression test: streamed output must be byte-for-byte equal to the existing
# deterministic in-memory export for the fixture. This catches receiver/format
# regressions while preserving compatibility for other internal callers.
# -----------------------------------------------------------------------------
test_rel = "app/src/test/java/org/unirevlab/security/analysis/ReportJsonExporterTest.kt"
test = read(test_rel)
if "streamed = java.io.StringWriter()" not in test:
    old = '''        val first = ReportJsonExporter.export(report)\n        val second = ReportJsonExporter.export(report)\n        assertEquals(first, second)\n'''
    new = '''        val first = ReportJsonExporter.export(report)\n        val second = ReportJsonExporter.export(report)\n        val streamed = java.io.StringWriter()\n        ReportJsonExporter.write(report, streamed)\n        assertEquals(first, second)\n        assertEquals(first, streamed.toString())\n'''
    if old not in test:
        raise SystemExit("ReportJsonExporterTest marker changed")
    test = test.replace(old, new, 1)
    write(test_rel, test)
    print(f"patched: {test_rel}")
else:
    print(f"already patched: {test_rel}")


# Version bump. Analysis semantics remain v0.22.5; app version records the export fix.
gradle_rel = "app/build.gradle.kts"
gradle = read(gradle_rel)
if 'versionName = "0.22.6-dev-stream-export"' not in gradle:
    gradle = gradle.replace('versionCode = 23\n        versionName = "0.22.5-dev-native-speed"',
                            'versionCode = 24\n        versionName = "0.22.6-dev-stream-export"', 1)
    if 'versionName = "0.22.6-dev-stream-export"' not in gradle:
        raise SystemExit("build.gradle version marker changed")
    write(gradle_rel, gradle)
    print(f"patched: {gradle_rel}")
else:
    print(f"already patched: {gradle_rel}")
