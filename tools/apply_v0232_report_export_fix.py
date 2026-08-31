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
        raise SystemExit(f"patch state mismatch: {rel}\nmissing:\n{old[:1200]}")
    write(rel, text.replace(old, new, 1))
    print(f"patched: {rel}")


# 1) Prepare the full report completely before SAF CreateDocument creates an external file.
spool_rel = "app/src/main/java/org/unirevlab/security/analysis/ReportExportSpool.kt"
spool = r'''package org.unirevlab.security.analysis

import java.io.BufferedOutputStream
import java.io.BufferedWriter
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.io.RandomAccessFile
import java.security.DigestOutputStream
import java.security.MessageDigest
import org.unirevlab.security.model.StaticAnalysisReport

data class PreparedReportFile(
    val file: File,
    val sizeBytes: Long,
    val sha256: String,
    val artifactSha256: String,
)

/**
 * Builds the deterministic JSON in app-private storage before a SAF destination is created.
 * This prevents a user-visible 0-byte document while a large report is still being serialized.
 */
object ReportExportSpool {
    fun prepare(report: StaticAnalysisReport, directory: File): PreparedReportFile {
        require(directory.isDirectory || directory.mkdirs()) { "Не удалось создать каталог экспорта" }
        directory.listFiles { file -> file.name.startsWith(PREFIX) && file.name.endsWith(SUFFIX) }
            ?.forEach { stale -> runCatching { stale.delete() } }

        val temp = File.createTempFile(PREFIX, SUFFIX, directory)
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            FileOutputStream(temp).use { fileOut ->
                DigestOutputStream(BufferedOutputStream(fileOut, BUFFER_BYTES), digest).use { digestOut ->
                    BufferedWriter(OutputStreamWriter(digestOut, Charsets.UTF_8), CHAR_BUFFER_CHARS).use { writer ->
                        ReportJsonExporter.write(report, writer)
                    }
                }
            }
            // Make the private spool durable before the user picks a destination.
            RandomAccessFile(temp, "rw").use { it.fd.sync() }
            val size = temp.length()
            require(size > 2L) { "Сериализованный отчёт пуст" }
            PreparedReportFile(
                file = temp,
                sizeBytes = size,
                sha256 = digest.digest().joinToString("") { "%02x".format(it) },
                artifactSha256 = report.artifact.sha256,
            )
        } catch (failure: Throwable) {
            runCatching { temp.delete() }
            throw failure
        }
    }

    private const val PREFIX = "unirevlab-report-spool-"
    private const val SUFFIX = ".json.tmp"
    private const val BUFFER_BYTES = 128 * 1024
    private const val CHAR_BUFFER_CHARS = 32 * 1024
}
'''
if not (ROOT / spool_rel).exists():
    write(spool_rel, spool)
    print(f"created: {spool_rel}")
else:
    print(f"already exists: {spool_rel}")

# 2) Truly stream JSON string escaping instead of building a second String for every field.
exporter_rel = "app/src/main/java/org/unirevlab/security/analysis/ReportJsonExporter.kt"
old_tail = r'''    private fun Appendable.stringArrayField(name: String, values: List<String>, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": [")
        values.forEachIndexed { index, value ->
            if (index > 0) append(", ")
            append('"').append(escape(value)).append('"')
        }
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.field(name: String, value: String, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": \"").append(escape(value)).append('"')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.nullableStringField(name: String, value: String?, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": ")
        if (value == null) append("null") else append('"').append(escape(value)).append('"')
        if (comma) append(',')
        append('\n')
    }
'''
new_tail = r'''    private fun Appendable.stringArrayField(name: String, values: List<String>, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": [")
        values.forEachIndexed { index, value ->
            if (index > 0) append(", ")
            append('"')
            appendEscaped(value)
            append('"')
        }
        append(']')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.field(name: String, value: String, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": \"")
        appendEscaped(value)
        append('"')
        if (comma) append(',')
        append('\n')
    }

    private fun Appendable.nullableStringField(name: String, value: String?, level: Int, comma: Boolean) {
        append(indent(level)).append('"').append(name).append("\": ")
        if (value == null) {
            append("null")
        } else {
            append('"')
            appendEscaped(value)
            append('"')
        }
        if (comma) append(',')
        append('\n')
    }
'''
replace_once(exporter_rel, old_tail, new_tail)

old_escape = r'''    private fun indent(level: Int) = "  ".repeat(level)

    private fun escape(input: String): String = buildString(input.length + 8) {
        input.forEach { ch ->
            when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (ch.code < 0x20) append("\\u%04x".format(ch.code)) else append(ch)
            }
        }
    }
}'''
new_escape = r'''    private fun indent(level: Int) = "  ".repeat(level)

    private fun Appendable.appendEscaped(input: String) {
        input.forEach { ch ->
            when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (ch.code < 0x20) {
                    append("\\u")
                    append(HEX[(ch.code ushr 12) and 0xf])
                    append(HEX[(ch.code ushr 8) and 0xf])
                    append(HEX[(ch.code ushr 4) and 0xf])
                    append(HEX[ch.code and 0xf])
                } else {
                    append(ch)
                }
            }
        }
    }

    private const val HEX = "0123456789abcdef"
}'''
replace_once(exporter_rel, old_escape, new_escape)

# 3) MainActivity: spool first, then launch CreateDocument, then verified durable copy.
main_rel = "app/src/main/java/org/unirevlab/security/MainActivity.kt"
replace_once(main_rel, "import android.os.Bundle\n", "import android.os.Bundle\nimport android.os.ParcelFileDescriptor\n")
replace_once(main_rel, "import java.io.File\n", "import java.io.File\nimport java.io.FileOutputStream\n")
replace_once(
    main_rel,
    "import org.unirevlab.security.analysis.ReportJsonExporter\n",
    "import org.unirevlab.security.analysis.ReportJsonExporter\nimport org.unirevlab.security.analysis.ReportExportSpool\nimport org.unirevlab.security.analysis.PreparedReportFile\n",
)

replace_once(
    main_rel,
    '''    var patchFinding by remember { mutableStateOf<Finding?>(null) }\n    var lastArtifactUri by remember { mutableStateOf<android.net.Uri?>(null) }\n''',
    '''    var patchFinding by remember { mutableStateOf<Finding?>(null) }\n    var lastArtifactUri by remember { mutableStateOf<android.net.Uri?>(null) }\n    var preparedReportExport by remember { mutableStateOf<PreparedReportFile?>(null) }\n    var reportExportStatus by remember { mutableStateOf<String?>(null) }\n''',
)

replace_once(
    main_rel,
    '''                scope = next.assessment\n                report = next\n                error = null\n''',
    '''                scope = next.assessment\n                preparedReportExport?.file?.let { runCatching { it.delete() } }\n                preparedReportExport = null\n                reportExportStatus = null\n                report = next\n                error = null\n''',
)

old_saver = r'''    val reportSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val current = report
        if (uri != null && current != null) {
            coroutineScope.launch {
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        val temp = File.createTempFile("unirevlab-report-export-", ".json", context.cacheDir)
                        try {
                            temp.bufferedWriter(Charsets.UTF_8, 128 * 1024).use { writer ->
                                ReportJsonExporter.write(current, writer)
                            }
                            require(temp.length() > 2L) { "Сериализованный отчёт пуст" }
                            context.contentResolver.openOutputStream(uri, "wt").use { output ->
                                requireNotNull(output) { "Не удалось открыть файл отчёта" }
                                temp.inputStream().buffered(128 * 1024).use { input ->
                                    input.copyTo(output, 128 * 1024)
                                }
                                output.flush()
                            }
                        } finally {
                            temp.delete()
                        }
                    }
                }
                result.exceptionOrNull()?.let {
                    runCatching { context.contentResolver.delete(uri, null, null) }
                }
                error = result.exceptionOrNull()?.message
            }
        }
    }
'''
new_saver = r'''    val reportSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val prepared = preparedReportExport
        if (uri == null) {
            prepared?.file?.let { runCatching { it.delete() } }
            preparedReportExport = null
            reportExportStatus = "Сохранение JSON отменено."
        } else if (prepared == null || !prepared.file.isFile || prepared.file.length() != prepared.sizeBytes) {
            runCatching { context.contentResolver.delete(uri, null, null) }
            preparedReportExport = null
            reportExportStatus = "Подготовленный JSON потерян; сформируйте отчёт ещё раз."
            error = "Подготовленный JSON-файл недоступен"
        } else {
            coroutineScope.launch {
                isInspecting = true
                error = null
                reportExportStatus = "Запись полного JSON (${formatBytes(prepared.sizeBytes)})…"
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        persistPreparedReport(context, uri, prepared)
                    }
                }
                if (result.isSuccess) {
                    prepared.file.delete()
                    preparedReportExport = null
                    reportExportStatus = "JSON сохранён: ${formatBytes(prepared.sizeBytes)}, SHA-256 ${prepared.sha256.take(16)}…"
                } else {
                    runCatching { context.contentResolver.delete(uri, null, null) }
                    reportExportStatus = "Не удалось записать JSON. Подготовленный файл сохранён для повторной попытки."
                    error = "Экспорт JSON: ${result.exceptionOrNull()?.message ?: result.exceptionOrNull()?.javaClass?.simpleName ?: "неизвестная ошибка"}"
                }
                isInspecting = false
            }
        }
    }
'''
replace_once(main_rel, old_saver, new_saver)

old_save_callback = r'''            onSaveReport = {
                val safeName = report?.artifact?.displayName?.substringBeforeLast('.')?.replace(Regex("[^A-Za-z0-9._-]"), "_")?.take(80) ?: "assessment"
                reportSaver.launch("$safeName-unirevlab-report.json")
            },
'''
new_save_callback = r'''            exportStatus = reportExportStatus,
            onSaveReport = {
                val current = report
                if (current != null && !isInspecting) {
                    val safeName = current.artifact.displayName.substringBeforeLast('.').replace(Regex("[^A-Za-z0-9._-]"), "_").take(80).ifBlank { "assessment" }
                    val existing = preparedReportExport?.takeIf {
                        it.artifactSha256 == current.artifact.sha256 && it.file.isFile && it.file.length() == it.sizeBytes
                    }
                    if (existing != null) {
                        reportExportStatus = "JSON уже подготовлен (${formatBytes(existing.sizeBytes)}). Выберите место сохранения."
                        reportSaver.launch("$safeName-unirevlab-report.json")
                    } else {
                        coroutineScope.launch {
                            isInspecting = true
                            error = null
                            reportExportStatus = "Формирование полного детерминированного JSON во внутреннем хранилище…"
                            preparedReportExport?.file?.let { runCatching { it.delete() } }
                            preparedReportExport = null
                            val result = runCatching {
                                withContext(Dispatchers.IO) {
                                    ReportExportSpool.prepare(current, File(context.cacheDir, "report-export"))
                                }
                            }
                            isInspecting = false
                            result.getOrNull()?.let { prepared ->
                                preparedReportExport = prepared
                                reportExportStatus = "JSON подготовлен: ${formatBytes(prepared.sizeBytes)}. Теперь выберите место сохранения."
                                reportSaver.launch("$safeName-unirevlab-report.json")
                            }
                            result.exceptionOrNull()?.let { failure ->
                                reportExportStatus = "JSON не создан — внешний 0-байтный файл не создавался."
                                error = "Формирование JSON: ${failure.message ?: failure.javaClass.simpleName}"
                            }
                        }
                    }
                }
            },
'''
replace_once(main_rel, old_save_callback, new_save_callback)

replace_once(
    main_rel,
    '''                    coordinatorSyncStatus = null\n                    route = Route.SCOPE\n''',
    '''                    coordinatorSyncStatus = null\n                    preparedReportExport?.file?.let { runCatching { it.delete() } }\n                    preparedReportExport = null\n                    reportExportStatus = null\n                    route = Route.SCOPE\n''',
)

# Top-level durable SAF copy helpers.
main_text = read(main_rel)
if "private fun persistPreparedReport(" not in main_text:
    helper = r'''

private fun persistPreparedReport(context: android.content.Context, uri: android.net.Uri, prepared: PreparedReportFile): Long {
    val resolver = context.contentResolver
    val copied = runCatching {
        val descriptor = requireNotNull(resolver.openFileDescriptor(uri, "rwt")) { "Не удалось открыть файл назначения" }
        ParcelFileDescriptor.AutoCloseOutputStream(descriptor).use { output ->
            val count = prepared.file.inputStream().buffered(128 * 1024).use { input ->
                input.copyTo(output, 128 * 1024)
            }
            output.flush()
            descriptor.fileDescriptor.sync()
            count
        }
    }.getOrElse { primaryFailure ->
        runCatching {
            resolver.openOutputStream(uri, "wt").use { output ->
                requireNotNull(output) { "Не удалось открыть файл назначения" }
                val count = prepared.file.inputStream().buffered(128 * 1024).use { input ->
                    input.copyTo(output, 128 * 1024)
                }
                output.flush()
                count
            }
        }.getOrElse { fallbackFailure ->
            fallbackFailure.addSuppressed(primaryFailure)
            throw fallbackFailure
        }
    }
    require(copied == prepared.sizeBytes) { "Записано $copied из ${prepared.sizeBytes} байт" }
    val providerLength = runCatching {
        resolver.openAssetFileDescriptor(uri, "r")?.use { descriptor -> descriptor.length }
    }.getOrNull()
    if (providerLength != null && providerLength >= 0L) {
        require(providerLength == prepared.sizeBytes) {
            "Провайдер сохранил $providerLength из ${prepared.sizeBytes} байт"
        }
    }
    return copied
}

private fun formatBytes(bytes: Long): String = when {
    bytes >= 1024L * 1024L -> "%.1f MiB".format(java.util.Locale.US, bytes / (1024.0 * 1024.0))
    bytes >= 1024L -> "%.1f KiB".format(java.util.Locale.US, bytes / 1024.0)
    else -> "$bytes B"
}
'''
    main_text += helper
    write(main_rel, main_text)
    print(f"patched helpers: {main_rel}")

# 4) Dashboard shows exact export phase and prevents concurrent export actions.
dash_rel = "app/src/main/java/org/unirevlab/security/ui/DashboardScreen.kt"
replace_once(
    dash_rel,
    '''    error: String?,\n    onPickArtifact: () -> Unit,\n''',
    '''    error: String?,\n    exportStatus: String? = null,\n    onPickArtifact: () -> Unit,\n''',
)
replace_once(
    dash_rel,
    '''                            Text("Операция выполняется", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)\n                            LinearProgressIndicator(Modifier.fillMaxWidth())\n                            Text(\n                                "Подождите завершения текущей операции.",\n''',
    '''                            Text(exportStatus ?: "Операция выполняется", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)\n                            LinearProgressIndicator(Modifier.fillMaxWidth())\n                            Text(\n                                if (exportStatus != null) "Не закрывайте приложение до завершения этой операции." else "Подождите завершения текущей операции.",\n''',
)
replace_once(
    dash_rel,
    '''                Text("Экспорт", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)\n                OutlinedButton(onClick = onSaveReport, modifier = Modifier.fillMaxWidth()) {\n                    Text("JSON — полный детерминированный отчёт")\n                }\n                OutlinedButton(onClick = onSaveCycloneDx, modifier = Modifier.fillMaxWidth()) {\n                    Text("CycloneDX 1.6 — SBOM")\n                }\n                OutlinedButton(onClick = onSaveSpdx, modifier = Modifier.fillMaxWidth()) {\n                    Text("SPDX 3.0.1 — JSON-LD")\n                }\n''',
    '''                Text("Экспорт", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)\n                exportStatus?.let {\n                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)\n                }\n                OutlinedButton(onClick = onSaveReport, enabled = !isInspecting, modifier = Modifier.fillMaxWidth()) {\n                    Text("JSON — полный детерминированный отчёт")\n                }\n                OutlinedButton(onClick = onSaveCycloneDx, enabled = !isInspecting, modifier = Modifier.fillMaxWidth()) {\n                    Text("CycloneDX 1.6 — SBOM")\n                }\n                OutlinedButton(onClick = onSaveSpdx, enabled = !isInspecting, modifier = Modifier.fillMaxWidth()) {\n                    Text("SPDX 3.0.1 — JSON-LD")\n                }\n''',
)

# 5) JVM regression test: spool must be non-empty, deterministic and byte-identical to export().
test_rel = "app/src/test/java/org/unirevlab/security/analysis/ReportExportSpoolTest.kt"
test = r'''package org.unirevlab.security.analysis

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.ManifestSummary
import org.unirevlab.security.model.StaticAnalysisReport

class ReportExportSpoolTest {
    @Test
    fun preparedFileIsNonEmptyDurableAndMatchesDeterministicExporter() {
        val directory = Files.createTempDirectory("unirevlab-export-test").toFile()
        try {
            val report = StaticAnalysisReport(
                engineVersion = "test",
                assessment = AssessmentScope(
                    assessmentId = "test-id",
                    createdAtEpochMs = 1,
                    projectName = "Test",
                    organization = "Org",
                    purpose = "Authorized test",
                    confirmsAuthority = true,
                ),
                artifact = ArtifactSummary(
                    displayName = "target.apk",
                    sizeBytes = 42,
                    sha256 = "a".repeat(64),
                    archiveEntries = 3,
                    dexFiles = 1,
                    nativeLibraries = 0,
                    hasAndroidManifest = true,
                    suspiciousArchivePaths = 0,
                    truncatedArchiveScan = false,
                ),
                manifest = ManifestSummary(
                    packageName = "org.example",
                    versionName = "1.0",
                    versionCode = 1,
                    minSdk = 26,
                    targetSdk = 36,
                    debuggable = false,
                    allowBackup = false,
                    fullBackupContentConfigured = false,
                    dataExtractionRulesConfigured = false,
                    usesCleartextTraffic = false,
                    networkSecurityConfigConfigured = false,
                    requestedPermissions = listOf("z.permission", "a.permission"),
                    dangerousPermissions = emptyList(),
                    components = emptyList(),
                    signingCertificateSha256 = emptyList(),
                ),
                findings = emptyList(),
            )
            val prepared = ReportExportSpool.prepare(report, directory)
            assertTrue(prepared.file.isFile)
            assertTrue(prepared.sizeBytes > 2L)
            assertEquals(prepared.sizeBytes, prepared.file.length())
            assertEquals(64, prepared.sha256.length)
            assertEquals(ReportJsonExporter.export(report), prepared.file.readText(Charsets.UTF_8))
        } finally {
            directory.deleteRecursively()
        }
    }
}
'''
if not (ROOT / test_rel).exists():
    write(test_rel, test)
    print(f"created: {test_rel}")
else:
    print(f"already exists: {test_rel}")

# Version bump.
gradle_rel = "app/build.gradle.kts"
gradle = read(gradle_rel)
if 'versionName = "0.23.2-dev-report-export"' not in gradle:
    if 'versionCode = 26' not in gradle or 'versionName = "0.23.1-dev-patch-lab-native"' not in gradle:
        raise SystemExit("unexpected app version before v0.23.2")
    gradle = gradle.replace('versionCode = 26', 'versionCode = 27', 1)
    gradle = gradle.replace('versionName = "0.23.1-dev-patch-lab-native"', 'versionName = "0.23.2-dev-report-export"', 1)
    write(gradle_rel, gradle)
    print(f"patched: {gradle_rel}")

print("v0.23.2 report export fix applied")
