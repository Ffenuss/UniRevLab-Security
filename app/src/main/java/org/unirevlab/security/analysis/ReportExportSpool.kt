package org.unirevlab.security.analysis

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
