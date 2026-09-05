package org.unirevlab.security.ai

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.zip.ZipInputStream

data class ImportedReport(
    val file: File,
    val displayName: String,
    val sizeBytes: Long,
)

class ReportImportStore(context: Context) {
    private val appContext = context.applicationContext
    private val root = File(appContext.filesDir, DIRECTORY).apply {
        require(isDirectory || mkdirs()) { "Не удалось создать хранилище AI-отчёта" }
    }

    fun current(): ImportedReport? {
        val file = File(root, REPORT_FILE)
        if (!file.isFile || file.length() <= 0) return null
        val name = File(root, NAME_FILE).takeIf(File::isFile)?.readText(Charsets.UTF_8)?.trim().orEmpty()
        return ImportedReport(file, name.ifBlank { REPORT_FILE }, file.length())
    }

    fun import(uri: Uri): ImportedReport {
        val originalName = displayName(uri)
        val staging = File(root, STAGING_FILE)
        appContext.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Не удалось открыть выбранный файл" }
            FileOutputStream(staging, false).use { output -> input.copyBoundedTo(output, MAX_CONTAINER_BYTES) }
        }

        val destination = File(root, REPORT_FILE)
        val temporary = File(root, TEMP_REPORT_FILE)
        try {
            if (staging.isZip()) extractFullReport(staging, temporary) else staging.inputStream().use { input ->
                FileOutputStream(temporary, false).use { output -> input.copyBoundedTo(output, MAX_REPORT_BYTES) }
            }
            validateJsonObject(temporary)
            replaceAtomically(temporary, destination)
            File(root, NAME_FILE).writeText(originalName.take(240), Charsets.UTF_8)
            return ImportedReport(destination, originalName, destination.length())
        } finally {
            staging.delete()
            temporary.delete()
        }
    }

    private fun extractFullReport(archive: File, destination: File) {
        ZipInputStream(BufferedInputStream(FileInputStream(archive))).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                val normalized = entry.name.replace('\\', '/').substringAfterLast('/')
                if (!entry.isDirectory && normalized == FULL_REPORT_ENTRY) {
                    FileOutputStream(destination, false).use { output -> zip.copyBoundedTo(output, MAX_REPORT_BYTES) }
                    return
                }
                zip.closeEntry()
            }
        }
        error("В архиве нет $FULL_REPORT_ENTRY")
    }

    private fun validateJsonObject(file: File) {
        require(file.length() in 2..MAX_REPORT_BYTES) { "Полный отчёт пуст или слишком велик" }
        file.reader(Charsets.UTF_8).use { reader ->
            while (true) {
                val value = reader.read()
                require(value >= 0) { "Полный отчёт пуст" }
                val char = value.toChar()
                if (!char.isWhitespace()) {
                    require(char == '{') { "Выбранный файл не похож на full-report.json" }
                    return
                }
            }
        }
    }

    private fun File.isZip(): Boolean = inputStream().use { input ->
        input.read() == 'P'.code && input.read() == 'K'.code
    }

    private fun java.io.InputStream.copyBoundedTo(output: java.io.OutputStream, limit: Long) {
        val buffer = ByteArray(BUFFER_BYTES)
        var total = 0L
        while (true) {
            val read = read(buffer)
            if (read < 0) break
            total += read
            require(total <= limit) { "Файл превышает допустимый размер" }
            output.write(buffer, 0, read)
        }
    }

    private fun replaceAtomically(source: File, destination: File) {
        if (!source.renameTo(destination)) {
            FileOutputStream(destination, false).use { output -> source.inputStream().use { it.copyTo(output) } }
        }
    }

    private fun displayName(uri: Uri): String = runCatching {
        appContext.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }
    }.getOrNull()?.takeIf { it.isNotBlank() }
        ?: uri.lastPathSegment?.substringAfterLast('/')
        ?: REPORT_FILE

    companion object {
        private const val DIRECTORY = "ai-report-chat"
        private const val REPORT_FILE = "imported-full-report.json"
        private const val NAME_FILE = "imported-report-name.txt"
        private const val STAGING_FILE = ".selected-report.bin"
        private const val TEMP_REPORT_FILE = ".full-report.tmp"
        private const val FULL_REPORT_ENTRY = "full-report.json"
        private const val BUFFER_BYTES = 64 * 1024
        private const val MAX_REPORT_BYTES = 1_073_741_824L
        private const val MAX_CONTAINER_BYTES = 1_288_490_188L
    }
}
