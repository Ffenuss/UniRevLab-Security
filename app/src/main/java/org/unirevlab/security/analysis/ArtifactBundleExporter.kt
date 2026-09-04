package org.unirevlab.security.analysis

import android.content.Context
import android.net.Uri
import org.json.JSONArray
import org.json.JSONObject
import org.unirevlab.security.model.AuditSourceKind
import org.unirevlab.security.model.AuditSourceSpec
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

data class ArtifactBundleResult(
    val includedEntries: Int,
    val omittedEntries: Int,
    val includedBytes: Long,
)

/**
 * Builds a bounded evidence bundle from untrusted APK/ZIP input.
 *
 * This exporter only copies passive analysis inputs. It never loads native libraries, executes
 * target code, rewrites bytecode, injects payloads, or changes the source archive.
 */
object ArtifactBundleExporter {
    fun export(
        context: Context,
        source: AuditSourceSpec,
        destination: File,
        cancelled: () -> Boolean = { false },
        onProgress: (current: Int, message: String) -> Unit = { _, _ -> },
    ): ArtifactBundleResult {
        require(destination.parentFile?.isDirectory == true || destination.parentFile?.mkdirs() == true) {
            "Не удалось создать каталог экспорта"
        }
        val inputs = sourceInputs(context, source)
        val records = mutableListOf<Record>()
        var included = 0
        var omitted = 0
        var totalBytes = 0L
        var sourceFileEntriesSeen = 0
        var selectedCandidateEntries = 0
        var excludedBySelection = 0

        destination.outputStream().buffered().use { rawOutput ->
            ZipOutputStream(rawOutput).use { output ->
                inputs.forEachIndexed { sourceIndex, inputSource ->
                    ensureActive(cancelled)
                    inputSource.open().use { rawInput ->
                        ZipInputStream(BufferedInputStream(rawInput)).use { input ->
                            while (true) {
                                ensureActive(cancelled)
                                val entry = input.nextEntry ?: break
                                if (entry.isDirectory) {
                                    input.closeEntry()
                                    continue
                                }
                                sourceFileEntriesSeen++
                                if (!isRelevant(entry.name)) {
                                    excludedBySelection++
                                    input.closeEntry()
                                    continue
                                }
                                selectedCandidateEntries++
                                val safePath = safeEntryPath(entry.name)
                                if (safePath == null || included >= MAX_INCLUDED_ENTRIES) {
                                    omitted++
                                    records += Record(inputSource.label, entry.name, classify(entry.name), entry.size, null, false, "unsafe path or entry limit")
                                    input.closeEntry()
                                    continue
                                }
                                if (entry.size > MAX_SINGLE_ENTRY_BYTES || totalBytes >= MAX_TOTAL_BYTES) {
                                    omitted++
                                    records += Record(inputSource.label, entry.name, classify(entry.name), entry.size, null, false, "size limit")
                                    input.closeEntry()
                                    continue
                                }

                                val outputName = "source-${(sourceIndex + 1).toString().padStart(2, '0')}/$safePath"
                                val digest = MessageDigest.getInstance("SHA-256")
                                output.putNextEntry(ZipEntry(outputName).apply { time = 0L })
                                var copied = 0L
                                var accepted = true
                                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                                while (true) {
                                    ensureActive(cancelled)
                                    val read = input.read(buffer)
                                    if (read <= 0) break
                                    if (copied + read > MAX_SINGLE_ENTRY_BYTES || totalBytes + copied + read > MAX_TOTAL_BYTES) {
                                        accepted = false
                                        break
                                    }
                                    copied += read
                                    digest.update(buffer, 0, read)
                                    output.write(buffer, 0, read)
                                }
                                output.closeEntry()
                                input.closeEntry()

                                if (!accepted) {
                                    // The bounded prefix is still useful evidence, but is explicitly marked partial.
                                    included++
                                    omitted++
                                    totalBytes += copied
                                    records += Record(inputSource.label, entry.name, classify(entry.name), copied, digest.digest().toHex(), true, "bounded prefix only")
                                } else {
                                    included++
                                    totalBytes += copied
                                    records += Record(inputSource.label, entry.name, classify(entry.name), copied, digest.digest().toHex(), true, null)
                                }
                                onProgress(included + omitted, "Артефакт: ${entry.name.substringAfterLast('/')}")
                            }
                        }
                    }
                }

                val inventory = JSONObject()
                    .put("schemaVersion", "1.1")
                    .put("sourceKind", source.kind.name)
                    .put("sourceDisplayName", source.displayName)
                    .put("sourceFileEntriesSeen", sourceFileEntriesSeen)
                    .put("selectedCandidateEntries", selectedCandidateEntries)
                    .put("excludedBySelection", excludedBySelection)
                    .put("includedEntries", included)
                    .put("omittedEntries", omitted)
                    .put("includedBytes", totalBytes)
                    .put(
                        "countSemantics",
                        "omittedEntries counts only selected evidence candidates rejected or copied partially; excludedBySelection counts ordinary APK entries outside this evidence bundle's allowlist.",
                    )
                    .put(
                        "sources",
                        JSONArray(inputs.mapIndexed { index, input ->
                            JSONObject()
                                .put("outputPrefix", "source-${(index + 1).toString().padStart(2, '0')}/")
                                .put("sourceLabel", input.label)
                        }),
                    )
                    .put("safety", "Passive analysis artifacts only; no target code was executed or modified.")
                    .put("entries", JSONArray(records.map(Record::toJson)))
                    .toString(2)
                    .toByteArray(Charsets.UTF_8)
                output.putNextEntry(ZipEntry("inventory.json").apply { time = 0L })
                output.write(inventory)
                output.closeEntry()
            }
        }
        return ArtifactBundleResult(included, omitted, totalBytes)
    }

    private fun sourceInputs(context: Context, source: AuditSourceSpec): List<InputSource> = when (source.kind) {
        AuditSourceKind.FILE_URI -> {
            val uri = Uri.parse(requireNotNull(source.uri))
            listOf(InputSource("selected-file") {
                requireNotNull(context.contentResolver.openInputStream(uri)) { "Не удалось повторно открыть выбранный файл" }
            })
        }
        AuditSourceKind.INSTALLED_APP -> {
            (listOf(requireNotNull(source.baseApkPath)) + source.splitApkPaths).map { path ->
                val file = File(path)
                InputSource(file.name) {
                    require(file.isFile && file.canRead()) { "APK установленного приложения недоступен: ${file.name}" }
                    FileInputStream(file)
                }
            }
        }
    }

    private fun isRelevant(name: String): Boolean {
        val normalized = name.lowercase(Locale.ROOT)
        val base = normalized.substringAfterLast('/')
        return normalized == "androidmanifest.xml" ||
            normalized == "resources.arsc" ||
            (base.startsWith("classes") && base.endsWith(".dex")) ||
            (normalized.startsWith("lib/") && normalized.endsWith(".so")) ||
            base.endsWith(".apk") ||
            base == "global-metadata.dat" ||
            base.endsWith(".dll") ||
            base.endsWith(".hbc") ||
            base == "index.android.bundle" ||
            base == "kernel_blob.bin" ||
            base.contains("isolate_snapshot") ||
            base.contains("vm_snapshot") ||
            base.endsWith(".pak") ||
            base.endsWith(".obb") ||
            normalized.endsWith("network_security_config.xml") ||
            isGradleEvidence(normalized)
    }

    private fun classify(name: String): String {
        val normalized = name.lowercase(Locale.ROOT)
        val base = normalized.substringAfterLast('/')
        return when {
            normalized == "androidmanifest.xml" -> "ANDROID_MANIFEST"
            normalized == "resources.arsc" -> "ANDROID_RESOURCES"
            base.startsWith("classes") && base.endsWith(".dex") -> "DEX"
            base == "libil2cpp.so" -> "IL2CPP_LIBRARY"
            base == "global-metadata.dat" -> "IL2CPP_METADATA"
            base.endsWith(".apk") -> "NESTED_APK"
            normalized.startsWith("lib/") && normalized.endsWith(".so") -> "NATIVE_LIBRARY"
            base.endsWith(".dll") -> "MANAGED_ASSEMBLY"
            base.endsWith(".hbc") || base == "index.android.bundle" -> "JAVASCRIPT_RUNTIME"
            base.contains("snapshot") || base == "kernel_blob.bin" -> "FLUTTER_RUNTIME"
            base.endsWith(".pak") || base.endsWith(".obb") -> "UNREAL_CONTAINER"
            isGradleEvidence(normalized) -> "GRADLE_MODULE_METADATA"
            else -> "CONFIGURATION"
        }
    }

    private fun isGradleEvidence(normalized: String): Boolean {
        val base = normalized.substringAfterLast('/')
        return normalized.endsWith(".kotlin_module") ||
            normalized.endsWith(".version") ||
            base.contains("_version") ||
            normalized.contains("meta-inf/com/android/build/gradle/") ||
            normalized.contains("aar-metadata.properties") ||
            normalized.contains("bundle-metadata/") ||
            normalized.endsWith("assets/dexopt/baseline.prof") ||
            normalized.endsWith("assets/dexopt/baseline.profm") ||
            normalized.matches(Regex("(?:^|/)res/xml/splits[0-9]*\\.xml$"))
    }

    private fun safeEntryPath(raw: String): String? {
        if (raw.isBlank() || raw.startsWith('/') || raw.startsWith('\\')) return null
        if (raw.contains('\\')) return null
        val segments = raw.split('/')
        if (segments.any { it.isBlank() || it == "." || it == ".." }) return null
        return segments.joinToString("/") { segment ->
            segment.replace(Regex("[^A-Za-z0-9._-]"), "_").take(160)
        }.take(480)
    }

    private fun ensureActive(cancelled: () -> Boolean) {
        if (cancelled()) throw java.util.concurrent.CancellationException("Экспорт отменён")
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private data class InputSource(val label: String, val open: () -> InputStream)

    private data class Record(
        val source: String,
        val entry: String,
        val kind: String,
        val sizeBytes: Long,
        val sha256: String?,
        val included: Boolean,
        val note: String?,
    ) {
        fun toJson(): JSONObject = JSONObject()
            .put("source", source)
            .put("entry", entry)
            .put("kind", kind)
            .put("sizeBytes", sizeBytes)
            .put("sha256", sha256 ?: JSONObject.NULL)
            .put("included", included)
            .put("note", note ?: JSONObject.NULL)
    }

    private const val MAX_INCLUDED_ENTRIES = 256
    private const val MAX_SINGLE_ENTRY_BYTES = 256L * 1024L * 1024L
    private const val MAX_TOTAL_BYTES = 768L * 1024L * 1024L
}
