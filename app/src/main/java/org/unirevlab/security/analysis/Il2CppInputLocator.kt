package org.unirevlab.security.analysis

import android.content.Context
import android.net.Uri
import java.io.File
import java.io.InputStream
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import org.unirevlab.security.model.AuditSourceKind
import org.unirevlab.security.model.AuditSourceSpec

/** Locates and extracts the real metadata/library pair directly from APK, APKS, or installed splits. */
object Il2CppInputLocator {
    data class Result(
        val metadataFile: File?,
        val libraries: List<RealIl2CppDumpEngine.NamedLibrary>,
        val diagnostics: List<String>,
        private val temporaryFiles: List<File>,
    ) {
        fun cleanup() = temporaryFiles.forEach(File::delete)
    }

    fun locate(
        context: Context,
        source: AuditSourceSpec,
        workingDirectory: File,
        token: String,
        cancelled: () -> Boolean = { false },
    ): Result {
        require(workingDirectory.isDirectory || workingDirectory.mkdirs()) { "Unable to create IL2CPP working directory" }
        val temporary = mutableListOf<File>()
        val diagnostics = mutableListOf<String>()
        val libraries = linkedMapOf<String, RealIl2CppDumpEngine.NamedLibrary>()
        var metadata: File? = null
        var serial = 0

        fun extract(zip: ZipFile, entry: ZipEntry, label: String, limit: Long): File {
            ensureActive(cancelled)
            val destination = File(workingDirectory, ".il2cpp-$token-${serial++}-${safe(label)}")
            zip.getInputStream(entry).buffered(BUFFER_BYTES).use { input ->
                destination.outputStream().buffered(BUFFER_BYTES).use { output -> input.copyBounded(output, limit, cancelled) }
            }
            temporary += destination
            return destination
        }

        fun scanFlat(archive: File, label: String, collectNested: Boolean): List<Pair<String, File>> {
            val nested = mutableListOf<Pair<String, File>>()
            runCatching {
                ZipFile(archive).use { zip ->
                    val entries = zip.entries().asSequence().filterNot(ZipEntry::isDirectory).toList()
                    if (metadata == null) {
                        entries.firstOrNull { entry ->
                            entry.name.substringAfterLast('/').equals("global-metadata.dat", true) && entry.accepts(MAX_METADATA_BYTES)
                        }?.let { entry -> metadata = extract(zip, entry, "global-metadata.dat", MAX_METADATA_BYTES) }
                    }
                    entries.asSequence()
                        .filter { it.name.substringAfterLast('/').equals("libil2cpp.so", true) && it.accepts(MAX_LIBRARY_BYTES) }
                        .sortedBy { abiPriority(inferAbi(it.name)) }
                        .forEach { entry ->
                            if (libraries.size >= MAX_ABIS) return@forEach
                            val inferred = inferAbi(entry.name)
                            if (inferred in libraries) return@forEach
                            val abi = uniqueAbi(inferred, libraries.keys)
                            val file = extract(zip, entry, "$abi-libil2cpp.so", MAX_LIBRARY_BYTES)
                            libraries[abi] = RealIl2CppDumpEngine.NamedLibrary(abi, "$label!/${entry.name}", file)
                        }
                    if (collectNested) {
                        entries.asSequence()
                            .filter { it.name.endsWith(".apk", true) && it.accepts(MAX_CONTAINER_BYTES) }
                            .take(MAX_NESTED_APKS)
                            .forEach { entry ->
                                val file = extract(zip, entry, "nested-${entry.name.substringAfterLast('/')}", MAX_CONTAINER_BYTES)
                                nested += "$label!/${entry.name}" to file
                            }
                    }
                }
            }.onFailure {
                if (it is java.util.concurrent.CancellationException) throw it
                diagnostics += "$label: ${it.message ?: it.javaClass.simpleName}"
            }
            return nested
        }

        val topLevel = when (source.kind) {
            AuditSourceKind.INSTALLED_APP -> (listOfNotNull(source.baseApkPath) + source.splitApkPaths).mapNotNull { path ->
                File(path).takeIf { it.isFile && it.canRead() }?.let { path to it }
            }
            AuditSourceKind.FILE_URI -> {
                val destination = File(workingDirectory, ".il2cpp-$token-selected.container")
                context.contentResolver.openInputStream(Uri.parse(requireNotNull(source.uri))).use { input ->
                    requireNotNull(input) { "Unable to reopen selected artifact" }
                    destination.outputStream().buffered(BUFFER_BYTES).use { output -> input.copyBounded(output, MAX_CONTAINER_BYTES, cancelled) }
                }
                temporary += destination
                listOf(source.displayName to destination)
            }
        }

        val nested = topLevel.flatMap { (label, file) -> scanFlat(file, label, collectNested = true) }
        nested.forEach { (label, file) ->
            if (metadata != null && libraries.size >= MAX_ABIS) return@forEach
            scanFlat(file, label, collectNested = false)
        }
        return Result(metadata, libraries.values.toList(), diagnostics, temporary)
    }

    private fun InputStream.copyBounded(output: java.io.OutputStream, limit: Long, cancelled: () -> Boolean) {
        val buffer = ByteArray(BUFFER_BYTES)
        var total = 0L
        while (true) {
            ensureActive(cancelled)
            val read = read(buffer)
            if (read < 0) break
            if (read == 0) continue
            total += read
            require(total <= limit) { "IL2CPP input exceeds the ${limit / (1024 * 1024)} MiB disk-streaming limit" }
            output.write(buffer, 0, read)
        }
    }

    private fun ZipEntry.accepts(limit: Long): Boolean = size < 0 || size in 1..limit

    private fun inferAbi(path: String): String = path.split('/', '\\').firstOrNull {
        it.equals("arm64-v8a", true) || it.equals("armeabi-v7a", true) || it.equals("x86_64", true) || it.equals("x86", true)
    }?.lowercase(Locale.ROOT) ?: "unknown"

    private fun uniqueAbi(candidate: String, existing: Set<String>): String {
        if (candidate !in existing) return candidate
        var index = 2
        while ("$candidate-$index" in existing) index++
        return "$candidate-$index"
    }

    private fun abiPriority(abi: String): Int = ABI_PRIORITY.indexOf(abi).let { if (it < 0) Int.MAX_VALUE else it }
    private fun safe(value: String): String = value.replace(Regex("[^A-Za-z0-9._-]"), "_").takeLast(96).ifBlank { "artifact.bin" }

    private fun ensureActive(cancelled: () -> Boolean) {
        if (cancelled()) throw java.util.concurrent.CancellationException("IL2CPP input discovery cancelled")
    }

    private val ABI_PRIORITY = listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
    private const val MAX_ABIS = 4
    private const val MAX_NESTED_APKS = 32
    private const val MAX_METADATA_BYTES = 256L * 1024L * 1024L
    private const val MAX_LIBRARY_BYTES = 768L * 1024L * 1024L
    private const val MAX_CONTAINER_BYTES = 2L * 1024L * 1024L * 1024L
    private const val BUFFER_BYTES = 128 * 1024
}
