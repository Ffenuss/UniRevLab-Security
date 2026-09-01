package org.unirevlab.security.analysis

import java.io.File
import java.io.FileOutputStream
import java.io.InterruptedIOException
import java.util.Locale
import java.util.zip.ZipException
import java.util.zip.ZipFile

/**
 * Recognizes backup/container formats whose outer ZIP contains one base APK and optional split APKs.
 * Plain APKs are deliberately rejected so a normal application package is never reinterpreted as a set.
 */
object NestedApkSet {
    data class Item(
        val entryName: String,
        val file: File,
        val prefix: String,
        val isBase: Boolean,
    )

    data class Extracted(
        val root: File,
        val items: List<Item>,
    ) {
        val base: Item get() = items.first { it.isBase }
        val splits: List<Item> get() = items.filterNot { it.isBase }
        fun cleanup() { root.deleteRecursively() }
        fun selectForReportEntry(reportEntry: String?): Item {
            if (reportEntry.isNullOrBlank()) return base
            val prefix = reportEntry.substringBefore("!/", missingDelimiterValue = "")
            if (prefix == "base.apk") return base
            if (prefix.startsWith("split:")) {
                val leaf = prefix.removePrefix("split:")
                return splits.firstOrNull { it.file.name == leaf || it.entryName.substringAfterLast('/') == leaf } ?: base
            }
            return base
        }
    }

    private data class Candidate(val name: String, val size: Long)

    fun extract(container: File, destinationRoot: File): Extracted? {
        val outer = ApkArchiveIndex.build(container) ?: return null
        if (outer.archiveHasManifest || outer.dexEntryCount > 0 || outer.nativeEntryCount > 0) return null

        val candidates = try {
            ZipFile(container).use { zip ->
                val result = ArrayList<Candidate>()
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    checkCancelled()
                    val entry = entries.nextElement()
                    if (entry.isDirectory) continue
                    val lower = entry.name.lowercase(Locale.ROOT)
                    if (!lower.endsWith(".apk")) continue
                    if (entry.size > MAX_SINGLE_APK_BYTES) throw IllegalArgumentException("Nested APK exceeds size limit")
                    result += Candidate(entry.name, entry.size)
                    require(result.size <= MAX_APK_COUNT) { "APK-set contains too many APK files" }
                }
                result
            }
        } catch (e: InterruptedIOException) {
            throw e
        } catch (_: ZipException) {
            return null
        }
        if (candidates.isEmpty()) return null

        val declared = candidates.sumOf { it.size.coerceAtLeast(0L) }
        require(declared <= MAX_TOTAL_EXTRACTED_BYTES) { "APK-set exceeds decompression limit" }
        destinationRoot.deleteRecursively()
        require(destinationRoot.mkdirs() || destinationRoot.isDirectory) { "Cannot create APK-set workspace" }

        val extracted = ArrayList<Pair<Candidate, File>>(candidates.size)
        var copiedTotal = 0L
        try {
            ZipFile(container).use { zip ->
                candidates.forEachIndexed { index, candidate ->
                    checkCancelled()
                    val entry = requireNotNull(zip.getEntry(candidate.name)) { "Nested APK disappeared from container" }
                    val out = File(destinationRoot, "apk-${index.toString().padStart(3, '0')}-${safeLeaf(candidate.name)}")
                    var copied = 0L
                    zip.getInputStream(entry).buffered(BUFFER).use { input ->
                        FileOutputStream(out).buffered(BUFFER).use { output ->
                            val buffer = ByteArray(BUFFER)
                            while (true) {
                                checkCancelled()
                                val read = input.read(buffer)
                                if (read < 0) break
                                if (read == 0) continue
                                copied += read
                                copiedTotal += read
                                require(copied <= MAX_SINGLE_APK_BYTES) { "Nested APK exceeds decompression limit" }
                                require(copiedTotal <= MAX_TOTAL_EXTRACTED_BYTES) { "APK-set exceeds decompression limit" }
                                output.write(buffer, 0, read)
                            }
                        }
                    }
                    require(out.length() > 0L) { "Nested APK is empty" }
                    val indexInfo = ApkArchiveIndex.build(out) ?: error("Nested .apk is not a valid ZIP/APK: ${candidate.name}")
                    require(indexInfo.archiveHasManifest) { "Nested APK has no AndroidManifest.xml: ${candidate.name}" }
                    extracted += candidate to out
                }
            }
        } catch (t: Throwable) {
            destinationRoot.deleteRecursively()
            throw t
        }

        val basePair = extracted.firstOrNull { it.first.name.substringAfterLast('/').equals("base.apk", ignoreCase = true) }
            ?: extracted.filter { (_, file) -> ApkArchiveIndex.build(file)?.dexEntryCount?.let { it > 0 } == true }.maxByOrNull { it.second.length() }
            ?: extracted.maxByOrNull { it.second.length() }
            ?: return null

        val ordered = buildList {
            add(basePair)
            extracted.filterNot { it === basePair }.sortedBy { it.first.name }.forEach(::add)
        }
        val items = ordered.mapIndexed { index, (candidate, file) ->
            val base = index == 0
            val leaf = file.name.substringAfterLast('-').ifBlank { safeLeaf(candidate.name) }
            val originalLeaf = candidate.name.substringAfterLast('/').ifBlank { leaf }
            Item(
                entryName = candidate.name,
                file = file,
                prefix = if (base) "base.apk" else "split:$originalLeaf",
                isBase = base,
            )
        }
        return Extracted(destinationRoot, items)
    }

    private fun safeLeaf(name: String): String = name.substringAfterLast('/').replace(Regex("[^A-Za-z0-9._-]"), "_").take(120).ifBlank { "split.apk" }

    private fun checkCancelled() {
        if (Thread.currentThread().isInterrupted) throw InterruptedIOException("APK-set extraction cancelled")
    }

    private const val MAX_APK_COUNT = 128
    private const val MAX_SINGLE_APK_BYTES = 2L * 1024L * 1024L * 1024L
    private const val MAX_TOTAL_EXTRACTED_BYTES = 4L * 1024L * 1024L * 1024L
    private const val BUFFER = 128 * 1024
}
