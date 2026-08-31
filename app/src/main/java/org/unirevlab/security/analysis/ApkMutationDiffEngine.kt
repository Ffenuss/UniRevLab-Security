package org.unirevlab.security.analysis

import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.ZipFile

/** Content-level comparison of the original and laboratory APKs. Compression/layout differences
 * are intentionally ignored: each ZIP entry is compared by uncompressed SHA-256. */
object ApkMutationDiffEngine {
    data class EntryDiff(
        val entryName: String,
        val change: String,
        val beforeSize: Long?,
        val afterSize: Long?,
        val beforeSha256: String?,
        val afterSha256: String?,
        val expectedLabChange: Boolean,
        val signatureMetadata: Boolean,
    )

    data class ApkDiffReport(
        val originalSha256: String,
        val modifiedSha256: String,
        val entries: List<EntryDiff>,
        val contentChanges: Int,
        val signatureMetadataChanges: Int,
        val unexpectedContentChanges: List<String>,
    )

    data class CodeDiff(
        val kind: String,
        val target: String,
        val beforeSha256: String,
        val afterSha256: String,
        val removedLines: Int,
        val addedLines: Int,
        val preview: String,
    )

    fun compare(original: File, modified: File, expectedChangedEntries: Collection<String>): ApkDiffReport {
        require(original.isFile && original.length() > 0L) { "Исходный APK недоступен" }
        require(modified.isFile && modified.length() > 0L) { "Модифицированный APK недоступен" }
        val before = entryFingerprints(original)
        val after = entryFingerprints(modified)
        val expected = expectedChangedEntries.toSet()
        val names = (before.keys + after.keys).toSortedSet()
        val diffs = names.mapNotNull { name ->
            val b = before[name]
            val a = after[name]
            val change = when {
                b == null -> "ADDED"
                a == null -> "REMOVED"
                b.sha256 != a.sha256 -> "CHANGED"
                else -> null
            } ?: return@mapNotNull null
            EntryDiff(
                entryName = name,
                change = change,
                beforeSize = b?.size,
                afterSize = a?.size,
                beforeSha256 = b?.sha256,
                afterSha256 = a?.sha256,
                expectedLabChange = name in expected,
                signatureMetadata = isSignatureMetadata(name),
            )
        }
        val unexpected = diffs.filter { !it.signatureMetadata && !it.expectedLabChange }.map { it.entryName }
        return ApkDiffReport(
            originalSha256 = sha256(original),
            modifiedSha256 = sha256(modified),
            entries = diffs,
            contentChanges = diffs.count { !it.signatureMetadata },
            signatureMetadataChanges = diffs.count { it.signatureMetadata },
            unexpectedContentChanges = unexpected,
        )
    }

    fun diffText(kind: String, target: String, before: String, after: String): CodeDiff {
        val b = before.replace("\r\n", "\n").split('\n')
        val a = after.replace("\r\n", "\n").split('\n')
        var prefix = 0
        while (prefix < b.size && prefix < a.size && b[prefix] == a[prefix]) prefix++
        var suffix = 0
        while (suffix < b.size - prefix && suffix < a.size - prefix && b[b.lastIndex - suffix] == a[a.lastIndex - suffix]) suffix++
        val removed = b.subList(prefix, b.size - suffix)
        val added = a.subList(prefix, a.size - suffix)
        val contextBefore = b.subList((prefix - 2).coerceAtLeast(0), prefix)
        val contextAfterStart = (b.size - suffix).coerceAtMost(b.size)
        val contextAfter = b.subList(contextAfterStart, (contextAfterStart + 2).coerceAtMost(b.size))
        val preview = buildString {
            contextBefore.forEach { append("  ").append(linePreview(it)).append('\n') }
            removed.take(MAX_DIFF_LINES).forEach { append("- ").append(linePreview(it)).append('\n') }
            if (removed.size > MAX_DIFF_LINES) append("- … ${removed.size - MAX_DIFF_LINES} строк скрыто\n")
            added.take(MAX_DIFF_LINES).forEach { append("+ ").append(linePreview(it)).append('\n') }
            if (added.size > MAX_DIFF_LINES) append("+ … ${added.size - MAX_DIFF_LINES} строк скрыто\n")
            contextAfter.forEach { append("  ").append(linePreview(it)).append('\n') }
        }.trimEnd()
        return CodeDiff(
            kind = kind,
            target = target,
            beforeSha256 = sha256(before.toByteArray(Charsets.UTF_8)),
            afterSha256 = sha256(after.toByteArray(Charsets.UTF_8)),
            removedLines = removed.size,
            addedLines = added.size,
            preview = preview,
        )
    }

    private data class Fingerprint(val size: Long, val sha256: String)

    private fun entryFingerprints(apk: File): Map<String, Fingerprint> = buildMap {
        ZipFile(apk).use { zip ->
            val entries = zip.entries()
            val buffer = ByteArray(BUFFER)
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.isDirectory) continue
                val digest = MessageDigest.getInstance("SHA-256")
                var size = 0L
                zip.getInputStream(entry).buffered(BUFFER).use { input ->
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        if (read > 0) {
                            digest.update(buffer, 0, read)
                            size += read
                        }
                    }
                }
                put(entry.name, Fingerprint(size, digest.digest().hex()))
            }
        }
    }

    private fun isSignatureMetadata(name: String): Boolean {
        val upper = name.uppercase(Locale.ROOT)
        if (!upper.startsWith("META-INF/")) return false
        val leaf = upper.substringAfterLast('/')
        return leaf == "MANIFEST.MF" || leaf.endsWith(".SF") || leaf.endsWith(".RSA") || leaf.endsWith(".DSA") || leaf.endsWith(".EC")
    }

    private fun linePreview(value: String): String = value.replace("\t", "    ").take(320)

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).buffered(BUFFER).use { input ->
            val buffer = ByteArray(BUFFER)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read > 0) digest.update(buffer, 0, read)
            }
        }
        return digest.digest().hex()
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).hex()
    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    private const val BUFFER = 128 * 1024
    private const val MAX_DIFF_LINES = 48
}
