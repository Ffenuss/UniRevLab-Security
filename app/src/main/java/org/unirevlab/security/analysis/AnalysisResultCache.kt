package org.unirevlab.security.analysis

import org.unirevlab.security.model.StaticAnalysisReport
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.security.MessageDigest
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/**
 * App-private, content-addressed warm cache for normalized static-analysis facts.
 *
 * The cache is deliberately keyed by artifact SHA-256 + engine/schema version. Any parser/rule
 * change therefore invalidates older entries instead of silently reusing stale coverage.
 */
class AnalysisResultCache(
    private val directory: File,
    private val engineVersion: String,
    private val maxBytes: Long = 256L * 1024L * 1024L,
    private val maxEntries: Int = 6,
) {
    init {
        runCatching { directory.mkdirs() }
    }

    fun load(artifactSha256: String): StaticAnalysisReport? {
        val file = fileFor(artifactSha256)
        if (!file.isFile || file.length() <= 0L || file.length() > maxBytes) return null
        return runCatching {
            ObjectInputStream(GZIPInputStream(BufferedInputStream(FileInputStream(file), BUFFER_BYTES))).use { input ->
                val report = input.readObject() as? StaticAnalysisReport ?: return@use null
                if (report.engineVersion != engineVersion || report.artifact.sha256 != artifactSha256) null else report
            }
        }.getOrElse {
            runCatching { file.delete() }
            null
        }?.also { file.setLastModified(System.currentTimeMillis()) }
    }

    fun store(report: StaticAnalysisReport) {
        if (report.engineVersion != engineVersion) return
        val target = fileFor(report.artifact.sha256)
        val temp = File(directory, target.name + ".tmp-${System.nanoTime()}")
        val success = runCatching {
            directory.mkdirs()
            ObjectOutputStream(GZIPOutputStream(BufferedOutputStream(FileOutputStream(temp), BUFFER_BYTES))).use { output ->
                output.writeObject(report)
            }
            require(temp.length() in 1..maxBytes) { "analysis cache entry exceeds bound" }
            if (target.exists() && !target.delete()) error("failed to replace analysis cache entry")
            require(temp.renameTo(target)) { "failed to publish analysis cache entry" }
            target.setLastModified(System.currentTimeMillis())
            true
        }.getOrDefault(false)
        if (!success) temp.delete()
        trim()
    }

    private fun trim() {
        val files = directory.listFiles { f -> f.isFile && f.name.endsWith(CACHE_SUFFIX) }
            ?.sortedByDescending { it.lastModified() }
            .orEmpty()
        var retainedBytes = 0L
        files.forEachIndexed { index, file ->
            retainedBytes += file.length().coerceAtLeast(0)
            if (index >= maxEntries || retainedBytes > maxBytes) file.delete()
        }
    }

    private fun fileFor(artifactSha256: String): File {
        val safeHash = artifactSha256.lowercase().filter { it in '0'..'9' || it in 'a'..'f' }.take(64)
        val versionHash = MessageDigest.getInstance("SHA-256")
            .digest(engineVersion.toByteArray(Charsets.UTF_8))
            .take(6)
            .joinToString("") { "%02x".format(it) }
        return File(directory, "$safeHash-$versionHash$CACHE_SUFFIX")
    }

    private companion object {
        const val BUFFER_BYTES = 64 * 1024
        const val CACHE_SUFFIX = ".analysis.gz"
    }
}
