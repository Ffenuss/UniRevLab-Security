package org.unirevlab.security.data

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.security.MessageDigest
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Internal, integrity-checked snapshot format for reopening a completed analysis after process exit.
 * Files are never imported from untrusted external storage. The compressed blob is SHA-256 checked
 * before Java deserialization and decompression is bounded to avoid corrupted-file expansion.
 */
object ReportSnapshotCodec {
    data class SnapshotMeta(
        val fileName: String,
        val sizeBytes: Long,
        val sha256: String,
        val formatVersion: Int = FORMAT_VERSION,
    )

    fun write(report: StaticAnalysisReport, directory: File, fileName: String): SnapshotMeta {
        require(SAFE_FILE_NAME.matches(fileName)) { "Invalid snapshot file name" }
        require(directory.exists() || directory.mkdirs()) { "Cannot create history snapshot directory" }
        require(directory.isDirectory) { "History snapshot path is not a directory" }

        val target = File(directory, fileName)
        val temp = File(directory, "$fileName.tmp-${System.nanoTime()}")
        runCatching { temp.delete() }

        try {
            FileOutputStream(temp).use { fileOut ->
                val buffered = BufferedOutputStream(fileOut, BUFFER_BYTES)
                val gzip = GZIPOutputStream(buffered, BUFFER_BYTES)
                val header = DataOutputStream(gzip)
                header.writeInt(MAGIC)
                header.writeInt(FORMAT_VERSION)
                header.flush()
                val objectOut = ObjectOutputStream(gzip)
                objectOut.writeObject(report)
                objectOut.flush()
                gzip.finish()
                gzip.flush()
                buffered.flush()
                fileOut.fd.sync()
            }
            require(temp.length() in 1..MAX_COMPRESSED_BYTES) {
                "History snapshot size ${temp.length()} is outside the supported range"
            }
            if (target.exists() && !target.delete()) throw IOException("Cannot replace old history snapshot")
            if (!temp.renameTo(target)) throw IOException("Cannot atomically publish history snapshot")
            val sha = sha256(target)
            return SnapshotMeta(target.name, target.length(), sha)
        } catch (failure: Throwable) {
            runCatching { temp.delete() }
            throw failure
        }
    }

    fun read(
        file: File,
        expectedSizeBytes: Long,
        expectedSha256: String,
        expectedFormatVersion: Int,
    ): StaticAnalysisReport {
        require(expectedFormatVersion == FORMAT_VERSION) {
            "Unsupported history snapshot format $expectedFormatVersion"
        }
        require(file.isFile) { "Saved analysis snapshot is missing" }
        require(file.length() == expectedSizeBytes) {
            "Saved analysis snapshot size mismatch"
        }
        require(file.length() in 1..MAX_COMPRESSED_BYTES) { "Saved analysis snapshot is too large" }
        val actualSha = sha256(file)
        require(actualSha.equals(expectedSha256, ignoreCase = true)) {
            "Saved analysis snapshot integrity check failed"
        }

        FileInputStream(file).use { fileIn ->
            BufferedInputStream(fileIn, BUFFER_BYTES).use { buffered ->
                GZIPInputStream(buffered, BUFFER_BYTES).use { gzip ->
                    val limited = LimitedInputStream(gzip, MAX_UNCOMPRESSED_BYTES)
                    val header = DataInputStream(limited)
                    require(header.readInt() == MAGIC) { "Invalid history snapshot magic" }
                    val version = header.readInt()
                    require(version == FORMAT_VERSION) { "Unsupported history snapshot format $version" }
                    val value = ObjectInputStream(limited).use { input -> input.readObject() }
                    return value as? StaticAnalysisReport
                        ?: throw IOException("History snapshot does not contain a StaticAnalysisReport")
                }
            }
        }
    }

    fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val buffer = ByteArray(BUFFER_BYTES)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count > 0) digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    private class LimitedInputStream(input: InputStream, private val maxBytes: Long) : FilterInputStream(input) {
        private var count = 0L

        override fun read(): Int {
            val value = super.read()
            if (value >= 0) addCount(1)
            return value
        }

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            val value = super.read(buffer, offset, length)
            if (value > 0) addCount(value.toLong())
            return value
        }

        private fun addCount(delta: Long) {
            count += delta
            if (count > maxBytes) throw IOException("History snapshot exceeds decompression limit")
        }
    }

    const val FORMAT_VERSION = 1
    private const val MAGIC = 0x55524C48 // URLH / UniRevLab History
    private const val BUFFER_BYTES = 128 * 1024
    private const val MAX_COMPRESSED_BYTES = 256L * 1024L * 1024L
    private const val MAX_UNCOMPRESSED_BYTES = 768L * 1024L * 1024L
    private val SAFE_FILE_NAME = Regex("^[A-Za-z0-9._-]{1,160}$")
}
