package org.unirevlab.security.analysis

import java.io.File
import java.io.RandomAccessFile
import java.util.Locale
import java.util.zip.ZipFile

/** Passive APK signing-scheme inventory. No certificate validation is attempted here. */
object ApkSigningSchemeScanner {
    data class Summary(
        val schemes: List<String>,
        val signingBlockIds: List<String>,
        val v1SignatureFiles: List<String>,
        val parseError: String? = null,
    )

    fun scan(apk: File): Summary {
        val v1Files = runCatching { scanV1(apk) }.getOrDefault(emptyList())
        val block = runCatching { scanSigningBlock(apk) }
        val ids = block.getOrNull().orEmpty()
        val schemes = buildList {
            if (v1Files.any { it.endsWith(".SF", true) } && v1Files.any { it.endsWith(".RSA", true) || it.endsWith(".DSA", true) || it.endsWith(".EC", true) }) add("V1_JAR")
            if (APK_SIGNATURE_SCHEME_V2_BLOCK_ID in ids) add("V2")
            if (APK_SIGNATURE_SCHEME_V3_BLOCK_ID in ids) add("V3")
            if (APK_SIGNATURE_SCHEME_V31_BLOCK_ID in ids) add("V3.1")
        }
        return Summary(
            schemes = schemes,
            signingBlockIds = ids.map { "0x%08x".format(Locale.US, it) }.sorted(),
            v1SignatureFiles = v1Files.sorted(),
            parseError = block.exceptionOrNull()?.message?.take(240),
        )
    }

    private fun scanV1(apk: File): List<String> = ZipFile(apk).use { zip ->
        zip.entries().asSequence()
            .filter { !it.isDirectory }
            .map { it.name }
            .filter { name ->
                val u = name.uppercase(Locale.ROOT)
                u == "META-INF/MANIFEST.MF" || u.endsWith(".SF") || u.endsWith(".RSA") || u.endsWith(".DSA") || u.endsWith(".EC")
            }
            .take(MAX_V1_FILES)
            .toList()
    }

    private fun scanSigningBlock(apk: File): List<Long> = RandomAccessFile(apk, "r").use { raf ->
        val eocd = findEocd(raf)
        val centralDirOffset = readU32(raf, eocd + 16)
        require(centralDirOffset >= APK_SIG_BLOCK_FOOTER_SIZE) { "APK central directory too early for signing block" }
        val footer = centralDirOffset - APK_SIG_BLOCK_FOOTER_SIZE
        raf.seek(footer + 8)
        val magic = ByteArray(APK_SIG_BLOCK_MAGIC.size)
        raf.readFully(magic)
        if (!magic.contentEquals(APK_SIG_BLOCK_MAGIC)) return emptyList()
        val sizeInFooter = readU64(raf, footer)
        require(sizeInFooter >= 24 && sizeInFooter <= MAX_SIGNING_BLOCK_BYTES) { "APK signing block size outside bound" }
        val blockStart = centralDirOffset - (sizeInFooter + 8)
        require(blockStart >= 0) { "APK signing block start before file" }
        val sizeInHeader = readU64(raf, blockStart)
        require(sizeInHeader == sizeInFooter) { "APK signing block size mismatch" }
        val pairsEnd = footer
        var pos = blockStart + 8
        val ids = mutableListOf<Long>()
        var pairs = 0
        while (pos < pairsEnd) {
            require(++pairs <= MAX_PAIRS) { "Too many APK signing block pairs" }
            require(pos + 8 <= pairsEnd) { "Truncated APK signing pair length" }
            val len = readU64(raf, pos)
            require(len >= 4 && len <= MAX_PAIR_BYTES) { "APK signing pair length outside bound" }
            val next = pos + 8 + len
            require(next <= pairsEnd) { "APK signing pair exceeds block" }
            val id = readU32(raf, pos + 8)
            ids += id
            pos = next
        }
        ids.distinct().sorted()
    }

    private fun findEocd(raf: RandomAccessFile): Long {
        val length = raf.length()
        require(length >= 22) { "ZIP/APK too small" }
        val scan = minOf(length, MAX_EOCD_SCAN.toLong()).toInt()
        val start = length - scan
        val buffer = ByteArray(scan)
        raf.seek(start)
        raf.readFully(buffer)
        for (i in buffer.size - 22 downTo 0) {
            if (u32(buffer, i) == ZIP_EOCD_SIGNATURE) {
                val commentLength = u16(buffer, i + 20)
                if (i + 22 + commentLength == buffer.size) return start + i
            }
        }
        throw IllegalArgumentException("ZIP EOCD not found")
    }

    private fun readU32(raf: RandomAccessFile, offset: Long): Long {
        require(offset >= 0 && offset + 4 <= raf.length()) { "u32 outside file" }
        raf.seek(offset)
        val b = ByteArray(4); raf.readFully(b)
        return u32(b, 0)
    }
    private fun readU64(raf: RandomAccessFile, offset: Long): Long {
        require(offset >= 0 && offset + 8 <= raf.length()) { "u64 outside file" }
        raf.seek(offset)
        val b = ByteArray(8); raf.readFully(b)
        var v = 0L
        for (i in 0 until 8) v = v or ((b[i].toLong() and 0xffL) shl (8 * i))
        require(v >= 0) { "u64 value exceeds signed Long" }
        return v
    }
    private fun u16(b: ByteArray, o: Int): Int = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)
    private fun u32(b: ByteArray, o: Int): Long =
        (b[o].toLong() and 0xffL) or ((b[o + 1].toLong() and 0xffL) shl 8) or ((b[o + 2].toLong() and 0xffL) shl 16) or ((b[o + 3].toLong() and 0xffL) shl 24)

    const val APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871aL
    const val APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0L
    const val APK_SIGNATURE_SCHEME_V31_BLOCK_ID = 0x1b93ad61L
    private const val ZIP_EOCD_SIGNATURE = 0x06054b50L
    private const val APK_SIG_BLOCK_FOOTER_SIZE = 24L
    private const val MAX_EOCD_SCAN = 65_557
    private const val MAX_V1_FILES = 256
    private const val MAX_PAIRS = 128
    private const val MAX_SIGNING_BLOCK_BYTES = 64L * 1024L * 1024L
    private const val MAX_PAIR_BYTES = 32L * 1024L * 1024L
    private val APK_SIG_BLOCK_MAGIC = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
}
