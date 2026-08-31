package org.unirevlab.security.analysis

import java.io.RandomAccessFile
import org.junit.Assert.assertEquals
import org.junit.Test

class PositionalReadCacheTest {
    @Test
    fun positionalReadsCrossWindowWithoutChangingSequentialCursor() {
        val file = kotlin.io.path.createTempFile("positional-cache", ".bin").toFile()
        try {
            val bytes = ByteArray(70_000) { index -> (index and 0xff).toByte() }
            file.writeBytes(bytes)
            RandomAccessFile(file, "r").use { raf ->
                raf.seek(1234L)
                val before = raf.filePointer
                assertEquals(0xff or (0x00 shl 8), PositionalReadCache.u16Le(raf, 65_535L, bytes.size.toLong()))
                assertEquals(before, raf.filePointer)
                val expected = 65_534L and 0xff or
                    (((65_535L and 0xff) shl 8)) or
                    (((65_536L and 0xff) shl 16)) or
                    (((65_537L and 0xff) shl 24))
                assertEquals(expected, PositionalReadCache.u32Le(raf, 65_534L, bytes.size.toLong()))
                assertEquals(before, raf.filePointer)
            }
        } finally {
            file.delete()
        }
    }
}
