package org.unirevlab.security.analysis

import java.io.EOFException
import java.io.RandomAccessFile
import java.nio.ByteBuffer

/** Thread-local immutable-file read window for hot DEX random-access paths. */
internal object PositionalReadCache {
    private const val WINDOW_SIZE = 64 * 1024

    private class Window {
        var file: RandomAccessFile? = null
        var start: Long = -1L
        var length: Int = 0
        val bytes = ByteArray(WINDOW_SIZE)
    }

    private val local = ThreadLocal.withInitial(::Window)

    fun u8(raf: RandomAccessFile, offset: Long, bound: Long = raf.length()): Int {
        require(offset >= 0L && offset < bound) { "byte offset outside file" }
        val window = local.get()
        if (window.file !== raf || offset < window.start || offset >= window.start + window.length) {
            refill(window, raf, offset, bound)
        }
        val index = (offset - window.start).toInt()
        if (index !in 0 until window.length) throw EOFException("short positional read")
        return window.bytes[index].toInt() and 0xff
    }

    fun u16Le(raf: RandomAccessFile, offset: Long, bound: Long = raf.length()): Int =
        u8(raf, offset, bound) or (u8(raf, offset + 1L, bound) shl 8)

    fun u32Le(raf: RandomAccessFile, offset: Long, bound: Long = raf.length()): Long =
        u8(raf, offset, bound).toLong() or
            (u8(raf, offset + 1L, bound).toLong() shl 8) or
            (u8(raf, offset + 2L, bound).toLong() shl 16) or
            (u8(raf, offset + 3L, bound).toLong() shl 24)

    /** Returns decoded unsigned LEB128 value and the first byte after it. */
    fun uleb128At(raf: RandomAccessFile, offset: Long, bound: Long): Pair<Long, Long> {
        var cursor = offset
        var result = 0L
        var shift = 0
        repeat(5) {
            if (cursor >= bound) throw EOFException("truncated uleb128")
            val b = u8(raf, cursor++, bound)
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result to cursor
            shift += 7
        }
        throw IllegalArgumentException("uleb128 exceeds 5 bytes")
    }

    private fun refill(window: Window, raf: RandomAccessFile, offset: Long, bound: Long) {
        val start = (offset / WINDOW_SIZE.toLong()) * WINDOW_SIZE.toLong()
        val requested = minOf(WINDOW_SIZE.toLong(), bound - start).toInt()
        if (requested <= 0) throw EOFException("read window outside file")
        val buffer = ByteBuffer.wrap(window.bytes, 0, requested)
        var total = 0
        while (total < requested) {
            val read = raf.channel.read(buffer, start + total.toLong())
            if (read < 0) break
            if (read == 0) break
            total += read
        }
        window.file = raf
        window.start = start
        window.length = total
        if (offset >= start + total) throw EOFException("short positional read")
    }
}
