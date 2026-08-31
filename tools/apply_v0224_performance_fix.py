#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    if new in text:
        print(f"already patched: {rel}")
        return
    if old not in text:
        raise SystemExit(f"patch state mismatch: {rel}\nmissing block:\n{old[:600]}")
    write(rel, text.replace(old, new, 1))
    print(f"patched: {rel}")


def replace_between(rel: str, start: str, end: str, replacement: str) -> None:
    text = read(rel)
    if replacement in text:
        print(f"already patched: {rel} :: {start.strip()[:48]}")
        return
    i = text.find(start)
    if i < 0:
        raise SystemExit(f"patch state mismatch: {rel}\nmissing start: {start}")
    j = text.find(end, i)
    if j < 0:
        raise SystemExit(f"patch state mismatch: {rel}\nmissing end: {end}")
    write(rel, text[:i] + replacement + text[j:])
    print(f"patched: {rel} :: {start.strip()[:48]}")


# -----------------------------------------------------------------------------
# Shared positional 64 KiB read window.
# RandomAccessFile.seek()+readUnsignedByte() on every Dalvik code unit was the
# dominant cost on large multidex apps. Positional FileChannel reads do not
# disturb the sequential class_data cursor and collapse millions of seeks into
# roughly one read per 64 KiB window per worker thread.
# -----------------------------------------------------------------------------
positional_rel = "app/src/main/java/org/unirevlab/security/analysis/PositionalReadCache.kt"
positional_source = '''package org.unirevlab.security.analysis

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
'''
if not (ROOT / positional_rel).exists():
    write(positional_rel, positional_source)
    print(f"created: {positional_rel}")
elif read(positional_rel) != positional_source:
    raise SystemExit(f"patch state mismatch: {positional_rel}")
else:
    print(f"already patched: {positional_rel}")


# -----------------------------------------------------------------------------
# Cheap secret prefilters: do not run three regex engines on every DEX string.
# -----------------------------------------------------------------------------
replace_between(
    "app/src/main/java/org/unirevlab/security/analysis/SensitiveStringClassifier.kt",
    "    fun detectKind(value: String): String? {\n",
    "    fun sha256(value: String): String =",
    '''    fun detectKind(value: String): String? {
        // Most DEX strings are class names, resources or ordinary literals. Avoid allocating
        // trim() results and invoking regex engines unless a cheap marker can possibly match.
        if (value.indexOf("PRIVATE KEY", ignoreCase = false) >= 0 && PRIVATE_KEY_MARKERS.any { value.contains(it) }) {
            return "PRIVATE_KEY_MATERIAL"
        }
        if (value.indexOf("eyJ", ignoreCase = false) >= 0 && JWT_REGEX.containsMatchIn(value)) return "JWT_LIKE_TOKEN"
        if (value.indexOf("AIza", ignoreCase = false) >= 0 && GOOGLE_API_KEY_REGEX.containsMatchIn(value)) return "GOOGLE_API_KEY_LIKE"
        if ((value.indexOf("AKIA", ignoreCase = false) >= 0 || value.indexOf("ASIA", ignoreCase = false) >= 0) &&
            AWS_ACCESS_KEY_REGEX.containsMatchIn(value)
        ) return "AWS_ACCESS_KEY_ID_LIKE"
        return null
    }

''',
)


# -----------------------------------------------------------------------------
# DexStringScanner: positional reads + adaptive string buffers + URL prefilter.
# -----------------------------------------------------------------------------
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/DexStringScanner.kt",
    '''                URL_REGEX.findAll(decoded.value).forEach { match ->
                    val sanitized = sanitizeUrl(match.value)
                    val ref = DexStringReference(dexEntry, index, sanitized)
                    if (sanitized.startsWith("http://", ignoreCase = true)) {
                        if (httpUrls.size < limits.maxUrls && ref !in httpUrls) httpUrls += ref else truncated = true
                    } else if (sanitized.startsWith("https://", ignoreCase = true)) {
                        if (httpsUrls.size < limits.maxUrls && ref !in httpsUrls) httpsUrls += ref else truncated = true
                    }
                }
''',
    '''                if (decoded.value.indexOf("http", ignoreCase = true) >= 0) {
                    URL_REGEX.findAll(decoded.value).forEach { match ->
                        val sanitized = sanitizeUrl(match.value)
                        val ref = DexStringReference(dexEntry, index, sanitized)
                        if (sanitized.startsWith("http://", ignoreCase = true)) {
                            if (httpUrls.size < limits.maxUrls && ref !in httpUrls) httpUrls += ref else truncated = true
                        } else if (sanitized.startsWith("https://", ignoreCase = true)) {
                            if (httpsUrls.size < limits.maxUrls && ref !in httpsUrls) httpsUrls += ref else truncated = true
                        }
                    }
                }
''',
)

replace_between(
    "app/src/main/java/org/unirevlab/security/analysis/DexStringScanner.kt",
    "    private fun readStringByIndex(raf: RandomAccessFile, h: Header, index: Int, maxStringBytes: Int): DecodedString {\n",
    "    private fun readStringData(raf: RandomAccessFile, offset: Long, fileSize: Long, maxStringBytes: Int): DecodedString {",
    '''    private fun readStringByIndex(raf: RandomAccessFile, h: Header, index: Int, maxStringBytes: Int): DecodedString {
        if (index !in 0 until h.stringIdsSize) throw DexFormatException("string_idx outside string_ids")
        val itemOffset = PositionalReadCache.u32Le(raf, h.stringIdsOff + index.toLong() * 4L, h.fileSize)
        if (itemOffset >= h.fileSize) throw DexFormatException("string_data_off outside DEX")
        return readStringData(raf, itemOffset, h.fileSize, maxStringBytes)
    }

''',
)

replace_between(
    "app/src/main/java/org/unirevlab/security/analysis/DexStringScanner.kt",
    "    private fun readStringData(raf: RandomAccessFile, offset: Long, fileSize: Long, maxStringBytes: Int): DecodedString {\n",
    "    private fun decodeModifiedUtf8(bytes: ByteArray, length: Int, expectedUtf16Units: Long): String {",
    '''    private fun readStringData(raf: RandomAccessFile, offset: Long, fileSize: Long, maxStringBytes: Int): DecodedString {
        val (expectedUtf16Units, dataStart) = try {
            PositionalReadCache.uleb128At(raf, offset, fileSize)
        } catch (e: Exception) {
            throw DexFormatException(e.message ?: "invalid string length")
        }
        val expectedBytesHint = (expectedUtf16Units.coerceAtMost(maxStringBytes.toLong()) * 2L)
            .coerceAtLeast(64L)
            .coerceAtMost(4_096L)
            .toInt()
        var bytes = ByteArray(minOf(maxStringBytes, expectedBytesHint))
        var count = 0
        var cursor = dataStart
        var truncated = false
        var terminated = false
        while (cursor < fileSize) {
            if ((count and 0x0fff) == 0) checkCancelled()
            val b = try {
                PositionalReadCache.u8(raf, cursor++, fileSize)
            } catch (_: Exception) {
                throw DexFormatException("truncated string_data_item")
            }
            if (b == 0) {
                terminated = true
                break
            }
            if (count >= maxStringBytes) {
                truncated = true
                while (cursor < fileSize) {
                    val next = try { PositionalReadCache.u8(raf, cursor++, fileSize) } catch (_: Exception) { break }
                    if (next == 0) {
                        terminated = true
                        break
                    }
                }
                break
            }
            if (count == bytes.size) {
                val nextSize = minOf(maxStringBytes, maxOf(bytes.size + 1, bytes.size * 2))
                bytes = bytes.copyOf(nextSize)
            }
            bytes[count++] = b.toByte()
        }
        if (!terminated) throw DexFormatException("string_data_item missing terminator")
        return DecodedString(decodeModifiedUtf8(bytes, count, expectedUtf16Units), truncated)
    }

''',
)

replace_between(
    "app/src/main/java/org/unirevlab/security/analysis/DexStringScanner.kt",
    "    private fun typeDescriptor(raf: RandomAccessFile, h: Header, typeIndex: Int, maxStringBytes: Int): String {\n",
    "    private fun readMethod(raf: RandomAccessFile, h: Header, dexEntry: String, methodIndex: Int, limits: Limits): DexMethodReference {",
    '''    private fun typeDescriptor(raf: RandomAccessFile, h: Header, typeIndex: Int, maxStringBytes: Int): String {
        if (typeIndex !in 0 until h.typeIdsSize) throw DexFormatException("type_idx outside type_ids")
        val stringIndex = PositionalReadCache.u32Le(raf, h.typeIdsOff + typeIndex.toLong() * 4L, h.fileSize).toIntChecked("descriptor_idx")
        return readStringByIndex(raf, h, stringIndex, maxStringBytes).value
    }

''',
)

replace_between(
    "app/src/main/java/org/unirevlab/security/analysis/DexStringScanner.kt",
    "    private fun readU16(raf: RandomAccessFile, offset: Long): Int {\n",
    "    private fun readU32(raf: RandomAccessFile, offset: Long): Long {",
    '''    private fun readU16(raf: RandomAccessFile, offset: Long): Int {
        ensureRange(offset, 2, raf.length(), "u16")
        return PositionalReadCache.u16Le(raf, offset, raf.length())
    }

''',
)
replace_between(
    "app/src/main/java/org/unirevlab/security/analysis/DexStringScanner.kt",
    "    private fun readU32(raf: RandomAccessFile, offset: Long): Long {\n",
    "    private fun ensureRange(offset: Long, size: Long, bound: Long, label: String) {",
    '''    private fun readU32(raf: RandomAccessFile, offset: Long): Long {
        ensureRange(offset, 4, raf.length(), "u32")
        return PositionalReadCache.u32Le(raf, offset, raf.length())
    }

''',
)


# -----------------------------------------------------------------------------
# DexCodeScanner: same positional read cache, adaptive string buffers, linear CFG,
# and stop expensive CFG/constant work once the corresponding bounded outputs are full.
# -----------------------------------------------------------------------------
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/DexCodeScanner.kt",
    '''        val decodedInstructions = mutableListOf<Instruction>()
        var pc = 0
        var truncated = false
''',
    '''        val keepFlowEvidence =
            blocks.size < limits.maxBasicBlocks || constants.size < limits.maxConstants || observations.size < limits.maxInvokeObservations
        val decodedInstructions = if (keepFlowEvidence) ArrayList<Instruction>() else null
        var pc = 0
        var truncated = false
        if (!keepFlowEvidence &&
            calls.size >= limits.maxCallXrefs && strings.size >= limits.maxStringXrefs &&
            types.size >= limits.maxTypeXrefs && fields.size >= limits.maxFieldXrefs
        ) {
            // Every bounded bytecode evidence collection is already saturated. Continuing to decode
            // this method cannot change the report, so account for its code size and stop here.
            return Triple(meta, insnsSizeLong, true)
        }
''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/DexCodeScanner.kt",
    '''            decodedInstructions += decodeControlFlowInstruction(raf, insnsOff, pc, insnsSize, unit0, width)
            pc += width
''',
    '''            decodedInstructions?.add(decodeControlFlowInstruction(raf, insnsOff, pc, insnsSize, unit0, width))
            pc += width
''',
)

replace_between(
    "app/src/main/java/org/unirevlab/security/analysis/DexCodeScanner.kt",
    "        val methodBlocks = buildBasicBlocks(dexEntry, caller, decodedInstructions, insnsSize)\n",
    "        return Triple(meta, insnsSizeLong, truncated)\n",
    '''        if (decodedInstructions != null) {
            val methodBlocks = buildBasicBlocks(dexEntry, caller, decodedInstructions, insnsSize)
            if (blocks.size < limits.maxBasicBlocks) {
                val remaining = limits.maxBasicBlocks - blocks.size
                val accepted = minOf(remaining, methodBlocks.size)
                for (index in 0 until accepted) blocks += methodBlocks[index]
                if (methodBlocks.size > accepted) truncated = true
            } else if (methodBlocks.isNotEmpty()) truncated = true

            val needConstants = constants.size < limits.maxConstants
            val needObservations = observations.size < limits.maxInvokeObservations
            if (needConstants || needObservations) {
                val observed = observeConstants(
                    raf, h, dexEntry, caller, insnsOff, insnsSize, decodedInstructions, methodBlocks, limits, methodRef,
                    collectConstants = needConstants,
                    collectObservations = needObservations,
                )
                val methodConstants = observed.first
                val methodObservations = observed.second
                if (needConstants) {
                    val remaining = limits.maxConstants - constants.size
                    val accepted = minOf(remaining, methodConstants.size)
                    for (index in 0 until accepted) constants += methodConstants[index]
                    if (methodConstants.size > accepted) truncated = true
                }
                if (needObservations) {
                    val remaining = limits.maxInvokeObservations - observations.size
                    val accepted = minOf(remaining, methodObservations.size)
                    for (index in 0 until accepted) observations += methodObservations[index]
                    if (methodObservations.size > accepted) truncated = true
                }
            }
        }
''',
)

replace_between(
    "app/src/main/java/org/unirevlab/security/analysis/DexCodeScanner.kt",
    "    private fun buildBasicBlocks(\n",
    "    /**\n     * Performs local constant propagation inside individual basic blocks only.",
    '''    private fun buildBasicBlocks(
        dexEntry: String,
        caller: MethodRef,
        instructions: List<Instruction>,
        insnsSize: Int,
    ): List<DexBasicBlock> {
        if (instructions.isEmpty()) return emptyList()
        val leaders = java.util.TreeSet<Int>()
        leaders += 0
        for (insn in instructions) {
            for (target in insn.branchTargets) leaders += target
            val next = insn.pc + insn.width
            if ((insn.branchTargets.isNotEmpty() || !insn.fallsThrough) && next < insnsSize) leaders += next
        }
        val starts = leaders.filter { it in 0 until insnsSize }
        if (starts.isEmpty()) return emptyList()
        val instructionByPc = HashMap<Int, Instruction>(instructions.size * 4 / 3 + 1)
        for (insn in instructions) instructionByPc[insn.pc] = insn
        val output = ArrayList<DexBasicBlock>(starts.size)
        var instructionCursor = 0
        for (index in starts.indices) {
            val start = starts[index]
            val end = starts.getOrNull(index + 1) ?: insnsSize
            if (end <= start || instructionByPc[start] == null) continue
            while (instructionCursor < instructions.size && instructions[instructionCursor].pc < start) instructionCursor++
            var cursor = instructionCursor
            var last: Instruction? = null
            while (cursor < instructions.size && instructions[cursor].pc < end) {
                last = instructions[cursor]
                cursor++
            }
            instructionCursor = cursor
            val tail = last ?: continue
            val successors = linkedSetOf<Int>()
            for (target in tail.branchTargets) if (leaders.contains(target)) successors += target
            val fallthrough = tail.pc + tail.width
            if (tail.fallsThrough && fallthrough < insnsSize) {
                val position = starts.binarySearch(fallthrough)
                val insertion = if (position >= 0) position else -position - 1
                starts.getOrNull(insertion)?.let(successors::add)
            }
            val terminal = when {
                tail.terminalKind != "FALLTHROUGH" -> tail.terminalKind
                successors.isEmpty() -> "END"
                else -> "FALLTHROUGH"
            }
            output += DexBasicBlock(
                dexEntry = dexEntry,
                methodIndex = caller.methodIndex,
                blockIndex = index,
                startCodeUnit = start,
                endCodeUnitExclusive = end,
                successorCodeUnits = successors.toList().sorted(),
                terminalKind = terminal,
            )
        }
        return output
    }

''',
)

replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/DexCodeScanner.kt",
    '''        limits: Limits,
        methodRef: (Int) -> MethodRef,
    ): Pair<List<DexConstantReference>, List<DexInvokeObservation>> {
''',
    '''        limits: Limits,
        methodRef: (Int) -> MethodRef,
        collectConstants: Boolean = true,
        collectObservations: Boolean = true,
    ): Pair<List<DexConstantReference>, List<DexInvokeObservation>> {
''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/DexCodeScanner.kt",
    '''        fun record(register: Int, kind: String, value: String, pc: Int) {
            state[register] = RegValue(kind, value)
            constants += DexConstantReference(dexEntry, caller.methodIndex, register, kind, value, pc)
        }
''',
    '''        fun record(register: Int, kind: String, value: String, pc: Int) {
            state[register] = RegValue(kind, value)
            if (collectConstants) constants += DexConstantReference(dexEntry, caller.methodIndex, register, kind, value, pc)
        }
''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/DexCodeScanner.kt",
    '''                        if (args.isNotEmpty()) {
                            out += DexInvokeObservation(
''',
    '''                        if (collectObservations && args.isNotEmpty()) {
                            out += DexInvokeObservation(
''',
)

replace_between(
    "app/src/main/java/org/unirevlab/security/analysis/DexCodeScanner.kt",
    "    private fun readString(raf: RandomAccessFile, h: Header, index: Int, maxBytes: Int): String {\n",
    "    private fun readUleb128(raf: RandomAccessFile, fileSize: Long): Long {",
    '''    private fun readString(raf: RandomAccessFile, h: Header, index: Int, maxBytes: Int): String {
        if (index !in 0 until h.stringIdsSize) throw DexCodeFormatException("string index outside table")
        val offset = PositionalReadCache.u32Le(raf, h.stringIdsOff + index.toLong() * 4L, h.fileSize)
        if (offset >= h.fileSize) throw DexCodeFormatException("string_data_off outside DEX")
        val (expectedUtf16Units, dataStart) = try {
            PositionalReadCache.uleb128At(raf, offset, h.fileSize)
        } catch (e: Exception) {
            throw DexCodeFormatException(e.message ?: "invalid string length")
        }
        val expectedBytesHint = (expectedUtf16Units.coerceAtMost(maxBytes.toLong()) * 2L)
            .coerceAtLeast(64L)
            .coerceAtMost(4_096L)
            .toInt()
        var bytes = ByteArray(minOf(maxBytes, expectedBytesHint))
        var count = 0
        var cursor = dataStart
        var terminated = false
        while (cursor < h.fileSize) {
            val b = try { PositionalReadCache.u8(raf, cursor++, h.fileSize) } catch (_: Exception) { break }
            if (b == 0) {
                terminated = true
                break
            }
            if (count >= maxBytes) throw DexCodeFormatException("string exceeds bounded code-xref limit")
            if (count == bytes.size) {
                val nextSize = minOf(maxBytes, maxOf(bytes.size + 1, bytes.size * 2))
                bytes = bytes.copyOf(nextSize)
            }
            bytes[count++] = b.toByte()
        }
        if (!terminated) throw DexCodeFormatException("unterminated string")
        return String(bytes, 0, count, Charsets.UTF_8)
    }

''',
)
replace_between(
    "app/src/main/java/org/unirevlab/security/analysis/DexCodeScanner.kt",
    "    private fun readU16(raf: RandomAccessFile, offset: Long): Int {\n",
    "    private fun readU32(raf: RandomAccessFile, offset: Long): Long {",
    '''    private fun readU16(raf: RandomAccessFile, offset: Long): Int {
        ensureRange(offset, 2, raf.length(), "u16")
        return PositionalReadCache.u16Le(raf, offset, raf.length())
    }

''',
)
replace_between(
    "app/src/main/java/org/unirevlab/security/analysis/DexCodeScanner.kt",
    "    private fun readU32(raf: RandomAccessFile, offset: Long): Long {\n",
    "    private fun Long.toIntChecked(label: String): Int {",
    '''    private fun readU32(raf: RandomAccessFile, offset: Long): Long {
        ensureRange(offset, 4, raf.length(), "u32")
        return PositionalReadCache.u32Le(raf, offset, raf.length())
    }

''',
)


# -----------------------------------------------------------------------------
# Background resilience: if Android recreates only the service while the process/job is still
# alive, reacquire the wake lock instead of permanently losing the foreground keeper.
# -----------------------------------------------------------------------------
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/AnalysisForegroundService.kt",
    '''        acquireWakeLock()
        startForeground(NOTIFICATION_ID, buildNotification(state))
        return START_NOT_STICKY
''',
    '''        acquireWakeLock()
        startForeground(NOTIFICATION_ID, buildNotification(state))
        return START_STICKY
''',
)

# Give the dedicated CPU workers a slight scheduling preference while the app is an active
# foreground-service workload. This does not change Android power-management policy.
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt",
    '''        private val CPU_EXECUTOR: java.util.concurrent.ExecutorService =
            java.util.concurrent.Executors.newFixedThreadPool(DEX_PARALLELISM) { runnable ->
                Thread(runnable, "unirevlab-analysis").apply { isDaemon = true }
            }
''',
    '''        private val CPU_EXECUTOR: java.util.concurrent.ExecutorService =
            java.util.concurrent.Executors.newFixedThreadPool(DEX_PARALLELISM) { runnable ->
                Thread({
                    runCatching { android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_MORE_FAVORABLE) }
                    runnable.run()
                }, "unirevlab-analysis").apply { isDaemon = true }
            }
''',
)

# Version markers.
replace_once(
    "app/build.gradle.kts",
    '''        versionCode = 21
        versionName = "0.22.3-dev-progress-ux"
''',
    '''        versionCode = 22
        versionName = "0.22.4-dev-fast-dex"
''',
)
replace_once(
    "app/src/main/java/org/unirevlab/security/analysis/LocalArtifactInspector.kt",
    '        const val ENGINE_VERSION = "0.22.2-dev-dex-stability-eta"\n',
    '        const val ENGINE_VERSION = "0.22.4-dev-fast-dex"\n',
)

# JVM correctness test for positional cache (including a 64 KiB window boundary) and pointer safety.
test_rel = "app/src/test/java/org/unirevlab/security/analysis/PositionalReadCacheTest.kt"
test_source = '''package org.unirevlab.security.analysis

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
'''
if not (ROOT / test_rel).exists():
    write(test_rel, test_source)
    print(f"created: {test_rel}")
elif read(test_rel) != test_source:
    raise SystemExit(f"patch state mismatch: {test_rel}")
else:
    print(f"already patched: {test_rel}")

print("v0.22.4 fast DEX/background patch applied")
