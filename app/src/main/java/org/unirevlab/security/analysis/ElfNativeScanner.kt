package org.unirevlab.security.analysis

import org.unirevlab.security.model.NativeLibrarySummary
import org.unirevlab.security.model.NativeSecretCandidate
import org.unirevlab.security.model.NativeSymbolReference
import java.io.File
import java.io.RandomAccessFile

/**
 * Bounded ELF inventory for APK native libraries.
 * The target library is treated as data only: it is never loaded, linked, or executed.
 */
object ElfNativeScanner {
    data class Limits(
        val maxElfBytes: Long = 2L * 1024L * 1024L * 1024L,
        val maxSections: Int = 4096,
        val maxProgramHeaders: Int = 512,
        val maxSymbols: Int = 30_000,
        val maxReportedImports: Int = 2_000,
        val maxReportedExports: Int = 2_000,
        val maxNeededLibraries: Int = 256,
        val maxAsciiScanBytes: Long = 64L * 1024L * 1024L,
        val maxUrls: Int = 200,
        val maxSecretCandidates: Int = 100,
        val maxStringLength: Int = 8192,
    )

    class ElfFormatException(message: String) : Exception(message)

    private data class Header(
        val is64: Boolean,
        val type: Int,
        val machine: Int,
        val phoff: Long,
        val shoff: Long,
        val phentsize: Int,
        val phnum: Int,
        val shentsize: Int,
        val shnum: Int,
        val shstrndx: Int,
    )

    private data class Section(
        val index: Int,
        val nameOffset: Long,
        val type: Long,
        val offset: Long,
        val size: Long,
        val link: Int,
        val entrySize: Long,
        var name: String = "",
    )

    fun scan(entryName: String, file: File, limits: Limits = Limits()): NativeLibrarySummary {
        require(file.length() <= limits.maxElfBytes) { "ELF exceeds ${limits.maxElfBytes} byte limit" }
        RandomAccessFile(file, "r").use { raf ->
            val header = readHeader(raf)
            if (header.shnum > limits.maxSections) throw ElfFormatException("ELF section count exceeds limit")
            if (header.phnum > limits.maxProgramHeaders) throw ElfFormatException("ELF program-header count exceeds limit")

            var truncated = false
            val sections = readSections(raf, header)
            resolveSectionNames(raf, sections, header.shstrndx)

            val hardening = inspectProgramHeaders(raf, header)
            val symbols = inspectDynamicSymbols(entryName, raf, header, sections, limits).also { if (it.truncated) truncated = true }
            val dynamic = inspectDynamicSection(raf, header, sections, limits).also { if (it.truncated) truncated = true }
            val strings = scanAscii(raf, limits).also { if (it.truncated) truncated = true }
            val buildId = readBuildId(raf, sections)
            val hasSymtab = sections.any { it.type == SHT_SYMTAB }

            val jniSymbols = (symbols.exports.map { it.name } + symbols.imports.map { it.name })
                .filter { it == "JNI_OnLoad" || it.startsWith("Java_") }
                .distinct()
                .take(limits.maxReportedExports)

            return NativeLibrarySummary(
                entryName = entryName,
                abi = abiFrom(entryName, header.machine),
                elfClass = if (header.is64) "ELF64" else "ELF32",
                machine = machineName(header.machine),
                fileType = fileTypeName(header.type),
                sizeBytes = file.length(),
                buildId = buildId,
                neededLibraries = dynamic.needed.distinct(),
                importedSymbols = symbols.imports,
                exportedSymbols = symbols.exports,
                jniSymbols = jniSymbols,
                hasJniOnLoad = jniSymbols.contains("JNI_OnLoad"),
                registerNativesIndicator = strings.registerNatives,
                executableStack = hardening.executableStack,
                hasGnuRelro = hardening.gnuRelro,
                bindNow = dynamic.bindNow,
                hasStackCanaryImport = symbols.imports.any { it.name == "__stack_chk_fail" || it.name == "__stack_chk_guard" },
                stripped = !hasSymtab,
                httpUrls = strings.httpUrls,
                secretCandidates = strings.secretCandidates.map { it.copy(libraryEntry = entryName) },
                truncated = truncated,
            )
        }
    }

    private fun readHeader(raf: RandomAccessFile): Header {
        if (raf.length() < 52) throw ElfFormatException("ELF header is truncated")
        val ident = ByteArray(16)
        raf.seek(0)
        raf.readFully(ident)
        if (!(ident[0] == 0x7f.toByte() && ident[1] == 'E'.code.toByte() && ident[2] == 'L'.code.toByte() && ident[3] == 'F'.code.toByte())) {
            throw ElfFormatException("invalid ELF magic")
        }
        val is64 = when (ident[4].toInt() and 0xff) {
            1 -> false
            2 -> true
            else -> throw ElfFormatException("unsupported ELF class")
        }
        if ((ident[5].toInt() and 0xff) != 1) throw ElfFormatException("only little-endian ELF is supported")
        val minimum = if (is64) 64L else 52L
        if (raf.length() < minimum) throw ElfFormatException("ELF header is truncated")

        val type = u16(raf, 16)
        val machine = u16(raf, 18)
        val phoff = if (is64) u64(raf, 32) else u32(raf, 28)
        val shoff = if (is64) u64(raf, 40) else u32(raf, 32)
        val phentsize = u16(raf, if (is64) 54 else 42)
        val phnum = u16(raf, if (is64) 56 else 44)
        val shentsize = u16(raf, if (is64) 58 else 46)
        val shnum = u16(raf, if (is64) 60 else 48)
        val shstrndx = u16(raf, if (is64) 62 else 50)
        val expectedPh = if (is64) 56 else 32
        val expectedSh = if (is64) 64 else 40
        if (phnum > 0 && phentsize < expectedPh) throw ElfFormatException("unexpected program-header entry size")
        if (shnum > 0 && shentsize < expectedSh) throw ElfFormatException("unexpected section-header entry size")
        ensureTable(phoff, phentsize.toLong(), phnum, raf.length(), "program headers")
        ensureTable(shoff, shentsize.toLong(), shnum, raf.length(), "section headers")
        return Header(is64, type, machine, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx)
    }

    private fun readSections(raf: RandomAccessFile, h: Header): MutableList<Section> {
        val result = ArrayList<Section>(h.shnum)
        repeat(h.shnum) { index ->
            val base = h.shoff + index.toLong() * h.shentsize
            val section = if (h.is64) {
                Section(
                    index = index,
                    nameOffset = u32(raf, base),
                    type = u32(raf, base + 4),
                    offset = u64(raf, base + 24),
                    size = u64(raf, base + 32),
                    link = u32(raf, base + 40).toIntChecked("section link"),
                    entrySize = u64(raf, base + 56),
                )
            } else {
                Section(
                    index = index,
                    nameOffset = u32(raf, base),
                    type = u32(raf, base + 4),
                    offset = u32(raf, base + 16),
                    size = u32(raf, base + 20),
                    link = u32(raf, base + 24).toIntChecked("section link"),
                    entrySize = u32(raf, base + 36),
                )
            }
            if (section.type != SHT_NOBITS) ensureRange(section.offset, section.size, raf.length(), "section[$index]")
            result += section
        }
        return result
    }

    private fun resolveSectionNames(raf: RandomAccessFile, sections: MutableList<Section>, shstrndx: Int) {
        if (shstrndx !in sections.indices) return
        val table = sections[shstrndx]
        for (section in sections) {
            section.name = readCString(raf, table.offset, table.size, section.nameOffset, 512)
        }
    }

    private data class Hardening(val executableStack: Boolean?, val gnuRelro: Boolean)

    private fun inspectProgramHeaders(raf: RandomAccessFile, h: Header): Hardening {
        var executableStack: Boolean? = null
        var relro = false
        repeat(h.phnum) { index ->
            val base = h.phoff + index.toLong() * h.phentsize
            val type = u32(raf, base)
            val flags = if (h.is64) u32(raf, base + 4) else u32(raf, base + 24)
            if (type == PT_GNU_STACK) executableStack = (flags and PF_X) != 0L
            if (type == PT_GNU_RELRO) relro = true
        }
        return Hardening(executableStack, relro)
    }

    private data class SymbolInventory(
        val imports: List<NativeSymbolReference>,
        val exports: List<NativeSymbolReference>,
        val truncated: Boolean,
    )

    private fun inspectDynamicSymbols(entryName: String, raf: RandomAccessFile, h: Header, sections: List<Section>, limits: Limits): SymbolInventory {
        val dynsym = sections.firstOrNull { it.type == SHT_DYNSYM } ?: return SymbolInventory(emptyList(), emptyList(), false)
        val strtab = sections.getOrNull(dynsym.link) ?: throw ElfFormatException(".dynsym string-table link is invalid")
        val entrySize = when {
            dynsym.entrySize > 0 -> dynsym.entrySize
            h.is64 -> 24L
            else -> 16L
        }
        val minSize = if (h.is64) 24L else 16L
        if (entrySize < minSize) throw ElfFormatException("invalid .dynsym entry size")
        val declared = dynsym.size / entrySize
        val toScan = minOf(declared, limits.maxSymbols.toLong()).toInt()
        var truncated = declared > toScan
        val imports = mutableListOf<NativeSymbolReference>()
        val exports = mutableListOf<NativeSymbolReference>()

        repeat(toScan) { i ->
            val base = dynsym.offset + i.toLong() * entrySize
            val nameOff = u32(raf, base)
            val info = if (h.is64) u8(raf, base + 4) else u8(raf, base + 12)
            val shndx = if (h.is64) u16(raf, base + 6) else u16(raf, base + 14)
            val value = if (h.is64) u64(raf, base + 8) else u32(raf, base + 4)
            val symbolSize = if (h.is64) u64(raf, base + 16) else u32(raf, base + 8)
            val name = readCString(raf, strtab.offset, strtab.size, nameOff, 8192)
            if (name.isEmpty()) return@repeat
            val binding = bindingName(info ushr 4)
            val type = symbolTypeName(info and 0x0f)
            val defined = shndx != SHN_UNDEF
            val ref = NativeSymbolReference(
                libraryEntry = entryName,
                name = name,
                binding = binding,
                symbolType = type,
                defined = defined,
                virtualAddress = value.takeIf { defined && it != 0L },
                sizeBytes = symbolSize.takeIf { it > 0L },
            )
            if (defined) {
                if (exports.size < limits.maxReportedExports) exports += ref else truncated = true
            } else {
                if (imports.size < limits.maxReportedImports) imports += ref else truncated = true
            }
        }
        return SymbolInventory(imports, exports, truncated)
    }

    private data class DynamicInfo(val needed: List<String>, val bindNow: Boolean, val truncated: Boolean)

    private fun inspectDynamicSection(raf: RandomAccessFile, h: Header, sections: List<Section>, limits: Limits): DynamicInfo {
        val dynamic = sections.firstOrNull { it.type == SHT_DYNAMIC } ?: return DynamicInfo(emptyList(), false, false)
        val strtab = sections.getOrNull(dynamic.link) ?: throw ElfFormatException("dynamic string-table link is invalid")
        val entrySize = if (h.is64) 16L else 8L
        val count = dynamic.size / entrySize
        val maxEntries = minOf(count, 100_000L).toInt()
        var bindNow = false
        var truncated = count > maxEntries
        val neededOffsets = mutableListOf<Long>()
        for (i in 0 until maxEntries) {
            val base = dynamic.offset + i.toLong() * entrySize
            val tag = if (h.is64) u64(raf, base) else u32(raf, base)
            val value = if (h.is64) u64(raf, base + 8) else u32(raf, base + 4)
            when (tag) {
                DT_NULL -> break
                DT_NEEDED -> if (neededOffsets.size < limits.maxNeededLibraries) neededOffsets += value else truncated = true
                DT_BIND_NOW -> bindNow = true
                DT_FLAGS -> if ((value and DF_BIND_NOW) != 0L) bindNow = true
                DT_FLAGS_1 -> if ((value and DF_1_NOW) != 0L) bindNow = true
            }
        }
        val needed = neededOffsets.map { readCString(raf, strtab.offset, strtab.size, it, 4096) }.filter { it.isNotEmpty() }
        return DynamicInfo(needed, bindNow, truncated)
    }

    private data class AsciiInfo(
        val httpUrls: List<String>,
        val secretCandidates: List<NativeSecretCandidate>,
        val registerNatives: Boolean,
        val truncated: Boolean,
    )

    private fun scanAscii(raf: RandomAccessFile, limits: Limits): AsciiInfo {
        val bytesToScan = minOf(raf.length(), limits.maxAsciiScanBytes)
        raf.seek(0)
        val buffer = ByteArray(64 * 1024)
        val current = StringBuilder()
        val urls = linkedSetOf<String>()
        val secretCandidates = mutableListOf<NativeSecretCandidate>()
        var registerNatives = false
        var remaining = bytesToScan
        var truncated = raf.length() > bytesToScan

        fun consumeCurrent() {
            if (current.length < 4) {
                current.setLength(0)
                return
            }
            val value = current.toString()
            if (value.contains("RegisterNatives")) registerNatives = true
            URL_REGEX.findAll(value).forEach { m ->
                if (urls.size < limits.maxUrls) urls += sanitizeUrl(m.value) else truncated = true
            }
            SensitiveStringClassifier.detectKind(value)?.let { kind ->
                if (secretCandidates.size < limits.maxSecretCandidates) {
                    secretCandidates += NativeSecretCandidate(
                        kind = kind,
                        libraryEntry = "",
                        valueSha256 = SensitiveStringClassifier.sha256(value),
                        redactedPreview = SensitiveStringClassifier.redacted(value),
                    )
                } else truncated = true
            }
            current.setLength(0)
        }

        while (remaining > 0) {
            val read = raf.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
            if (read <= 0) break
            remaining -= read
            for (i in 0 until read) {
                val b = buffer[i].toInt() and 0xff
                if (b in 0x20..0x7e) {
                    if (current.length < limits.maxStringLength) current.append(b.toChar()) else truncated = true
                } else {
                    consumeCurrent()
                }
            }
        }
        consumeCurrent()
        return AsciiInfo(urls.toList(), secretCandidates.distinctBy { it.kind to it.valueSha256 }, registerNatives, truncated)
    }

    private fun readBuildId(raf: RandomAccessFile, sections: List<Section>): String? {
        for (section in sections.filter { it.type == SHT_NOTE }) {
            var cursor = section.offset
            val end = section.offset + section.size
            while (cursor + 12 <= end) {
                val namesz = u32(raf, cursor)
                val descsz = u32(raf, cursor + 4)
                val type = u32(raf, cursor + 8)
                cursor += 12
                if (namesz > 4096 || descsz > 1024 * 1024) break
                ensureRange(cursor, namesz, end, "ELF note name")
                val nameBytes = readBytes(raf, cursor, namesz.toInt())
                cursor = align4(cursor + namesz)
                ensureRange(cursor, descsz, end, "ELF note desc")
                val desc = readBytes(raf, cursor, descsz.toInt())
                cursor = align4(cursor + descsz)
                val name = nameBytes.takeWhile { it != 0.toByte() }.toByteArray().toString(Charsets.US_ASCII)
                if (name == "GNU" && type == NT_GNU_BUILD_ID) return desc.joinToString("") { "%02x".format(it) }
            }
        }
        return null
    }

    private fun readCString(raf: RandomAccessFile, tableOffset: Long, tableSize: Long, relativeOffset: Long, maxBytes: Int): String {
        if (relativeOffset < 0 || relativeOffset >= tableSize) return ""
        val absolute = tableOffset + relativeOffset
        val end = tableOffset + tableSize
        raf.seek(absolute)
        val bytes = ByteArray(maxBytes)
        var count = 0
        while (raf.filePointer < end && count < maxBytes) {
            val b = raf.read()
            if (b <= 0) break
            bytes[count++] = b.toByte()
        }
        return String(bytes, 0, count, Charsets.UTF_8)
    }

    private fun readBytes(raf: RandomAccessFile, offset: Long, size: Int): ByteArray {
        val out = ByteArray(size)
        raf.seek(offset)
        raf.readFully(out)
        return out
    }

    private fun u8(raf: RandomAccessFile, offset: Long): Int {
        ensureRange(offset, 1, raf.length(), "u8")
        raf.seek(offset)
        return raf.readUnsignedByte()
    }

    private fun u16(raf: RandomAccessFile, offset: Long): Int {
        ensureRange(offset, 2, raf.length(), "u16")
        raf.seek(offset)
        return raf.readUnsignedByte() or (raf.readUnsignedByte() shl 8)
    }

    private fun u32(raf: RandomAccessFile, offset: Long): Long {
        ensureRange(offset, 4, raf.length(), "u32")
        raf.seek(offset)
        return raf.readUnsignedByte().toLong() or
            (raf.readUnsignedByte().toLong() shl 8) or
            (raf.readUnsignedByte().toLong() shl 16) or
            (raf.readUnsignedByte().toLong() shl 24)
    }

    private fun u64(raf: RandomAccessFile, offset: Long): Long {
        val lo = u32(raf, offset)
        val hi = u32(raf, offset + 4)
        if ((hi and 0x80000000L) != 0L) throw ElfFormatException("ELF 64-bit value exceeds signed parser range")
        return lo or (hi shl 32)
    }

    private fun ensureTable(offset: Long, entrySize: Long, count: Int, bound: Long, label: String) {
        if (count == 0) return
        if (offset <= 0 || entrySize <= 0) throw ElfFormatException("invalid $label")
        val bytes = checkedMul(entrySize, count.toLong())
        ensureRange(offset, bytes, bound, label)
    }

    private fun ensureRange(offset: Long, size: Long, bound: Long, label: String) {
        if (offset < 0 || size < 0 || offset > bound || size > bound - offset) throw ElfFormatException("$label range outside ELF")
    }

    private fun checkedMul(a: Long, b: Long): Long {
        if (a != 0L && b > Long.MAX_VALUE / a) throw ElfFormatException("integer overflow")
        return a * b
    }

    private fun Long.toIntChecked(label: String): Int {
        if (this > Int.MAX_VALUE) throw ElfFormatException("$label too large")
        return toInt()
    }

    private fun align4(value: Long): Long = (value + 3L) and -4L

    private fun sanitizeUrl(value: String): String {
        val clean = value.substringBefore('#').substringBefore('?').take(512)
        val schemeEnd = clean.indexOf("://")
        if (schemeEnd < 0) return clean
        val authorityStart = schemeEnd + 3
        val pathStart = clean.indexOf('/', authorityStart).let { if (it < 0) clean.length else it }
        val authority = clean.substring(authorityStart, pathStart)
        val safeAuthority = authority.substringAfterLast('@')
        return clean.substring(0, authorityStart) + safeAuthority + clean.substring(pathStart)
    }

    private fun abiFrom(entryName: String, machine: Int): String = when {
        entryName.startsWith("lib/arm64-v8a/") -> "arm64-v8a"
        entryName.startsWith("lib/armeabi-v7a/") -> "armeabi-v7a"
        entryName.startsWith("lib/x86_64/") -> "x86_64"
        entryName.startsWith("lib/x86/") -> "x86"
        else -> machineName(machine)
    }

    private fun machineName(machine: Int): String = when (machine) {
        3 -> "x86"
        40 -> "ARM"
        62 -> "x86_64"
        183 -> "AArch64"
        243 -> "RISC-V"
        else -> "machine-$machine"
    }

    private fun fileTypeName(type: Int): String = when (type) {
        1 -> "REL"
        2 -> "EXEC"
        3 -> "DYN"
        4 -> "CORE"
        else -> "type-$type"
    }

    private fun bindingName(binding: Int): String = when (binding) {
        0 -> "LOCAL"
        1 -> "GLOBAL"
        2 -> "WEAK"
        else -> "binding-$binding"
    }

    private fun symbolTypeName(type: Int): String = when (type) {
        0 -> "NOTYPE"
        1 -> "OBJECT"
        2 -> "FUNC"
        3 -> "SECTION"
        4 -> "FILE"
        6 -> "TLS"
        10 -> "IFUNC"
        else -> "type-$type"
    }

    private const val SHT_SYMTAB = 2L
    private const val SHT_DYNAMIC = 6L
    private const val SHT_NOTE = 7L
    private const val SHT_NOBITS = 8L
    private const val SHT_DYNSYM = 11L
    private const val SHN_UNDEF = 0
    private const val PT_GNU_STACK = 0x6474e551L
    private const val PT_GNU_RELRO = 0x6474e552L
    private const val PF_X = 0x1L
    private const val DT_NULL = 0L
    private const val DT_NEEDED = 1L
    private const val DT_BIND_NOW = 24L
    private const val DT_FLAGS = 30L
    private const val DT_FLAGS_1 = 0x6ffffffbL
    private const val DF_BIND_NOW = 0x8L
    private const val DF_1_NOW = 0x1L
    private const val NT_GNU_BUILD_ID = 3L
    private val URL_REGEX = Regex("https?://[^\\s\\\"'<>]+", RegexOption.IGNORE_CASE)
}
