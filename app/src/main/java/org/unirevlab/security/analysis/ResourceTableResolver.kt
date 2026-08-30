package org.unirevlab.security.analysis

import org.unirevlab.security.model.ResourceReferenceChain
import org.unirevlab.security.model.ResourceReferenceHop
import org.unirevlab.security.model.ResourceResolutionSummary
import org.unirevlab.security.model.ResourceTableSummary
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Bounded parser for the subset of resources.arsc required to resolve compiled resource IDs.
 *
 * It supports normal, sparse and offset16 type-offset layouts plus bounded complex/bag entry
 * metadata. String/file values are resolved through the global pool; complex entries are reported
 * structurally without recursively interpreting application-controlled map semantics.
 */
object ResourceTableResolver {
    data class Limits(
        val maxBytes: Int = 64 * 1024 * 1024,
        val maxChunks: Int = 200_000,
        val maxStrings: Int = 200_000,
        val maxStringBytes: Int = 64 * 1024,
        val maxEntries: Int = 200_000,
        val maxPackages: Int = 64,
    )

    fun scanApk(apk: File, sourceArchive: String = apk.name, limits: Limits = Limits()): ResourceTableSummary? {
        return runCatching {
            ZipFile(apk).use { zip ->
                val entry = zip.getEntry("resources.arsc") ?: return null
                require(entry.size in 0..limits.maxBytes.toLong()) { "resources.arsc exceeds bounded parser limit" }
                val bytes = zip.getInputStream(entry).use { readBounded(it, limits.maxBytes) }
                parse(bytes, limits, sourceArchive)
            }
        }.getOrElse {
            ResourceTableSummary(sources = listOf(org.unirevlab.security.model.ResourceTableSourceSummary(sourceArchive, parseErrors = 1)), parseErrors = 1, truncated = false)
        }
    }

    fun parse(bytes: ByteArray, limits: Limits = Limits(), sourceArchive: String = "resources.arsc"): ResourceTableSummary {
        if (bytes.size < 12) return ResourceTableSummary(sources = listOf(org.unirevlab.security.model.ResourceTableSourceSummary(sourceArchive, parseErrors = 1)), parseErrors = 1)
        val root = header(bytes, 0)
        if (root.kind != RES_TABLE_TYPE || root.size > bytes.size || root.headerSize < 12) {
            return ResourceTableSummary(sources = listOf(org.unirevlab.security.model.ResourceTableSourceSummary(sourceArchive, parseErrors = 1)), parseErrors = 1)
        }
        var parseErrors = 0
        var truncated = false
        var chunks = 0
        var cursor = root.headerSize
        var globalPool: StringPool? = null
        val packages = mutableListOf<String>()
        val resolutions = mutableListOf<ResourceResolutionSummary>()

        while (cursor + 8 <= root.size && chunks < limits.maxChunks) {
            chunks++
            val h = try { header(bytes, cursor) } catch (_: Throwable) { parseErrors++; break }
            if (h.size < h.headerSize || h.size < 8 || cursor.toLong() + h.size > root.size.toLong()) {
                parseErrors++
                break
            }
            when (h.kind) {
                RES_STRING_POOL_TYPE -> if (globalPool == null) {
                    globalPool = runCatching { StringPool.parse(bytes, cursor, h, limits) }.getOrElse { parseErrors++; null }
                }
                RES_TABLE_PACKAGE_TYPE -> {
                    if (packages.size >= limits.maxPackages) {
                        truncated = true
                    } else {
                        val parsed = runCatching { parsePackage(bytes, cursor, h, globalPool, limits, resolutions.size, sourceArchive) }
                        parsed.onSuccess { pkg ->
                            packages += pkg.name
                            resolutions += pkg.entries
                            parseErrors += pkg.parseErrors
                            truncated = truncated || pkg.truncated
                        }.onFailure { parseErrors++ }
                    }
                }
            }
            cursor += h.size
            if (resolutions.size >= limits.maxEntries) { truncated = true; break }
        }
        if (chunks >= limits.maxChunks && cursor < root.size) truncated = true
        val orderedResolutions = resolutions.take(limits.maxEntries)
            .distinctBy { Triple(it.resourceId, it.sourceArchive, it.configurationSha256) }
            .sortedWith(compareBy<ResourceResolutionSummary>({ it.resourceId }, { it.sourceArchive }, { it.configurationSha256 ?: "" }))
        val chains = buildReferenceChains(orderedResolutions)
        val packageList = packages.distinct().sorted()
        return ResourceTableSummary(
            packages = packageList,
            resolutions = orderedResolutions,
            referenceChains = chains,
            sources = listOf(org.unirevlab.security.model.ResourceTableSourceSummary(
                sourceArchive = sourceArchive,
                packages = packageList,
                resolutionCount = orderedResolutions.size,
                configurationCount = orderedResolutions.mapNotNull { it.configurationSha256 }.distinct().size,
                parseErrors = parseErrors,
                truncated = truncated || chains.any { it.depthExceeded },
            )),
            parseErrors = parseErrors,
            truncated = truncated || chains.any { it.depthExceeded },
        )
    }

    fun resolveReference(summary: ResourceTableSummary?, reference: String?): ResourceResolutionSummary? {
        val id = parseReferenceId(reference) ?: return null
        val values = summary?.resolutions ?: return null
        val byId = values.groupBy { it.resourceId }
        val seen = mutableSetOf<Long>()
        var current = byId[id]?.sortedWith(resourceVariantOrder())?.firstOrNull() ?: return null
        repeat(MAX_REFERENCE_DEPTH) {
            if (!seen.add(current.resourceId)) return null
            if (current.dataType != TYPE_REFERENCE) return current
            current = chooseTargetVariant(byId[current.dataValue and 0xffff_ffffL].orEmpty(), current) ?: return null
        }
        return null
    }

    private fun buildReferenceChains(
        resolutions: List<ResourceResolutionSummary>,
        maxChains: Int = MAX_REFERENCE_CHAINS,
        maxDepth: Int = MAX_REFERENCE_DEPTH,
    ): List<ResourceReferenceChain> {
        val byId = resolutions.groupBy { it.resourceId }
        val roots = resolutions.filter { it.dataType == TYPE_REFERENCE }.take(maxChains)
        return roots.map { root ->
            val hops = mutableListOf<ResourceReferenceHop>()
            val seen = mutableSetOf<Long>()
            var current: ResourceResolutionSummary? = root
            var cycle = false
            var depthExceeded = false
            var unresolved = false
            var terminal: ResourceResolutionSummary? = null
            var ambiguous = false
            repeat(maxDepth) {
                val item = current ?: return@repeat
                if (!seen.add(item.resourceId)) { cycle = true; current = null; return@repeat }
                hops += ResourceReferenceHop(
                    resourceId = item.resourceId, dataType = item.dataType, dataValue = item.dataValue,
                    typeName = item.typeName, entryName = item.entryName, stringValue = item.stringValue, fileEntry = item.fileEntry,
                    sourceArchive = item.sourceArchive, configurationSha256 = item.configurationSha256,
                )
                if (item.dataType != TYPE_REFERENCE) { terminal = item; current = null; return@repeat }
                val candidates = byId[item.dataValue and 0xffff_ffffL].orEmpty()
                if (candidates.isEmpty()) { unresolved = true; current = null; return@repeat }
                if (candidates.size > 1) ambiguous = true
                current = chooseTargetVariant(candidates, item)
            }
            if (current != null && !cycle && !unresolved && terminal == null) depthExceeded = true
            ResourceReferenceChain(
                requestedResourceId = root.resourceId, hops = hops, terminalResourceId = terminal?.resourceId,
                terminalFileEntry = terminal?.fileEntry, cycleDetected = cycle, depthExceeded = depthExceeded, unresolved = unresolved,
                ambiguousVariant = ambiguous, sourceArchive = root.sourceArchive, configurationSha256 = root.configurationSha256,
            )
        }
    }

    fun merge(values: List<ResourceTableSummary>): ResourceTableSummary? {
        if (values.isEmpty()) return null
        val resolutions = values.flatMap { it.resolutions }
            .distinctBy { Triple(it.resourceId, it.sourceArchive, it.configurationSha256) }
            .sortedWith(compareBy<ResourceResolutionSummary>({ it.resourceId }, { it.sourceArchive }, { it.configurationSha256 ?: "" }))
        val chains = buildReferenceChains(resolutions)
        return ResourceTableSummary(
            packages = values.flatMap { it.packages }.distinct().sorted(),
            resolutions = resolutions,
            referenceChains = chains,
            sources = values.flatMap { it.sources }.distinctBy { it.sourceArchive }.sortedBy { it.sourceArchive },
            parseErrors = values.sumOf { it.parseErrors },
            truncated = values.any { it.truncated } || chains.any { it.depthExceeded },
        )
    }

    private fun resourceVariantOrder() = compareBy<ResourceResolutionSummary>(
        { if (it.sourceArchive == "base.apk") 0 else 1 },
        { if (it.configurationSha256 == null) 0 else 1 },
        { it.sourceArchive },
        { it.configurationSha256 ?: "" },
    )

    private fun chooseTargetVariant(candidates: List<ResourceResolutionSummary>, from: ResourceResolutionSummary): ResourceResolutionSummary? {
        if (candidates.isEmpty()) return null
        return candidates.firstOrNull { it.sourceArchive == from.sourceArchive && it.configurationSha256 == from.configurationSha256 }
            ?: candidates.firstOrNull { it.sourceArchive == from.sourceArchive }
            ?: candidates.sortedWith(resourceVariantOrder()).firstOrNull()
    }

    fun parseReferenceId(reference: String?): Long? {
        val raw = reference?.trim()?.removePrefix("@") ?: return null
        if (!raw.startsWith("0x", true)) return null
        return raw.substring(2).toLongOrNull(16)?.and(0xffff_ffffL)
    }

    private data class PackageResult(
        val name: String,
        val entries: List<ResourceResolutionSummary>,
        val parseErrors: Int,
        val truncated: Boolean,
    )

    private fun parsePackage(
        bytes: ByteArray,
        start: Int,
        h: Header,
        globalPool: StringPool?,
        limits: Limits,
        alreadyReported: Int,
        sourceArchive: String,
    ): PackageResult {
        require(h.headerSize >= 284 && start + h.headerSize <= bytes.size) { "Invalid resources package header" }
        val packageId = u32(bytes, start + 8)
        val packageName = readFixedUtf16(bytes, start + 12, 128)
        val typeStringsRel = u32(bytes, start + 268)
        val keyStringsRel = u32(bytes, start + 276)
        val typeIdOffset = if (h.headerSize >= 288) u32(bytes, start + 284) else 0
        val end = start + h.size
        var parseErrors = 0
        var truncated = false
        val typePool = runCatching {
            val offset = checkedRelative(start, typeStringsRel, end)
            val sh = header(bytes, offset)
            require(sh.kind == RES_STRING_POOL_TYPE)
            StringPool.parse(bytes, offset, sh, limits)
        }.getOrElse { parseErrors++; null }
        val keyPool = runCatching {
            val offset = checkedRelative(start, keyStringsRel, end)
            val sh = header(bytes, offset)
            require(sh.kind == RES_STRING_POOL_TYPE)
            StringPool.parse(bytes, offset, sh, limits)
        }.getOrElse { parseErrors++; null }

        val entries = mutableListOf<ResourceResolutionSummary>()
        var cursor = start + h.headerSize
        var chunks = 0
        while (cursor + 8 <= end && chunks < limits.maxChunks) {
            chunks++
            val ch = try { header(bytes, cursor) } catch (_: Throwable) { parseErrors++; break }
            if (ch.size < ch.headerSize || ch.size < 8 || cursor.toLong() + ch.size > end.toLong()) {
                parseErrors++
                break
            }
            if (ch.kind == RES_TABLE_TYPE_TYPE) {
                val remaining = limits.maxEntries - alreadyReported - entries.size
                if (remaining <= 0) { truncated = true; break }
                val typeEntries = runCatching {
                    parseTypeChunk(bytes, cursor, ch, packageId, typeIdOffset, packageName, typePool, keyPool, globalPool, remaining, sourceArchive)
                }
                typeEntries.onSuccess { result ->
                    entries += result.entries
                    truncated = truncated || result.truncated
                }.onFailure { parseErrors++ }
            }
            cursor += ch.size
        }
        return PackageResult(packageName, entries, parseErrors, truncated)
    }

    private data class TypeResult(val entries: List<ResourceResolutionSummary>, val truncated: Boolean)

    private fun parseTypeChunk(
        bytes: ByteArray,
        start: Int,
        h: Header,
        packageId: Int,
        typeIdOffset: Int,
        packageName: String,
        typePool: StringPool?,
        keyPool: StringPool?,
        globalPool: StringPool?,
        remaining: Int,
        sourceArchive: String,
    ): TypeResult {
        require(h.headerSize >= 20) { "Invalid type chunk header" }
        val rawTypeId = u8(bytes, start + 8)
        val flags = u8(bytes, start + 9)
        if (rawTypeId == 0) return TypeResult(emptyList(), false)
        val entryCount = u32(bytes, start + 12)
        val entriesStart = u32(bytes, start + 16)
        val configurationSha256 = if (h.headerSize > 20 && start + h.headerSize <= bytes.size) {
            MessageDigest.getInstance("SHA-256").digest(bytes.copyOfRange(start + 20, start + h.headerSize)).joinToString("") { "%02x".format(it) }
        } else null
        if (entryCount < 0 || entryCount > 2_000_000) return TypeResult(emptyList(), true)
        val offsetsBase = start + h.headerSize
        val chunkEnd = start + h.size
        val dataBase = checkedRelative(start, entriesStart, chunkEnd)
        val descriptors = ArrayList<Pair<Int, Int>>(minOf(entryCount, remaining))
        when {
            flags and FLAG_SPARSE != 0 -> {
                require(offsetsBase.toLong() + entryCount.toLong() * 4 <= chunkEnd.toLong()) { "Sparse offsets outside chunk" }
                repeat(entryCount) { i ->
                    val at = offsetsBase + i * 4
                    val index = u16(bytes, at)
                    val relUnits = u16(bytes, at + 2)
                    if (relUnits != NO_ENTRY16) descriptors += index to (relUnits * 4)
                }
            }
            flags and FLAG_OFFSET16 != 0 -> {
                require(offsetsBase.toLong() + entryCount.toLong() * 2 <= chunkEnd.toLong()) { "Offset16 table outside chunk" }
                repeat(entryCount) { index ->
                    val relUnits = u16(bytes, offsetsBase + index * 2)
                    if (relUnits != NO_ENTRY16) descriptors += index to (relUnits * 4)
                }
            }
            else -> {
                require(offsetsBase.toLong() + entryCount.toLong() * 4 <= chunkEnd.toLong()) { "Type offsets outside chunk" }
                repeat(entryCount) { index ->
                    val rel = u32(bytes, offsetsBase + index * 4)
                    if (rel != NO_ENTRY) descriptors += index to rel
                }
            }
        }
        val effectiveTypeId = rawTypeId + typeIdOffset
        val typeName = typePool?.optional(rawTypeId - 1)
        val out = mutableListOf<ResourceResolutionSummary>()
        var truncated = descriptors.size > remaining
        for ((index, rel) in descriptors.take(remaining)) {
            if (index !in 0..0xffff) continue
            val entry = dataBase.toLong() + rel.toLong()
            if (entry < dataBase || entry + 8 > chunkEnd.toLong()) continue
            val ep = entry.toInt()
            val entrySize = u16(bytes, ep)
            val entryFlags = u16(bytes, ep + 2)
            val keyIndex = u32(bytes, ep + 4)
            if (entrySize < 8 || ep + entrySize > chunkEnd) continue
            val resourceId = ((packageId.toLong() and 0xff) shl 24) or
                ((effectiveTypeId.toLong() and 0xff) shl 16) or (index.toLong() and 0xffff)
            if (entryFlags and ENTRY_FLAG_COMPLEX != 0) {
                if (entrySize < 16 || ep + 16 > chunkEnd) continue
                val parent = u32(bytes, ep + 8).toLong() and 0xffff_ffffL
                val count = u32(bytes, ep + 12)
                if (count < 0 || count > MAX_COMPLEX_MAPS || ep.toLong() + entrySize + count.toLong() * 12 > chunkEnd.toLong()) {
                    truncated = true
                    continue
                }
                out += ResourceResolutionSummary(
                    resourceId = resourceId, packageId = packageId, typeId = effectiveTypeId, entryId = index,
                    packageName = packageName.takeIf { it.isNotBlank() }, typeName = typeName,
                    entryName = keyPool?.optional(keyIndex), dataType = TYPE_NULL, dataValue = 0,
                    complex = true, parentResourceId = parent.takeIf { it != 0L }, mapEntryCount = count,
                    sourceArchive = sourceArchive, configurationSha256 = configurationSha256,
                )
                continue
            }
            val valueAt = ep + entrySize
            if (valueAt + 8 > chunkEnd) continue
            val valueSize = u16(bytes, valueAt)
            if (valueSize < 8) continue
            val dataType = u8(bytes, valueAt + 3)
            val data = u32(bytes, valueAt + 4).toLong() and 0xffff_ffffL
            val stringValue = if (dataType == TYPE_STRING) globalPool?.optional(data.toInt()) else null
            val fileEntry = stringValue?.takeIf { it.startsWith("res/") }
            out += ResourceResolutionSummary(
                resourceId = resourceId, packageId = packageId, typeId = effectiveTypeId, entryId = index,
                packageName = packageName.takeIf { it.isNotBlank() }, typeName = typeName,
                entryName = keyPool?.optional(keyIndex), dataType = dataType, dataValue = data,
                stringValue = stringValue, fileEntry = fileEntry,
                sourceArchive = sourceArchive, configurationSha256 = configurationSha256,
            )
        }
        return TypeResult(out, truncated)
    }

    private data class Header(val kind: Int, val headerSize: Int, val size: Int)
    private fun header(bytes: ByteArray, offset: Int): Header {
        require(offset >= 0 && offset + 8 <= bytes.size)
        return Header(u16(bytes, offset), u16(bytes, offset + 2), u32(bytes, offset + 4))
    }

    private class StringPool(private val values: List<String>) {
        fun optional(index: Int): String? = values.getOrNull(index)

        companion object {
            fun parse(bytes: ByteArray, start: Int, h: Header, limits: Limits): StringPool {
                require(h.headerSize >= 28 && start + h.size <= bytes.size)
                val count = u32(bytes, start + 8)
                val flags = u32(bytes, start + 16)
                val stringsStart = u32(bytes, start + 20)
                require(count in 0..limits.maxStrings)
                val offsets = start + h.headerSize
                require(offsets.toLong() + count.toLong() * 4 <= start.toLong() + h.size)
                val utf8 = flags and UTF8_FLAG != 0
                val out = ArrayList<String>(count)
                repeat(count) { i ->
                    val rel = u32(bytes, offsets + i * 4)
                    val pos = checkedRelative(start, stringsStart + rel, start + h.size)
                    out += if (utf8) readUtf8(bytes, pos, start + h.size, limits.maxStringBytes)
                    else readUtf16(bytes, pos, start + h.size, limits.maxStringBytes)
                }
                return StringPool(out)
            }
        }
    }

    private fun readUtf8(bytes: ByteArray, start: Int, end: Int, max: Int): String {
        var p = start
        val (_, p1) = len8(bytes, p, end); p = p1
        val (size, p2) = len8(bytes, p, end); p = p2
        require(size <= max && p + size <= end)
        val decoder = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        return decoder.decode(java.nio.ByteBuffer.wrap(bytes, p, size)).toString()
    }

    private fun readUtf16(bytes: ByteArray, start: Int, end: Int, max: Int): String {
        val (units, p) = len16(bytes, start, end)
        val size = units * 2
        require(size <= max && p + size <= end)
        return bytes.copyOfRange(p, p + size).toString(Charsets.UTF_16LE)
    }

    private fun len8(b: ByteArray, p: Int, end: Int): Pair<Int, Int> {
        require(p < end); val a = u8(b, p)
        return if (a and 0x80 == 0) a to (p + 1) else { require(p + 1 < end); (((a and 0x7f) shl 8) or u8(b, p + 1)) to (p + 2) }
    }

    private fun len16(b: ByteArray, p: Int, end: Int): Pair<Int, Int> {
        require(p + 2 <= end); val a = u16(b, p)
        return if (a and 0x8000 == 0) a to (p + 2) else { require(p + 4 <= end); (((a and 0x7fff) shl 16) or u16(b, p + 2)) to (p + 4) }
    }

    private fun readFixedUtf16(bytes: ByteArray, start: Int, maxUnits: Int): String {
        val out = StringBuilder()
        repeat(maxUnits) { i ->
            val code = u16(bytes, start + i * 2)
            if (code == 0) return out.toString()
            out.append(code.toChar())
        }
        return out.toString()
    }

    private fun checkedRelative(base: Int, relative: Int, end: Int): Int {
        val value = base.toLong() + relative.toLong()
        require(value >= base && value < end)
        return value.toInt()
    }

    private fun readBounded(input: java.io.InputStream, maxBytes: Int): ByteArray {
        val out = ByteArrayOutputStream(minOf(maxBytes, 1024 * 1024))
        val buffer = ByteArray(64 * 1024)
        var total = 0
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            total += n
            require(total <= maxBytes)
            out.write(buffer, 0, n)
        }
        return out.toByteArray()
    }

    private fun u8(b: ByteArray, o: Int): Int { require(o in b.indices); return b[o].toInt() and 0xff }
    private fun u16(b: ByteArray, o: Int): Int { require(o >= 0 && o + 2 <= b.size); return u8(b, o) or (u8(b, o + 1) shl 8) }
    private fun u32(b: ByteArray, o: Int): Int { require(o >= 0 && o + 4 <= b.size); return u8(b, o) or (u8(b, o + 1) shl 8) or (u8(b, o + 2) shl 16) or (u8(b, o + 3) shl 24) }

    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_TABLE_TYPE = 0x0002
    private const val RES_TABLE_PACKAGE_TYPE = 0x0200
    private const val RES_TABLE_TYPE_TYPE = 0x0201
    private const val UTF8_FLAG = 0x00000100
    private const val FLAG_SPARSE = 0x01
    private const val FLAG_OFFSET16 = 0x02
    private const val ENTRY_FLAG_COMPLEX = 0x0001
    private const val TYPE_NULL = 0x00
    private const val TYPE_REFERENCE = 0x01
    private const val TYPE_STRING = 0x03
    private const val NO_ENTRY = -1
    private const val NO_ENTRY16 = 0xffff
    private const val MAX_COMPLEX_MAPS = 65_536
    private const val MAX_REFERENCE_DEPTH = 16
    private const val MAX_REFERENCE_CHAINS = 4_096
}
