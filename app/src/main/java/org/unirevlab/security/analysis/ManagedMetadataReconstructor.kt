package org.unirevlab.security.analysis

import org.unirevlab.security.model.ManagedAssemblyReferenceSummary
import org.unirevlab.security.model.ManagedMemberReferenceSummary
import org.unirevlab.security.model.ManagedMetadataStreamSummary
import org.unirevlab.security.model.ManagedMetadataTableSummary
import org.unirevlab.security.model.ManagedMethodDefinitionSummary
import org.unirevlab.security.model.ManagedTypeDefinitionSummary
import org.unirevlab.security.model.ManagedTypeReferenceSummary
import java.nio.charset.StandardCharsets

/**
 * Bounded ECMA-335 metadata-table reconstruction.
 *
 * It parses metadata as data only. Method bodies are not executed and signature blobs are not
 * interpreted in this stage; their heap indexes are retained for later analysis.
 */
object ManagedMetadataReconstructor {
    data class Limits(
        val maxTypeRefs: Int = 20_000,
        val maxTypeDefs: Int = 20_000,
        val maxMethodDefs: Int = 60_000,
        val maxMemberRefs: Int = 60_000,
        val maxAssemblyRefs: Int = 4_000,
        val maxStringBytes: Int = 16 * 1024,
    )

    data class Result(
        val tables: List<ManagedMetadataTableSummary>,
        val assemblyName: String?,
        val assemblyVersion: String?,
        val typeReferences: List<ManagedTypeReferenceSummary>,
        val typeDefinitions: List<ManagedTypeDefinitionSummary>,
        val methodDefinitions: List<ManagedMethodDefinitionSummary>,
        val memberReferences: List<ManagedMemberReferenceSummary>,
        val assemblyReferences: List<ManagedAssemblyReferenceSummary>,
        val truncated: Boolean,
    )

    fun reconstruct(
        bytes: ByteArray,
        metadataRoot: Int,
        metadataSize: Long,
        streams: List<ManagedMetadataStreamSummary>,
        limits: Limits = Limits(),
    ): Result {
        val tablesStream = streams.firstOrNull { it.name == "#~" || it.name == "#-" }
            ?: return Result(emptyList(), null, null, emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), false)
        val stringsStream = streams.firstOrNull { it.name == "#Strings" }

        val start = checkedOffset(metadataRoot, tablesStream.offset, bytes.size, "tables stream")
        val end = checkedEnd(start, tablesStream.sizeBytes, bytes.size, "tables stream")
        require(start + 24 <= end) { "CLI tables stream header is truncated" }

        val heapSizes = u8(bytes, start + 6)
        val valid = u64le(bytes, start + 8)
        val rowCounts = LongArray(64)
        var cursor = start + 24
        val tableSummaries = mutableListOf<ManagedMetadataTableSummary>()
        for (tableId in 0 until 64) {
            if (((valid ushr tableId) and 1L) == 0L) continue
            require(cursor + 4 <= end) { "CLI table row-count directory is truncated" }
            val rows = u32le(bytes, cursor)
            rowCounts[tableId] = rows
            TABLE_NAMES[tableId]?.let { tableSummaries += ManagedMetadataTableSummary(tableId, it, rows) }
            cursor += 4
        }

        val dataOffsets = LongArray(64) { -1L }
        var dataCursor = cursor.toLong()
        for (tableId in 0 until 64) {
            val rows = rowCounts[tableId]
            if (rows == 0L) continue
            val rowSize = rowSize(tableId, rowCounts, heapSizes)
            require(rowSize > 0) { "unsupported ECMA-335 metadata table $tableId" }
            dataOffsets[tableId] = dataCursor
            val bytesForTable = checkedMul(rows, rowSize.toLong())
            require(dataCursor <= end.toLong() && bytesForTable <= end.toLong() - dataCursor) {
                "CLI metadata table ${TABLE_NAMES[tableId] ?: tableId} exceeds #~ stream"
            }
            dataCursor += bytesForTable
        }

        val strings = StringsHeap(bytes, metadataRoot, metadataSize, stringsStream, limits.maxStringBytes)
        var truncated = false

        val typeRefs = mutableListOf<ManagedTypeReferenceSummary>()
        val typeRefRows = rowCounts[1]
        val typeRefLimit = minOf(typeRefRows, limits.maxTypeRefs.toLong()).toInt()
        if (typeRefRows > typeRefLimit) truncated = true
        repeat(typeRefLimit) { zeroIndex ->
            val reader = RowReader(bytes, dataOffsets[1] + zeroIndex.toLong() * rowSize(1, rowCounts, heapSizes), heapSizes, rowCounts)
            val scope = reader.coded(RESOLUTION_SCOPE)
            val name = strings.get(reader.stringIndex())
            val namespace = strings.get(reader.stringIndex())
            typeRefs += ManagedTypeReferenceSummary(
                index = zeroIndex + 1,
                namespace = namespace,
                name = name,
                fullName = fullName(namespace, name),
                resolutionScopeToken = scope,
            )
        }

        data class RawTypeDef(
            val index: Int, val namespace: String, val name: String, val flags: Long, val extends: Long?,
            val fieldStart: Int, val methodStart: Int,
        )
        val rawTypes = mutableListOf<RawTypeDef>()
        val typeRows = rowCounts[2]
        val typeLimit = minOf(typeRows, limits.maxTypeDefs.toLong()).toInt()
        if (typeRows > typeLimit) truncated = true
        repeat(typeLimit) { zeroIndex ->
            val reader = RowReader(bytes, dataOffsets[2] + zeroIndex.toLong() * rowSize(2, rowCounts, heapSizes), heapSizes, rowCounts)
            val flags = reader.u32()
            val name = strings.get(reader.stringIndex())
            val namespace = strings.get(reader.stringIndex())
            val extends = reader.coded(TYPE_DEF_OR_REF)
            val fieldStart = reader.tableIndex(4).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            val methodStart = reader.tableIndex(6).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            rawTypes += RawTypeDef(zeroIndex + 1, namespace, name, flags, extends, fieldStart, methodStart)
        }
        val typeDefs = rawTypes.mapIndexed { i, t ->
            val nextField = rawTypes.getOrNull(i + 1)?.fieldStart ?: (rowCounts[4] + 1).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            val nextMethod = rawTypes.getOrNull(i + 1)?.methodStart ?: (rowCounts[6] + 1).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            ManagedTypeDefinitionSummary(
                index = t.index,
                namespace = t.namespace,
                name = t.name,
                fullName = fullName(t.namespace, t.name),
                flags = t.flags,
                extendsToken = t.extends,
                fieldStart = t.fieldStart,
                fieldCount = (nextField - t.fieldStart).coerceAtLeast(0),
                methodStart = t.methodStart,
                methodCount = (nextMethod - t.methodStart).coerceAtLeast(0),
            )
        }

        fun declaringTypeForMethod(methodIndex1: Int): String {
            val owner = typeDefs.lastOrNull { it.methodStart in 1..methodIndex1 }
                ?.takeIf { methodIndex1 < it.methodStart + it.methodCount }
            return owner?.fullName ?: "<global>"
        }

        val methodDefs = mutableListOf<ManagedMethodDefinitionSummary>()
        val methodRows = rowCounts[6]
        val methodLimit = minOf(methodRows, limits.maxMethodDefs.toLong()).toInt()
        if (methodRows > methodLimit) truncated = true
        repeat(methodLimit) { zeroIndex ->
            val reader = RowReader(bytes, dataOffsets[6] + zeroIndex.toLong() * rowSize(6, rowCounts, heapSizes), heapSizes, rowCounts)
            val rva = reader.u32()
            val implFlags = reader.u16()
            val flags = reader.u16()
            val name = strings.get(reader.stringIndex())
            val signature = reader.blobIndex()
            val paramStart = reader.tableIndex(8).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            val index = zeroIndex + 1
            methodDefs += ManagedMethodDefinitionSummary(index, declaringTypeForMethod(index), rva, implFlags, flags, name, signature, paramStart)
        }

        val memberRefs = mutableListOf<ManagedMemberReferenceSummary>()
        val memberRows = rowCounts[10]
        val memberLimit = minOf(memberRows, limits.maxMemberRefs.toLong()).toInt()
        if (memberRows > memberLimit) truncated = true
        repeat(memberLimit) { zeroIndex ->
            val reader = RowReader(bytes, dataOffsets[10] + zeroIndex.toLong() * rowSize(10, rowCounts, heapSizes), heapSizes, rowCounts)
            val parent = reader.coded(MEMBER_REF_PARENT)
            val name = strings.get(reader.stringIndex())
            val signature = reader.blobIndex()
            memberRefs += ManagedMemberReferenceSummary(zeroIndex + 1, parent, name, signature)
        }

        var assemblyName: String? = null
        var assemblyVersion: String? = null
        if (rowCounts[32] > 0) {
            val reader = RowReader(bytes, dataOffsets[32], heapSizes, rowCounts)
            reader.u32() // HashAlgId
            val major = reader.u16(); val minor = reader.u16(); val build = reader.u16(); val revision = reader.u16()
            reader.u32() // flags
            reader.blobIndex()
            assemblyName = strings.get(reader.stringIndex()).ifBlank { null }
            reader.stringIndex() // culture
            assemblyVersion = "$major.$minor.$build.$revision"
        }

        val assemblyRefs = mutableListOf<ManagedAssemblyReferenceSummary>()
        val assemblyRefRows = rowCounts[35]
        val assemblyRefLimit = minOf(assemblyRefRows, limits.maxAssemblyRefs.toLong()).toInt()
        if (assemblyRefRows > assemblyRefLimit) truncated = true
        repeat(assemblyRefLimit) { zeroIndex ->
            val reader = RowReader(bytes, dataOffsets[35] + zeroIndex.toLong() * rowSize(35, rowCounts, heapSizes), heapSizes, rowCounts)
            val major = reader.u16(); val minor = reader.u16(); val build = reader.u16(); val revision = reader.u16()
            val flags = reader.u32()
            reader.blobIndex()
            val name = strings.get(reader.stringIndex())
            val culture = strings.get(reader.stringIndex()).ifBlank { null }
            reader.blobIndex()
            assemblyRefs += ManagedAssemblyReferenceSummary(zeroIndex + 1, name, "$major.$minor.$build.$revision", culture, flags)
        }

        return Result(tableSummaries, assemblyName, assemblyVersion, typeRefs, typeDefs, methodDefs, memberRefs, assemblyRefs, truncated)
    }

    private class StringsHeap(
        private val bytes: ByteArray,
        metadataRoot: Int,
        metadataSize: Long,
        stream: ManagedMetadataStreamSummary?,
        private val maxStringBytes: Int,
    ) {
        private val start: Int
        private val size: Int
        init {
            if (stream == null) { start = 0; size = 0 }
            else {
                start = checkedOffset(metadataRoot, stream.offset, bytes.size, "#Strings")
                val end = checkedEnd(start, stream.sizeBytes, bytes.size, "#Strings")
                require(end.toLong() <= metadataRoot.toLong() + metadataSize) { "#Strings exceeds metadata root" }
                size = end - start
            }
        }
        fun get(index: Long): String {
            if (index <= 0 || index >= size) return ""
            val absolute = start + index.toInt()
            val endLimit = minOf(start + size, absolute + maxStringBytes)
            var end = absolute
            while (end < endLimit && bytes[end] != 0.toByte()) end++
            if (end == endLimit && end < start + size) return ""
            return bytes.copyOfRange(absolute, end).toString(StandardCharsets.UTF_8).take(1024)
        }
    }

    private class RowReader(
        private val bytes: ByteArray,
        start: Long,
        private val heapSizes: Int,
        private val rowCounts: LongArray,
    ) {
        private var cursor = start.toInt()
        fun u16(): Int = read(2).toInt()
        fun u32(): Long = read(4)
        fun stringIndex(): Long = read(if ((heapSizes and 0x01) != 0) 4 else 2)
        fun guidIndex(): Long = read(if ((heapSizes and 0x02) != 0) 4 else 2)
        fun blobIndex(): Long = read(if ((heapSizes and 0x04) != 0) 4 else 2)
        fun tableIndex(table: Int): Long = read(tableIndexSize(table, rowCounts))
        fun coded(coded: CodedIndex): Long? {
            val raw = read(codedIndexSize(coded, rowCounts))
            if (raw == 0L) return null
            val tagMask = (1L shl coded.tagBits) - 1
            val tag = (raw and tagMask).toInt()
            val row = raw ushr coded.tagBits
            val table = coded.tables.getOrNull(tag) ?: return null
            if (table < 0 || row == 0L) return null
            return (table.toLong() shl 24) or row
        }
        private fun read(width: Int): Long {
            require(width == 2 || width == 4)
            require(cursor >= 0 && cursor + width <= bytes.size) { "CLI metadata row is truncated" }
            val out = if (width == 2) u16le(bytes, cursor).toLong() else u32le(bytes, cursor)
            cursor += width
            return out
        }
    }

    private data class CodedIndex(val tagBits: Int, val tables: IntArray)
    private val TYPE_DEF_OR_REF = CodedIndex(2, intArrayOf(2, 1, 27, -1))
    private val RESOLUTION_SCOPE = CodedIndex(2, intArrayOf(0, 26, 35, 1))
    private val MEMBER_REF_PARENT = CodedIndex(3, intArrayOf(2, 1, 26, 6, 27, -1, -1, -1))
    private val HAS_CONSTANT = CodedIndex(2, intArrayOf(4, 8, 23, -1))
    private val HAS_CUSTOM_ATTRIBUTE = CodedIndex(5, intArrayOf(6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1))
    private val CUSTOM_ATTRIBUTE_TYPE = CodedIndex(3, intArrayOf(-1, -1, 6, 10, -1, -1, -1, -1))
    private val HAS_FIELD_MARSHAL = CodedIndex(1, intArrayOf(4,8))
    private val HAS_DECL_SECURITY = CodedIndex(2, intArrayOf(2,6,32,-1))
    private val HAS_SEMANTICS = CodedIndex(1, intArrayOf(20,23))
    private val METHOD_DEF_OR_REF = CodedIndex(1, intArrayOf(6,10))
    private val MEMBER_FORWARDED = CodedIndex(1, intArrayOf(4,6))
    private val IMPLEMENTATION = CodedIndex(2, intArrayOf(38,35,39,-1))
    private val TYPE_OR_METHOD_DEF = CodedIndex(1, intArrayOf(2,6))

    private fun rowSize(id: Int, rows: LongArray, heaps: Int): Int {
        val str = if ((heaps and 0x01) != 0) 4 else 2
        val guid = if ((heaps and 0x02) != 0) 4 else 2
        val blob = if ((heaps and 0x04) != 0) 4 else 2
        fun t(i: Int) = tableIndexSize(i, rows)
        fun c(x: CodedIndex) = codedIndexSize(x, rows)
        return when (id) {
            0 -> 2 + str + guid * 3
            1 -> c(RESOLUTION_SCOPE) + str * 2
            2 -> 4 + str * 2 + c(TYPE_DEF_OR_REF) + t(4) + t(6)
            3 -> t(4)
            4 -> 2 + str + blob
            5 -> t(6)
            6 -> 4 + 2 + 2 + str + blob + t(8)
            7 -> t(8)
            8 -> 2 + 2 + str
            9 -> t(2) + c(TYPE_DEF_OR_REF)
            10 -> c(MEMBER_REF_PARENT) + str + blob
            11 -> 2 + c(HAS_CONSTANT) + blob
            12 -> c(HAS_CUSTOM_ATTRIBUTE) + c(CUSTOM_ATTRIBUTE_TYPE) + blob
            13 -> c(HAS_FIELD_MARSHAL) + blob
            14 -> 2 + c(HAS_DECL_SECURITY) + blob
            15 -> 2 + 4 + t(2)
            16 -> 4 + t(4)
            17 -> blob
            18 -> t(2) + t(20)
            19 -> t(20)
            20 -> 2 + str + c(TYPE_DEF_OR_REF)
            21 -> t(2) + t(23)
            22 -> t(23)
            23 -> 2 + str + blob
            24 -> 2 + t(6) + c(HAS_SEMANTICS)
            25 -> t(2) + c(METHOD_DEF_OR_REF) * 2
            26 -> str
            27 -> blob
            28 -> 2 + c(MEMBER_FORWARDED) + str + t(26)
            29 -> 4 + t(4)
            30 -> 8
            31 -> 4
            32 -> 4 + 2*4 + 4 + blob + str*2
            33 -> 4
            34 -> 12
            35 -> 2*4 + 4 + blob + str*2 + blob
            36 -> 4 + t(35)
            37 -> 12 + t(35)
            38 -> 4 + str + blob
            39 -> 4 + 4 + str*2 + c(IMPLEMENTATION)
            40 -> 4 + 4 + str + c(IMPLEMENTATION)
            41 -> t(2) * 2
            42 -> 2 + 2 + c(TYPE_OR_METHOD_DEF) + str
            43 -> c(METHOD_DEF_OR_REF) + blob
            44 -> t(42) + c(TYPE_DEF_OR_REF)
            else -> 0
        }
    }

    private fun tableIndexSize(table: Int, rows: LongArray): Int = if (rows.getOrElse(table) { 0 } < 0x10000L) 2 else 4
    private fun codedIndexSize(coded: CodedIndex, rows: LongArray): Int {
        val maxRows = coded.tables.filter { it >= 0 }.maxOfOrNull { rows.getOrElse(it) { 0 } } ?: 0
        return if (maxRows < (1L shl (16 - coded.tagBits))) 2 else 4
    }

    private fun fullName(namespace: String, name: String): String = if (namespace.isBlank()) name else "$namespace.$name"
    private fun checkedOffset(base: Int, relative: Long, bound: Int, label: String): Int {
        require(relative >= 0 && relative <= Int.MAX_VALUE)
        val out = base.toLong() + relative
        require(out in 0 until bound.toLong()) { "$label offset is out of bounds" }
        return out.toInt()
    }
    private fun checkedEnd(start: Int, size: Long, bound: Int, label: String): Int {
        require(size >= 0 && size <= Int.MAX_VALUE)
        val end = start.toLong() + size
        require(end in start.toLong()..bound.toLong()) { "$label range is out of bounds" }
        return end.toInt()
    }
    private fun checkedMul(a: Long, b: Long): Long {
        require(a >= 0 && b >= 0 && (a == 0L || b <= Long.MAX_VALUE / a)) { "metadata size overflow" }
        return a * b
    }
    private fun u8(bytes: ByteArray, off: Int) = bytes[off].toInt() and 0xff
    private fun u16le(bytes: ByteArray, off: Int): Int {
        require(off >= 0 && off + 2 <= bytes.size)
        return (bytes[off].toInt() and 0xff) or ((bytes[off+1].toInt() and 0xff) shl 8)
    }
    private fun u32le(bytes: ByteArray, off: Int): Long {
        require(off >= 0 && off + 4 <= bytes.size)
        return (bytes[off].toLong() and 0xff) or ((bytes[off+1].toLong() and 0xff) shl 8) or
            ((bytes[off+2].toLong() and 0xff) shl 16) or ((bytes[off+3].toLong() and 0xff) shl 24)
    }
    private fun u64le(bytes: ByteArray, off: Int): Long {
        val lo = u32le(bytes, off)
        val hi = u32le(bytes, off+4)
        return lo or (hi shl 32)
    }

    private val TABLE_NAMES = mapOf(
        0 to "Module", 1 to "TypeRef", 2 to "TypeDef", 3 to "FieldPtr", 4 to "Field", 5 to "MethodPtr",
        6 to "MethodDef", 7 to "ParamPtr", 8 to "Param", 9 to "InterfaceImpl", 10 to "MemberRef",
        11 to "Constant", 12 to "CustomAttribute", 13 to "FieldMarshal", 14 to "DeclSecurity", 15 to "ClassLayout",
        16 to "FieldLayout", 17 to "StandAloneSig", 18 to "EventMap", 19 to "EventPtr", 20 to "Event",
        21 to "PropertyMap", 22 to "PropertyPtr", 23 to "Property", 24 to "MethodSemantics", 25 to "MethodImpl",
        26 to "ModuleRef", 27 to "TypeSpec", 28 to "ImplMap", 29 to "FieldRVA", 30 to "ENCLog", 31 to "ENCMap",
        32 to "Assembly", 33 to "AssemblyProcessor", 34 to "AssemblyOS", 35 to "AssemblyRef", 36 to "AssemblyRefProcessor",
        37 to "AssemblyRefOS", 38 to "File", 39 to "ExportedType", 40 to "ManifestResource", 41 to "NestedClass",
        42 to "GenericParam", 43 to "MethodSpec", 44 to "GenericParamConstraint",
    )
}
