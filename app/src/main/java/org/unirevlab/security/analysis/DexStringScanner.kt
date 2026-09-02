package org.unirevlab.security.analysis

import org.unirevlab.security.model.DexClassReference
import org.unirevlab.security.model.DexFieldReference
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.DexNativeMethodDeclaration
import org.unirevlab.security.model.DexStringReference
import org.unirevlab.security.model.SecretCandidate
import java.io.File
import java.io.InterruptedIOException
import java.io.RandomAccessFile

/**
 * Bounded DEX indexer for static inventory. It never loads classes or executes target bytecode.
 * The parser validates top-level tables before resolving strings/types/classes/methods.
 */
object DexStringScanner {
    data class Limits(
        val maxDexBytes: Long = 96L * 1024L * 1024L,
        val maxStrings: Int = 300_000,
        val maxStringBytes: Int = 64 * 1024,
        val maxTypes: Int = 100_000,
        val maxClasses: Int = 50_000,
        val maxMethods: Int = 150_000,
        val maxFields: Int = 150_000,
        val maxReportedClasses: Int = 4_000,
        val maxReportedMethods: Int = 8_000,
        val maxReportedFields: Int = 24_000,
        val maxNativeMethods: Int = 4_000,
        val maxEncodedMembersPerClass: Int = 100_000,
        val maxProtoParameters: Int = 512,
        val maxUrls: Int = 300,
        val maxSecretCandidates: Int = 100,
    )

    data class CodeLocation(
        val methodIndex: Int,
        val codeOffset: Long,
    )

    /**
     * Reusable structural state for DexCodeScanner. It is emitted only when every method_id and
     * class_def was indexed, so the code scanner can fail closed to its original full pass whenever
     * defensive limits prevent complete reuse.
     */
    data class StructuralIndex(
        val methodsByIndex: List<DexMethodReference?>,
        val codeLocationsInClassOrder: List<CodeLocation>,
    )

    data class FileResult(
        val stringsDeclared: Int,
        val stringsScanned: Int,
        val typesDeclared: Int,
        val typesIndexed: Int,
        val classesDeclared: Int,
        val classesIndexed: Int,
        val methodsDeclared: Int,
        val methodsIndexed: Int,
        val fieldsDeclared: Int = 0,
        val fieldsIndexed: Int = 0,
        val fields: List<DexFieldReference> = emptyList(),
        val classes: List<DexClassReference>,
        val methods: List<DexMethodReference>,
        val nativeMethods: List<DexNativeMethodDeclaration>,
        val httpUrls: List<DexStringReference>,
        val httpsUrls: List<DexStringReference>,
        val secretCandidates: List<SecretCandidate>,
        val structuralIndex: StructuralIndex? = null,
        val truncated: Boolean,
    )

    class DexFormatException(message: String) : Exception(message)

    private data class Header(
        val fileSize: Long,
        val stringIdsSize: Int,
        val stringIdsOff: Long,
        val typeIdsSize: Int,
        val typeIdsOff: Long,
        val protoIdsSize: Int,
        val protoIdsOff: Long,
        val fieldIdsSize: Int,
        val fieldIdsOff: Long,
        val methodIdsSize: Int,
        val methodIdsOff: Long,
        val classDefsSize: Int,
        val classDefsOff: Long,
    )

    fun scan(
        dexEntry: String,
        file: File,
        limits: Limits = Limits(),
        onProgress: ((percent: Int, detail: String, completed: Int, total: Int) -> Unit)? = null,
    ): FileResult {
        require(file.length() <= limits.maxDexBytes) { "DEX exceeds ${limits.maxDexBytes} byte limit" }
        checkCancelled()
        onProgress?.invoke(0, "Читаем DEX header", 0, 1)
        RandomAccessFile(file, "r").use { raf ->
            val h = readHeader(raf)
            var truncated = false

            val toScanStrings = minOf(h.stringIdsSize, limits.maxStrings)
            if (h.stringIdsSize > toScanStrings) truncated = true
            val httpUrls = mutableListOf<DexStringReference>()
            val httpsUrls = mutableListOf<DexStringReference>()
            val secrets = mutableListOf<SecretCandidate>()
            var stringsScanned = 0

            for (index in 0 until toScanStrings) {
                if ((index and 0xff) == 0) {
                    checkCancelled()
                    onProgress?.invoke(scaleProgress(0, 35, index, toScanStrings), "Строки DEX", index, toScanStrings)
                }
                val decoded = readStringByIndex(raf, h, index, limits.maxStringBytes)
                if (decoded.truncated) truncated = true
                stringsScanned++
                if (decoded.value.indexOf("http", ignoreCase = true) >= 0) {
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
                SensitiveStringClassifier.detectKind(decoded.value)?.let { kind ->
                    if (secrets.size < limits.maxSecretCandidates) {
                        secrets += SecretCandidate(
                            kind = kind,
                            dexEntry = dexEntry,
                            stringIndex = index,
                            valueSha256 = SensitiveStringClassifier.sha256(decoded.value),
                            redactedPreview = SensitiveStringClassifier.redacted(decoded.value),
                        )
                    } else truncated = true
                }
            }

            checkCancelled()
            onProgress?.invoke(35, "Строки DEX готовы", toScanStrings, toScanStrings)

            val toIndexTypes = minOf(h.typeIdsSize, limits.maxTypes)
            if (h.typeIdsSize > toIndexTypes) truncated = true
            var typesIndexed = 0
            repeat(toIndexTypes) { typeIndex ->
                if ((typeIndex and 0xff) == 0) {
                    checkCancelled()
                    onProgress?.invoke(scaleProgress(35, 45, typeIndex, toIndexTypes), "Типы DEX", typeIndex, toIndexTypes)
                }
                typeDescriptor(raf, h, typeIndex, limits.maxStringBytes)
                typesIndexed++
            }
            onProgress?.invoke(45, "Типы DEX готовы", toIndexTypes, toIndexTypes)

            val fields = mutableListOf<DexFieldReference>()
            val toIndexFields = minOf(h.fieldIdsSize, limits.maxFields)
            if (h.fieldIdsSize > toIndexFields) truncated = true
            repeat(toIndexFields) { fieldIndex ->
                if ((fieldIndex and 0xff) == 0) {
                    checkCancelled()
                    onProgress?.invoke(scaleProgress(45, 53, fieldIndex, toIndexFields), "Поля DEX", fieldIndex, toIndexFields)
                }
                val field = readField(raf, h, dexEntry, fieldIndex, limits)
                if (fields.size < limits.maxReportedFields) fields += field else truncated = true
            }
            onProgress?.invoke(53, "Поля DEX готовы", toIndexFields, toIndexFields)

            val methods = mutableListOf<DexMethodReference>()
            val methodLookup = HashMap<Int, DexMethodReference>()
            val toIndexMethods = minOf(h.methodIdsSize, limits.maxMethods)
            val methodsByIndex = arrayOfNulls<DexMethodReference>(toIndexMethods)
            val codeLocations = ArrayList<CodeLocation>()
            if (h.methodIdsSize > toIndexMethods) truncated = true
            repeat(toIndexMethods) { methodIndex ->
                if ((methodIndex and 0xff) == 0) {
                    checkCancelled()
                    onProgress?.invoke(scaleProgress(53, 68, methodIndex, toIndexMethods), "Методы DEX", methodIndex, toIndexMethods)
                }
                val method = readMethod(raf, h, dexEntry, methodIndex, limits)
                methodLookup[methodIndex] = method
                methodsByIndex[methodIndex] = method
                if (methods.size < limits.maxReportedMethods) methods += method else truncated = true
            }

            onProgress?.invoke(68, "Методы DEX готовы", toIndexMethods, toIndexMethods)
            val classes = mutableListOf<DexClassReference>()
            val nativeMethods = mutableListOf<DexNativeMethodDeclaration>()
            val toIndexClasses = minOf(h.classDefsSize, limits.maxClasses)
            if (h.classDefsSize > toIndexClasses) truncated = true
            repeat(toIndexClasses) { classDefIndex ->
                if ((classDefIndex and 0x7f) == 0) {
                    checkCancelled()
                    onProgress?.invoke(scaleProgress(68, 100, classDefIndex, toIndexClasses), "Классы и class_data", classDefIndex, toIndexClasses)
                }
                val base = h.classDefsOff + classDefIndex.toLong() * 32L
                val classIdx = readU32(raf, base).toIntChecked("class_idx")
                val accessFlags = readU32(raf, base + 4)
                val superIdxLong = readU32(raf, base + 8)
                val interfacesOff = readU32(raf, base + 12)
                val sourceFileIdxLong = readU32(raf, base + 16)
                val classDataOff = readU32(raf, base + 24)
                if (classIdx !in 0 until h.typeIdsSize) throw DexFormatException("class_idx outside type_ids")
                val descriptor = typeDescriptor(raf, h, classIdx, limits.maxStringBytes)
                val superDescriptor = if (superIdxLong == NO_INDEX) null else {
                    val superIdx = superIdxLong.toIntChecked("superclass_idx")
                    if (superIdx !in 0 until h.typeIdsSize) throw DexFormatException("superclass_idx outside type_ids")
                    typeDescriptor(raf, h, superIdx, limits.maxStringBytes)
                }
                val interfaces = if (interfacesOff == 0L) {
                    emptyList()
                } else {
                    ensureRange(interfacesOff, 4, h.fileSize, "class interfaces type_list")
                    val countLong = readU32(raf, interfacesOff)
                    if (countLong > limits.maxProtoParameters) throw DexFormatException("class interface count exceeds limit")
                    ensureRange(interfacesOff + 4, countLong.checkedMul(2), h.fileSize, "class interfaces")
                    buildList {
                        repeat(countLong.toInt()) { interfaceIndex ->
                            val typeIdx = readU16(raf, interfacesOff + 4 + interfaceIndex.toLong() * 2L)
                            if (typeIdx !in 0 until h.typeIdsSize) throw DexFormatException("interface type_idx outside type_ids")
                            add(typeDescriptor(raf, h, typeIdx, limits.maxStringBytes))
                        }
                    }
                }
                val sourceFile = if (sourceFileIdxLong == NO_INDEX) {
                    null
                } else {
                    val sourceFileIdx = sourceFileIdxLong.toIntChecked("source_file_idx")
                    if (sourceFileIdx !in 0 until h.stringIdsSize) throw DexFormatException("source_file_idx outside string_ids")
                    readStringByIndex(raf, h, sourceFileIdx, limits.maxStringBytes).value.take(512)
                }
                val classRef = DexClassReference(
                    dexEntry = dexEntry,
                    classIndex = classDefIndex,
                    descriptor = descriptor,
                    superDescriptor = superDescriptor,
                    accessFlags = accessFlags,
                    interfaces = interfaces,
                    sourceFile = sourceFile,
                )
                if (classes.size < limits.maxReportedClasses) classes += classRef else truncated = true

                if (classDataOff != 0L) {
                    if (classDataOff >= h.fileSize) throw DexFormatException("class_data_off outside DEX")
                    val classNatives = readNativeMethodsFromClassData(
                        raf = raf,
                        h = h,
                        dexEntry = dexEntry,
                        classDataOff = classDataOff,
                        methodLookup = methodLookup,
                        limits = limits,
                        codeLocations = codeLocations,
                    )
                    for (native in classNatives) {
                        if (nativeMethods.size < limits.maxNativeMethods) nativeMethods += native else truncated = true
                    }
                }
            }

            checkCancelled()
            onProgress?.invoke(100, "DEX structure inventory готов", toIndexClasses, toIndexClasses)
            return FileResult(
                stringsDeclared = h.stringIdsSize,
                stringsScanned = stringsScanned,
                typesDeclared = h.typeIdsSize,
                typesIndexed = typesIndexed,
                classesDeclared = h.classDefsSize,
                classesIndexed = toIndexClasses,
                methodsDeclared = h.methodIdsSize,
                methodsIndexed = toIndexMethods,
                fieldsDeclared = h.fieldIdsSize,
                fieldsIndexed = toIndexFields,
                fields = fields,
                classes = classes,
                methods = methods,
                // These collections are produced from a single monotonic DEX traversal; avoid
                // end-of-scan copies so large files do not create a second transient object graph.
                nativeMethods = nativeMethods,
                httpUrls = httpUrls,
                httpsUrls = httpsUrls,
                secretCandidates = secrets,
                structuralIndex = if (toIndexMethods == h.methodIdsSize && toIndexClasses == h.classDefsSize) {
                    StructuralIndex(methodsByIndex.asList(), codeLocations.toList())
                } else null,
                truncated = truncated,
            )
        }
    }

    private fun readHeader(raf: RandomAccessFile): Header {
        if (raf.length() < HEADER_SIZE) throw DexFormatException("DEX header is truncated")
        val magic = ByteArray(8)
        raf.seek(0)
        raf.readFully(magic)
        if (!(magic[0] == 'd'.code.toByte() && magic[1] == 'e'.code.toByte() && magic[2] == 'x'.code.toByte() && magic[3] == '\n'.code.toByte() && magic[7] == 0.toByte())) {
            throw DexFormatException("invalid DEX magic")
        }
        val fileSize = readU32(raf, 0x20)
        val headerSize = readU32(raf, 0x24)
        val endianTag = readU32(raf, 0x28)
        if (headerSize != HEADER_SIZE.toLong()) throw DexFormatException("unexpected DEX header size $headerSize")
        if (endianTag != ENDIAN_CONSTANT) throw DexFormatException("unsupported DEX endian tag 0x${endianTag.toString(16)}")
        if (fileSize > raf.length() || fileSize < HEADER_SIZE) throw DexFormatException("invalid DEX file_size")

        fun table(sizeOff: Long, dataOff: Long, itemBytes: Long, label: String): Pair<Int, Long> {
            val sizeLong = readU32(raf, sizeOff)
            val off = readU32(raf, dataOff)
            if (sizeLong > Int.MAX_VALUE) throw DexFormatException("$label size too large")
            val size = sizeLong.toInt()
            if (size > 0 && off == 0L) throw DexFormatException("$label has non-zero size with zero offset")
            if (size > 0) ensureRange(off, sizeLong.checkedMul(itemBytes), fileSize, label)
            else if (off != 0L) ensureRange(off, 0, fileSize, label)
            return size to off
        }

        val strings = table(0x38, 0x3c, 4, "string_ids")
        val types = table(0x40, 0x44, 4, "type_ids")
        val protos = table(0x48, 0x4c, 12, "proto_ids")
        val fields = table(0x50, 0x54, 8, "field_ids")
        val methods = table(0x58, 0x5c, 8, "method_ids")
        val classes = table(0x60, 0x64, 32, "class_defs")
        return Header(fileSize, strings.first, strings.second, types.first, types.second, protos.first, protos.second, fields.first, fields.second, methods.first, methods.second, classes.first, classes.second)
    }

    private data class DecodedString(val value: String, val truncated: Boolean)

    private class BoundedLru<K, V>(private val limit: Int) : java.util.LinkedHashMap<K, V>(limit, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, V>?): Boolean = size > limit
    }

    private class MetadataCache {
        var file: RandomAccessFile? = null
        val strings = BoundedLru<Int, DecodedString>(4_096)
        val types = BoundedLru<Int, String>(4_096)
        val prototypes = BoundedLru<Int, String>(2_048)

        fun use(raf: RandomAccessFile) {
            if (file !== raf) {
                file = raf
                strings.clear()
                types.clear()
                prototypes.clear()
            }
        }
    }

    private val metadataCache = ThreadLocal.withInitial(::MetadataCache)

    private fun readStringByIndex(raf: RandomAccessFile, h: Header, index: Int, maxStringBytes: Int): DecodedString {
        if (index !in 0 until h.stringIdsSize) throw DexFormatException("string_idx outside string_ids")
        val cache = metadataCache.get().also { it.use(raf) }
        cache.strings[index]?.let { return it }
        val itemOffset = PositionalReadCache.u32Le(raf, h.stringIdsOff + index.toLong() * 4L, h.fileSize)
        if (itemOffset >= h.fileSize) throw DexFormatException("string_data_off outside DEX")
        val decoded = readStringData(raf, itemOffset, h.fileSize, maxStringBytes)
        // Descriptors, names and prototype atoms are tiny and highly repetitive. Avoid retaining
        // unusually large literals in the LRU merely for a possible second lookup.
        if (decoded.value.length <= 2_048) cache.strings[index] = decoded
        return decoded
    }

    private fun readStringData(raf: RandomAccessFile, offset: Long, fileSize: Long, maxStringBytes: Int): DecodedString {
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

    private fun decodeModifiedUtf8(bytes: ByteArray, length: Int, expectedUtf16Units: Long): String {
        val out = StringBuilder(minOf(length, 4096))
        var i = 0
        var units = 0L
        while (i < length) {
            val b0 = bytes[i].toInt() and 0xff
            when {
                b0 and 0x80 == 0 -> {
                    if (b0 == 0) throw DexFormatException("embedded NUL in MUTF-8 data")
                    out.append(b0.toChar())
                    i++
                    units++
                }
                b0 and 0xe0 == 0xc0 -> {
                    if (i + 1 >= length) throw DexFormatException("truncated MUTF-8 sequence")
                    val b1 = bytes[i + 1].toInt() and 0xff
                    if (b1 and 0xc0 != 0x80) throw DexFormatException("invalid MUTF-8 continuation")
                    val value = ((b0 and 0x1f) shl 6) or (b1 and 0x3f)
                    out.append(value.toChar())
                    i += 2
                    units++
                }
                b0 and 0xf0 == 0xe0 -> {
                    if (i + 2 >= length) throw DexFormatException("truncated MUTF-8 sequence")
                    val b1 = bytes[i + 1].toInt() and 0xff
                    val b2 = bytes[i + 2].toInt() and 0xff
                    if (b1 and 0xc0 != 0x80 || b2 and 0xc0 != 0x80) throw DexFormatException("invalid MUTF-8 continuation")
                    val value = ((b0 and 0x0f) shl 12) or ((b1 and 0x3f) shl 6) or (b2 and 0x3f)
                    out.append(value.toChar())
                    i += 3
                    units++
                }
                else -> throw DexFormatException("unsupported MUTF-8 leading byte")
            }
        }
        // A truncated retained byte buffer may intentionally contain fewer units than declared.
        if (length < 64 * 1024 && units != expectedUtf16Units) {
            // Do not reject legacy/edge DEX solely on count mismatch after successful bounded decoding.
        }
        return out.toString()
    }

    private fun typeDescriptor(raf: RandomAccessFile, h: Header, typeIndex: Int, maxStringBytes: Int): String {
        if (typeIndex !in 0 until h.typeIdsSize) throw DexFormatException("type_idx outside type_ids")
        val cache = metadataCache.get().also { it.use(raf) }
        cache.types[typeIndex]?.let { return it }
        val stringIndex = PositionalReadCache.u32Le(raf, h.typeIdsOff + typeIndex.toLong() * 4L, h.fileSize).toIntChecked("descriptor_idx")
        val value = readStringByIndex(raf, h, stringIndex, maxStringBytes).value
        if (value.length <= 2_048) cache.types[typeIndex] = value
        return value
    }

    private fun readField(raf: RandomAccessFile, h: Header, dexEntry: String, fieldIndex: Int, limits: Limits): DexFieldReference {
        if (fieldIndex !in 0 until h.fieldIdsSize) throw DexFormatException("field_idx outside field_ids")
        val base = h.fieldIdsOff + fieldIndex.toLong() * 8L
        val classIdx = readU16(raf, base)
        val typeIdx = readU16(raf, base + 2)
        val nameIdx = readU32(raf, base + 4).toIntChecked("field name_idx")
        if (classIdx !in 0 until h.typeIdsSize) throw DexFormatException("field class_idx outside type_ids")
        if (typeIdx !in 0 until h.typeIdsSize) throw DexFormatException("field type_idx outside type_ids")
        return DexFieldReference(
            dexEntry = dexEntry,
            fieldIndex = fieldIndex,
            declaringClass = typeDescriptor(raf, h, classIdx, limits.maxStringBytes),
            name = readStringByIndex(raf, h, nameIdx, limits.maxStringBytes).value,
            type = typeDescriptor(raf, h, typeIdx, limits.maxStringBytes),
        )
    }

    private fun readMethod(raf: RandomAccessFile, h: Header, dexEntry: String, methodIndex: Int, limits: Limits): DexMethodReference {
        if (methodIndex !in 0 until h.methodIdsSize) throw DexFormatException("method_idx outside method_ids")
        val base = h.methodIdsOff + methodIndex.toLong() * 8L
        val classIdx = readU16(raf, base)
        val protoIdx = readU16(raf, base + 2)
        val nameIdx = readU32(raf, base + 4).toIntChecked("method name_idx")
        if (classIdx !in 0 until h.typeIdsSize) throw DexFormatException("method class_idx outside type_ids")
        if (protoIdx !in 0 until h.protoIdsSize) throw DexFormatException("method proto_idx outside proto_ids")
        val declaringClass = typeDescriptor(raf, h, classIdx, limits.maxStringBytes)
        val name = readStringByIndex(raf, h, nameIdx, limits.maxStringBytes).value
        val prototype = readPrototype(raf, h, protoIdx, limits)
        return DexMethodReference(dexEntry, methodIndex, declaringClass, name, prototype)
    }

    private fun readPrototype(raf: RandomAccessFile, h: Header, protoIdx: Int, limits: Limits): String {
        if (protoIdx !in 0 until h.protoIdsSize) throw DexFormatException("proto_idx outside proto_ids")
        val cache = metadataCache.get().also { it.use(raf) }
        cache.prototypes[protoIdx]?.let { return it }
        val base = h.protoIdsOff + protoIdx.toLong() * 12L
        val returnTypeIdx = readU32(raf, base + 4).toIntChecked("return_type_idx")
        val parametersOff = readU32(raf, base + 8)
        val returnType = typeDescriptor(raf, h, returnTypeIdx, limits.maxStringBytes)
        val value = if (parametersOff == 0L) {
            "()$returnType"
        } else {
            ensureRange(parametersOff, 4, h.fileSize, "type_list")
            val countLong = readU32(raf, parametersOff)
            if (countLong > limits.maxProtoParameters) throw DexFormatException("prototype parameter count exceeds limit")
            ensureRange(parametersOff + 4, countLong.checkedMul(2), h.fileSize, "type_list items")
            val params = buildString {
                repeat(countLong.toInt()) { index ->
                    val typeIdx = readU16(raf, parametersOff + 4 + index.toLong() * 2L)
                    append(typeDescriptor(raf, h, typeIdx, limits.maxStringBytes))
                }
            }
            "($params)$returnType"
        }
        if (value.length <= 4_096) cache.prototypes[protoIdx] = value
        return value
    }

    private fun readNativeMethodsFromClassData(
        raf: RandomAccessFile,
        h: Header,
        dexEntry: String,
        classDataOff: Long,
        methodLookup: Map<Int, DexMethodReference>,
        limits: Limits,
        codeLocations: MutableList<CodeLocation>,
    ): List<DexNativeMethodDeclaration> {
        raf.seek(classDataOff)
        val staticFields = readUleb128(raf, h.fileSize)
        val instanceFields = readUleb128(raf, h.fileSize)
        val directMethods = readUleb128(raf, h.fileSize)
        val virtualMethods = readUleb128(raf, h.fileSize)
        val totalMembers = staticFields + instanceFields + directMethods + virtualMethods
        if (totalMembers > limits.maxEncodedMembersPerClass) throw DexFormatException("class_data member count exceeds limit")

        repeat((staticFields + instanceFields).toInt()) { memberIndex ->
            if ((memberIndex and 0xff) == 0) checkCancelled()
            readUleb128(raf, h.fileSize) // field_idx_diff
            readUleb128(raf, h.fileSize) // access_flags
        }

        val result = mutableListOf<DexNativeMethodDeclaration>()
        fun readMethodList(count: Int) {
            var methodIndex = 0L
            repeat(count) { memberIndex ->
                if ((memberIndex and 0xff) == 0) checkCancelled()
                methodIndex += readUleb128(raf, h.fileSize)
                val accessFlags = readUleb128(raf, h.fileSize)
                val codeOff = readUleb128(raf, h.fileSize)
                if (methodIndex > Int.MAX_VALUE || methodIndex >= h.methodIdsSize) throw DexFormatException("encoded method_idx outside method_ids")
                if (codeOff != 0L) codeLocations += CodeLocation(methodIndex.toInt(), codeOff)
                if ((accessFlags and ACC_NATIVE) != 0L) {
                    val ref = methodLookup[methodIndex.toInt()] ?: run {
                        val classDataCursor = raf.filePointer
                        val resolved = readMethod(raf, h, dexEntry, methodIndex.toInt(), limits)
                        raf.seek(classDataCursor)
                        resolved
                    }
                    result += DexNativeMethodDeclaration(
                        dexEntry = dexEntry,
                        methodIndex = ref.methodIndex,
                        declaringClass = ref.declaringClass,
                        name = ref.name,
                        prototype = ref.prototype,
                        accessFlags = accessFlags,
                    )
                }
            }
        }
        readMethodList(directMethods.toInt())
        readMethodList(virtualMethods.toInt())
        return result
    }

    private fun readUleb128(raf: RandomAccessFile, fileSize: Long): Long {
        var result = 0L
        var shift = 0
        repeat(5) {
            if (raf.filePointer >= fileSize) throw DexFormatException("truncated uleb128")
            val b = raf.readUnsignedByte()
            result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
        throw DexFormatException("uleb128 exceeds 5 bytes")
    }

    private fun readU16(raf: RandomAccessFile, offset: Long): Int {
        ensureRange(offset, 2, raf.length(), "u16")
        return PositionalReadCache.u16Le(raf, offset, raf.length())
    }

    private fun readU32(raf: RandomAccessFile, offset: Long): Long {
        ensureRange(offset, 4, raf.length(), "u32")
        return PositionalReadCache.u32Le(raf, offset, raf.length())
    }

    private fun ensureRange(offset: Long, size: Long, bound: Long, label: String) {
        if (offset < 0 || size < 0 || offset > bound || size > bound - offset) throw DexFormatException("$label range outside DEX")
    }

    private fun Long.checkedMul(other: Long): Long {
        if (this != 0L && other > Long.MAX_VALUE / this) throw DexFormatException("integer overflow")
        return this * other
    }

    private fun Long.toIntChecked(label: String): Int {
        if (this > Int.MAX_VALUE) throw DexFormatException("$label too large")
        return toInt()
    }

    private fun checkCancelled() {
        if (Thread.currentThread().isInterrupted) throw InterruptedIOException("DEX analysis cancelled")
    }

    private fun scaleProgress(from: Int, to: Int, completed: Int, total: Int): Int {
        if (total <= 0) return to
        val fraction = (completed.toDouble() / total.toDouble()).coerceIn(0.0, 1.0)
        return from + ((to - from) * fraction).toInt()
    }

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

    private const val HEADER_SIZE = 0x70L
    private const val ENDIAN_CONSTANT = 0x12345678L
    private const val NO_INDEX = 0xffffffffL
    private const val ACC_NATIVE = 0x0100L
    private val URL_REGEX = Regex("https?://[^\\s\\\"'<>]+", RegexOption.IGNORE_CASE)
}
