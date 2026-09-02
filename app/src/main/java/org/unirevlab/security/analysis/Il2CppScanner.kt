package org.unirevlab.security.analysis

import org.unirevlab.security.model.Il2CppMetadataSummary
import org.unirevlab.security.model.Il2CppFieldDefinitionSummary
import org.unirevlab.security.model.Il2CppMethodDefinitionSummary
import org.unirevlab.security.model.Il2CppRegistrationCandidate
import org.unirevlab.security.model.Il2CppSummary
import org.unirevlab.security.model.Il2CppTableRange
import org.unirevlab.security.model.Il2CppTypeDefinitionSummary
import org.unirevlab.security.model.NativeSummary
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipException
import java.util.zip.ZipFile

/**
 * Defensive Unity IL2CPP detector/indexer.
 *
 * M2.2 adds bounded, version-aware metadata reconstruction for the well-understood v27-v31 legacy
 * metadata layout. It reconstructs metadata type/method identities only; it does not recover live
 * runtime addresses, patch code, or execute libil2cpp.so.
 */
object Il2CppScanner {
    data class Limits(
        val maxMetadataBytes: Long = 64L * 1024L * 1024L,
        val maxPrintableStrings: Int = 12_000,
        val maxAssemblyCandidates: Int = 300,
        val maxManagedNameCandidates: Int = 1_000,
        val maxApiSymbols: Int = 1_000,
        val maxUnityMarkerBytes: Int = 4 * 1024 * 1024,
        val maxHeaderPairs: Int = 128,
        val maxTypeDefinitions: Int = 20_000,
        val maxMethodDefinitions: Int = 50_000,
        val maxFieldDefinitions: Int = 50_000,
        val maxMetadataStringBytes: Int = 16 * 1024,
    )

    data class PairAnalysis(
        val native: NativeSummary,
        val il2cpp: Il2CppSummary,
    )

    fun scanApk(
        apk: File,
        native: NativeSummary?,
        limits: Limits = Limits(),
        archiveEntryNames: Collection<String>? = null,
    ): Il2CppSummary? {
        val il2cppLibs = native?.libraries.orEmpty()
            .filter { it.entryName.substringAfterLast('/').equals("libil2cpp.so", ignoreCase = true) }
        val apiSet = java.util.TreeSet<String>()
        val registrationMap = LinkedHashMap<Triple<String, String, String>, Il2CppRegistrationCandidate>()
        fun consumeSymbol(symbol: org.unirevlab.security.model.NativeSymbolReference) {
            if (symbol.name.startsWith("il2cpp_") && apiSet.size < limits.maxApiSymbols + 1) apiSet += symbol.name
            if (registrationMap.size >= 128) return
            val normalized = symbol.name.lowercase()
            val kind = when {
                normalized.contains("coderegistration") || normalized == "g_code_registration" -> "CODE_REGISTRATION_SYMBOL"
                normalized.contains("metadataregistration") || normalized == "g_metadata_registration" -> "METADATA_REGISTRATION_SYMBOL"
                normalized.contains("il2cpp_codegen_register") -> "CODEGEN_REGISTER_SYMBOL"
                else -> null
            } ?: return
            val candidate = Il2CppRegistrationCandidate(
                kind = kind,
                libraryEntry = symbol.libraryEntry,
                symbolName = symbol.name,
                virtualAddress = symbol.virtualAddress,
                sizeBytes = symbol.sizeBytes,
                validatedDefinedSymbol = symbol.defined && symbol.virtualAddress != null,
            )
            registrationMap.putIfAbsent(Triple(candidate.kind, candidate.libraryEntry, candidate.symbolName), candidate)
        }
        for (lib in il2cppLibs) {
            lib.exportedSymbols.forEach(::consumeSymbol)
            lib.importedSymbols.forEach(::consumeSymbol)
        }
        val apiSymbols = apiSet.take(limits.maxApiSymbols)
        val registrationCandidates = registrationMap.values.toList()

        return try {
            ZipFile(apk).use { zip ->
                val metadataEntry = if (archiveEntryNames != null) {
                    archiveEntryNames.asSequence()
                        .filter { it.substringAfterLast('/').equals("global-metadata.dat", ignoreCase = true) }
                        .minOrNull()
                        ?.let(zip::getEntry)
                } else {
                    buildList {
                        val entries = zip.entries()
                        while (entries.hasMoreElements()) {
                            val e = entries.nextElement()
                            if (!e.isDirectory && e.name.substringAfterLast('/').equals("global-metadata.dat", ignoreCase = true)) add(e)
                        }
                    }.sortedBy { it.name }.firstOrNull()
                }

                if (metadataEntry == null && il2cppLibs.isEmpty()) return null
                var parseErrors = 0
                var truncated = false
                val metadata = if (metadataEntry != null) {
                    if (metadataEntry.size < 0 || metadataEntry.size > limits.maxMetadataBytes) {
                        truncated = true
                        emptyMetadata(
                            metadataEntry.name,
                            metadataEntry.size.coerceAtLeast(0),
                            "global-metadata.dat exceeds bounded local-analysis limit",
                            truncated = true,
                        )
                    } else {
                        runCatching {
                            val bytes = zip.getInputStream(metadataEntry).use { input -> readBounded(input, limits.maxMetadataBytes) }
                            val versions = scanUnityVersionCandidates(zip, limits)
                            parseMetadata(metadataEntry.name, bytes, versions, limits)
                        }.getOrElse { error ->
                            parseErrors++
                            emptyMetadata(
                                metadataEntry.name,
                                metadataEntry.size.coerceAtLeast(0),
                                error.message?.take(240) ?: error::class.java.simpleName,
                            )
                        }
                    }
                } else null

                val indicators = buildList {
                    if (metadataEntry != null) add("GLOBAL_METADATA_PRESENT")
                    if (metadata?.magicValid == true) add("METADATA_MAGIC_VALID")
                    if (metadata?.typeDefinitions?.isNotEmpty() == true) add("TYPE_DEFINITIONS_RECONSTRUCTED")
                    if (metadata?.methodDefinitions?.isNotEmpty() == true) add("METHOD_DEFINITIONS_RECONSTRUCTED")
                    if (il2cppLibs.isNotEmpty()) add("LIBIL2CPP_PRESENT")
                    if (apiSymbols.isNotEmpty()) add("IL2CPP_API_SYMBOLS_PRESENT")
                    if (apiSymbols.any { it.contains("class_from_name") }) add("CLASS_LOOKUP_API_PRESENT")
                    if (apiSymbols.any { it.contains("method_get") || it.contains("class_get_method") }) add("METHOD_INTROSPECTION_API_PRESENT")
                    if (registrationCandidates.isNotEmpty()) add("REGISTRATION_SYMBOL_CANDIDATES_PRESENT")
                }
                val detected = (metadata?.magicValid == true && il2cppLibs.isNotEmpty()) ||
                    (metadataEntry != null && il2cppLibs.isNotEmpty()) || apiSymbols.size >= 3
                val confidence = when {
                    metadata?.magicValid == true && il2cppLibs.isNotEmpty() -> "HIGH"
                    metadataEntry != null && il2cppLibs.isNotEmpty() -> "MEDIUM"
                    else -> "LOW"
                }
                Il2CppSummary(
                    detected = detected,
                    confidence = confidence,
                    metadata = metadata,
                    libil2cppLibraries = il2cppLibs.map { it.entryName }.distinct().sorted(),
                    il2cppApiSymbols = apiSymbols,
                    registrationIndicators = indicators,
                    registrationCandidates = registrationCandidates,
                    parseErrors = parseErrors,
                    truncated = truncated || metadata?.truncated == true || metadata?.reconstructionTruncated == true,
                )
            }
        } catch (_: ZipException) {
            if (il2cppLibs.isEmpty()) null else Il2CppSummary(
                detected = true,
                confidence = "LOW",
                metadata = null,
                libil2cppLibraries = il2cppLibs.map { it.entryName },
                il2cppApiSymbols = apiSymbols,
                registrationIndicators = listOf("LIBIL2CPP_PRESENT"),
                registrationCandidates = registrationCandidates,
                parseErrors = 1,
                truncated = false,
            )
        }
    }

    /** Analyze a dumped global-metadata.dat + matching libil2cpp.so as inert files. */
    fun scanPair(
        metadataFile: File,
        libraryFile: File,
        limits: Limits = Limits(),
    ): PairAnalysis {
        require(metadataFile.isFile && metadataFile.canRead()) { "global-metadata.dat is not readable" }
        require(libraryFile.isFile && libraryFile.canRead()) { "libil2cpp.so is not readable" }
        require(metadataFile.length() in 1..limits.maxMetadataBytes) {
            "global-metadata.dat exceeds bounded local-analysis limit"
        }

        val library = ElfNativeScanner.scan("libil2cpp.so", libraryFile)
        val native = NativeSummary(
            librariesDiscovered = 1,
            librariesScanned = 1,
            libraries = listOf(library),
            parseErrors = if (library.parseError == null) 0 else 1,
            truncated = library.truncated,
        )

        var metadataParseErrors = 0
        val metadata = runCatching {
            val bytes = metadataFile.inputStream().buffered().use { readBounded(it, limits.maxMetadataBytes) }
            parseMetadata(metadataFile.name, bytes, emptyList(), limits)
        }.getOrElse { failure ->
            metadataParseErrors++
            emptyMetadata(
                metadataFile.name,
                metadataFile.length(),
                failure.message?.take(240) ?: failure::class.java.simpleName,
            )
        }

        val apiSet = java.util.TreeSet<String>()
        val registrationMap = LinkedHashMap<Triple<String, String, String>, Il2CppRegistrationCandidate>()
        fun consumeSymbol(symbol: org.unirevlab.security.model.NativeSymbolReference) {
            if (symbol.name.startsWith("il2cpp_") && apiSet.size < limits.maxApiSymbols + 1) apiSet += symbol.name
            if (registrationMap.size >= 128) return
            val normalized = symbol.name.lowercase()
            val kind = when {
                normalized.contains("coderegistration") || normalized == "g_code_registration" -> "CODE_REGISTRATION_SYMBOL"
                normalized.contains("metadataregistration") || normalized == "g_metadata_registration" -> "METADATA_REGISTRATION_SYMBOL"
                normalized.contains("il2cpp_codegen_register") -> "CODEGEN_REGISTER_SYMBOL"
                else -> null
            } ?: return
            val candidate = Il2CppRegistrationCandidate(
                kind = kind,
                libraryEntry = symbol.libraryEntry,
                symbolName = symbol.name,
                virtualAddress = symbol.virtualAddress,
                sizeBytes = symbol.sizeBytes,
                validatedDefinedSymbol = symbol.defined && symbol.virtualAddress != null,
            )
            registrationMap.putIfAbsent(Triple(candidate.kind, candidate.libraryEntry, candidate.symbolName), candidate)
        }
        library.exportedSymbols.forEach(::consumeSymbol)
        library.importedSymbols.forEach(::consumeSymbol)
        val apiSymbols = apiSet.take(limits.maxApiSymbols)
        val registrations = registrationMap.values.toList()

        val indicators = buildList {
            add("STANDALONE_IL2CPP_PAIR")
            add("LIBIL2CPP_PRESENT")
            if (metadata.magicValid) add("METADATA_MAGIC_VALID")
            if (metadata.typeDefinitions.isNotEmpty()) add("TYPE_DEFINITIONS_RECONSTRUCTED")
            if (metadata.methodDefinitions.isNotEmpty()) add("METHOD_DEFINITIONS_RECONSTRUCTED")
            if (metadata.fieldDefinitions.isNotEmpty()) add("FIELD_DEFINITIONS_RECONSTRUCTED")
            if (apiSymbols.isNotEmpty()) add("IL2CPP_API_SYMBOLS_PRESENT")
            if (registrations.isNotEmpty()) add("REGISTRATION_SYMBOL_CANDIDATES_PRESENT")
        }
        val detected = metadata.magicValid
        val confidence = when {
            metadata.magicValid && metadata.typeDefinitions.isNotEmpty() -> "HIGH"
            metadata.magicValid -> "MEDIUM"
            else -> "LOW"
        }
        val il2cpp = Il2CppSummary(
            detected = detected,
            confidence = confidence,
            metadata = metadata,
            libil2cppLibraries = listOf("libil2cpp.so"),
            il2cppApiSymbols = apiSymbols,
            registrationIndicators = indicators,
            registrationCandidates = registrations,
            parseErrors = metadataParseErrors + native.parseErrors,
            truncated = metadata.truncated || metadata.reconstructionTruncated || native.truncated,
        )
        return PairAnalysis(native, il2cpp)
    }

    private fun emptyMetadata(
        entryName: String,
        size: Long,
        error: String,
        truncated: Boolean = false,
    ) = Il2CppMetadataSummary(
        entryName = entryName,
        sizeBytes = size,
        magicValid = false,
        metadataVersion = null,
        headerPairsScanned = 0,
        assemblyNameCandidates = emptyList(),
        managedNameCandidates = emptyList(),
        unityVersionCandidates = emptyList(),
        parseError = error,
        truncated = truncated,
    )

    private fun parseMetadata(
        entryName: String,
        bytes: ByteArray,
        unityVersions: List<String>,
        limits: Limits,
    ): Il2CppMetadataSummary {
        if (bytes.size < 8) throw IllegalArgumentException("IL2CPP metadata header is truncated")
        val magic = u32le(bytes, 0)
        val version = i32le(bytes, 4)
        val magicValid = magic == IL2CPP_METADATA_MAGIC

        var pairs = 0
        var off = 8
        while (off + 8 <= bytes.size && pairs < limits.maxHeaderPairs) {
            val tableOffset = u32le(bytes, off)
            val tableCountOrBytes = u32le(bytes, off + 4)
            if (tableOffset == 0L && tableCountOrBytes == 0L) {
                pairs++
                off += 8
                continue
            }
            if (tableOffset > bytes.size.toLong() || tableCountOrBytes > bytes.size.toLong()) break
            if (tableOffset + tableCountOrBytes > bytes.size.toLong()) break
            pairs++
            off += 8
        }

        val printable = extractPrintableStrings(bytes, limits.maxPrintableStrings)
        val assemblies = printable.asSequence()
            .filter { isAssemblyCandidate(it) }
            .distinct().take(limits.maxAssemblyCandidates).sorted().toList()
        val names = printable.asSequence()
            .filter { isManagedNameCandidate(it) }
            .filterNot { isAssemblyCandidate(it) }
            .distinct().take(limits.maxManagedNameCandidates).sorted().toList()
        val versionCandidates = (unityVersions + printable.filter { UNITY_VERSION.matches(it) })
            .distinct().sorted().take(32)

        val structured = if (magicValid) reconstructLegacyMetadata(bytes, version, limits) else StructuredResult.unsupported(null)

        return Il2CppMetadataSummary(
            entryName = entryName,
            sizeBytes = bytes.size.toLong(),
            magicValid = magicValid,
            metadataVersion = if (version in 1..1000) version else null,
            headerPairsScanned = pairs,
            assemblyNameCandidates = assemblies,
            managedNameCandidates = names,
            unityVersionCandidates = versionCandidates,
            layoutProfile = structured.layoutProfile,
            tableRanges = structured.tableRanges,
            typeDefinitions = structured.types,
            methodDefinitions = structured.methods,
            fieldDefinitions = structured.fields,
            reconstructionTruncated = structured.truncated,
            parseError = when {
                !magicValid -> "unexpected IL2CPP metadata magic 0x${magic.toString(16)}"
                structured.error != null -> structured.error
                else -> null
            },
            truncated = false,
        )
    }

    private data class StructuredResult(
        val layoutProfile: String?,
        val tableRanges: List<Il2CppTableRange>,
        val types: List<Il2CppTypeDefinitionSummary>,
        val methods: List<Il2CppMethodDefinitionSummary>,
        val fields: List<Il2CppFieldDefinitionSummary>,
        val truncated: Boolean,
        val error: String?,
    ) {
        companion object {
            fun unsupported(error: String?) = StructuredResult(null, emptyList(), emptyList(), emptyList(), emptyList(), false, error)
        }
    }

    /**
     * Reconstructs the stable header/table subset used by metadata versions 27-31. The table header
     * stores byte offsets and byte sizes. v27-v30 method definitions are 32 bytes; v31 adds the
     * return-parameter token and is 36 bytes. Type definitions in this range are 88 bytes.
     */
    private fun reconstructLegacyMetadata(bytes: ByteArray, version: Int, limits: Limits): StructuredResult {
        if (version !in 27..31) {
            return StructuredResult.unsupported("structured reconstruction is not enabled for metadata version $version")
        }
        val layout = if (version == 31) "IL2CPP_METADATA_V31" else "IL2CPP_METADATA_V27_V30"
        fun pair(index: Int, name: String): Il2CppTableRange? {
            val base = 8 + index * 8
            if (base + 8 > bytes.size) return null
            val offset = u32le(bytes, base)
            val size = u32le(bytes, base + 4)
            if (offset == 0L && size == 0L) return Il2CppTableRange(name, 0, 0)
            if (offset > bytes.size.toLong() || size > bytes.size.toLong() || offset + size > bytes.size.toLong()) return null
            return Il2CppTableRange(name, offset, size)
        }

        val namedPairs = listOf(
            0 to "stringLiterals", 1 to "stringLiteralData", 2 to "strings", 3 to "events",
            4 to "properties", 5 to "methods", 6 to "parameterDefaultValues", 7 to "fieldDefaultValues",
            8 to "fieldAndParameterDefaultValueData", 9 to "fieldMarshaledSizes", 10 to "parameters",
            11 to "fields", 12 to "genericParameters", 13 to "genericParameterConstraints",
            14 to "genericContainers", 15 to "nestedTypes", 16 to "interfaces", 17 to "vtableMethods",
            18 to "interfaceOffsets", 19 to "typeDefinitions",
        )
        val ranges = namedPairs.mapNotNull { (i, n) -> pair(i, n) }
        val strings = ranges.firstOrNull { it.name == "strings" }
        val methodsRange = ranges.firstOrNull { it.name == "methods" }
        val fieldsRange = ranges.firstOrNull { it.name == "fields" }
        val typesRange = ranges.firstOrNull { it.name == "typeDefinitions" }
        if (strings == null || methodsRange == null || typesRange == null || strings.sizeBytes == 0L) {
            return StructuredResult(layout, ranges, emptyList(), emptyList(), emptyList(), false, "required IL2CPP metadata tables are absent")
        }

        fun metadataString(relativeOffset: Long): String? {
            if (relativeOffset < 0 || relativeOffset >= strings.sizeBytes) return null
            val start = strings.offset + relativeOffset
            val endLimit = minOf(strings.offset + strings.sizeBytes, start + limits.maxMetadataStringBytes)
            if (start < 0 || start >= bytes.size || endLimit > bytes.size) return null
            var end = start.toInt()
            val max = endLimit.toInt()
            while (end < max && bytes[end] != 0.toByte()) end++
            if (end == max) return null
            return bytes.copyOfRange(start.toInt(), end).toString(Charsets.UTF_8).take(512)
        }

        val typeRecordSize = 88
        val methodRecordSize = if (version == 31) 36 else 32
        val fieldRecordSize = 12
        val declaredTypes = (typesRange.sizeBytes / typeRecordSize).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        val declaredMethods = (methodsRange.sizeBytes / methodRecordSize).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        val declaredFields = ((fieldsRange?.sizeBytes ?: 0L) / fieldRecordSize).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        var truncated = typesRange.sizeBytes % typeRecordSize != 0L || methodsRange.sizeBytes % methodRecordSize != 0L ||
            ((fieldsRange?.sizeBytes ?: 0L) % fieldRecordSize != 0L)
        val typeCount = minOf(declaredTypes, limits.maxTypeDefinitions)
        val methodCount = minOf(declaredMethods, limits.maxMethodDefinitions)
        val fieldCount = minOf(declaredFields, limits.maxFieldDefinitions)
        if (typeCount < declaredTypes || methodCount < declaredMethods || fieldCount < declaredFields) truncated = true

        val types = mutableListOf<Il2CppTypeDefinitionSummary>()
        repeat(typeCount) { index ->
            val baseLong = typesRange.offset + index.toLong() * typeRecordSize
            if (baseLong < 0 || baseLong + typeRecordSize > bytes.size) return@repeat
            val base = baseLong.toInt()
            val name = metadataString(u32le(bytes, base)) ?: return@repeat
            val namespace = metadataString(u32le(bytes, base + 4)).orEmpty()
            val fieldStart = i32le(bytes, base + 32)
            val methodStart = i32le(bytes, base + 36)
            val methodCountForType = u16le(bytes, base + 64)
            val fieldCountForType = u16le(bytes, base + 68)
            val token = u32le(bytes, base + 84)
            types += Il2CppTypeDefinitionSummary(
                index = index,
                namespace = namespace,
                name = name,
                fullName = if (namespace.isBlank()) name else "$namespace.$name",
                methodStart = methodStart,
                methodCount = methodCountForType,
                fieldStart = fieldStart,
                fieldCount = fieldCountForType,
                token = token,
            )
        }
        val typeByIndex = types.associateBy { it.index }

        val fieldOwner = HashMap<Int, Il2CppTypeDefinitionSummary>()
        types.forEach { type ->
            if (type.fieldStart >= 0 && type.fieldCount > 0) {
                repeat(type.fieldCount) { relative ->
                    fieldOwner.putIfAbsent(type.fieldStart + relative, type)
                }
            }
        }
        val fields = mutableListOf<Il2CppFieldDefinitionSummary>()
        val fieldTable = fieldsRange
        if (fieldTable != null) {
            repeat(fieldCount) { index ->
                val baseLong = fieldTable.offset + index.toLong() * fieldRecordSize
                if (baseLong < 0 || baseLong + fieldRecordSize > bytes.size) return@repeat
                val base = baseLong.toInt()
                val name = metadataString(u32le(bytes, base)) ?: return@repeat
                val owner = fieldOwner[index]
                fields += Il2CppFieldDefinitionSummary(
                    index = index,
                    declaringTypeIndex = owner?.index ?: -1,
                    declaringType = owner?.fullName ?: "<unresolved-field-owner>",
                    name = name,
                    typeIndex = i32le(bytes, base + 4),
                    token = u32le(bytes, base + 8),
                )
            }
        }

        val methods = mutableListOf<Il2CppMethodDefinitionSummary>()
        repeat(methodCount) { index ->
            val baseLong = methodsRange.offset + index.toLong() * methodRecordSize
            if (baseLong < 0 || baseLong + methodRecordSize > bytes.size) return@repeat
            val base = baseLong.toInt()
            val name = metadataString(u32le(bytes, base)) ?: return@repeat
            val declaringTypeIndex = i32le(bytes, base + 4)
            val tokenOffset = if (version == 31) 24 else 20
            val flagsOffset = if (version == 31) 28 else 24
            val parameterCountOffset = if (version == 31) 34 else 30
            methods += Il2CppMethodDefinitionSummary(
                index = index,
                declaringTypeIndex = declaringTypeIndex,
                declaringType = typeByIndex[declaringTypeIndex]?.fullName ?: "<type#$declaringTypeIndex>",
                name = name,
                parameterCount = u16le(bytes, base + parameterCountOffset),
                token = u32le(bytes, base + tokenOffset),
                flags = u16le(bytes, base + flagsOffset),
            )
        }

        return StructuredResult(layout, ranges, types, methods, fields, truncated, null)
    }

    private fun extractPrintableStrings(bytes: ByteArray, max: Int): List<String> {
        val out = ArrayList<String>(minOf(max, 1024))
        var start = -1
        var i = 0
        while (i <= bytes.size) {
            val printable = i < bytes.size && (bytes[i].toInt() and 0xff) in 0x20..0x7e
            if (printable && start < 0) start = i
            if (!printable && start >= 0) {
                val len = i - start
                if (len in 4..180) {
                    val value = bytes.copyOfRange(start, i).toString(Charsets.US_ASCII)
                    if (out.size < max) out += value else break
                }
                start = -1
            }
            i++
        }
        return out
    }

    private fun isAssemblyCandidate(value: String): Boolean {
        val v = value.trim()
        return v.endsWith(".dll", true) || v == "Assembly-CSharp" || v.startsWith("Assembly-CSharp-") ||
            v.startsWith("UnityEngine.") || v == "mscorlib" || v == "netstandard"
    }

    private fun isManagedNameCandidate(value: String): Boolean {
        if (value.length !in 4..140 || value.any { it == '/' || it == '\\' }) return false
        if (!value.any(Char::isLetter)) return false
        return MANAGED_NAME.matches(value) && !UNITY_VERSION.matches(value)
    }

    private fun scanUnityVersionCandidates(zip: ZipFile, limits: Limits): List<String> {
        val candidates = mutableListOf<String>()
        val names = listOf(
            "assets/bin/Data/globalgamemanagers",
            "assets/bin/Data/data.unity3d",
            "assets/bin/Data/Resources/unity_builtin_extra",
        )
        for (name in names) {
            val entry = zip.getEntry(name) ?: continue
            if (entry.size < 0 || entry.size > limits.maxUnityMarkerBytes) continue
            val bytes = runCatching { zip.getInputStream(entry).use { readBounded(it, limits.maxUnityMarkerBytes.toLong()) } }.getOrNull() ?: continue
            extractPrintableStrings(bytes, 2_000).filterTo(candidates) { UNITY_VERSION.matches(it) }
        }
        return candidates.distinct().take(32)
    }

    private fun readBounded(input: java.io.InputStream, maxBytes: Long): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            total += read
            require(total <= maxBytes) { "input exceeds bounded IL2CPP analysis limit" }
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }

    private fun u16le(bytes: ByteArray, offset: Int): Int {
        if (offset < 0 || offset + 2 > bytes.size) throw IllegalArgumentException("IL2CPP metadata u16 outside file")
        return (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)
    }

    private fun u32le(bytes: ByteArray, offset: Int): Long {
        if (offset < 0 || offset + 4 > bytes.size) throw IllegalArgumentException("IL2CPP metadata u32 outside file")
        return (bytes[offset].toLong() and 0xff) or
            ((bytes[offset + 1].toLong() and 0xff) shl 8) or
            ((bytes[offset + 2].toLong() and 0xff) shl 16) or
            ((bytes[offset + 3].toLong() and 0xff) shl 24)
    }

    private fun i32le(bytes: ByteArray, offset: Int): Int = u32le(bytes, offset).toInt()

    private val MANAGED_NAME = Regex("[A-Za-z_<>][A-Za-z0-9_.$+`<>:-]*")
    private val UNITY_VERSION = Regex("20\\d{2}\\.\\d+\\.\\d+[abfp]\\d+(?:[A-Za-z0-9.-]*)?")
    private const val IL2CPP_METADATA_MAGIC = 0xFAB11BAFL
}
