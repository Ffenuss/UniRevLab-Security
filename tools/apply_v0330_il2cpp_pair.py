#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
model_path = ROOT / "app/src/main/java/org/unirevlab/security/model/StaticAnalysisModels.kt"
scanner_path = ROOT / "app/src/main/java/org/unirevlab/security/analysis/Il2CppScanner.kt"
build_path = ROOT / "app/build.gradle.kts"

model = model_path.read_text(encoding="utf-8")
scanner = scanner_path.read_text(encoding="utf-8")
build = build_path.read_text(encoding="utf-8")

# ---- model: exact field inventory from global-metadata.dat ----
if "data class Il2CppFieldDefinitionSummary(" not in model:
    anchor = '''data class Il2CppMetadataSummary(\n'''
    field_model = '''data class Il2CppFieldDefinitionSummary(\n    val index: Int,\n    val declaringTypeIndex: Int,\n    val declaringType: String,\n    val name: String,\n    val typeIndex: Int,\n    val token: Long,\n) : java.io.Serializable\n\n'''
    if anchor not in model:
        raise SystemExit("StaticAnalysisModels: Il2CppMetadataSummary anchor missing")
    model = model.replace(anchor, field_model + anchor, 1)

if "val fieldDefinitions: List<Il2CppFieldDefinitionSummary>" not in model:
    anchor = '''    val methodDefinitions: List<Il2CppMethodDefinitionSummary> = emptyList(),\n'''
    if anchor not in model:
        raise SystemExit("StaticAnalysisModels: methodDefinitions anchor missing")
    model = model.replace(anchor, anchor + '''    val fieldDefinitions: List<Il2CppFieldDefinitionSummary> = emptyList(),\n''', 1)

# ---- scanner: imports / limits ----
if "import org.unirevlab.security.model.Il2CppFieldDefinitionSummary" not in scanner:
    scanner = scanner.replace(
        "import org.unirevlab.security.model.Il2CppMetadataSummary\n",
        "import org.unirevlab.security.model.Il2CppMetadataSummary\nimport org.unirevlab.security.model.Il2CppFieldDefinitionSummary\n",
        1,
    )

if "val maxFieldDefinitions:" not in scanner:
    scanner = scanner.replace(
        "        val maxMethodDefinitions: Int = 50_000,\n",
        "        val maxMethodDefinitions: Int = 50_000,\n        val maxFieldDefinitions: Int = 50_000,\n",
        1,
    )

# ---- scanner: standalone pair API ----
if "data class PairAnalysis(" not in scanner:
    limits_end = '''    )\n\n    fun scanApk(\n'''
    insert = '''    )\n\n    data class PairAnalysis(\n        val native: NativeSummary,\n        val il2cpp: Il2CppSummary,\n    )\n\n    fun scanApk(\n'''
    if limits_end not in scanner:
        raise SystemExit("Il2CppScanner: Limits end anchor missing")
    scanner = scanner.replace(limits_end, insert, 1)

if "fun scanPair(" not in scanner:
    anchor = '''    private fun emptyMetadata(\n'''
    pair_fn = r'''    /** Analyze a dumped global-metadata.dat + matching libil2cpp.so as inert files. */
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

'''
    if anchor not in scanner:
        raise SystemExit("Il2CppScanner: emptyMetadata anchor missing")
    scanner = scanner.replace(anchor, pair_fn + anchor, 1)

# ---- scanner: structured field table ----
if "val fields: List<Il2CppFieldDefinitionSummary>" not in scanner:
    old = '''        val types: List<Il2CppTypeDefinitionSummary>,\n        val methods: List<Il2CppMethodDefinitionSummary>,\n        val truncated: Boolean,\n'''
    new = '''        val types: List<Il2CppTypeDefinitionSummary>,\n        val methods: List<Il2CppMethodDefinitionSummary>,\n        val fields: List<Il2CppFieldDefinitionSummary>,\n        val truncated: Boolean,\n'''
    if old not in scanner:
        raise SystemExit("Il2CppScanner: StructuredResult fields anchor missing")
    scanner = scanner.replace(old, new, 1)
    scanner = scanner.replace(
        '''fun unsupported(error: String?) = StructuredResult(null, emptyList(), emptyList(), emptyList(), false, error)''',
        '''fun unsupported(error: String?) = StructuredResult(null, emptyList(), emptyList(), emptyList(), emptyList(), false, error)''',
        1,
    )

if "fieldDefinitions = structured.fields" not in scanner:
    scanner = scanner.replace(
        '''            methodDefinitions = structured.methods,\n            reconstructionTruncated = structured.truncated,\n''',
        '''            methodDefinitions = structured.methods,\n            fieldDefinitions = structured.fields,\n            reconstructionTruncated = structured.truncated,\n''',
        1,
    )

# Fix StructuredResult constructor used for missing required tables after adding fields.
scanner = scanner.replace(
    '''return StructuredResult(layout, ranges, emptyList(), emptyList(), false, "required IL2CPP metadata tables are absent")''',
    '''return StructuredResult(layout, ranges, emptyList(), emptyList(), emptyList(), false, "required IL2CPP metadata tables are absent")''',
)

if "val fieldsRange = ranges.firstOrNull" not in scanner:
    scanner = scanner.replace(
        '''        val methodsRange = ranges.firstOrNull { it.name == "methods" }\n        val typesRange = ranges.firstOrNull { it.name == "typeDefinitions" }\n''',
        '''        val methodsRange = ranges.firstOrNull { it.name == "methods" }\n        val fieldsRange = ranges.firstOrNull { it.name == "fields" }\n        val typesRange = ranges.firstOrNull { it.name == "typeDefinitions" }\n''',
        1,
    )

if "val fieldRecordSize = 12" not in scanner:
    scanner = scanner.replace(
        '''        val typeRecordSize = 88\n        val methodRecordSize = if (version == 31) 36 else 32\n        val declaredTypes = (typesRange.sizeBytes / typeRecordSize).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()\n        val declaredMethods = (methodsRange.sizeBytes / methodRecordSize).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()\n        var truncated = typesRange.sizeBytes % typeRecordSize != 0L || methodsRange.sizeBytes % methodRecordSize != 0L\n        val typeCount = minOf(declaredTypes, limits.maxTypeDefinitions)\n        val methodCount = minOf(declaredMethods, limits.maxMethodDefinitions)\n        if (typeCount < declaredTypes || methodCount < declaredMethods) truncated = true\n''',
        '''        val typeRecordSize = 88\n        val methodRecordSize = if (version == 31) 36 else 32\n        val fieldRecordSize = 12\n        val declaredTypes = (typesRange.sizeBytes / typeRecordSize).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()\n        val declaredMethods = (methodsRange.sizeBytes / methodRecordSize).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()\n        val declaredFields = ((fieldsRange?.sizeBytes ?: 0L) / fieldRecordSize).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()\n        var truncated = typesRange.sizeBytes % typeRecordSize != 0L || methodsRange.sizeBytes % methodRecordSize != 0L ||\n            ((fieldsRange?.sizeBytes ?: 0L) % fieldRecordSize != 0L)\n        val typeCount = minOf(declaredTypes, limits.maxTypeDefinitions)\n        val methodCount = minOf(declaredMethods, limits.maxMethodDefinitions)\n        val fieldCount = minOf(declaredFields, limits.maxFieldDefinitions)\n        if (typeCount < declaredTypes || methodCount < declaredMethods || fieldCount < declaredFields) truncated = true\n''',
        1,
    )

if "val fields = mutableListOf<Il2CppFieldDefinitionSummary>()" not in scanner:
    anchor = '''        val methods = mutableListOf<Il2CppMethodDefinitionSummary>()\n'''
    field_parse = '''        val fieldOwner = HashMap<Int, Il2CppTypeDefinitionSummary>()\n        types.forEach { type ->\n            if (type.fieldStart >= 0 && type.fieldCount > 0) {\n                repeat(type.fieldCount) { relative ->\n                    fieldOwner.putIfAbsent(type.fieldStart + relative, type)\n                }\n            }\n        }\n        val fields = mutableListOf<Il2CppFieldDefinitionSummary>()\n        val fieldTable = fieldsRange\n        if (fieldTable != null) {\n            repeat(fieldCount) { index ->\n                val baseLong = fieldTable.offset + index.toLong() * fieldRecordSize\n                if (baseLong < 0 || baseLong + fieldRecordSize > bytes.size) return@repeat\n                val base = baseLong.toInt()\n                val name = metadataString(u32le(bytes, base)) ?: return@repeat\n                val owner = fieldOwner[index]\n                fields += Il2CppFieldDefinitionSummary(\n                    index = index,\n                    declaringTypeIndex = owner?.index ?: -1,\n                    declaringType = owner?.fullName ?: "<unresolved-field-owner>",\n                    name = name,\n                    typeIndex = i32le(bytes, base + 4),\n                    token = u32le(bytes, base + 8),\n                )\n            }\n        }\n\n'''
    if anchor not in scanner:
        raise SystemExit("Il2CppScanner: methods parse anchor missing")
    scanner = scanner.replace(anchor, field_parse + anchor, 1)

scanner = scanner.replace(
    '''return StructuredResult(layout, ranges, types, methods, truncated, null)''',
    '''return StructuredResult(layout, ranges, types, methods, fields, truncated, null)''',
)

# ---- version ----
build = build.replace('versionCode = 43', 'versionCode = 44')
build = build.replace('versionName = "0.32.0-preview-durable-history"', 'versionName = "0.33.0-preview-il2cpp-pair"')
# In case the previous migration has not yet run on a fresh checkout.
build = build.replace('versionCode = 42', 'versionCode = 44')
build = build.replace('versionName = "0.31.0-preview-semantic-recovery"', 'versionName = "0.33.0-preview-il2cpp-pair"')
build = build.replace('versionCode = 41', 'versionCode = 44')
build = build.replace('versionName = "0.30.0-preview-full-mapping"', 'versionName = "0.33.0-preview-il2cpp-pair"')

model_path.write_text(model, encoding="utf-8")
scanner_path.write_text(scanner, encoding="utf-8")
build_path.write_text(build, encoding="utf-8")
print("v0.33 IL2CPP pair reconstruction applied")
