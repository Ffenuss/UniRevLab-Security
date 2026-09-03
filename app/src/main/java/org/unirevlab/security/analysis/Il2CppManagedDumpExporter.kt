package org.unirevlab.security.analysis

import java.io.File
import java.io.RandomAccessFile
import org.unirevlab.security.model.Il2CppMethodDefinitionSummary
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Deterministic C#-like IL2CPP managed metadata reconstruction for defensive review.
 *
 * This is intentionally not a patch script. It reconstructs namespace/type/member structure,
 * method signatures that can be recovered from global-metadata.dat, analyst aliases and validated
 * native identity evidence. Runtime RVA/VA/patch offsets are deliberately not emitted.
 */
object Il2CppManagedDumpExporter {
    private fun Appendable.append(value: Any?): Appendable = append(value.toString())
    private data class ParameterSignature(
        val name: String,
        val typeIndex: Int,
    )

    private data class MethodSignature(
        val returnTypeIndex: Int,
        val parameters: List<ParameterSignature>,
    )

    private data class MetadataSignatureIndex(
        val version: Int,
        val methods: Map<Int, MethodSignature>,
        val warnings: List<String>,
    )

    fun export(
        report: StaticAnalysisReport,
        maxMethods: Int = 100_000,
        maxFields: Int = 100_000,
    ): String = export(report, metadataFile = null, maxMethods = maxMethods, maxFields = maxFields)

    fun export(
        report: StaticAnalysisReport,
        metadataFile: File?,
        maxMethods: Int = 100_000,
        maxFields: Int = 100_000,
    ): String = buildString {
        write(report, metadataFile, this, maxMethods, maxFields)
    }

    /** Streams the dump so large IL2CPP projects do not require a second in-memory copy. */
    fun write(
        report: StaticAnalysisReport,
        metadataFile: File?,
        out: Appendable,
        maxMethods: Int = 100_000,
        maxFields: Int = 100_000,
    ) {
        val il2cpp = report.il2cpp
        val metadata = il2cpp?.metadata
        if (il2cpp?.detected != true || metadata == null) {
            out.run {
                appendLine("// UniRevLab IL2CPP reconstructed managed dump")
                appendLine("// artifact_sha256=${report.artifact.sha256}")
                appendLine("// status=IL2CPP_METADATA_NOT_AVAILABLE")
            }
            return
        }

        val signatureIndex = metadataFile
            ?.takeIf { it.isFile && it.canRead() }
            ?.let { runCatching { readSignatureIndex(it, metadata.methodDefinitions) }.getOrNull() }
        val nativeEvidence = Il2CppNativeEvidenceEngine.analyze(report)
        val nativeEvidenceByMethod = nativeEvidence.methods.associateBy { it.methodIndex }
        val analystMapping = Il2CppSemanticMappingEngine.analyze(report)
        val bestAliasBySymbol = analystMapping.entries
            .groupBy { it.kind to it.symbolIndex }
            .mapValues { (_, values) -> values.minByOrNull(::mappingRank) }
        val methodsByType = metadata.methodDefinitions.groupBy { it.declaringTypeIndex }
        val fieldsByType = metadata.fieldDefinitions.groupBy { it.declaringTypeIndex }
        val methodLimit = maxMethods.coerceAtLeast(0)
        val fieldLimit = maxFields.coerceAtLeast(0)
        var emittedMethods = 0
        var emittedFields = 0

        out.run {
            appendLine("// UniRevLab IL2CPP reconstructed managed dump v3")
            appendLine("// artifact_sha256=${report.artifact.sha256}")
            appendLine("// metadata_entry=${metadata.entryName}")
            appendLine("// metadata_version=${metadata.metadataVersion ?: signatureIndex?.version ?: "unknown"}")
            appendLine("// layout_profile=${metadata.layoutProfile ?: "unknown"}")
            appendLine("// types=${metadata.typeDefinitions.size} methods=${metadata.methodDefinitions.size} fields=${metadata.fieldDefinitions.size}")
            appendLine("// coverage=${if (!metadata.truncated && !metadata.reconstructionTruncated && metadata.parseError == null) "COMPLETE" else "PARTIAL"}")
            appendLine("// Names below are exact identities present in global-metadata.dat; they may already be obfuscated.")
            appendLine("// analyst-alias comments are hypotheses/navigation labels, never claimed original developer names.")
            appendLine("// TypeRef#N means the metadata type index is known but its concrete Il2CppType still requires MetadataRegistration resolution.")
            appendLine("// Native evidence is identity/token validated. Runtime RVA/VA/patch offsets are not emitted.")
            appendLine("// native_evidence_available=${nativeEvidence.correlationDataAvailable} verified=${nativeEvidence.verified} supported=${nativeEvidence.supported} weak=${nativeEvidence.weak} conflicting=${nativeEvidence.conflicting}")
            signatureIndex?.warnings.orEmpty().forEach { appendLine("// signature-warning: ${sanitize(it)}") }
            appendLine()

            metadata.typeDefinitions.sortedBy { it.index }.forEach { type ->
                val namespace = type.namespace.takeIf { it.isNotBlank() }
                if (namespace != null) {
                    append("namespace ").append(safeQualifiedIdentifier(namespace)).appendLine()
                    appendLine("{")
                }
                appendLine("    // TypeDefIndex: ${type.index} · token: 0x${type.token.toString(16)}")
                bestAliasBySymbol["TYPE" to type.index]?.let { alias ->
                    appendLine("    // analyst-alias: ${safeIdentifier(alias.alias)} · ${alias.basis}/${alias.confidence}${alias.semanticCategory?.let { " · $it" } ?: ""}")
                }
                append("    class ").append(safeIdentifier(type.name)).appendLine()
                appendLine("    {")

                val typeFields = fieldsByType[type.index].orEmpty().sortedBy { it.index }
                if (typeFields.isNotEmpty()) appendLine("        // Fields")
                typeFields.forEach { field ->
                    if (emittedFields >= fieldLimit) return@forEach
                    bestAliasBySymbol["FIELD" to field.index]?.let { alias ->
                        appendLine("        // analyst-alias: ${safeIdentifier(alias.alias)} · ${alias.basis}/${alias.confidence}${alias.semanticCategory?.let { " · $it" } ?: ""}")
                    }
                    append("        // FieldIndex: ").append(field.index)
                        .append(" · token: 0x").append(field.token.toString(16))
                        .append(" · typeIndex: ").append(field.typeIndex)
                        .appendLine()
                    append("        /*TypeRef#").append(field.typeIndex).append("*/ object ")
                        .append(safeIdentifier(field.name)).appendLine(";")
                    emittedFields++
                }

                val typeMethods = methodsByType[type.index].orEmpty().sortedBy { it.index }
                if (typeMethods.isNotEmpty()) {
                    if (typeFields.isNotEmpty()) appendLine()
                    appendLine("        // Methods")
                }
                typeMethods.forEach { method ->
                    if (emittedMethods >= methodLimit) return@forEach
                    val signature = signatureIndex?.methods?.get(method.index)
                    bestAliasBySymbol["METHOD" to method.index]?.let { alias ->
                        appendLine("        // analyst-alias: ${safeIdentifier(alias.alias)} · ${alias.basis}/${alias.confidence}${alias.semanticCategory?.let { " · $it" } ?: ""}")
                        alias.evidence.take(2).forEach { evidence -> appendLine("        // evidence: ${sanitize(evidence)}") }
                    }
                    nativeEvidenceByMethod[method.index]?.takeIf { evidence ->
                        evidence.verdict != Il2CppNativeEvidenceEngine.Verdict.CONFLICTING &&
                            !evidence.nativeFunctionName.isNullOrBlank()
                    }?.let { correlation ->
                        append("        // native-evidence: ").append(correlation.verdict)
                            .append(" · ").append(sanitize(correlation.nativeFunctionName.orEmpty()))
                        correlation.sourceConfidence?.takeIf { it.isNotBlank() }?.let { append(" · confidence=").append(sanitize(it)) }
                        appendLine()
                    }
                    append("        // MethodIndex: ").append(method.index)
                        .append(" · token: 0x").append(method.token.toString(16))
                        .append(" · flags: 0x").append(method.flags.toString(16))
                        .appendLine()
                    val modifiers = methodModifiers(method.flags)
                    append("        ")
                    if (modifiers.isNotBlank()) append(modifiers).append(' ')
                    val returnTypeIndex = signature?.returnTypeIndex
                    if (returnTypeIndex != null) {
                        append("/*TypeRef#").append(returnTypeIndex).append("*/ object ")
                    } else {
                        append("object ")
                    }
                    append(safeIdentifier(method.name)).append('(')
                    val parameters = signature?.parameters
                    if (parameters != null && parameters.size == method.parameterCount) {
                        parameters.forEachIndexed { index, parameter ->
                            if (index > 0) append(", ")
                            append("/*TypeRef#").append(parameter.typeIndex).append("*/ object ")
                                .append(safeIdentifier(parameter.name.ifBlank { "arg$index" }))
                        }
                    } else {
                        repeat(method.parameterCount) { index ->
                            if (index > 0) append(", ")
                            append("object arg").append(index)
                        }
                    }
                    appendLine(");")
                    emittedMethods++
                }

                appendLine("    }")
                if (namespace != null) appendLine("}")
                appendLine()
            }

            if (emittedFields < metadata.fieldDefinitions.size) appendLine("// fields_truncated=true emitted=$emittedFields")
            if (emittedMethods < metadata.methodDefinitions.size) appendLine("// methods_truncated=true emitted=$emittedMethods")
            appendLine("// ---- IL2CPP ANALYST MAPPING ----")
            analystMapping.mappingText.lineSequence().forEach { line -> append("// ").appendLine(line) }
        }
    }

    private fun mappingRank(entry: Il2CppSemanticMappingEngine.Entry): Int = when (entry.basis) {
        Il2CppSemanticMappingEngine.Basis.EXACT_SEMANTIC -> 0
        Il2CppSemanticMappingEngine.Basis.CONTEXTUAL -> 1
        Il2CppSemanticMappingEngine.Basis.STRUCTURAL -> 2
    }

    /**
     * Reads only the method/parameter/string tables needed for human-readable signatures. It uses
     * RandomAccessFile so a large metadata file is not duplicated in memory by the exporter.
     */
    private fun readSignatureIndex(
        file: File,
        reportMethods: List<Il2CppMethodDefinitionSummary>,
    ): MetadataSignatureIndex {
        RandomAccessFile(file, "r").use { raf ->
            require(raf.length() >= 168L) { "metadata header is truncated" }
            val magic = readU32Le(raf, 0)
            require(magic == 0xFAB11BAFL) { "unexpected metadata magic" }
            val version = readI32Le(raf, 4)
            require(version in 27..31) { "signature reconstruction is enabled for metadata v27-v31" }
            val strings = readPair(raf, 2, "strings")
            val methods = readPair(raf, 5, "methods")
            val parameters = readPair(raf, 10, "parameters")
            val methodRecordSize = if (version == 31) 36 else 32
            require(methods.size % methodRecordSize == 0L) { "unexpected method table record size" }
            val methodCount = (methods.size / methodRecordSize).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            val parameterRecordSize = when {
                parameters.size == 0L -> 12
                parameters.size % 12L == 0L -> 12
                parameters.size % 16L == 0L -> 16
                else -> 12
            }
            val parameterCount = if (parameters.size == 0L) 0 else
                (parameters.size / parameterRecordSize).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            val warnings = mutableListOf<String>()
            if (parameters.size > 0L && parameters.size % parameterRecordSize != 0L) {
                warnings += "parameter table size is not aligned to the inferred record size; parameter names/types may be partial"
            }
            val stringCache = HashMap<Long, String>()
            fun metadataString(relativeOffset: Long): String? {
                if (relativeOffset < 0 || relativeOffset >= strings.size) return null
                return stringCache.getOrPut(relativeOffset) {
                    readCString(raf, strings.offset + relativeOffset, minOf(1024L, strings.size - relativeOffset)) ?: ""
                }.takeIf { it.isNotEmpty() }
            }

            val out = HashMap<Int, MethodSignature>()
            reportMethods.forEach { method ->
                if (method.index !in 0 until methodCount) return@forEach
                val base = methods.offset + method.index.toLong() * methodRecordSize
                val returnTypeIndex = readI32Le(raf, base + 8)
                val parameterStart = readI32Le(raf, base + 12)
                val parsedParameters = ArrayList<ParameterSignature>(method.parameterCount)
                if (method.parameterCount > 0 && parameterStart >= 0) {
                    repeat(method.parameterCount) { relative ->
                        val index = parameterStart + relative
                        if (index !in 0 until parameterCount) return@repeat
                        val pBase = parameters.offset + index.toLong() * parameterRecordSize
                        val nameIndex = readU32Le(raf, pBase)
                        val typeIndexOffset = if (parameterRecordSize == 16) 12L else 8L
                        val typeIndex = readI32Le(raf, pBase + typeIndexOffset)
                        val name = metadataString(nameIndex) ?: "arg$relative"
                        parsedParameters += ParameterSignature(name = name, typeIndex = typeIndex)
                    }
                }
                out[method.index] = MethodSignature(returnTypeIndex, parsedParameters)
            }
            return MetadataSignatureIndex(version, out, warnings)
        }
    }

    private data class TableRange(val offset: Long, val size: Long)

    private fun readPair(raf: RandomAccessFile, index: Int, label: String): TableRange {
        val base = 8L + index.toLong() * 8L
        val offset = readU32Le(raf, base)
        val size = readU32Le(raf, base + 4)
        require(offset >= 0L && size >= 0L && offset <= raf.length() && size <= raf.length() - offset) {
            "$label table is outside metadata file"
        }
        return TableRange(offset, size)
    }

    private fun readCString(raf: RandomAccessFile, offset: Long, maxBytes: Long): String? {
        if (offset < 0 || offset >= raf.length() || maxBytes <= 0) return null
        raf.seek(offset)
        val out = java.io.ByteArrayOutputStream(minOf(maxBytes, 128L).toInt())
        var remaining = minOf(maxBytes, raf.length() - offset)
        while (remaining > 0) {
            val value = raf.read()
            if (value < 0 || value == 0) break
            out.write(value)
            remaining--
        }
        return out.toByteArray().toString(Charsets.UTF_8).take(512)
    }

    private fun readU32Le(raf: RandomAccessFile, offset: Long): Long {
        raf.seek(offset)
        val b0 = raf.readUnsignedByte().toLong()
        val b1 = raf.readUnsignedByte().toLong()
        val b2 = raf.readUnsignedByte().toLong()
        val b3 = raf.readUnsignedByte().toLong()
        return b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
    }

    private fun readI32Le(raf: RandomAccessFile, offset: Long): Int = readU32Le(raf, offset).toInt()

    private fun methodModifiers(flags: Int): String {
        val modifiers = mutableListOf<String>()
        when (flags and 0x0007) {
            0x0001 -> modifiers += "private"
            0x0002 -> modifiers += "private protected"
            0x0003 -> modifiers += "internal"
            0x0004 -> modifiers += "protected"
            0x0005 -> modifiers += "protected internal"
            0x0006 -> modifiers += "public"
        }
        if ((flags and 0x0010) != 0) modifiers += "static"
        if ((flags and 0x0040) != 0) modifiers += "virtual"
        if ((flags and 0x0400) != 0) modifiers += "abstract"
        return modifiers.joinToString(" ")
    }

    private fun safeQualifiedIdentifier(value: String): String = value.split('.').joinToString(".") { safeIdentifier(it) }

    private fun safeIdentifier(value: String): String {
        if (value.isBlank()) return "unnamed"
        val sanitized = buildString(value.length + 1) {
            value.forEachIndexed { index, ch ->
                when {
                    ch == '_' || ch.isLetterOrDigit() -> {
                        if (index == 0 && ch.isDigit()) append('_')
                        append(ch)
                    }
                    ch == '`' -> append('_')
                    else -> append('_')
                }
            }
        }
        return if (sanitized in CSHARP_KEYWORDS) "@$sanitized" else sanitized
    }

    private fun sanitize(value: String): String = value
        .replace('\n', ' ')
        .replace('\r', ' ')
        .replace('\t', ' ')
        .take(320)

    private val CSHARP_KEYWORDS = setOf(
        "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked",
        "class", "const", "continue", "decimal", "default", "delegate", "do", "double", "else",
        "enum", "event", "explicit", "extern", "false", "finally", "fixed", "float", "for", "foreach",
        "goto", "if", "implicit", "in", "int", "interface", "internal", "is", "lock", "long", "namespace",
        "new", "null", "object", "operator", "out", "override", "params", "private", "protected", "public",
        "readonly", "ref", "return", "sbyte", "sealed", "short", "sizeof", "stackalloc", "static", "string",
        "struct", "switch", "this", "throw", "true", "try", "typeof", "uint", "ulong", "unchecked", "unsafe",
        "ushort", "using", "virtual", "void", "volatile", "while",
    )
}
