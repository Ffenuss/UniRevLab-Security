package org.unirevlab.security.analysis

import org.unirevlab.security.model.DexFieldXref
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Builds an original-style, reversible analyst mapping for the DEX symbols available in the
 * bounded static index. The output intentionally distinguishes recovered exact names from
 * evidence-based analyst aliases and deterministic fallbacks.
 *
 * Without an official R8/ProGuard mapping file the pre-obfuscation identifiers are information
 * that may no longer exist in the APK. Therefore this engine never labels inferred names as exact.
 */
object FullMappingEngine {
    enum class Origin { EXACT, SEMANTIC, STRUCTURAL, PRESERVED }

    data class Symbol(
        val kind: String,
        val ownerDescriptor: String,
        val obfuscatedSymbol: String,
        val reconstructedName: String,
        val origin: Origin,
        val confidence: AnalystMappingEngine.Confidence,
        val evidence: List<String>,
    )

    data class Result(
        val classesMapped: Int,
        val methodsMapped: Int,
        val fieldsMapped: Int,
        val exactSymbols: Int,
        val semanticSymbols: Int,
        val structuralSymbols: Int,
        val preservedSymbols: Int,
        val dexCoverageComplete: Boolean,
        val fieldInventoryComplete: Boolean,
        val symbols: List<Symbol>,
        val originalStyleMappingText: String,
        val provenanceMappingText: String,
    )

    fun generate(
        report: StaticAnalysisReport,
        officialMapping: DeobfuscationEngine.MappingSummary? = null,
        maxSymbols: Int = 50_000,
    ): Result {
        val dex = report.dex ?: return emptyResult(report)
        if (maxSymbols <= 0) return emptyResult(report)

        val automatic = AnalystMappingEngine.generate(report, maxEntries = maxSymbols)
        val automaticBySymbol = automatic.entries.associateBy { it.obfuscatedSymbol }
        val exact = officialMapping?.let { MappingDeobfuscator.resolve(report, it, limit = maxSymbols) }.orEmpty()
        val exactBySymbol = exact.associateBy { it.obfuscatedSymbol }

        val classRefs = dex.classes
            .asSequence()
            .filterNot { isFrameworkDescriptor(it.descriptor) || isGeneratedDescriptor(it.descriptor) }
            .distinctBy { it.dexEntry to it.descriptor }
            .toList()
        val classDescriptors = classRefs.mapTo(LinkedHashSet()) { it.descriptor }
        val classNames = LinkedHashMap<String, String>()
        val out = ArrayList<Symbol>(minOf(maxSymbols, classRefs.size + dex.methods.size + dex.fieldXrefs.size))

        fun add(symbol: Symbol) {
            if (out.size < maxSymbols) out += symbol
        }

        classRefs.forEach { cls ->
            val exactAlias = exactBySymbol[cls.descriptor]
            val automaticAlias = automaticBySymbol[cls.descriptor]
            val readable = !looksObfuscatedSimpleName(simpleClassName(cls.descriptor))
            val reconstructed = when {
                exactAlias != null -> exactAlias.originalSymbol
                automaticAlias != null -> recoveredClassName(cls.descriptor, automaticAlias.alias)
                readable -> descriptorToDotName(cls.descriptor)
                else -> recoveredClassName(cls.descriptor, "Class_c${cls.classIndex}")
            }
            classNames[cls.descriptor] = reconstructed
            add(
                Symbol(
                    kind = "CLASS",
                    ownerDescriptor = cls.descriptor,
                    obfuscatedSymbol = cls.descriptor,
                    reconstructedName = reconstructed,
                    origin = when {
                        exactAlias != null -> Origin.EXACT
                        automaticAlias?.basis == AnalystMappingEngine.Basis.SEMANTIC -> Origin.SEMANTIC
                        readable -> Origin.PRESERVED
                        else -> Origin.STRUCTURAL
                    },
                    confidence = when {
                        exactAlias != null -> AnalystMappingEngine.Confidence.HIGH
                        automaticAlias != null -> automaticAlias.confidence
                        readable -> AnalystMappingEngine.Confidence.HIGH
                        else -> AnalystMappingEngine.Confidence.LOW
                    },
                    evidence = when {
                        exactAlias != null -> listOf(exactAlias.evidence)
                        automaticAlias != null -> automaticAlias.evidence
                        readable -> listOf("Readable DEX class name preserved")
                        else -> listOf("Deterministic class alias from DEX class index")
                    },
                ),
            )
        }

        dex.methods.asSequence()
            .filter { it.declaringClass in classDescriptors }
            .distinctBy { Triple(it.dexEntry, it.methodIndex, it.declaringClass) }
            .forEach { method ->
                if (out.size >= maxSymbols) return@forEach
                val symbolKey = methodSymbol(method)
                val exactAlias = exactBySymbol[symbolKey]
                val automaticAlias = automaticBySymbol[symbolKey]
                val readable = method.name == "<init>" || method.name == "<clinit>" || !looksObfuscatedSimpleName(method.name)
                val reconstructedName = when {
                    exactAlias != null -> extractExactMemberName(exactAlias.originalSymbol, method.name)
                    automaticAlias != null -> automaticAlias.alias
                    readable -> method.name
                    else -> "method_m${method.methodIndex}"
                }
                add(
                    Symbol(
                        kind = "METHOD",
                        ownerDescriptor = method.declaringClass,
                        obfuscatedSymbol = symbolKey,
                        reconstructedName = reconstructedName,
                        origin = when {
                            exactAlias != null -> Origin.EXACT
                            automaticAlias?.basis == AnalystMappingEngine.Basis.SEMANTIC -> Origin.SEMANTIC
                            readable -> Origin.PRESERVED
                            else -> Origin.STRUCTURAL
                        },
                        confidence = when {
                            exactAlias != null -> AnalystMappingEngine.Confidence.HIGH
                            automaticAlias != null -> automaticAlias.confidence
                            readable -> AnalystMappingEngine.Confidence.HIGH
                            else -> AnalystMappingEngine.Confidence.LOW
                        },
                        evidence = when {
                            exactAlias != null -> listOf(exactAlias.evidence)
                            automaticAlias != null -> automaticAlias.evidence
                            readable -> listOf("Readable DEX member name preserved")
                            else -> listOf("Deterministic method alias from DEX method index")
                        },
                    ),
                )
            }

        dex.fieldXrefs.asSequence()
            .filter { it.declaringClass in classDescriptors }
            .distinctBy { Triple(it.dexEntry, it.fieldIndex, it.declaringClass) }
            .forEach { field ->
                if (out.size >= maxSymbols) return@forEach
                val key = fieldSymbol(field)
                val exactAlias = exactBySymbol[key]
                val automaticAlias = automaticBySymbol[key]
                val readable = !looksObfuscatedSimpleName(field.fieldName)
                val reconstructedName = when {
                    exactAlias != null -> extractExactFieldName(exactAlias.originalSymbol, field.fieldName)
                    automaticAlias != null -> automaticAlias.alias
                    readable -> field.fieldName
                    else -> "field_f${field.fieldIndex}"
                }
                add(
                    Symbol(
                        kind = "FIELD",
                        ownerDescriptor = field.declaringClass,
                        obfuscatedSymbol = key,
                        reconstructedName = reconstructedName,
                        origin = when {
                            exactAlias != null -> Origin.EXACT
                            automaticAlias?.basis == AnalystMappingEngine.Basis.SEMANTIC -> Origin.SEMANTIC
                            readable -> Origin.PRESERVED
                            else -> Origin.STRUCTURAL
                        },
                        confidence = when {
                            exactAlias != null -> AnalystMappingEngine.Confidence.HIGH
                            automaticAlias != null -> automaticAlias.confidence
                            readable -> AnalystMappingEngine.Confidence.HIGH
                            else -> AnalystMappingEngine.Confidence.LOW
                        },
                        evidence = when {
                            exactAlias != null -> listOf(exactAlias.evidence)
                            automaticAlias != null -> automaticAlias.evidence
                            readable -> listOf("Readable DEX field name preserved")
                            else -> listOf("Deterministic field alias from DEX field index")
                        },
                    ),
                )
            }

        val ordered = out.sortedWith(compareBy<Symbol>({ classNames[it.ownerDescriptor] ?: it.ownerDescriptor }, { kindOrder(it.kind) }, { it.obfuscatedSymbol }))
        val classesMapped = ordered.count { it.kind == "CLASS" }
        val methodsMapped = ordered.count { it.kind == "METHOD" }
        val fieldsMapped = ordered.count { it.kind == "FIELD" }
        val dexCoverageComplete = !dex.truncated && dex.parseErrors == 0 &&
            dex.classesIndexed >= dex.classesDeclared && dex.methodsIndexed >= dex.methodsDeclared

        return Result(
            classesMapped = classesMapped,
            methodsMapped = methodsMapped,
            fieldsMapped = fieldsMapped,
            exactSymbols = ordered.count { it.origin == Origin.EXACT },
            semanticSymbols = ordered.count { it.origin == Origin.SEMANTIC },
            structuralSymbols = ordered.count { it.origin == Origin.STRUCTURAL },
            preservedSymbols = ordered.count { it.origin == Origin.PRESERVED },
            dexCoverageComplete = dexCoverageComplete,
            // Current report model exposes field references, not the entire field_ids declaration table.
            // This flag deliberately remains false until the structural DEX inventory is extended.
            fieldInventoryComplete = false,
            symbols = ordered,
            originalStyleMappingText = renderOriginalStyle(report, ordered, classNames),
            provenanceMappingText = renderProvenance(report, ordered, dexCoverageComplete),
        )
    }

    private fun renderOriginalStyle(
        report: StaticAnalysisReport,
        symbols: List<Symbol>,
        classNames: Map<String, String>,
    ): String = buildString {
        appendLine("# UniRevLab Security reconstructed mapping")
        appendLine("# artifact_sha256=${report.artifact.sha256}")
        appendLine("# This file follows the class/member shape of R8/ProGuard mapping.txt.")
        appendLine("# EXACT names require the official mapping. SEMANTIC/STRUCTURAL names are analyst aliases.")
        val byOwner = symbols.groupBy { it.ownerDescriptor }
        classNames.entries.sortedBy { it.value }.forEach { (descriptor, reconstructedClass) ->
            append(reconstructedClass).append(" -> ").append(descriptorToDotName(descriptor)).appendLine(":")
            byOwner[descriptor].orEmpty().filter { it.kind == "FIELD" }.forEach { field ->
                val parsed = parseFieldSymbol(field.obfuscatedSymbol)
                append("    ")
                    .append(descriptorToJavaType(parsed.type, classNames)).append(' ')
                    .append(field.reconstructedName).append(" -> ")
                    .append(parsed.name).appendLine()
            }
            byOwner[descriptor].orEmpty().filter { it.kind == "METHOD" }.forEach { method ->
                val parsed = parseMethodSymbol(method.obfuscatedSymbol)
                append("    ")
                    .append(descriptorToJavaType(parsed.returnType, classNames)).append(' ')
                    .append(method.reconstructedName)
                    .append('(')
                    .append(parsed.parameters.joinToString(",") { descriptorToJavaType(it, classNames) })
                    .append(") -> ")
                    .append(parsed.name)
                    .appendLine()
            }
        }
    }

    private fun renderProvenance(
        report: StaticAnalysisReport,
        symbols: List<Symbol>,
        dexCoverageComplete: Boolean,
    ): String = buildString {
        appendLine("# UniRevLab Security full analyst mapping v2")
        appendLine("# artifact_sha256=${report.artifact.sha256}")
        appendLine("# dex_coverage_complete=$dexCoverageComplete")
        appendLine("# field_inventory_complete=false")
        appendLine("# IMPORTANT: only EXACT entries claim developer-original names.")
        appendLine("# format: KIND | OBFUSCATED_SYMBOL | RECONSTRUCTED_NAME | ORIGIN | CONFIDENCE | EVIDENCE")
        symbols.forEach { item ->
            append(item.kind).append(" | ")
                .append(escape(item.obfuscatedSymbol)).append(" | ")
                .append(escape(item.reconstructedName)).append(" | ")
                .append(item.origin).append(" | ")
                .append(item.confidence).append(" | ")
                .append(escape(item.evidence.take(3).joinToString("; ")))
                .appendLine()
        }
    }

    private fun emptyResult(report: StaticAnalysisReport) = Result(
        classesMapped = 0,
        methodsMapped = 0,
        fieldsMapped = 0,
        exactSymbols = 0,
        semanticSymbols = 0,
        structuralSymbols = 0,
        preservedSymbols = 0,
        dexCoverageComplete = false,
        fieldInventoryComplete = false,
        symbols = emptyList(),
        originalStyleMappingText = "# UniRevLab Security reconstructed mapping\n# artifact_sha256=${report.artifact.sha256}\n",
        provenanceMappingText = "# UniRevLab Security full analyst mapping v2\n# artifact_sha256=${report.artifact.sha256}\n",
    )

    private fun recoveredClassName(descriptor: String, alias: String): String {
        val originalPackage = descriptor.removePrefix("L").removeSuffix(";").substringBeforeLast('/', "")
            .replace('/', '.')
            .replace(Regex("[^A-Za-z0-9_.]"), "_")
            .trim('.')
        val safeAlias = alias.replace(Regex("[^A-Za-z0-9_$]"), "_").ifBlank { "RecoveredClass" }
        return buildString {
            append("unirevlab.recovered")
            if (originalPackage.isNotBlank()) append('.').append(originalPackage)
            append('.').append(safeAlias)
        }
    }

    private fun methodSymbol(method: DexMethodReference): String =
        "${method.declaringClass}->${method.name}${method.prototype}"

    private fun fieldSymbol(field: DexFieldXref): String =
        "${field.declaringClass}->${field.fieldName}:${field.fieldType}"

    private fun extractExactMemberName(original: String, fallback: String): String {
        val beforeProto = original.substringBefore('(')
        return beforeProto.substringAfterLast('.').ifBlank { fallback }
    }

    private fun extractExactFieldName(original: String, fallback: String): String =
        original.substringBefore(':').substringAfterLast('.').ifBlank { fallback }

    private data class ParsedMethod(val name: String, val parameters: List<String>, val returnType: String)
    private data class ParsedField(val name: String, val type: String)

    private fun parseMethodSymbol(symbol: String): ParsedMethod {
        val member = symbol.substringAfter("->")
        val name = member.substringBefore('(')
        val proto = member.substringAfter(name)
        val close = proto.indexOf(')')
        if (!proto.startsWith('(') || close < 0) return ParsedMethod(name, emptyList(), "V")
        val paramsText = proto.substring(1, close)
        val returnType = proto.substring(close + 1).ifBlank { "V" }
        return ParsedMethod(name, splitDescriptors(paramsText), returnType)
    }

    private fun parseFieldSymbol(symbol: String): ParsedField {
        val member = symbol.substringAfter("->")
        return ParsedField(member.substringBefore(':'), member.substringAfter(':', "Ljava/lang/Object;"))
    }

    private fun splitDescriptors(text: String): List<String> {
        if (text.isEmpty()) return emptyList()
        val out = mutableListOf<String>()
        var index = 0
        while (index < text.length) {
            val start = index
            while (index < text.length && text[index] == '[') index++
            if (index >= text.length) break
            if (text[index] == 'L') {
                val end = text.indexOf(';', index)
                if (end < 0) break
                index = end + 1
            } else {
                index++
            }
            out += text.substring(start, index)
        }
        return out
    }

    private fun descriptorToJavaType(descriptor: String, classNames: Map<String, String>): String {
        var d = descriptor
        var arrays = 0
        while (d.startsWith("[")) {
            arrays++
            d = d.substring(1)
        }
        val base = when (d) {
            "V" -> "void"
            "Z" -> "boolean"
            "B" -> "byte"
            "S" -> "short"
            "C" -> "char"
            "I" -> "int"
            "J" -> "long"
            "F" -> "float"
            "D" -> "double"
            else -> classNames[d] ?: descriptorToDotName(d)
        }
        return base + "[]".repeat(arrays)
    }

    private fun descriptorToDotName(descriptor: String): String = when {
        descriptor.startsWith('L') && descriptor.endsWith(';') -> descriptor.substring(1, descriptor.length - 1).replace('/', '.')
        else -> descriptor
    }

    private fun simpleClassName(descriptor: String): String =
        descriptor.removePrefix("L").removeSuffix(";").substringAfterLast('/').substringBefore('$')

    private fun looksObfuscatedSimpleName(name: String): Boolean {
        if (name in SAFE_SHORT_NAMES) return false
        return (name.length <= 2 && name.all { it.isLetterOrDigit() || it == '_' || it == '$' }) || OPAQUE_NAME.matches(name)
    }

    private fun isFrameworkDescriptor(descriptor: String): Boolean = FRAMEWORK_PREFIXES.any(descriptor::startsWith)

    private fun isGeneratedDescriptor(descriptor: String): Boolean {
        val simple = descriptor.removeSuffix(";").substringAfterLast('/')
        return simple == "R" || simple.startsWith("R$") || simple == "BuildConfig"
    }

    private fun kindOrder(kind: String): Int = when (kind) {
        "CLASS" -> 0
        "FIELD" -> 1
        "METHOD" -> 2
        else -> 3
    }

    private fun escape(value: String): String = value
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", "\\n")
        .replace("\r", "")

    private val OPAQUE_NAME = Regex("^[a-zA-Z]{1,2}[0-9]{0,2}$")
    private val SAFE_SHORT_NAMES = setOf("R", "id", "get", "set", "run", "map", "let", "use", "add", "put")
    private val FRAMEWORK_PREFIXES = listOf(
        "Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/", "Lkotlinx/",
        "Lorg/json/", "Lokhttp3/", "Lretrofit2/", "Lcom/google/", "Lcom/android/",
    )
}
