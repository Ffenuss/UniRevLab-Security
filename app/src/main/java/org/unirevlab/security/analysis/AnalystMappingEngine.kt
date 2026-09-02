package org.unirevlab.security.analysis

import org.unirevlab.security.model.DexFieldXref
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Builds a deterministic analyst mapping for obfuscated DEX symbols.
 *
 * The mapping is intentionally explicit about provenance: semantic aliases are inferred from
 * evidence already collected by the static analyzer, while symbols without enough semantic
 * evidence receive stable structural aliases. These aliases are analysis labels, not claims that
 * the developer's original pre-R8/ProGuard identifiers have been recovered.
 */
object AnalystMappingEngine {
    enum class Confidence { HIGH, MEDIUM, LOW }
    enum class Basis { SEMANTIC, STRUCTURAL }

    data class Entry(
        val kind: String,
        val obfuscatedSymbol: String,
        val alias: String,
        val confidence: Confidence,
        val basis: Basis,
        val evidence: List<String>,
    )

    data class Result(
        val obfuscationScore: Int,
        val likelyObfuscated: Boolean,
        val suspectedSymbols: Int,
        val mappedSymbols: Int,
        val semanticMappings: Int,
        val structuralMappings: Int,
        val coverageComplete: Boolean,
        val entries: List<Entry>,
        val mappingText: String,
    )

    fun generate(report: StaticAnalysisReport, maxEntries: Int = 10_000): Result {
        val summary = DeobfuscationEngine.analyze(report, maxAliases = maxEntries.coerceAtLeast(0))
        val dex = report.dex
        if (dex == null || maxEntries <= 0) {
            return Result(
                obfuscationScore = summary.score,
                likelyObfuscated = summary.likelyObfuscated,
                suspectedSymbols = 0,
                mappedSymbols = 0,
                semanticMappings = 0,
                structuralMappings = 0,
                coverageComplete = false,
                entries = emptyList(),
                mappingText = renderMapping(report, summary, emptyList(), truncated = false),
            )
        }

        val semantic = summary.aliases.associateBy { it.original }
        val entries = LinkedHashMap<String, Entry>()
        var suspected = 0
        var truncated = false

        fun add(entry: Entry) {
            suspected++
            if (entries.size >= maxEntries) {
                truncated = true
                return
            }
            entries.putIfAbsent("${entry.kind}|${entry.obfuscatedSymbol}", entry)
        }

        dex.classes.asSequence()
            .filterNot { isFrameworkDescriptor(it.descriptor) || isGeneratedDescriptor(it.descriptor) }
            .filter { looksObfuscatedClass(it.descriptor) }
            .forEach { cls ->
                val exact = semantic[cls.descriptor]
                add(
                    if (exact != null) {
                        Entry(
                            kind = "CLASS",
                            obfuscatedSymbol = cls.descriptor,
                            alias = sanitizeAlias(exact.suggestedAlias, "Class_c${cls.classIndex}"),
                            confidence = exact.confidence.toMappingConfidence(),
                            basis = Basis.SEMANTIC,
                            evidence = exact.reasons,
                        )
                    } else {
                        Entry(
                            kind = "CLASS",
                            obfuscatedSymbol = cls.descriptor,
                            alias = "Class_c${cls.classIndex}",
                            confidence = Confidence.LOW,
                            basis = Basis.STRUCTURAL,
                            evidence = listOf("Short/opaque class identifier; stable alias uses DEX class index"),
                        )
                    },
                )
            }

        dex.methods.asSequence()
            .filterNot { it.name == "<init>" || it.name == "<clinit>" }
            .filterNot { isFrameworkDescriptor(it.declaringClass) }
            .filter(::looksObfuscatedMethod)
            .forEach { method ->
                val symbol = methodSymbol(method)
                val exact = semantic[symbol]
                add(
                    if (exact != null) {
                        Entry(
                            kind = "METHOD",
                            obfuscatedSymbol = symbol,
                            alias = sanitizeAlias(exact.suggestedAlias, "Method_m${method.methodIndex}"),
                            confidence = exact.confidence.toMappingConfidence(),
                            basis = Basis.SEMANTIC,
                            evidence = exact.reasons,
                        )
                    } else {
                        Entry(
                            kind = "METHOD",
                            obfuscatedSymbol = symbol,
                            alias = "Method_m${method.methodIndex}",
                            confidence = Confidence.LOW,
                            basis = Basis.STRUCTURAL,
                            evidence = listOf("Short/opaque method identifier; stable alias uses DEX method index"),
                        )
                    },
                )
            }

        dex.fieldXrefs.asSequence()
            .distinctBy { FieldKey(it.dexEntry, it.declaringClass, it.fieldIndex) }
            .filterNot { isFrameworkDescriptor(it.declaringClass) }
            .filter(::looksObfuscatedField)
            .forEach { field ->
                add(
                    Entry(
                        kind = "FIELD",
                        obfuscatedSymbol = "${field.declaringClass}->${field.fieldName}:${field.fieldType}",
                        alias = "Field_f${field.fieldIndex}",
                        confidence = Confidence.LOW,
                        basis = Basis.STRUCTURAL,
                        evidence = listOf("Referenced short/opaque field identifier; stable alias uses DEX field index"),
                    ),
                )
            }

        val ordered = entries.values.sortedWith(
            compareBy<Entry>({ basisOrder(it.basis) }, { confidenceOrder(it.confidence) }, { kindOrder(it.kind) }, { it.obfuscatedSymbol }),
        )
        val semanticCount = ordered.count { it.basis == Basis.SEMANTIC }
        val structuralCount = ordered.size - semanticCount
        val complete = summary.coverageComplete && !truncated

        return Result(
            obfuscationScore = summary.score,
            likelyObfuscated = summary.likelyObfuscated,
            suspectedSymbols = suspected,
            mappedSymbols = ordered.size,
            semanticMappings = semanticCount,
            structuralMappings = structuralCount,
            coverageComplete = complete,
            entries = ordered,
            mappingText = renderMapping(report, summary, ordered, truncated),
        )
    }

    private fun renderMapping(
        report: StaticAnalysisReport,
        summary: DeobfuscationEngine.Summary,
        entries: List<Entry>,
        truncated: Boolean,
    ): String = buildString {
        appendLine("# UniRevLab Security analyst mapping v1")
        appendLine("# artifact_sha256=${report.artifact.sha256}")
        appendLine("# obfuscation_score=${summary.score}/100")
        appendLine("# likely_obfuscated=${summary.likelyObfuscated}")
        appendLine("# dex_coverage_complete=${summary.coverageComplete}")
        appendLine("# IMPORTANT: aliases below are analyst labels, not recovered developer-original identifiers.")
        appendLine("# SEMANTIC = inferred from static evidence; STRUCTURAL = deterministic neutral fallback.")
        if (truncated) appendLine("# truncated=true")
        appendLine("# format: KIND | OBFUSCATED_SYMBOL | ANALYST_ALIAS | CONFIDENCE | BASIS | EVIDENCE")
        entries.forEach { entry ->
            append(entry.kind).append(" | ")
                .append(escape(entry.obfuscatedSymbol)).append(" | ")
                .append(escape(entry.alias)).append(" | ")
                .append(entry.confidence).append(" | ")
                .append(entry.basis).append(" | ")
                .append(escape(entry.evidence.take(3).joinToString("; ")))
                .appendLine()
        }
    }

    private fun methodSymbol(method: DexMethodReference): String =
        "${method.declaringClass}->${method.name}${method.prototype}"

    private fun looksObfuscatedClass(descriptor: String): Boolean {
        val simple = descriptor.removePrefix("L").removeSuffix(";")
            .substringAfterLast('/')
            .substringBefore('$')
        if (simple in SAFE_SHORT_CLASS_NAMES) return false
        return (simple.length <= 2 && simple.all(::isIdentifierChar)) || OPAQUE_NAME.matches(simple)
    }

    private fun looksObfuscatedMethod(method: DexMethodReference): Boolean {
        val name = method.name
        if (name in SAFE_SHORT_METHOD_NAMES) return false
        return (name.length <= 2 && name.all(::isIdentifierChar)) || OPAQUE_NAME.matches(name)
    }

    private fun looksObfuscatedField(field: DexFieldXref): Boolean {
        val name = field.fieldName
        if (name in SAFE_SHORT_FIELD_NAMES) return false
        return (name.length <= 2 && name.all(::isIdentifierChar)) || OPAQUE_NAME.matches(name)
    }

    private fun isFrameworkDescriptor(descriptor: String): Boolean = FRAMEWORK_PREFIXES.any(descriptor::startsWith)

    private fun isGeneratedDescriptor(descriptor: String): Boolean {
        val simple = descriptor.removeSuffix(";").substringAfterLast('/')
        return simple == "R" || simple.startsWith("R$") || simple == "BuildConfig"
    }

    private fun sanitizeAlias(value: String, fallback: String): String {
        val clean = value.map { ch -> if (ch.isLetterOrDigit() || ch == '_' || ch == '$') ch else '_' }
            .joinToString("")
            .trim('_')
            .take(120)
        return clean.ifBlank { fallback }
    }

    private fun escape(value: String): String = value
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", "\\n")
        .replace("\r", "")

    private fun isIdentifierChar(ch: Char): Boolean = ch.isLetterOrDigit() || ch == '_' || ch == '$'

    private fun DeobfuscationEngine.AliasConfidence.toMappingConfidence(): Confidence = when (this) {
        DeobfuscationEngine.AliasConfidence.HIGH -> Confidence.HIGH
        DeobfuscationEngine.AliasConfidence.MEDIUM -> Confidence.MEDIUM
        DeobfuscationEngine.AliasConfidence.LOW -> Confidence.LOW
    }

    private fun basisOrder(value: Basis): Int = if (value == Basis.SEMANTIC) 0 else 1
    private fun confidenceOrder(value: Confidence): Int = when (value) {
        Confidence.HIGH -> 0
        Confidence.MEDIUM -> 1
        Confidence.LOW -> 2
    }
    private fun kindOrder(value: String): Int = when (value) {
        "CLASS" -> 0
        "METHOD" -> 1
        "FIELD" -> 2
        else -> 3
    }

    private data class FieldKey(val dexEntry: String, val declaringClass: String, val fieldIndex: Int)

    private val OPAQUE_NAME = Regex("^[a-zA-Z]{1,2}[0-9]{0,2}$")
    private val FRAMEWORK_PREFIXES = listOf(
        "Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/", "Lkotlinx/",
        "Lorg/json/", "Lokhttp3/", "Lretrofit2/", "Lcom/google/", "Lcom/android/",
    )
    private val SAFE_SHORT_CLASS_NAMES = setOf("R")
    private val SAFE_SHORT_METHOD_NAMES = setOf(
        "get", "set", "run", "add", "put", "pop", "map", "let", "also", "apply", "use",
        "onCreate", "onStart", "onStop", "onResume", "onPause", "onDestroy", "invoke",
    )
    private val SAFE_SHORT_FIELD_NAMES = setOf("id", "x", "y", "z")
}
