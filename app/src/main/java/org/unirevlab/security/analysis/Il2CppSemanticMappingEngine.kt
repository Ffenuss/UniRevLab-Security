package org.unirevlab.security.analysis

import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Address-free semantic/structural analyst mapping for IL2CPP metadata.
 *
 * The aliases produced here are navigation labels inferred from metadata context. They are never
 * presented as recovered original developer identifiers and contain no runtime address/patch data.
 */
object Il2CppSemanticMappingEngine {
    enum class Confidence { HIGH, MEDIUM, LOW }
    enum class Basis { EXACT_SEMANTIC, CONTEXTUAL, STRUCTURAL }

    data class Entry(
        val kind: String,
        val symbolIndex: Int,
        val originalIdentity: String,
        val alias: String,
        val confidence: Confidence,
        val basis: Basis,
        val semanticCategory: String?,
        val evidence: List<String>,
    )

    data class Result(
        val obfuscationScore: Int,
        val likelyObfuscated: Boolean,
        val suspectedSymbols: Int,
        val mappedSymbols: Int,
        val semanticMappings: Int,
        val contextualMappings: Int,
        val structuralMappings: Int,
        val coverageComplete: Boolean,
        val entries: List<Entry>,
        val mappingText: String,
    )

    private data class TypeContext(
        val categories: Set<String>,
        val evidenceByCategory: Map<String, List<String>>,
        val typeHasDirectSemanticCategory: Set<String>,
    )

    fun analyze(report: StaticAnalysisReport, maxEntries: Int = 10_000): Result {
        val il2cpp = report.il2cpp
        val metadata = il2cpp?.metadata
        if (il2cpp?.detected != true || metadata == null) {
            return emptyResult(report.artifact.sha256)
        }

        val methodsByType = metadata.methodDefinitions.groupBy { it.declaringTypeIndex }
        val fieldsByType = metadata.fieldDefinitions.groupBy { it.declaringTypeIndex }
        val contexts = metadata.typeDefinitions.associate { type ->
            val evidence = linkedMapOf<String, MutableList<String>>()
            val directTypeCategories = semanticCategories(type.fullName)
            directTypeCategories.forEach { category ->
                evidence.getOrPut(category) { mutableListOf() }
                    .add("type ${type.fullName}")
            }
            methodsByType[type.index].orEmpty().forEach { method ->
                val identity = "${method.declaringType}.${method.name}"
                semanticCategories(method.name).forEach { category ->
                    evidence.getOrPut(category) { mutableListOf() }
                        .add("method $identity")
                }
            }
            fieldsByType[type.index].orEmpty().forEach { field ->
                val identity = "${field.declaringType}.${field.name}"
                semanticCategories(field.name).forEach { category ->
                    evidence.getOrPut(category) { mutableListOf() }
                        .add("field $identity")
                }
            }
            type.index to TypeContext(
                categories = evidence.keys,
                evidenceByCategory = evidence.mapValues { (_, values) -> values.distinct().take(6) },
                typeHasDirectSemanticCategory = directTypeCategories,
            )
        }

        val entries = ArrayList<Entry>()
        val limit = maxEntries.coerceAtLeast(0)
        var suspected = 0
        var weightedTotal = 0
        var weightedSuspected = 0

        fun account(kind: String, name: String): Boolean {
            val weight = if (kind == "TYPE") 3 else 1
            weightedTotal += weight
            val obfuscated = isLikelyObfuscatedName(name, kind)
            if (obfuscated) {
                suspected++
                weightedSuspected += weight
            }
            return obfuscated
        }

        fun add(entry: Entry) {
            if (entries.size < limit) entries += entry
        }

        metadata.typeDefinitions.sortedBy { it.index }.forEach { type ->
            val obfuscated = account("TYPE", type.name)
            val direct = semanticCategories(type.fullName)
            val context = contexts[type.index]
            when {
                direct.isNotEmpty() -> {
                    direct.forEach { category ->
                        add(
                            Entry(
                                kind = "TYPE",
                                symbolIndex = type.index,
                                originalIdentity = type.fullName,
                                alias = semanticAlias(category, "TYPE", type.index),
                                confidence = Confidence.HIGH,
                                basis = Basis.EXACT_SEMANTIC,
                                semanticCategory = category,
                                evidence = listOf(
                                    "Semantic marker is present in the exact managed type identity from global-metadata.dat.",
                                    "Alias is an analyst navigation label, not a recovered source name.",
                                ),
                            ),
                        )
                    }
                }
                obfuscated -> add(contextualOrStructural("TYPE", type.index, type.fullName, context))
            }
        }

        metadata.fieldDefinitions.sortedBy { it.index }.forEach { field ->
            val identity = "${field.declaringType}.${field.name}"
            val obfuscated = account("FIELD", field.name)
            val direct = semanticCategories(field.name)
            val context = contexts[field.declaringTypeIndex]
            when {
                direct.isNotEmpty() -> direct.forEach { category ->
                    add(
                        Entry(
                            kind = "FIELD",
                            symbolIndex = field.index,
                            originalIdentity = identity,
                            alias = semanticAlias(category, "FIELD", field.index),
                            confidence = Confidence.HIGH,
                            basis = Basis.EXACT_SEMANTIC,
                            semanticCategory = category,
                            evidence = listOf(
                                "Semantic marker is present in the exact managed field identity from global-metadata.dat.",
                                "fieldIndex=${field.index}, typeIndex=${field.typeIndex}, token=0x${field.token.toString(16)}",
                            ),
                        ),
                    )
                }
                obfuscated -> add(contextualOrStructural("FIELD", field.index, identity, context))
            }
        }

        metadata.methodDefinitions.sortedBy { it.index }.forEach { method ->
            val identity = "${method.declaringType}.${method.name}"
            val obfuscated = account("METHOD", method.name)
            val direct = semanticCategories(method.name)
            val context = contexts[method.declaringTypeIndex]
            when {
                direct.isNotEmpty() -> direct.forEach { category ->
                    add(
                        Entry(
                            kind = "METHOD",
                            symbolIndex = method.index,
                            originalIdentity = identity,
                            alias = semanticAlias(category, "METHOD", method.index),
                            confidence = Confidence.HIGH,
                            basis = Basis.EXACT_SEMANTIC,
                            semanticCategory = category,
                            evidence = listOf(
                                "Semantic marker is present in the exact managed method identity from global-metadata.dat.",
                                "methodIndex=${method.index}, params=${method.parameterCount}, token=0x${method.token.toString(16)}",
                            ),
                        ),
                    )
                }
                obfuscated -> add(contextualOrStructural("METHOD", method.index, identity, context))
            }
        }

        val score = if (weightedTotal == 0) 0 else ((weightedSuspected * 100.0) / weightedTotal).toInt().coerceIn(0, 100)
        val likelyObfuscated = suspected >= 5 && score >= 20
        val complete = metadata.magicValid && metadata.parseError == null &&
            !metadata.truncated && !metadata.reconstructionTruncated && il2cpp.parseErrors == 0 && !il2cpp.truncated
        val ordered = entries.sortedWith(
            compareBy<Entry>({ basisOrder(it.basis) }, { confidenceOrder(it.confidence) }, { it.kind }, { it.symbolIndex }, { it.semanticCategory.orEmpty() }),
        )
        val text = renderMapping(
            artifactSha256 = report.artifact.sha256,
            metadataVersion = metadata.metadataVersion,
            score = score,
            likelyObfuscated = likelyObfuscated,
            suspected = suspected,
            coverageComplete = complete,
            entries = ordered,
        )
        return Result(
            obfuscationScore = score,
            likelyObfuscated = likelyObfuscated,
            suspectedSymbols = suspected,
            mappedSymbols = ordered.size,
            semanticMappings = ordered.count { it.basis == Basis.EXACT_SEMANTIC },
            contextualMappings = ordered.count { it.basis == Basis.CONTEXTUAL },
            structuralMappings = ordered.count { it.basis == Basis.STRUCTURAL },
            coverageComplete = complete,
            entries = ordered,
            mappingText = text,
        )
    }

    private fun contextualOrStructural(
        kind: String,
        index: Int,
        identity: String,
        context: TypeContext?,
    ): Entry {
        val category = context?.categories?.singleOrNull()
        if (category != null) {
            val evidence = context.evidenceByCategory[category].orEmpty()
            val medium = category in context.typeHasDirectSemanticCategory || evidence.size >= 2
            return Entry(
                kind = kind,
                symbolIndex = index,
                originalIdentity = identity,
                alias = contextualAlias(category, kind, index),
                confidence = if (medium) Confidence.MEDIUM else Confidence.LOW,
                basis = Basis.CONTEXTUAL,
                semanticCategory = category,
                evidence = buildList {
                    add("The symbol name itself looks obfuscated; semantic role is inferred only from its enclosing type context.")
                    evidence.take(4).forEach { add("Context evidence: $it") }
                    add("Treat this as a review candidate, not as a recovered original identifier or confirmed runtime value.")
                },
            )
        }
        return Entry(
            kind = kind,
            symbolIndex = index,
            originalIdentity = identity,
            alias = structuralAlias(kind, index),
            confidence = Confidence.LOW,
            basis = Basis.STRUCTURAL,
            semanticCategory = null,
            evidence = listOf(
                "Short/opaque managed name suggests obfuscation.",
                "No unique semantic category could be inferred from metadata context; a stable structural analyst alias was assigned.",
            ),
        )
    }

    private fun semanticCategories(value: String): Set<String> {
        val normalized = normalize(value)
        return buildSet {
            if (PREMIUM_MARKERS.any { normalized.contains(it) }) add("PREMIUM")
            if (ENTITLEMENT_MARKERS.any { normalized.contains(it) }) add("ENTITLEMENT")
            if (SUBSCRIPTION_MARKERS.any { normalized.contains(it) }) add("SUBSCRIPTION")
            if (PURCHASE_MARKERS.any { normalized.contains(it) }) add("PURCHASE")
            if (ADS_MARKERS.any { normalized.contains(it) }) add("ADS_REMOVAL")
            if (VALIDATION_MARKERS.any { normalized.contains(it) }) add("RECEIPT_VALIDATION")
        }
    }

    private fun isLikelyObfuscatedName(name: String, kind: String): Boolean {
        val raw = name.trim()
        if (raw.isBlank()) return true
        if (raw in COMMON_NAMES || raw.startsWith("<") || raw.startsWith("op_")) return false
        val simplified = raw.removePrefix("get_").removePrefix("set_").trimStart('_')
        if (simplified in COMMON_NAMES) return false
        if (!OPAQUE_NAME.matches(simplified)) return false
        return when (kind) {
            "TYPE" -> simplified.length <= 2
            "METHOD", "FIELD" -> simplified.length <= 2
            else -> false
        }
    }

    private fun semanticAlias(category: String, kind: String, index: Int): String =
        "${category.lowercase()}_${kind.lowercase()}_$index"

    private fun contextualAlias(category: String, kind: String, index: Int): String =
        "${category.lowercase()}_related_${kind.lowercase()}_$index"

    private fun structuralAlias(kind: String, index: Int): String = when (kind) {
        "TYPE" -> "Type_t$index"
        "METHOD" -> "Method_m$index"
        "FIELD" -> "Field_f$index"
        else -> "Symbol_s$index"
    }

    private fun renderMapping(
        artifactSha256: String,
        metadataVersion: Int?,
        score: Int,
        likelyObfuscated: Boolean,
        suspected: Int,
        coverageComplete: Boolean,
        entries: List<Entry>,
    ): String = buildString {
        appendLine("# UniRevLab IL2CPP analyst mapping v1")
        appendLine("# artifact_sha256=$artifactSha256")
        appendLine("# metadata_version=${metadataVersion ?: "unknown"}")
        appendLine("# obfuscation_score=$score")
        appendLine("# likely_obfuscated=$likelyObfuscated")
        appendLine("# suspected_symbols=$suspected")
        appendLine("# coverage=${if (coverageComplete) "COMPLETE" else "PARTIAL"}")
        appendLine("# IMPORTANT: aliases are analyst navigation labels inferred from static metadata context; they are not recovered original developer names.")
        appendLine("# CONTEXTUAL entries are review hypotheses only and do not prove a field's live runtime value or authorization result.")
        appendLine("# KIND | INDEX | ORIGINAL_IDENTITY | ANALYST_ALIAS | CONFIDENCE | BASIS | SEMANTIC_CATEGORY | EVIDENCE")
        entries.forEach { entry ->
            append(sanitize(entry.kind)).append(" | ")
            append(entry.symbolIndex).append(" | ")
            append(sanitize(entry.originalIdentity)).append(" | ")
            append(sanitize(entry.alias)).append(" | ")
            append(entry.confidence).append(" | ")
            append(entry.basis).append(" | ")
            append(entry.semanticCategory ?: "-").append(" | ")
            append(entry.evidence.joinToString("; ") { sanitize(it) }).appendLine()
        }
    }

    private fun emptyResult(sha: String) = Result(
        obfuscationScore = 0,
        likelyObfuscated = false,
        suspectedSymbols = 0,
        mappedSymbols = 0,
        semanticMappings = 0,
        contextualMappings = 0,
        structuralMappings = 0,
        coverageComplete = false,
        entries = emptyList(),
        mappingText = "# UniRevLab IL2CPP analyst mapping\n# artifact_sha256=$sha\n# status=IL2CPP_METADATA_NOT_AVAILABLE\n",
    )

    private fun sanitize(value: String): String = value
        .replace('|', '/')
        .replace('\n', ' ')
        .replace('\r', ' ')
        .replace('\t', ' ')
        .take(320)

    private fun normalize(value: String): String = value.lowercase().filter(Char::isLetterOrDigit)
    private fun basisOrder(value: Basis): Int = when (value) {
        Basis.EXACT_SEMANTIC -> 0
        Basis.CONTEXTUAL -> 1
        Basis.STRUCTURAL -> 2
    }
    private fun confidenceOrder(value: Confidence): Int = when (value) {
        Confidence.HIGH -> 0
        Confidence.MEDIUM -> 1
        Confidence.LOW -> 2
    }

    private val OPAQUE_NAME = Regex("[A-Za-z][A-Za-z0-9]?")
    private val COMMON_NAMES = setOf(
        ".ctor", ".cctor", "ctor", "cctor", "id", "x", "y", "z", "ui", "go", "ok",
        "Start", "Update", "Awake", "OnEnable", "OnDisable", "OnDestroy", "OnGUI",
        "Equals", "GetHashCode", "ToString", "Invoke", "MoveNext", "Dispose", "Reset",
    )
    private val PREMIUM_MARKERS = listOf(
        "premium", "ispremium", "premiumuser", "premiumaccount", "vipuser", "isvip", "paiduser", "paidaccount", "isproaccount",
    )
    private val ENTITLEMENT_MARKERS = listOf(
        "entitlement", "entitled", "hasaccess", "featureaccess", "accesslevel", "productowned", "ownsproduct", "unlockstate", "featureunlocked",
    )
    private val SUBSCRIPTION_MARKERS = listOf(
        "subscription", "subscribed", "subscriber", "membership", "memberactive", "subscriptionactive",
    )
    private val PURCHASE_MARKERS = listOf(
        "purchase", "purchased", "inapppurchase", "inappbilling", "billingclient", "checkout", "restorepurchase", "iapmanager", "storeproduct",
    )
    private val ADS_MARKERS = listOf(
        "removeads", "adsremoved", "adfree", "noads", "disableads", "adsdisabled",
    )
    private val VALIDATION_MARKERS = listOf(
        "receipt", "verifyreceipt", "validatereceipt", "verifypurchase", "validatepurchase", "purchasevalidation", "servervalidation", "serververify", "backendverify", "storeverification",
    )
}
