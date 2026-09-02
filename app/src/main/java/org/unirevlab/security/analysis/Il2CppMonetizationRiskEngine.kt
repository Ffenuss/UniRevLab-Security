package org.unirevlab.security.analysis

import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Defensive IL2CPP monetization/entitlement attack-surface analysis.
 *
 * This engine works only with metadata and correlations already recovered by UniRevLab. It does
 * not patch libil2cpp, calculate a value to flip, or generate an unlock. Its purpose is to tell an
 * application owner which managed identities expose premium/IAP state to a client-side modder and
 * whether validation/server-side signals are also present.
 */
object Il2CppMonetizationRiskEngine {
    enum class Category {
        PREMIUM,
        ENTITLEMENT,
        SUBSCRIPTION,
        PURCHASE,
        ADS_REMOVAL,
        RECEIPT_VALIDATION,
    }

    enum class Confidence { HIGH, MEDIUM, LOW }

    enum class Posture {
        NOT_DETECTED,
        HIGH_REVIEW_PRIORITY,
        MIXED_CLIENT_AND_VALIDATION,
        VALIDATION_INDICATORS_PRESENT,
        METADATA_INCOMPLETE,
    }

    data class Candidate(
        val kind: String,
        val managedIdentity: String,
        val category: Category,
        val confidence: Confidence,
        val metadataToken: Long?,
        val methodIndex: Int?,
        val declaringType: String?,
        val nativeFunctionName: String?,
        val evidence: List<String>,
    )

    data class Result(
        val posture: Posture,
        val metadataVersion: Int?,
        val typeCount: Int,
        val methodCount: Int,
        val candidates: List<Candidate>,
        val monetizationCandidates: Int,
        val validationCandidates: Int,
        val clientStateCandidates: Int,
        val nativeCorrelations: Int,
        val coverageComplete: Boolean,
        val recommendations: List<String>,
    )

    fun analyze(report: StaticAnalysisReport, maxCandidates: Int = 500): Result {
        val il2cpp = report.il2cpp
        val metadata = il2cpp?.metadata
        if (il2cpp?.detected != true || metadata == null) {
            return Result(
                posture = Posture.NOT_DETECTED,
                metadataVersion = metadata?.metadataVersion,
                typeCount = metadata?.typeDefinitions?.size ?: 0,
                methodCount = metadata?.methodDefinitions?.size ?: 0,
                candidates = emptyList(),
                monetizationCandidates = 0,
                validationCandidates = 0,
                clientStateCandidates = 0,
                nativeCorrelations = 0,
                coverageComplete = false,
                recommendations = emptyList(),
            )
        }

        val nativeByMethod = report.correlations?.il2cppMethods.orEmpty()
            .groupBy { it.methodIndex }
        val candidates = LinkedHashMap<String, Candidate>()

        fun add(candidate: Candidate) {
            if (candidates.size >= maxCandidates.coerceAtLeast(0)) return
            val key = "${candidate.kind}|${candidate.managedIdentity}|${candidate.category}"
            candidates.putIfAbsent(key, candidate)
        }

        metadata.typeDefinitions.forEach { type ->
            classify(type.fullName).forEach { category ->
                add(
                    Candidate(
                        kind = "TYPE",
                        managedIdentity = type.fullName,
                        category = category,
                        confidence = Confidence.HIGH,
                        metadataToken = type.token,
                        methodIndex = null,
                        declaringType = type.fullName,
                        nativeFunctionName = null,
                        evidence = listOf(
                            "Exact managed type identity recovered from global-metadata.dat",
                            "Semantic marker: ${markerFor(type.fullName, category)}",
                        ),
                    ),
                )
            }
        }

        metadata.methodDefinitions.forEach { method ->
            val identity = "${method.declaringType}.${method.name}"
            classify(identity).forEach { category ->
                val native = nativeByMethod[method.index].orEmpty()
                    .firstOrNull { it.functionName.isNotBlank() }
                val evidence = buildList {
                    add("Exact managed method identity recovered from global-metadata.dat")
                    add("Semantic marker: ${markerFor(identity, category)}")
                    add("Metadata method index=${method.index}, token=0x${method.token.toString(16)}")
                    native?.let {
                        add("Correlated to recovered native function identity: ${it.functionName} (${it.confidence})")
                    }
                }
                add(
                    Candidate(
                        kind = "METHOD",
                        managedIdentity = identity,
                        category = category,
                        confidence = if (native != null) Confidence.HIGH else Confidence.HIGH,
                        metadataToken = method.token,
                        methodIndex = method.index,
                        declaringType = method.declaringType,
                        nativeFunctionName = native?.functionName,
                        evidence = evidence,
                    ),
                )
            }
        }

        metadata.managedNameCandidates.forEach { name ->
            classify(name).forEach { category ->
                add(
                    Candidate(
                        kind = "NAME",
                        managedIdentity = name,
                        category = category,
                        confidence = Confidence.MEDIUM,
                        metadataToken = null,
                        methodIndex = null,
                        declaringType = null,
                        nativeFunctionName = null,
                        evidence = listOf(
                            "Managed-name candidate recovered from global-metadata.dat string table",
                            "Semantic marker: ${markerFor(name, category)}",
                        ),
                    ),
                )
            }
        }

        val ordered = candidates.values.sortedWith(
            compareBy<Candidate>({ categoryOrder(it.category) }, { confidenceOrder(it.confidence) }, { it.managedIdentity }),
        )
        val monetization = ordered.count { it.category != Category.RECEIPT_VALIDATION }
        val validation = ordered.count { it.category == Category.RECEIPT_VALIDATION }
        val clientState = ordered.count(::looksLikeClientStateGate)
        val nativeCount = ordered.count { !it.nativeFunctionName.isNullOrBlank() }
        val complete = metadata.magicValid && metadata.parseError == null &&
            !metadata.truncated && !metadata.reconstructionTruncated && il2cpp.parseErrors == 0 && !il2cpp.truncated

        val posture = when {
            !complete && monetization == 0 && validation == 0 -> Posture.METADATA_INCOMPLETE
            clientState > 0 && validation == 0 -> Posture.HIGH_REVIEW_PRIORITY
            monetization > 0 && validation > 0 -> Posture.MIXED_CLIENT_AND_VALIDATION
            validation > 0 -> Posture.VALIDATION_INDICATORS_PRESENT
            else -> Posture.NOT_DETECTED
        }

        return Result(
            posture = posture,
            metadataVersion = metadata.metadataVersion,
            typeCount = metadata.typeDefinitions.size,
            methodCount = metadata.methodDefinitions.size,
            candidates = ordered,
            monetizationCandidates = monetization,
            validationCandidates = validation,
            clientStateCandidates = clientState,
            nativeCorrelations = nativeCount,
            coverageComplete = complete,
            recommendations = recommendations(posture, clientState, validation),
        )
    }

    private fun classify(value: String): Set<Category> {
        val normalized = normalize(value)
        return buildSet {
            if (PREMIUM_MARKERS.any(normalized::contains)) add(Category.PREMIUM)
            if (ENTITLEMENT_MARKERS.any(normalized::contains)) add(Category.ENTITLEMENT)
            if (SUBSCRIPTION_MARKERS.any(normalized::contains)) add(Category.SUBSCRIPTION)
            if (PURCHASE_MARKERS.any(normalized::contains)) add(Category.PURCHASE)
            if (ADS_MARKERS.any(normalized::contains)) add(Category.ADS_REMOVAL)
            if (VALIDATION_MARKERS.any(normalized::contains)) add(Category.RECEIPT_VALIDATION)
        }
    }

    private fun markerFor(value: String, category: Category): String {
        val normalized = normalize(value)
        val markers = when (category) {
            Category.PREMIUM -> PREMIUM_MARKERS
            Category.ENTITLEMENT -> ENTITLEMENT_MARKERS
            Category.SUBSCRIPTION -> SUBSCRIPTION_MARKERS
            Category.PURCHASE -> PURCHASE_MARKERS
            Category.ADS_REMOVAL -> ADS_MARKERS
            Category.RECEIPT_VALIDATION -> VALIDATION_MARKERS
        }
        return markers.firstOrNull(normalized::contains) ?: category.name.lowercase()
    }

    private fun looksLikeClientStateGate(candidate: Candidate): Boolean {
        if (candidate.category == Category.RECEIPT_VALIDATION || candidate.kind != "METHOD") return false
        val normalized = normalize(candidate.managedIdentity.substringAfterLast('.'))
        return CLIENT_STATE_PREFIXES.any(normalized::startsWith) || CLIENT_STATE_MARKERS.any(normalized::contains)
    }

    private fun recommendations(posture: Posture, clientState: Int, validation: Int): List<String> = buildList {
        if (clientState > 0) {
            add("Do not make premium/entitlement authorization depend only on a client-side boolean, property, PlayerPrefs value, or local save state.")
            add("Keep the authoritative entitlement on a backend account and treat local state only as a cache with an expiry/revalidation policy.")
        }
        if (validation == 0 && posture != Posture.NOT_DETECTED) {
            add("Add signed store-receipt/token validation and server-side entitlement verification; no validation identity was recovered from the indexed metadata.")
        } else if (validation > 0) {
            add("Review recovered receipt/validation methods to confirm that success is server-authoritative and cannot be replaced by a local cached result.")
        }
        if (posture == Posture.METADATA_INCOMPLETE) {
            add("Re-run with a compatible, complete global-metadata.dat and matching libil2cpp.so; current reconstruction coverage is incomplete.")
        }
        if (isEmpty()) add("No obvious monetization identity was recovered; this is not proof that monetization logic is absent.")
    }

    private fun normalize(value: String): String = value.lowercase().filter(Char::isLetterOrDigit)

    private fun categoryOrder(value: Category): Int = when (value) {
        Category.PREMIUM -> 0
        Category.ENTITLEMENT -> 1
        Category.SUBSCRIPTION -> 2
        Category.PURCHASE -> 3
        Category.ADS_REMOVAL -> 4
        Category.RECEIPT_VALIDATION -> 5
    }

    private fun confidenceOrder(value: Confidence): Int = when (value) {
        Confidence.HIGH -> 0
        Confidence.MEDIUM -> 1
        Confidence.LOW -> 2
    }

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
    private val CLIENT_STATE_PREFIXES = listOf("is", "has", "get", "set", "can", "owns")
    private val CLIENT_STATE_MARKERS = listOf("enabled", "active", "unlocked", "owned", "premium", "entitled", "subscribed")
}
