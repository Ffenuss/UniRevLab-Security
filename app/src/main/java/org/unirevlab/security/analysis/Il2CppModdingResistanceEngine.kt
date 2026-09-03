package org.unirevlab.security.analysis

import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Defensive trust-boundary assessment for IL2CPP monetization/entitlement surfaces.
 *
 * This engine deliberately answers whether security-sensitive state appears client-authoritative,
 * validation-backed, or inconclusive. It does not generate patch offsets, hooks, payloads, or
 * modified binaries.
 */
object Il2CppModdingResistanceEngine {
    enum class Authority {
        CLIENT_AUTHORITATIVE,
        MIXED,
        SERVER_GATED,
        INCONCLUSIVE,
    }

    enum class ReviewPriority { CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN }

    data class TargetAssessment(
        val managedIdentity: String,
        val category: Il2CppMonetizationRiskEngine.Category,
        val kind: String,
        val authority: Authority,
        val priority: ReviewPriority,
        val confidence: String,
        val metadataToken: Long?,
        val nativeVerdict: Il2CppNativeEvidenceEngine.Verdict?,
        val nativeFunctionName: String?,
        val evidence: List<String>,
        val hardeningActions: List<String>,
    )

    data class Result(
        val overallPriority: ReviewPriority,
        val clientAuthoritative: Int,
        val mixed: Int,
        val serverGated: Int,
        val inconclusive: Int,
        val validationSignals: Int,
        val nativeCorrelatedTargets: Int,
        val coverageComplete: Boolean,
        val targets: List<TargetAssessment>,
        val summary: String,
    )

    fun analyze(
        report: StaticAnalysisReport,
        risk: Il2CppMonetizationRiskEngine.Result = Il2CppMonetizationRiskEngine.analyze(report),
        nativeEvidence: Il2CppNativeEvidenceEngine.Result = Il2CppNativeEvidenceEngine.analyze(report),
        maxTargets: Int = 500,
    ): Result {
        val metadata = report.il2cpp?.metadata
        if (report.il2cpp?.detected != true || metadata == null) {
            return emptyResult("IL2CPP metadata is not available.")
        }

        val validationCandidates = risk.candidates.filter {
            it.category == Il2CppMonetizationRiskEngine.Category.RECEIPT_VALIDATION
        }
        val validationsByType = validationCandidates.groupBy { normalizeType(it.declaringType) }
        val nativeByMethod = nativeEvidence.methods.associateBy { it.methodIndex }

        val targets = risk.candidates.asSequence()
            .filter { it.category != Il2CppMonetizationRiskEngine.Category.RECEIPT_VALIDATION }
            .distinctBy { Triple(it.kind, it.managedIdentity, it.category) }
            .take(maxTargets.coerceAtLeast(0))
            .map { candidate ->
                val declaringType = normalizeType(candidate.declaringType)
                val localValidation = validationsByType[declaringType].orEmpty()
                val globalValidation = validationCandidates.isNotEmpty()
                val clientState = looksLikeClientControlledState(candidate)
                val explicitRemoteGate = localValidation.any(::looksExplicitlyRemoteValidation)
                val native = candidate.methodIndex?.let(nativeByMethod::get)
                    ?.takeUnless { it.verdict == Il2CppNativeEvidenceEngine.Verdict.CONFLICTING }

                val authority = when {
                    clientState && localValidation.isEmpty() && !globalValidation -> Authority.CLIENT_AUTHORITATIVE
                    clientState && (localValidation.isNotEmpty() || globalValidation) -> Authority.MIXED
                    !clientState && explicitRemoteGate -> Authority.SERVER_GATED
                    else -> Authority.INCONCLUSIVE
                }

                val priority = when (authority) {
                    Authority.CLIENT_AUTHORITATIVE -> when (candidate.confidence.uppercase()) {
                        "HIGH" -> ReviewPriority.CRITICAL
                        "MEDIUM" -> ReviewPriority.HIGH
                        else -> ReviewPriority.MEDIUM
                    }
                    Authority.MIXED -> if (clientState) ReviewPriority.HIGH else ReviewPriority.MEDIUM
                    Authority.SERVER_GATED -> ReviewPriority.LOW
                    Authority.INCONCLUSIVE -> ReviewPriority.UNKNOWN
                }

                TargetAssessment(
                    managedIdentity = candidate.managedIdentity,
                    category = candidate.category,
                    kind = candidate.kind,
                    authority = authority,
                    priority = priority,
                    confidence = candidate.confidence,
                    metadataToken = candidate.metadataToken,
                    nativeVerdict = native?.verdict,
                    nativeFunctionName = native?.nativeFunctionName ?: candidate.nativeFunctionName,
                    evidence = buildList {
                        addAll(candidate.evidence.take(5))
                        if (clientState) {
                            add("The recovered managed surface looks like a client-side state/getter/setter gate; changing local execution or state could affect the client-visible decision unless a trusted backend re-authorizes it.")
                        }
                        if (localValidation.isNotEmpty()) {
                            add("${localValidation.size} receipt/entitlement validation signal(s) exist in the same declaring type.")
                            localValidation.take(2).forEach { add("Validation evidence: ${it.managedIdentity}") }
                        } else if (globalValidation) {
                            add("Validation signals exist elsewhere in the recovered metadata, but a direct same-type trust link was not proven.")
                        } else {
                            add("No receipt/backend validation identity was recovered from the available IL2CPP metadata.")
                        }
                        native?.let {
                            add("Native identity correlation: ${it.verdict} · ${it.nativeFunctionName ?: "unnamed function"}.")
                        }
                        if (authority == Authority.SERVER_GATED) {
                            add("SERVER_GATED is assigned only from explicit remote/server/backend validation semantics; static evidence still cannot prove the backend actually enforces every request.")
                        }
                    }.distinct(),
                    hardeningActions = hardeningFor(authority, candidate.category),
                )
            }
            .sortedWith(compareBy<TargetAssessment>({ priorityOrder(it.priority) }, { it.category.name }, { it.managedIdentity }))
            .toList()

        val overall = targets.minByOrNull { priorityOrder(it.priority) }?.priority ?: ReviewPriority.UNKNOWN
        val coverageComplete = risk.coverageComplete &&
            metadata.magicValid && metadata.parseError == null && !metadata.truncated && !metadata.reconstructionTruncated
        val clientCount = targets.count { it.authority == Authority.CLIENT_AUTHORITATIVE }
        val mixedCount = targets.count { it.authority == Authority.MIXED }
        val serverCount = targets.count { it.authority == Authority.SERVER_GATED }
        val unknownCount = targets.count { it.authority == Authority.INCONCLUSIVE }
        val nativeCount = targets.count { it.nativeVerdict == Il2CppNativeEvidenceEngine.Verdict.VERIFIED || it.nativeVerdict == Il2CppNativeEvidenceEngine.Verdict.SUPPORTED }

        val summary = when {
            clientCount > 0 -> "$clientCount sensitive IL2CPP target(s) appear client-authoritative and should be treated as modding-resistance failures until server-side authorization proves otherwise."
            mixedCount > 0 -> "$mixedCount sensitive IL2CPP target(s) combine client-side state with validation signals; verify that backend authorization is mandatory for every protected action."
            serverCount > 0 && unknownCount == 0 -> "Recovered sensitive targets are dominated by explicit server/remote validation semantics; static evidence did not identify a standalone client-authoritative gate."
            targets.isEmpty() -> "No monetization/entitlement target was reconstructed from the available IL2CPP metadata."
            else -> "The recovered IL2CPP evidence is insufficient to prove where authorization is authoritative; manual trust-boundary review remains required."
        }

        return Result(
            overallPriority = overall,
            clientAuthoritative = clientCount,
            mixed = mixedCount,
            serverGated = serverCount,
            inconclusive = unknownCount,
            validationSignals = validationCandidates.size,
            nativeCorrelatedTargets = nativeCount,
            coverageComplete = coverageComplete,
            targets = targets,
            summary = summary,
        )
    }

    private fun looksLikeClientControlledState(candidate: Il2CppMonetizationRiskEngine.Candidate): Boolean {
        if (candidate.kind.contains("FIELD", ignoreCase = true)) return true
        val name = candidate.managedIdentity.substringAfterLast('.').lowercase()
        return name.startsWith("is") || name.startsWith("has") || name.startsWith("get_") ||
            name.startsWith("set_") || name.startsWith("can") || name.startsWith("owns") ||
            name.contains("enabled") || name.contains("active") || name.contains("unlocked") ||
            name.contains("owned") || name.contains("premium") || name.contains("entitled") ||
            name.contains("subscribed")
    }

    private fun looksExplicitlyRemoteValidation(candidate: Il2CppMonetizationRiskEngine.Candidate): Boolean {
        val text = candidate.managedIdentity.lowercase()
        return listOf("server", "remote", "backend", "cloud", "api", "receipt", "verify", "validate")
            .any(text::contains) &&
            listOf("server", "remote", "backend", "cloud", "api").any(text::contains)
    }

    private fun hardeningFor(
        authority: Authority,
        category: Il2CppMonetizationRiskEngine.Category,
    ): List<String> = buildList {
        when (authority) {
            Authority.CLIENT_AUTHORITATIVE -> {
                add("Move the authoritative ${category.name.lowercase()} decision to a trusted backend; treat local fields/getters only as cached UI state.")
                add("Require a short-lived, account-bound server entitlement for every protected transaction or capability.")
                add("Fail closed when backend authorization is missing, stale, malformed, replayed, or inconsistent with the signed-in account.")
            }
            Authority.MIXED -> {
                add("Verify that local ${category.name.lowercase()} state cannot authorize the protected operation before backend validation completes.")
                add("Bind receipt/entitlement validation to account, product, app build and nonce/replay protection on the server.")
            }
            Authority.SERVER_GATED -> {
                add("Keep the server decision authoritative and ensure the client cannot convert validation failures into success locally.")
                add("Add telemetry for impossible entitlement transitions and repeated integrity/authorization failures.")
            }
            Authority.INCONCLUSIVE -> {
                add("Trace this target to the final authorization sink and document the trust boundary before treating it as protected.")
            }
        }
        add("Use integrity/tamper controls only as defense-in-depth; they must not replace server-side authorization for paid entitlements.")
    }.distinct()

    private fun normalizeType(value: String?): String = value.orEmpty().trim()

    private fun priorityOrder(value: ReviewPriority): Int = when (value) {
        ReviewPriority.CRITICAL -> 0
        ReviewPriority.HIGH -> 1
        ReviewPriority.MEDIUM -> 2
        ReviewPriority.LOW -> 3
        ReviewPriority.UNKNOWN -> 4
    }

    private fun emptyResult(summary: String) = Result(
        overallPriority = ReviewPriority.UNKNOWN,
        clientAuthoritative = 0,
        mixed = 0,
        serverGated = 0,
        inconclusive = 0,
        validationSignals = 0,
        nativeCorrelatedTargets = 0,
        coverageComplete = false,
        targets = emptyList(),
        summary = summary,
    )
}
