package org.unirevlab.security.analysis

import org.unirevlab.security.model.Il2CppMethodNativeCorrelation
import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Conservative validation layer for IL2CPP managed-method/native-function correlations that were
 * already recovered by the static/Ghidra pipeline.
 *
 * This engine never derives patch offsets, never mutates a target, and never treats method ordering
 * alone as evidence. It only validates correlation identity/token consistency and ranks the
 * provenance of an existing correlation for defensive review.
 */
object Il2CppNativeEvidenceEngine {
    enum class Verdict { VERIFIED, SUPPORTED, WEAK, CONFLICTING }

    data class MethodEvidence(
        val methodIndex: Int,
        val managedIdentity: String,
        val metadataToken: Long,
        val verdict: Verdict,
        val correlationCount: Int,
        val matchingCorrelations: Int,
        val nativeFunctionName: String?,
        val libraryEntry: String?,
        val sourceEvidence: String?,
        val sourceConfidence: String?,
        val evidence: List<String>,
    )

    data class Result(
        val correlationDataAvailable: Boolean,
        val methodsConsidered: Int,
        val methodsWithCorrelation: Int,
        val verified: Int,
        val supported: Int,
        val weak: Int,
        val conflicting: Int,
        val inputCoverageComplete: Boolean,
        val methods: List<MethodEvidence>,
    ) {
        fun forMethod(methodIndex: Int): MethodEvidence? = methods.firstOrNull { it.methodIndex == methodIndex }
    }

    fun analyze(report: StaticAnalysisReport, maxMethods: Int = 100_000): Result {
        val il2cpp = report.il2cpp
        val metadata = il2cpp?.metadata
        if (il2cpp?.detected != true || metadata == null) {
            return emptyResult(report.correlations != null)
        }

        val methodLimit = maxMethods.coerceAtLeast(0)
        val methods = metadata.methodDefinitions.sortedBy { it.index }.take(methodLimit)
        val correlations = report.correlations?.il2cppMethods.orEmpty().groupBy { it.methodIndex }
        val assessed = ArrayList<MethodEvidence>()

        methods.forEach { method ->
            val candidates = correlations[method.index].orEmpty()
            if (candidates.isEmpty()) return@forEach

            val managedIdentity = "${method.declaringType}.${method.name}"
            val matching = candidates.filter { correlation ->
                sameMetadataEntry(metadata.entryName, correlation.metadataEntry) &&
                    correlation.methodIndex == method.index &&
                    correlation.declaringType == method.declaringType &&
                    correlation.methodName == method.name &&
                    correlation.token == method.token
            }
            val mismatched = candidates.size - matching.size
            val libraryConflicts = matching.groupBy { it.libraryEntry }.any { (_, sameLibrary) ->
                sameLibrary.map { it.functionRva }.distinct().size > 1
            }

            if (matching.isEmpty() || libraryConflicts) {
                assessed += MethodEvidence(
                    methodIndex = method.index,
                    managedIdentity = managedIdentity,
                    metadataToken = method.token,
                    verdict = Verdict.CONFLICTING,
                    correlationCount = candidates.size,
                    matchingCorrelations = matching.size,
                    nativeFunctionName = null,
                    libraryEntry = null,
                    sourceEvidence = null,
                    sourceConfidence = null,
                    evidence = buildList {
                        add("Correlation records exist for methodIndex=${method.index}, but they do not form one internally consistent metadata/native identity.")
                        if (matching.isEmpty()) add("No correlation matched declaring type, method name, metadata token and metadata entry together.")
                        if (libraryConflicts) add("At least one native library maps the same managed method to multiple distinct function RVAs; no native identity is selected.")
                        add("Conflicting evidence is intentionally not promoted into semantic or monetization conclusions.")
                    },
                )
                return@forEach
            }

            val selected = matching.sortedWith(
                compareByDescending<Il2CppMethodNativeCorrelation> { sourceRank(it.evidence) }
                    .thenByDescending { confidenceRank(it.confidence) }
                    .thenBy { it.libraryEntry }
                    .thenBy { it.functionRva },
            ).first()
            var verdict = verdictFor(selected)
            if (mismatched > 0 && verdict == Verdict.VERIFIED) verdict = Verdict.SUPPORTED

            assessed += MethodEvidence(
                methodIndex = method.index,
                managedIdentity = managedIdentity,
                metadataToken = method.token,
                verdict = verdict,
                correlationCount = candidates.size,
                matchingCorrelations = matching.size,
                nativeFunctionName = selected.functionName.takeIf { it.isNotBlank() },
                libraryEntry = selected.libraryEntry,
                sourceEvidence = selected.evidence,
                sourceConfidence = selected.confidence,
                evidence = buildList {
                    add("Managed identity and metadata token match the canonical global-metadata.dat method definition.")
                    add("Correlation provenance: ${selected.evidence} (${selected.confidence}).")
                    if (matching.size > 1) add("${matching.size} consistent correlations were recovered across native library entries/ABIs; the strongest deterministic representative is shown.")
                    if (mismatched > 0) add("$mismatched additional correlation record(s) failed metadata identity/token validation and were not trusted.")
                    selected.functionName.takeIf { it.isNotBlank() }?.let { add("Recovered native function identity: $it.") }
                    add("This evidence confirms a static identity link only; it does not prove a runtime return value, authorization result, or exploitable state.")
                },
            )
        }

        val ordered = assessed.sortedWith(compareBy({ verdictOrder(it.verdict) }, { it.methodIndex }))
        val metadataComplete = metadata.magicValid && metadata.parseError == null &&
            !metadata.truncated && !metadata.reconstructionTruncated && il2cpp.parseErrors == 0 && !il2cpp.truncated
        val correlationComplete = report.correlations != null && report.correlations.truncated.not()
        val methodsComplete = metadata.methodDefinitions.size <= methodLimit

        return Result(
            correlationDataAvailable = report.correlations != null,
            methodsConsidered = methods.size,
            methodsWithCorrelation = ordered.size,
            verified = ordered.count { it.verdict == Verdict.VERIFIED },
            supported = ordered.count { it.verdict == Verdict.SUPPORTED },
            weak = ordered.count { it.verdict == Verdict.WEAK },
            conflicting = ordered.count { it.verdict == Verdict.CONFLICTING },
            inputCoverageComplete = metadataComplete && correlationComplete && methodsComplete,
            methods = ordered,
        )
    }

    private fun verdictFor(correlation: Il2CppMethodNativeCorrelation): Verdict {
        val source = correlation.evidence.uppercase()
        val confidence = confidenceRank(correlation.confidence)
        return when {
            source in STRONG_SOURCES && confidence >= 3 && correlation.functionName.isNotBlank() -> Verdict.VERIFIED
            source in STRONG_SOURCES && confidence >= 2 -> Verdict.SUPPORTED
            source == "UNIQUE_TYPE_METHOD_IDENTITY" && confidence >= 2 -> Verdict.SUPPORTED
            else -> Verdict.WEAK
        }
    }

    private fun sourceRank(value: String): Int = when (value.uppercase()) {
        "CODEGEN_MODULE_METHOD_TOKEN_SLOT" -> 4
        "UNIQUE_METADATA_TOKEN_LITERAL" -> 3
        "UNIQUE_TYPE_METHOD_IDENTITY" -> 2
        else -> 1
    }

    private fun confidenceRank(value: String): Int = when (value.uppercase()) {
        "HIGH" -> 3
        "MEDIUM" -> 2
        "LOW" -> 1
        else -> 0
    }

    private fun verdictOrder(value: Verdict): Int = when (value) {
        Verdict.VERIFIED -> 0
        Verdict.SUPPORTED -> 1
        Verdict.WEAK -> 2
        Verdict.CONFLICTING -> 3
    }

    private fun sameMetadataEntry(expected: String, actual: String): Boolean {
        fun base(value: String): String = value.substringAfterLast('/').substringAfterLast('\\')
        return expected == actual || base(expected) == base(actual)
    }

    private fun emptyResult(dataAvailable: Boolean) = Result(
        correlationDataAvailable = dataAvailable,
        methodsConsidered = 0,
        methodsWithCorrelation = 0,
        verified = 0,
        supported = 0,
        weak = 0,
        conflicting = 0,
        inputCoverageComplete = false,
        methods = emptyList(),
    )

    private val STRONG_SOURCES = setOf(
        "CODEGEN_MODULE_METHOD_TOKEN_SLOT",
        "UNIQUE_METADATA_TOKEN_LITERAL",
    )
}
