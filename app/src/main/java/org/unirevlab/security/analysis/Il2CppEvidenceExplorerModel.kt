package org.unirevlab.security.analysis

import org.unirevlab.security.model.StaticAnalysisReport

/**
 * Read-only navigation model joining IL2CPP semantic analyst mappings with validated native
 * correlation evidence. The model intentionally exposes no function RVA, patch offset or mutation
 * primitive; its purpose is evidence review and hardening triage.
 */
object Il2CppEvidenceExplorerModel {
    enum class LinkStatus { VERIFIED, SUPPORTED, WEAK, CONFLICTING, MANAGED_ONLY }

    data class Row(
        val key: String,
        val kind: String,
        val symbolIndex: Int,
        val methodIndex: Int?,
        val managedIdentity: String,
        val analystAlias: String,
        val semanticCategory: String,
        val mappingConfidence: Il2CppSemanticMappingEngine.Confidence,
        val mappingBasis: Il2CppSemanticMappingEngine.Basis,
        val metadataToken: Long?,
        val linkStatus: LinkStatus,
        val nativeFunctionName: String?,
        val nativeLibrary: String?,
        val nativeProvenance: String?,
        val nativeConfidence: String?,
        val evidence: List<String>,
    )

    data class Result(
        val il2cppDetected: Boolean,
        val managedCoverageComplete: Boolean,
        val nativeDataAvailable: Boolean,
        val nativeCoverageComplete: Boolean,
        val semanticCandidates: Int,
        val verified: Int,
        val supported: Int,
        val weak: Int,
        val conflicting: Int,
        val managedOnly: Int,
        val rowsTruncated: Boolean,
        val rows: List<Row>,
    )

    fun build(report: StaticAnalysisReport, maxRows: Int = 2_000): Result {
        val il2cpp = report.il2cpp
        val metadata = il2cpp?.metadata
        if (il2cpp?.detected != true || metadata == null) {
            return emptyResult(il2cpp?.detected == true, report.correlations != null)
        }

        val limit = maxRows.coerceAtLeast(0)
        val mappingLimit = (limit.coerceAtLeast(1) * 8).coerceAtMost(100_000)
        val mapping = Il2CppSemanticMappingEngine.analyze(report, maxEntries = mappingLimit)
        val native = Il2CppNativeEvidenceEngine.analyze(report)
        val nativeByMethod = native.methods.associateBy { it.methodIndex }
        val methods = metadata.methodDefinitions.associateBy { it.index }
        val fields = metadata.fieldDefinitions.associateBy { it.index }
        val types = metadata.typeDefinitions.associateBy { it.index }

        val semanticEntries = mapping.entries.asSequence()
            .filter { it.semanticCategory != null }
            .toList()

        val rows = semanticEntries.take(limit).map { entry ->
            val method = if (entry.kind == "METHOD") methods[entry.symbolIndex] else null
            val token = when (entry.kind) {
                "METHOD" -> method?.token
                "FIELD" -> fields[entry.symbolIndex]?.token
                "TYPE" -> types[entry.symbolIndex]?.token
                else -> null
            }
            val nativeEvidence = method?.let { nativeByMethod[it.index] }
            val status = when (nativeEvidence?.verdict) {
                Il2CppNativeEvidenceEngine.Verdict.VERIFIED -> LinkStatus.VERIFIED
                Il2CppNativeEvidenceEngine.Verdict.SUPPORTED -> LinkStatus.SUPPORTED
                Il2CppNativeEvidenceEngine.Verdict.WEAK -> LinkStatus.WEAK
                Il2CppNativeEvidenceEngine.Verdict.CONFLICTING -> LinkStatus.CONFLICTING
                null -> LinkStatus.MANAGED_ONLY
            }
            Row(
                key = "${entry.kind}:${entry.symbolIndex}:${entry.semanticCategory}",
                kind = entry.kind,
                symbolIndex = entry.symbolIndex,
                methodIndex = method?.index,
                managedIdentity = entry.originalIdentity,
                analystAlias = entry.alias,
                semanticCategory = entry.semanticCategory!!,
                mappingConfidence = entry.confidence,
                mappingBasis = entry.basis,
                metadataToken = token,
                linkStatus = status,
                nativeFunctionName = nativeEvidence?.nativeFunctionName,
                nativeLibrary = nativeEvidence?.libraryEntry,
                nativeProvenance = nativeEvidence?.sourceEvidence,
                nativeConfidence = nativeEvidence?.sourceConfidence,
                evidence = (entry.evidence + nativeEvidence?.evidence.orEmpty()).distinct().take(12),
            )
        }

        return Result(
            il2cppDetected = true,
            managedCoverageComplete = mapping.coverageComplete,
            nativeDataAvailable = native.correlationDataAvailable,
            nativeCoverageComplete = native.inputCoverageComplete,
            semanticCandidates = semanticEntries.size,
            verified = rows.count { it.linkStatus == LinkStatus.VERIFIED },
            supported = rows.count { it.linkStatus == LinkStatus.SUPPORTED },
            weak = rows.count { it.linkStatus == LinkStatus.WEAK },
            conflicting = rows.count { it.linkStatus == LinkStatus.CONFLICTING },
            managedOnly = rows.count { it.linkStatus == LinkStatus.MANAGED_ONLY },
            rowsTruncated = semanticEntries.size > limit,
            rows = rows,
        )
    }

    fun filter(
        result: Result,
        query: String,
        status: LinkStatus? = null,
    ): List<Row> {
        val needle = query.trim().lowercase()
        return result.rows.filter { row ->
            val statusMatches = status == null || row.linkStatus == status
            if (!statusMatches) return@filter false
            if (needle.isBlank()) return@filter true
            val tokenText = row.metadataToken?.let { "0x${it.toString(16)}" }.orEmpty()
            listOf(
                row.kind,
                row.symbolIndex.toString(),
                row.methodIndex?.toString().orEmpty(),
                row.managedIdentity,
                row.analystAlias,
                row.semanticCategory,
                row.mappingConfidence.name,
                row.mappingBasis.name,
                row.linkStatus.name,
                tokenText,
                row.nativeFunctionName.orEmpty(),
                row.nativeLibrary.orEmpty(),
                row.nativeProvenance.orEmpty(),
                row.nativeConfidence.orEmpty(),
            ).any { it.lowercase().contains(needle) } ||
                row.evidence.any { it.lowercase().contains(needle) }
        }
    }

    private fun emptyResult(detected: Boolean, nativeDataAvailable: Boolean) = Result(
        il2cppDetected = detected,
        managedCoverageComplete = false,
        nativeDataAvailable = nativeDataAvailable,
        nativeCoverageComplete = false,
        semanticCandidates = 0,
        verified = 0,
        supported = 0,
        weak = 0,
        conflicting = 0,
        managedOnly = 0,
        rowsTruncated = false,
        rows = emptyList(),
    )
}
