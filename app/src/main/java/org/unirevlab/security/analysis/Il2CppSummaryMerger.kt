package org.unirevlab.security.analysis

import org.unirevlab.security.model.Il2CppSummary

/** Combines IL2CPP evidence that may be distributed across base and split APKs. */
internal object Il2CppSummaryMerger {
    fun merge(values: List<Il2CppSummary>): Il2CppSummary? {
        if (values.isEmpty()) return null
        val metadata = values.mapNotNull { it.metadata }.maxByOrNull { candidate ->
            (if (candidate.magicValid) 1_000_000 else 0) +
                candidate.typeDefinitions.size.coerceAtMost(100_000) * 2 +
                candidate.methodDefinitions.size.coerceAtMost(100_000)
        }
        val libraries = values.flatMap { it.libil2cppLibraries }.toSortedSet().toList()
        val apiSymbols = values.flatMap { it.il2cppApiSymbols }.toSortedSet().take(MAX_API_SYMBOLS)
        val registrations = values.flatMap { it.registrationCandidates }
            .distinctBy { Triple(it.kind, it.libraryEntry, it.symbolName) }
            .take(MAX_REGISTRATIONS)
        val indicators = values.flatMap { it.registrationIndicators }.toMutableSet().apply {
            if (values.size > 1 && metadata != null && libraries.isNotEmpty()) add("SPLIT_EVIDENCE_MERGED")
        }.toSortedSet().toList()
        val detected = values.any { it.detected } || (metadata != null && libraries.isNotEmpty()) || apiSymbols.size >= 3
        val confidence = when {
            metadata?.magicValid == true && libraries.isNotEmpty() -> "HIGH"
            metadata != null && libraries.isNotEmpty() -> "MEDIUM"
            else -> values.map { it.confidence }.maxByOrNull(::confidenceRank) ?: "LOW"
        }
        return Il2CppSummary(
            detected = detected,
            confidence = confidence,
            metadata = metadata,
            libil2cppLibraries = libraries,
            il2cppApiSymbols = apiSymbols,
            registrationIndicators = indicators,
            registrationCandidates = registrations,
            parseErrors = values.sumOf { it.parseErrors },
            truncated = values.any { it.truncated },
        )
    }

    private fun confidenceRank(value: String): Int = when (value.uppercase()) {
        "HIGH" -> 3
        "MEDIUM" -> 2
        else -> 1
    }

    private const val MAX_API_SYMBOLS = 1_000
    private const val MAX_REGISTRATIONS = 128
}
