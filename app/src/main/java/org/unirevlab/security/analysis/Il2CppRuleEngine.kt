package org.unirevlab.security.analysis

import org.unirevlab.security.model.Confidence
import org.unirevlab.security.model.Evidence
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.Il2CppSummary
import org.unirevlab.security.model.Severity

/** Detection/review rules only; IL2CPP presence is not treated as a vulnerability. */
object Il2CppRuleEngine {
    fun evaluate(value: Il2CppSummary): List<Finding> = buildList {
        if (value.detected) add(
            Finding(
                id = "IL2CPP-APPLICATION-SURFACE",
                title = "Unity IL2CPP application surface detected",
                severity = Severity.INFORMATIONAL,
                confidence = when (value.confidence) {
                    "HIGH" -> Confidence.HIGH
                    "MEDIUM" -> Confidence.MEDIUM
                    else -> Confidence.LOW
                },
                category = "RESILIENCE",
                description = "The artifact contains Unity IL2CPP metadata/native indicators. Managed metadata and libil2cpp should be included in authorized resilience, native memory-safety, and client-trust review.",
                evidence = buildList {
                    value.metadata?.let { add(Evidence(it.entryName, "metadata", "version=${it.metadataVersion ?: "unknown"}; magicValid=${it.magicValid}")) }
                    value.libil2cppLibraries.take(8).forEach { add(Evidence(it, "native", "libil2cpp")) }
                },
                remediation = "Treat IL2CPP as a native client implementation rather than a security boundary. Keep authoritative state and sensitive decisions server-side where applicable, strip unnecessary symbols, and include native parsers/JNI/interop boundaries in fuzzing and review.",
                requiresManualReview = true,
            )
        )
        if (value.metadata != null && !value.metadata.magicValid) add(
            Finding(
                id = "ANALYSIS-IL2CPP-METADATA-UNRECOGNIZED",
                title = "IL2CPP metadata layout could not be verified",
                severity = Severity.INFORMATIONAL,
                confidence = Confidence.CONFIRMED,
                category = "ANALYSIS",
                description = "A global-metadata.dat candidate was present but its standard IL2CPP metadata magic was not recognized. It may be transformed, protected, corrupt, or unrelated.",
                evidence = listOf(Evidence(value.metadata.entryName, "metadata", value.metadata.parseError ?: "unrecognized metadata")),
                remediation = "Confirm the Unity/IL2CPP build configuration and, for authorized analysis, use a version-specific/self-hosted worker or developer-provided symbols/metadata rather than assuming an offset layout.",
                requiresManualReview = true,
            )
        )
    }
}
