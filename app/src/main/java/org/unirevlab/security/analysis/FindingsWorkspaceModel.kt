package org.unirevlab.security.analysis

import java.util.Locale
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.Severity

/** Presentation model for the customer-facing findings workspace. */
object FindingsWorkspaceModel {
    data class Summary(
        val total: Int,
        val critical: Int,
        val high: Int,
        val medium: Int,
        val low: Int,
        val informational: Int,
        val manualReview: Int,
        val categories: List<String>,
    )

    data class Query(
        val text: String = "",
        val severities: Set<Severity> = Severity.entries.toSet(),
        val category: String? = null,
        val manualReviewOnly: Boolean = false,
    )

    fun summarize(findings: List<Finding>): Summary = Summary(
        total = findings.size,
        critical = findings.count { it.severity == Severity.CRITICAL },
        high = findings.count { it.severity == Severity.HIGH },
        medium = findings.count { it.severity == Severity.MEDIUM },
        low = findings.count { it.severity == Severity.LOW },
        informational = findings.count { it.severity == Severity.INFORMATIONAL },
        manualReview = findings.count { it.requiresManualReview },
        categories = findings.map { it.category }.filter { it.isNotBlank() }.distinct().sorted(),
    )

    fun filter(findings: List<Finding>, query: Query, limit: Int = 500): List<Finding> {
        if (limit <= 0 || query.severities.isEmpty()) return emptyList()
        val q = query.text.trim().lowercase(Locale.ROOT)
        val category = query.category?.takeIf { it.isNotBlank() }

        return findings.asSequence()
            .filter { it.severity in query.severities }
            .filter { category == null || it.category == category }
            .filter { !query.manualReviewOnly || it.requiresManualReview }
            .filter { finding ->
                q.isBlank() || searchableText(finding).contains(q)
            }
            .sortedWith(
                compareBy<Finding> { severityOrder(it.severity) }
                    .thenBy { confidenceOrder(it.confidence.name) }
                    .thenBy { it.category }
                    .thenBy { it.id },
            )
            .take(limit)
            .toList()
    }

    private fun searchableText(finding: Finding): String = buildString {
        append(finding.id).append(' ')
        append(finding.title).append(' ')
        append(finding.category).append(' ')
        append(finding.description).append(' ')
        append(finding.remediation).append(' ')
        finding.evidence.take(20).forEach {
            append(it.source).append(' ').append(it.location).append(' ').append(it.value).append(' ')
        }
        finding.references.forEach { append(it.standard).append(' ').append(it.id).append(' ') }
    }.lowercase(Locale.ROOT)

    private fun severityOrder(severity: Severity): Int = when (severity) {
        Severity.CRITICAL -> 0
        Severity.HIGH -> 1
        Severity.MEDIUM -> 2
        Severity.LOW -> 3
        Severity.INFORMATIONAL -> 4
    }

    private fun confidenceOrder(confidence: String): Int = when (confidence) {
        "CONFIRMED" -> 0
        "HIGH" -> 1
        "MEDIUM" -> 2
        "LOW" -> 3
        else -> 4
    }
}
