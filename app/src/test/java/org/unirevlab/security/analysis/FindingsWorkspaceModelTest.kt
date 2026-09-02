package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.Confidence
import org.unirevlab.security.model.Evidence
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.SecurityReference
import org.unirevlab.security.model.Severity

class FindingsWorkspaceModelTest {
    @Test
    fun prioritizesCriticalAndFiltersByEvidenceAndCategory() {
        val findings = listOf(
            finding(
                id = "MEDIUM_NET",
                severity = Severity.MEDIUM,
                category = "NETWORK",
                title = "Cleartext endpoint",
                evidenceValue = "http://example.test/api",
            ),
            finding(
                id = "CRIT_DESERIAL",
                severity = Severity.CRITICAL,
                category = "SERIALIZATION",
                title = "Externally reachable object deserialization",
                evidenceValue = "ObjectInputStream.readObject",
                manual = true,
            ),
            finding(
                id = "HIGH_IPC",
                severity = Severity.HIGH,
                category = "IPC",
                title = "Exported provider",
                evidenceValue = "content://example.provider",
            ),
        )

        val all = FindingsWorkspaceModel.filter(findings, FindingsWorkspaceModel.Query())
        assertEquals(listOf("CRIT_DESERIAL", "HIGH_IPC", "MEDIUM_NET"), all.map { it.id })

        val serialized = FindingsWorkspaceModel.filter(
            findings,
            FindingsWorkspaceModel.Query(text = "readObject", category = "SERIALIZATION"),
        )
        assertEquals(listOf("CRIT_DESERIAL"), serialized.map { it.id })

        val manual = FindingsWorkspaceModel.filter(
            findings,
            FindingsWorkspaceModel.Query(manualReviewOnly = true),
        )
        assertEquals(1, manual.size)
        assertTrue(manual.single().requiresManualReview)
    }

    @Test
    fun summaryReturnsCustomerSeverityCounts() {
        val findings = listOf(
            finding("C", Severity.CRITICAL, "A", "Critical", "e"),
            finding("H", Severity.HIGH, "A", "High", "e"),
            finding("M", Severity.MEDIUM, "B", "Medium", "e", manual = true),
            finding("I", Severity.INFORMATIONAL, "B", "Info", "e"),
        )
        val summary = FindingsWorkspaceModel.summarize(findings)
        assertEquals(4, summary.total)
        assertEquals(1, summary.critical)
        assertEquals(1, summary.high)
        assertEquals(1, summary.medium)
        assertEquals(0, summary.low)
        assertEquals(1, summary.informational)
        assertEquals(1, summary.manualReview)
        assertEquals(listOf("A", "B"), summary.categories)
    }

    private fun finding(
        id: String,
        severity: Severity,
        category: String,
        title: String,
        evidenceValue: String,
        manual: Boolean = false,
    ) = Finding(
        id = id,
        title = title,
        severity = severity,
        confidence = Confidence.HIGH,
        category = category,
        description = "Description for $title",
        evidence = listOf(Evidence("DEX", "classes.dex", evidenceValue)),
        remediation = "Apply remediation",
        references = listOf(SecurityReference("CWE", "CWE-20")),
        requiresManualReview = manual,
    )
}
