package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.Confidence
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.Severity
import org.unirevlab.security.model.StaticAnalysisReport

class ExecutiveSummaryEngineTest {
    @Test
    fun highestFindingControlsRiskBandWithoutInventingSecurityScore() {
        val report = report(
            listOf(
                finding("LOW-1", Severity.LOW),
                finding("HIGH-1", Severity.HIGH),
                finding("MED-1", Severity.MEDIUM),
            ),
        )

        val summary = ExecutiveSummaryEngine.summarize(report)

        assertEquals(ExecutiveSummaryEngine.RiskBand.HIGH, summary.riskBand)
        assertEquals(3, summary.totalFindings)
        assertEquals("HIGH-1", summary.topFindings.first().id)
    }

    @Test
    fun emptyStaticArtifactReportsNoFindingsAndNoArtificialCoverage() {
        val report = report(emptyList())
        val summary = ExecutiveSummaryEngine.summarize(report)

        assertEquals(ExecutiveSummaryEngine.RiskBand.NO_FINDINGS, summary.riskBand)
        assertEquals("N/A", summary.coverageLabel)
        val markdown = ExecutiveSummaryEngine.toMarkdown(report, summary)
        assertTrue(markdown.contains("not proof", ignoreCase = true))
        assertTrue(markdown.contains("Scope note"))
    }

    private fun report(findings: List<Finding>) = StaticAnalysisReport(
        engineVersion = "test",
        assessment = AssessmentScope(
            projectName = "Executive",
            organization = "Test",
            purpose = "regression",
            confirmsAuthority = true,
        ),
        artifact = ArtifactSummary(
            displayName = "sample.bin",
            sizeBytes = 1,
            sha256 = "00",
            archiveEntries = 0,
            dexFiles = 0,
            nativeLibraries = 0,
            hasAndroidManifest = false,
            suspiciousArchivePaths = 0,
            truncatedArchiveScan = false,
        ),
        manifest = null,
        dex = null,
        findings = findings,
    )

    private fun finding(id: String, severity: Severity) = Finding(
        id = id,
        title = "Finding $id",
        severity = severity,
        confidence = Confidence.HIGH,
        category = "TEST",
        description = "description",
        evidence = emptyList(),
        remediation = "fix $id",
    )
}
