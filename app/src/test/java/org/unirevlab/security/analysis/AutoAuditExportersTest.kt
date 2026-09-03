package org.unirevlab.security.analysis

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.StaticAnalysisReport

class AutoAuditExportersTest {
    private val report = StaticAnalysisReport(
        engineVersion = "0.26-test",
        assessment = AssessmentScope(
            assessmentId = "assessment-1",
            createdAtEpochMs = 1,
            projectName = "Project",
            organization = "Customer",
            purpose = "Authorized test",
            confirmsAuthority = true,
        ),
        artifact = ArtifactSummary(
            displayName = "target.apk",
            sizeBytes = 42,
            sha256 = "a".repeat(64),
            archiveEntries = 1,
            dexFiles = 0,
            nativeLibraries = 0,
            hasAndroidManifest = false,
            suspiciousArchivePaths = 0,
            truncatedArchiveScan = false,
        ),
        manifest = null,
        findings = emptyList(),
    )

    @Test
    fun offsetsAreEvidenceOnlyAndBoundToArtifact() {
        val json = JSONObject(OffsetEvidenceExporter.export(report))

        assertEquals("a".repeat(64), json.getString("artifactSha256"))
        assertTrue(json.getString("safety").contains("No executable hook"))
    }

    @Test
    fun verificationPlanAlwaysHasDefensiveBaseline() {
        val json = JSONObject(VerificationPlanExporter.export(report))

        assertEquals("NOT_EXECUTED", json.getString("executionStatus"))
        assertEquals("BASELINE-CLIENT-TRUST", json.getJSONArray("tests").getJSONObject(0).getString("id"))
    }

    @Test
    fun customerReportStatesMethodBoundary() {
        val markdown = CustomerReportExporter.export(report)

        assertTrue(markdown.contains("не содержит модифицированного APK"))
        assertTrue(markdown.contains("verification-plan.json"))
    }
}
