package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.ManifestSummary
import org.unirevlab.security.model.StaticAnalysisReport

class ReportJsonExporterTest {
    @Test
    fun outputIsDeterministicAndBoundToArtifactHash() {
        val report = StaticAnalysisReport(
            engineVersion = "test",
            assessment = AssessmentScope(assessmentId="test-id", createdAtEpochMs=1, projectName="Test", organization="Org", purpose="Authorized test", confirmsAuthority=true),
            artifact = ArtifactSummary(
                displayName = "target.apk",
                sizeBytes = 42,
                sha256 = "a".repeat(64),
                archiveEntries = 3,
                dexFiles = 1,
                nativeLibraries = 0,
                hasAndroidManifest = true,
                suspiciousArchivePaths = 0,
                truncatedArchiveScan = false,
            ),
            manifest = ManifestSummary(
                packageName = "org.example",
                versionName = "1.0",
                versionCode = 1,
                minSdk = 26,
                targetSdk = 36,
                debuggable = false,
                allowBackup = false,
                fullBackupContentConfigured = false,
                dataExtractionRulesConfigured = false,
                usesCleartextTraffic = false,
                networkSecurityConfigConfigured = false,
                requestedPermissions = listOf("z.permission", "a.permission"),
                dangerousPermissions = emptyList(),
                components = emptyList(),
                signingCertificateSha256 = emptyList(),
            ),
            findings = emptyList(),
        )

        val first = ReportJsonExporter.export(report)
        val second = ReportJsonExporter.export(report)
        assertEquals(first, second)
        assertTrue(first.contains("\"sha256\": \"${"a".repeat(64)}\""))
        assertTrue(first.indexOf("a.permission") < first.indexOf("z.permission"))
    }
}
