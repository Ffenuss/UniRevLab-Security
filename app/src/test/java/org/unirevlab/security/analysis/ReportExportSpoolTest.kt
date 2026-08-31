package org.unirevlab.security.analysis

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.ManifestSummary
import org.unirevlab.security.model.StaticAnalysisReport

class ReportExportSpoolTest {
    @Test
    fun preparedFileIsNonEmptyDurableAndMatchesDeterministicExporter() {
        val directory = Files.createTempDirectory("unirevlab-export-test").toFile()
        try {
            val report = StaticAnalysisReport(
                engineVersion = "test",
                assessment = AssessmentScope(
                    assessmentId = "test-id",
                    createdAtEpochMs = 1,
                    projectName = "Test",
                    organization = "Org",
                    purpose = "Authorized test",
                    confirmsAuthority = true,
                ),
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
            val prepared = ReportExportSpool.prepare(report, directory)
            assertTrue(prepared.file.isFile)
            assertTrue(prepared.sizeBytes > 2L)
            assertEquals(prepared.sizeBytes, prepared.file.length())
            assertEquals(64, prepared.sha256.length)
            assertEquals(ReportJsonExporter.export(report), prepared.file.readText(Charsets.UTF_8))
        } finally {
            directory.deleteRecursively()
        }
    }
}
