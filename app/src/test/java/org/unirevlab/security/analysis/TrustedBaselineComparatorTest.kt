package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentHistoryEntry
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.BaselineVerdict
import org.unirevlab.security.model.ManifestSummary
import org.unirevlab.security.model.StaticAnalysisReport

class TrustedBaselineComparatorTest {
    @Test
    fun sameShaIsSameArtifact() {
        val result = TrustedBaselineComparator.compare(baseline(sha = "aa", signer = "11"), report(sha = "aa", signer = "11"))
        assertEquals(BaselineVerdict.SAME_ARTIFACT, result.verdict)
        assertTrue(result.signerContinuity == true)
    }

    @Test
    fun changedShaWithSameSignerIsModified() {
        val result = TrustedBaselineComparator.compare(baseline(sha = "aa", signer = "11"), report(sha = "bb", signer = "11"))
        assertEquals(BaselineVerdict.MODIFIED, result.verdict)
        assertTrue(result.signerContinuity == true)
    }

    @Test
    fun changedShaAndSignerIsSignerChanged() {
        val result = TrustedBaselineComparator.compare(baseline(sha = "aa", signer = "11"), report(sha = "bb", signer = "22"))
        assertEquals(BaselineVerdict.SIGNER_CHANGED, result.verdict)
        assertFalse(result.signerContinuity ?: true)
    }

    @Test
    fun packageMismatchIsNotComparable() {
        val result = TrustedBaselineComparator.compare(
            baseline(sha = "aa", signer = "11", packageName = "org.example.a"),
            report(sha = "bb", signer = "11", packageName = "org.example.b"),
        )
        assertEquals(BaselineVerdict.NOT_COMPARABLE, result.verdict)
    }

    @Test
    fun noBaselineRemainsExplicitlyUnknown() {
        val result = TrustedBaselineComparator.compare(null, report(sha = "aa", signer = "11"))
        assertEquals(BaselineVerdict.NO_BASELINE, result.verdict)
    }

    private fun baseline(
        sha: String,
        signer: String,
        packageName: String = "org.example.app",
    ) = AssessmentHistoryEntry(
        id = "baseline-id",
        assessmentId = "assessment-old",
        analyzedAtEpochMs = 1L,
        projectName = "Regression",
        organization = "UniRevLab",
        artifactDisplayName = "baseline.apk",
        packageName = packageName,
        versionName = "1.0",
        versionCode = 1L,
        artifactSha256 = sha,
        sizeBytes = 100L,
        sourceKind = "FILE",
        splitApkCount = 0,
        signingCertificateSha256 = listOf(signer),
        findingCount = 0,
        criticalCount = 0,
        highCount = 0,
        mediumCount = 0,
        lowCount = 0,
        informationalCount = 0,
        dexFiles = 1,
        methodsIndexed = 10,
        nativeLibraries = 0,
        engineVersion = "test",
        schemaVersion = "test",
    )

    private fun report(
        sha: String,
        signer: String,
        packageName: String = "org.example.app",
    ) = StaticAnalysisReport(
        engineVersion = "test",
        assessment = AssessmentScope(
            assessmentId = "assessment-new",
            createdAtEpochMs = 2L,
            projectName = "Regression",
            organization = "UniRevLab",
            purpose = "Authorized test",
            confirmsAuthority = true,
        ),
        artifact = ArtifactSummary(
            displayName = "current.apk",
            sizeBytes = 120L,
            sha256 = sha,
            archiveEntries = 1,
            dexFiles = 1,
            nativeLibraries = 0,
            hasAndroidManifest = true,
            suspiciousArchivePaths = 0,
            truncatedArchiveScan = false,
            sourcePackageName = packageName,
        ),
        manifest = ManifestSummary(
            packageName = packageName,
            versionName = "2.0",
            versionCode = 2L,
            minSdk = 26,
            targetSdk = 36,
            debuggable = false,
            allowBackup = false,
            fullBackupContentConfigured = null,
            dataExtractionRulesConfigured = null,
            usesCleartextTraffic = false,
            networkSecurityConfigConfigured = null,
            requestedPermissions = emptyList(),
            dangerousPermissions = emptyList(),
            components = emptyList(),
            signingCertificateSha256 = listOf(signer),
        ),
        findings = emptyList(),
    )
}
