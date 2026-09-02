package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.StaticAnalysisReport

class DiagnosticsEngineTest {
    @Test
    fun healthyMinimalReportHasNoHardFailures() {
        val result = DiagnosticsEngine.run(report(dex = null))
        assertEquals(0, result.failed)
        assertTrue(result.warnings > 0)
        assertTrue(result.checks.any { it.id == "DEOB" && it.status == DiagnosticsEngine.Status.PASS })
    }

    @Test
    fun impossibleDexCountersProduceFailure() {
        val dex = DexSummary(
            dexFilesDiscovered = 1,
            dexFilesScanned = 2,
            stringsDeclared = 0,
            stringsScanned = 0,
            classesDeclared = 0,
            classesIndexed = 1,
            methodsDeclared = 0,
            methodsIndexed = 1,
            httpUrls = emptyList(),
            httpsUrls = emptyList(),
            secretCandidates = emptyList(),
            parseErrors = 0,
            truncated = false,
        )
        val result = DiagnosticsEngine.run(report(dex))
        assertTrue(result.failed >= 1)
        assertTrue(result.checks.any { it.id == "DEX_INDEX" && it.status == DiagnosticsEngine.Status.FAIL })
    }

    private fun report(dex: DexSummary?) = StaticAnalysisReport(
        engineVersion = "test",
        assessment = AssessmentScope(
            projectName = "test",
            organization = "test",
            purpose = "test",
            confirmsAuthority = true,
        ),
        artifact = ArtifactSummary(
            displayName = "test.apk",
            sizeBytes = 1,
            sha256 = "0".repeat(64),
            archiveEntries = 1,
            dexFiles = if (dex == null) 0 else 1,
            nativeLibraries = 0,
            hasAndroidManifest = true,
            suspiciousArchivePaths = 0,
            truncatedArchiveScan = false,
        ),
        manifest = null,
        dex = dex,
        findings = emptyList(),
    )
}
