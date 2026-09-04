package org.unirevlab.security.analysis

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.Confidence
import org.unirevlab.security.model.Evidence
import org.unirevlab.security.model.Finding
import org.unirevlab.security.model.NativeLibrarySummary
import org.unirevlab.security.model.NativeSummary
import org.unirevlab.security.model.NativeSymbolReference
import org.unirevlab.security.model.StaticAnalysisReport
import org.unirevlab.security.model.Severity

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
    fun verificationPlanIsLinkedToReportedFinding() {
        val withFinding = report.copy(
            findings = listOf(
                Finding(
                    id = "ANDROID-APP-LINK-PLACEHOLDER-HOST",
                    title = "placeholder",
                    severity = Severity.MEDIUM,
                    confidence = Confidence.CONFIRMED,
                    category = "PLATFORM",
                    description = "placeholder",
                    evidence = listOf(Evidence("manifest", "host", "{link_domain}")),
                    remediation = "replace",
                ),
            ),
        )

        val json = JSONObject(VerificationPlanExporter.export(withFinding))
        val test = (0 until json.getJSONArray("tests").length())
            .map { json.getJSONArray("tests").getJSONObject(it) }
            .single { it.getString("id") == "APP-LINK-VERIFICATION" }

        assertEquals("NOT_EXECUTED", test.getString("status"))
        assertEquals("ANDROID-APP-LINK-PLACEHOLDER-HOST", test.getJSONArray("sourceFindingIds").getString(0))
    }

    @Test
    fun customerReportStatesMethodBoundary() {
        val markdown = CustomerReportExporter.export(report)

        assertTrue(markdown.contains("Динамические проверки | НЕ ВЫПОЛНЕНЫ"))
        assertTrue(markdown.contains("не выдаёт сырой символ за готовый hook-offset"))
        assertTrue(markdown.contains("verification-plan.json"))
    }

    @Test
    fun offsetExportKeepsEvidenceFromEveryLibrary() {
        fun library(name: String, symbols: Int): NativeLibrarySummary {
            val entry = "lib/arm64-v8a/$name"
            return NativeLibrarySummary(
                entryName = entry,
                abi = "arm64-v8a",
                elfClass = "ELF64",
                machine = "AARCH64",
                fileType = "DYN",
                sizeBytes = 1,
                buildId = null,
                neededLibraries = emptyList(),
                importedSymbols = emptyList(),
                exportedSymbols = (0 until symbols).map { index ->
                    NativeSymbolReference(entry, "symbol_$index", "GLOBAL", "FUNC", true, index.toLong() + 1, 4)
                },
                jniSymbols = emptyList(),
                hasJniOnLoad = false,
                registerNativesIndicator = false,
                executableStack = false,
                hasGnuRelro = true,
                bindNow = true,
                hasStackCanaryImport = true,
                stripped = true,
                httpUrls = emptyList(),
            )
        }
        val withNative = report.copy(
            native = NativeSummary(
                librariesDiscovered = 2,
                librariesScanned = 2,
                libraries = listOf(library("liblarge.so", 2_100), library("liblate.so", 1)),
                parseErrors = 0,
                truncated = false,
            ),
        )

        val json = JSONObject(OffsetEvidenceExporter.export(withNative))
        val libraries = json.getJSONArray("nativeLibraries")

        assertTrue(libraries.getJSONObject(0).getBoolean("symbolsTruncated"))
        assertEquals(1, libraries.getJSONObject(1).getJSONArray("symbols").length())
        assertEquals("fair-per-library", json.getJSONObject("nativeSymbolCoverage").getString("selection"))
    }
}
