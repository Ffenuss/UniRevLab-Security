package org.unirevlab.security.analysis

import java.io.StringWriter
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.CrossRuntimeCorrelationSummary
import org.unirevlab.security.model.Il2CppMethodNativeCorrelation
import org.unirevlab.security.model.NativeLibrarySummary
import org.unirevlab.security.model.NativeSummary
import org.unirevlab.security.model.NativeSymbolReference
import org.unirevlab.security.model.StaticAnalysisReport

class OffsetReadableExporterTest {
    @Test
    fun createsSearchableHumanReportWithDemangledAndVerifiedRows() {
        val libraryEntry = "base.apk!lib/arm64-v8a/libil2cpp.so"
        val report = StaticAnalysisReport(
            engineVersion = "test",
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
                archiveEntries = 3,
                dexFiles = 1,
                nativeLibraries = 1,
                hasAndroidManifest = true,
                suspiciousArchivePaths = 0,
                truncatedArchiveScan = false,
            ),
            manifest = null,
            native = NativeSummary(
                librariesDiscovered = 1,
                librariesScanned = 1,
                libraries = listOf(
                    NativeLibrarySummary(
                        entryName = libraryEntry,
                        abi = "arm64-v8a",
                        elfClass = "ELF64",
                        machine = "AARCH64",
                        fileType = "DYN",
                        sizeBytes = 1_000,
                        buildId = "0123456789abcdef",
                        neededLibraries = emptyList(),
                        importedSymbols = emptyList(),
                        exportedSymbols = listOf(
                            NativeSymbolReference(
                                libraryEntry = libraryEntry,
                                name = "_ZN3UQM9UQMLogger7consoleEv",
                                binding = "GLOBAL",
                                symbolType = "FUNC",
                                defined = true,
                                virtualAddress = 0x41b54,
                                sizeBytes = 12,
                            )
                        ),
                        jniSymbols = emptyList(),
                        hasJniOnLoad = false,
                        registerNativesIndicator = false,
                        executableStack = false,
                        hasGnuRelro = true,
                        bindNow = true,
                        hasStackCanaryImport = true,
                        stripped = false,
                        httpUrls = emptyList(),
                    )
                ),
                parseErrors = 0,
                truncated = false,
            ),
            correlations = CrossRuntimeCorrelationSummary(
                il2cppMethods = listOf(
                    Il2CppMethodNativeCorrelation(
                        metadataEntry = "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                        methodIndex = 7,
                        declaringType = "Game.Player",
                        methodName = "Update",
                        token = 0x06000008,
                        libraryEntry = libraryEntry,
                        functionRva = 0x1234,
                        functionName = "Game.Player.Update",
                        evidence = "exact metadata token",
                        confidence = "HIGH",
                    )
                )
            ),
            findings = emptyList(),
        )

        val output = StringWriter()
        OffsetReadableExporter.write(report, output)
        val html = output.toString()

        assertTrue(html.contains("Game.Player.Update(…)"))
        assertTrue(html.contains("0x1234"))
        assertTrue(html.contains("UQM::UQMLogger::console(…)"))
        assertTrue(html.contains("0x41b54"))
        assertTrue(html.contains("applyFilters()"))
        assertTrue(html.contains("ABI: arm64-v8a"))
    }
}
