package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.NativeLibrarySummary
import org.unirevlab.security.model.NativeSummary
import org.unirevlab.security.model.NativeSymbolReference
import org.unirevlab.security.model.RuntimeProfileDetection
import org.unirevlab.security.model.RuntimeSummary
import org.unirevlab.security.model.StaticAnalysisReport

class ModificationSurfaceClassifierTest {
    @Test
    fun gameProfileHighlightsGameplayRva() {
        val result = ModificationSurfaceClassifier.analyze(
            report(
                runtimeKind = "UNITY_IL2CPP",
                symbolName = "PlayerStats_SetHealth",
            ),
        )

        assertEquals(ModificationSurfaceClassifier.TargetProfile.GAME_LIKELY, result.targetProfile)
        assertTrue(result.resolvedOffsets.any {
            it.category == "HEALTH_DAMAGE" && it.rva == 0x1234L && it.domain == "GAMEPLAY"
        })
    }

    @Test
    fun ordinaryAppHighlightsPremiumRvaWithoutCallingItGameplay() {
        val result = ModificationSurfaceClassifier.analyze(
            report(
                runtimeKind = null,
                symbolName = "Java_com_example_PremiumManager_isPremium",
            ),
        )

        assertEquals(ModificationSurfaceClassifier.TargetProfile.APPLICATION_LIKELY, result.targetProfile)
        assertTrue(result.resolvedOffsets.any {
            it.category == "PREMIUM_ENTITLEMENT" && it.domain == "MONETIZATION"
        })
        assertTrue(result.resolvedOffsets.none { it.domain == "GAMEPLAY" })
    }

    private fun report(runtimeKind: String?, symbolName: String): StaticAnalysisReport {
        val entry = "lib/arm64-v8a/libtarget.so"
        val library = NativeLibrarySummary(
            entryName = entry,
            abi = "arm64-v8a",
            elfClass = "ELF64",
            machine = "AARCH64",
            fileType = "DYN",
            sizeBytes = 1,
            buildId = "fixture-build-id",
            neededLibraries = emptyList(),
            importedSymbols = emptyList(),
            exportedSymbols = listOf(
                NativeSymbolReference(entry, symbolName, "GLOBAL", "FUNC", true, 0x1234L, 16),
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
        return StaticAnalysisReport(
            engineVersion = "test",
            assessment = AssessmentScope(
                assessmentId = "assessment",
                createdAtEpochMs = 1,
                projectName = "Project",
                organization = "Owner",
                purpose = "Authorized audit",
                confirmsAuthority = true,
            ),
            artifact = ArtifactSummary(
                displayName = "target.apk",
                sizeBytes = 1,
                sha256 = "a".repeat(64),
                archiveEntries = 1,
                dexFiles = 0,
                nativeLibraries = 1,
                hasAndroidManifest = true,
                suspiciousArchivePaths = 0,
                truncatedArchiveScan = false,
            ),
            manifest = null,
            native = NativeSummary(1, 1, listOf(library), parseErrors = 0, truncated = false),
            runtimes = runtimeKind?.let { RuntimeSummary(listOf(RuntimeProfileDetection(it, "HIGH", listOf("fixture")))) },
            findings = emptyList(),
        )
    }
}
