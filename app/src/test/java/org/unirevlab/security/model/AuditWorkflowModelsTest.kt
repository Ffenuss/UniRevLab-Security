package org.unirevlab.security.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AuditWorkflowModelsTest {
    @Test
    fun jobSpecRoundTripsWithInstalledSplitApks() {
        val scope = AssessmentScope(
            assessmentId = "assessment-1",
            createdAtEpochMs = 10,
            projectName = "Project",
            organization = "Customer",
            purpose = "Authorized review",
            confirmsAuthority = true,
        )
        val expected = AuditJobSpec(
            jobId = "12345678-1234-1234-1234-123456789abc",
            createdAtEpochMs = 20,
            scope = scope,
            source = AuditSourceSpec(
                kind = AuditSourceKind.INSTALLED_APP,
                displayName = "Target",
                packageName = "org.example.target",
                baseApkPath = "/data/app/base.apk",
                splitApkPaths = listOf("/data/app/split_config.arm64_v8a.apk"),
                versionName = "1.2.3",
                versionCode = 12,
            ),
            languageCode = "en",
        )

        assertEquals(expected, AuditWorkflowJson.decodeSpec(AuditWorkflowJson.encodeSpec(expected)))
    }

    @Test
    fun profileCreatesAuthorizedScopeAndKeepsModes() {
        val profile = AuditProfile("P", "O", "Purpose", dynamicAnalysis = true, networkTesting = true)
        val scope = profile.createScope()

        assertTrue(scope.confirmsAuthority)
        assertTrue(scope.staticAnalysis)
        assertTrue(scope.reverseEngineering)
        assertTrue(scope.dynamicAnalysis)
        assertTrue(scope.networkTesting)
    }

    @Test
    fun testModeProfileNeedsNoUserIdentityFields() {
        val profile = AuditProfile.testMode("ru")
        assertTrue(profile.isValid)
        assertEquals("Локальный тестовый режим", profile.organization)
    }

    @Test
    fun summaryPreservesRealDumpTruthState() {
        val expected = AuditJobSummary(
            jobId = "dump-job",
            completedAtEpochMs = 30,
            displayName = "Game",
            packageName = "org.example.game",
            artifactSha256 = "abc",
            runtimeLabels = listOf("UNITY_IL2CPP"),
            findings = 1,
            critical = 0,
            high = 0,
            medium = 1,
            dexMethods = 10,
            nativeLibraries = 8,
            il2cppDetected = true,
            il2cppMetadataVersion = 31,
            il2cppDetectionSource = "REAL_DUMP_COMPLETE",
            il2cppDumpStatus = "COMPLETE",
            il2cppSuccessfulAbis = listOf("arm64-v8a"),
            confirmedGameplaySurfaces = 12,
            confirmedApplicationSurfaces = 3,
            exportedArtifactCount = 20,
            outputFiles = listOf("il2cpp-dump.cs"),
        )

        assertEquals(expected, AuditWorkflowJson.decodeSummary(AuditWorkflowJson.encodeSummary(expected)))
    }
}
