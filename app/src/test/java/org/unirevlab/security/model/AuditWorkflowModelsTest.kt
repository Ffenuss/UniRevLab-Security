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
}
