package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.ComponentDexReachability
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexStringXref
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.ManifestDexReachabilitySummary
import org.unirevlab.security.model.StaticAnalysisReport

class ProductSecuritySuiteTest {
    @Test
    fun postureSeparatesDetectedChecksFromUnknownBaselineTamperState() {
        val dex = emptyDex(
            callXrefs = listOf(
                DexMethodCallXref(
                    dexEntry = "classes.dex",
                    callerMethodIndex = 7,
                    callerClass = "Lapp/Security;",
                    callerName = "checkInstaller",
                    calleeMethodIndex = -1,
                    calleeClass = "Landroid/content/pm/PackageManager;",
                    calleeName = "getInstallSourceInfo",
                    calleePrototype = "(Ljava/lang/String;)Landroid/content/pm/InstallSourceInfo;",
                    instructionOffsetCodeUnits = 12,
                ),
            ),
            stringXrefs = listOf(
                DexStringXref(
                    dexEntry = "classes.dex",
                    callerMethodIndex = 8,
                    callerClass = "Lapp/Security;",
                    callerName = "checkRoot",
                    stringIndex = 1,
                    value = "/system/xbin/su",
                    instructionOffsetCodeUnits = 3,
                ),
            ),
        )
        val posture = ProtectionPostureEngine.scan(report(dex))

        assertEquals(
            ProtectionPostureEngine.Status.PRESENT,
            posture.checks.first { it.id == "ROOT_DETECTION" }.status,
        )
        assertEquals(
            ProtectionPostureEngine.Status.PRESENT,
            posture.checks.first { it.id == "INSTALL_SOURCE" }.status,
        )
        assertEquals(
            ProtectionPostureEngine.Status.UNKNOWN,
            posture.checks.first { it.id == "BASELINE_TAMPER_STATUS" }.status,
        )
    }

    @Test
    fun serializationInspectorFindsExternallyReachableJavaObjectDeserialization() {
        val dex = emptyDex(
            callXrefs = listOf(
                DexMethodCallXref(
                    dexEntry = "classes.dex",
                    callerMethodIndex = 42,
                    callerClass = "Lapp/ExportedActivity;",
                    callerName = "handlePayload",
                    calleeMethodIndex = -1,
                    calleeClass = "Ljava/io/ObjectInputStream;",
                    calleeName = "readObject",
                    calleePrototype = "()Ljava/lang/Object;",
                    instructionOffsetCodeUnits = 9,
                ),
            ),
        )
        val base = report(dex)
        val withReachability = base.copy(
            manifestDexReachability = ManifestDexReachabilitySummary(
                components = listOf(
                    ComponentDexReachability(
                        componentKind = "activity",
                        componentName = "app.ExportedActivity",
                        classDescriptor = "Lapp/ExportedActivity;",
                        exported = true,
                        externallyAddressable = true,
                        classPresent = true,
                        entryMethodIndexes = listOf(40),
                        reachableMethodIndexes = listOf(40, 42),
                        reachableMethodCount = 2,
                        maxDepthReached = 1,
                        truncated = false,
                    ),
                ),
                externallyAddressableComponents = 1,
                reachableMethods = 2,
                truncated = false,
            ),
        )

        val result = SerializationInspector.scan(withReachability)
        assertEquals(1, result.deserializeCount)
        assertEquals(1, result.highRiskCount)
        assertEquals(1, result.externallyReachableCount)
        assertTrue(result.surfaces.single().callee.contains("ObjectInputStream"))
    }

    private fun report(dex: DexSummary) = StaticAnalysisReport(
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
            sha256 = "00",
            archiveEntries = 1,
            dexFiles = 1,
            nativeLibraries = 0,
            hasAndroidManifest = true,
            suspiciousArchivePaths = 0,
            truncatedArchiveScan = false,
        ),
        manifest = null,
        dex = dex,
        findings = emptyList(),
    )

    private fun emptyDex(
        callXrefs: List<DexMethodCallXref> = emptyList(),
        stringXrefs: List<DexStringXref> = emptyList(),
    ) = DexSummary(
        dexFilesDiscovered = 1,
        dexFilesScanned = 1,
        stringsDeclared = 0,
        stringsScanned = 0,
        callXrefs = callXrefs,
        stringXrefs = stringXrefs,
        httpUrls = emptyList(),
        httpsUrls = emptyList(),
        secretCandidates = emptyList(),
        parseErrors = 0,
        truncated = false,
    )
}
