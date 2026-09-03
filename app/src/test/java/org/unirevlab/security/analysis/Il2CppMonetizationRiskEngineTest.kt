package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.Il2CppFieldDefinitionSummary
import org.unirevlab.security.model.Il2CppMetadataSummary
import org.unirevlab.security.model.Il2CppMethodDefinitionSummary
import org.unirevlab.security.model.Il2CppSummary
import org.unirevlab.security.model.Il2CppTypeDefinitionSummary
import org.unirevlab.security.model.StaticAnalysisReport

class Il2CppMonetizationRiskEngineTest {
    @Test
    fun identifiesClientPremiumStateAndValidationWithoutGeneratingPatchData() {
        val report = report()
        val result = Il2CppMonetizationRiskEngine.analyze(report)

        assertEquals(Il2CppMonetizationRiskEngine.Posture.MIXED_CLIENT_AND_VALIDATION, result.posture)
        assertTrue(result.clientStateCandidates >= 1)
        assertTrue(result.validationCandidates >= 1)
        assertTrue(result.candidates.any {
            it.kind == "FIELD" && it.managedIdentity.contains("_isPremium") &&
                it.category == Il2CppMonetizationRiskEngine.Category.PREMIUM
        })
        assertTrue(result.candidates.any {
            it.managedIdentity.contains("get_IsPremium") &&
                it.category == Il2CppMonetizationRiskEngine.Category.PREMIUM
        })
        assertTrue(result.candidates.any {
            it.managedIdentity.contains("ValidateReceipt") &&
                it.category == Il2CppMonetizationRiskEngine.Category.RECEIPT_VALIDATION
        })
        assertTrue(result.recommendations.any { it.contains("server", ignoreCase = true) })
    }

    @Test
    fun managedDumpExportsCSharpLikeMetadataIdentitiesAndTokensWithoutPatchPayloads() {
        val dump = Il2CppManagedDumpExporter.export(report())

        assertTrue(dump.contains("namespace Game.Payments"))
        assertTrue(dump.contains("class PaymentEntitlement"))
        assertTrue(dump.contains("object _isPremium;"))
        assertTrue(dump.contains("get_IsPremium("))
        assertTrue(dump.contains("token: 0x6000001"))
        assertTrue(dump.contains("patch offsets are not emitted", ignoreCase = true))
        assertFalse(dump.contains("patchOffset="))
        assertFalse(dump.contains("hexPayload="))
    }

    private fun report(): StaticAnalysisReport {
        val metadata = Il2CppMetadataSummary(
            entryName = "assets/bin/Data/Managed/Metadata/global-metadata.dat",
            sizeBytes = 4096,
            magicValid = true,
            metadataVersion = 29,
            headerPairsScanned = 20,
            assemblyNameCandidates = listOf("Assembly-CSharp"),
            managedNameCandidates = listOf("PaymentEntitlement", "ValidateReceipt", "_isPremium"),
            unityVersionCandidates = listOf("2022.3"),
            layoutProfile = "v29",
            typeDefinitions = listOf(
                Il2CppTypeDefinitionSummary(
                    index = 0,
                    namespace = "Game.Payments",
                    name = "PaymentEntitlement",
                    fullName = "Game.Payments.PaymentEntitlement",
                    methodStart = 0,
                    methodCount = 2,
                    fieldStart = 0,
                    fieldCount = 1,
                    token = 0x02000001,
                ),
            ),
            methodDefinitions = listOf(
                Il2CppMethodDefinitionSummary(
                    index = 0,
                    declaringTypeIndex = 0,
                    declaringType = "Game.Payments.PaymentEntitlement",
                    name = "get_IsPremium",
                    parameterCount = 0,
                    token = 0x06000001,
                    flags = 0,
                ),
                Il2CppMethodDefinitionSummary(
                    index = 1,
                    declaringTypeIndex = 0,
                    declaringType = "Game.Payments.PaymentEntitlement",
                    name = "ValidateReceipt",
                    parameterCount = 1,
                    token = 0x06000002,
                    flags = 0,
                ),
            ),
            fieldDefinitions = listOf(
                Il2CppFieldDefinitionSummary(
                    index = 0,
                    declaringTypeIndex = 0,
                    declaringType = "Game.Payments.PaymentEntitlement",
                    name = "_isPremium",
                    typeIndex = 2,
                    token = 0x04000001,
                ),
            ),
        )
        val il2cpp = Il2CppSummary(
            detected = true,
            confidence = "HIGH",
            metadata = metadata,
            libil2cppLibraries = listOf("lib/arm64-v8a/libil2cpp.so"),
            il2cppApiSymbols = emptyList(),
            registrationIndicators = emptyList(),
            parseErrors = 0,
            truncated = false,
        )
        return StaticAnalysisReport(
            engineVersion = "test",
            assessment = AssessmentScope(
                projectName = "test",
                organization = "test",
                purpose = "authorized review",
                confirmsAuthority = true,
            ),
            artifact = ArtifactSummary(
                displayName = "unity.apk",
                sizeBytes = 1,
                sha256 = "00",
                archiveEntries = 1,
                dexFiles = 0,
                nativeLibraries = 1,
                hasAndroidManifest = true,
                suspiciousArchivePaths = 0,
                truncatedArchiveScan = false,
            ),
            manifest = null,
            il2cpp = il2cpp,
            findings = emptyList(),
        )
    }
}
