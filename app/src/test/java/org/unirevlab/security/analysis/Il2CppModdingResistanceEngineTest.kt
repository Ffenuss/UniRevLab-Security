package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
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

class Il2CppModdingResistanceEngineTest {
    @Test
    fun localPremiumFieldWithoutValidationIsClientAuthoritative() {
        val result = Il2CppModdingResistanceEngine.analyze(report(includeValidation = false))
        val target = result.targets.first { it.managedIdentity.endsWith("._isPremium") }

        assertEquals(Il2CppModdingResistanceEngine.Authority.CLIENT_AUTHORITATIVE, target.authority)
        assertEquals(Il2CppModdingResistanceEngine.ReviewPriority.CRITICAL, target.priority)
        assertTrue(result.clientAuthoritative >= 1)
        assertTrue(target.hardeningActions.any { it.contains("backend", ignoreCase = true) })
    }

    @Test
    fun localPremiumStateWithReceiptValidationIsMixedNotServerProven() {
        val result = Il2CppModdingResistanceEngine.analyze(report(includeValidation = true))
        val target = result.targets.first { it.managedIdentity.endsWith("._isPremium") }

        assertEquals(Il2CppModdingResistanceEngine.Authority.MIXED, target.authority)
        assertEquals(Il2CppModdingResistanceEngine.ReviewPriority.HIGH, target.priority)
        assertTrue(result.validationSignals >= 1)
        assertTrue(target.evidence.any { it.contains("validation", ignoreCase = true) })
    }

    private fun report(includeValidation: Boolean): StaticAnalysisReport {
        val methods = buildList {
            add(
                Il2CppMethodDefinitionSummary(
                    index = 0,
                    declaringTypeIndex = 0,
                    declaringType = "Game.Payments.PaymentEntitlement",
                    name = "get_IsPremium",
                    parameterCount = 0,
                    token = 0x06000001,
                    flags = 0x0006,
                ),
            )
            if (includeValidation) {
                add(
                    Il2CppMethodDefinitionSummary(
                        index = 1,
                        declaringTypeIndex = 0,
                        declaringType = "Game.Payments.PaymentEntitlement",
                        name = "ValidateReceipt",
                        parameterCount = 1,
                        token = 0x06000002,
                        flags = 0x0006,
                    ),
                )
            }
        }
        val metadata = Il2CppMetadataSummary(
            entryName = "global-metadata.dat",
            sizeBytes = 8192,
            magicValid = true,
            metadataVersion = 29,
            headerPairsScanned = 20,
            assemblyNameCandidates = listOf("Assembly-CSharp"),
            managedNameCandidates = listOf("PaymentEntitlement", "_isPremium", "get_IsPremium") +
                if (includeValidation) listOf("ValidateReceipt") else emptyList(),
            unityVersionCandidates = listOf("2022.3"),
            layoutProfile = "IL2CPP_METADATA_V27_V30",
            typeDefinitions = listOf(
                Il2CppTypeDefinitionSummary(
                    index = 0,
                    namespace = "Game.Payments",
                    name = "PaymentEntitlement",
                    fullName = "Game.Payments.PaymentEntitlement",
                    methodStart = 0,
                    methodCount = methods.size,
                    fieldStart = 0,
                    fieldCount = 1,
                    token = 0x02000001,
                ),
            ),
            methodDefinitions = methods,
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
        return StaticAnalysisReport(
            engineVersion = "test",
            assessment = AssessmentScope(projectName = "test", organization = "test", purpose = "authorized review", confirmsAuthority = true),
            artifact = ArtifactSummary(
                displayName = "pair",
                sizeBytes = 1,
                sha256 = "aa",
                archiveEntries = null,
                dexFiles = 0,
                nativeLibraries = 1,
                hasAndroidManifest = false,
                suspiciousArchivePaths = 0,
                truncatedArchiveScan = false,
                sourceKind = "IL2CPP_PAIR",
            ),
            manifest = null,
            il2cpp = Il2CppSummary(
                detected = true,
                confidence = "HIGH",
                metadata = metadata,
                libil2cppLibraries = listOf("libil2cpp.so"),
                il2cppApiSymbols = emptyList(),
                registrationIndicators = emptyList(),
                parseErrors = 0,
                truncated = false,
            ),
            findings = emptyList(),
        )
    }
}
