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

class Il2CppSemanticMappingEngineTest {
    @Test
    fun buildsContextualAliasesForObfuscatedMembersWithoutClaimingOriginalNames() {
        val result = Il2CppSemanticMappingEngine.analyze(report())

        assertTrue(result.likelyObfuscated)
        assertTrue(result.obfuscationScore > 0)
        assertTrue(result.semanticMappings >= 1)
        assertTrue(result.contextualMappings >= 2)
        assertTrue(result.structuralMappings >= 1)
        assertTrue(result.entries.any {
            it.kind == "FIELD" &&
                it.originalIdentity == "Game.Payments.PaymentEntitlement.a" &&
                it.basis == Il2CppSemanticMappingEngine.Basis.CONTEXTUAL &&
                it.semanticCategory == "ENTITLEMENT"
        })
        assertTrue(result.entries.any {
            it.kind == "METHOD" &&
                it.originalIdentity == "Game.Payments.PaymentEntitlement.b" &&
                it.alias.startsWith("entitlement_related_method_")
        })
        assertTrue(result.entries.any {
            it.originalIdentity == "Game.Internal.c" &&
                it.basis == Il2CppSemanticMappingEngine.Basis.STRUCTURAL
        })
        assertTrue(result.mappingText.contains("not recovered original developer names", ignoreCase = true))
        assertTrue(result.mappingText.contains("do not prove", ignoreCase = true))
    }

    @Test
    fun monetizationRiskIncludesContextualReviewCandidateButNotRuntimeValueClaim() {
        val result = Il2CppMonetizationRiskEngine.analyze(report())
        val contextual = result.candidates.firstOrNull {
            it.kind == "CONTEXT_FIELD" && it.managedIdentity == "Game.Payments.PaymentEntitlement.a"
        }

        assertTrue(contextual != null)
        assertEquals(Il2CppMonetizationRiskEngine.Category.ENTITLEMENT, contextual?.category)
        assertTrue(contextual?.evidence.orEmpty().any { it.contains("does not prove", ignoreCase = true) })
    }

    private fun report(): StaticAnalysisReport {
        val metadata = Il2CppMetadataSummary(
            entryName = "global-metadata.dat",
            sizeBytes = 8192,
            magicValid = true,
            metadataVersion = 29,
            headerPairsScanned = 20,
            assemblyNameCandidates = listOf("Assembly-CSharp"),
            managedNameCandidates = listOf("PaymentEntitlement"),
            unityVersionCandidates = listOf("2022.3.20f1"),
            layoutProfile = "IL2CPP_METADATA_V27_V30",
            typeDefinitions = listOf(
                Il2CppTypeDefinitionSummary(
                    index = 0,
                    namespace = "Game.Payments",
                    name = "PaymentEntitlement",
                    fullName = "Game.Payments.PaymentEntitlement",
                    methodStart = 0,
                    methodCount = 1,
                    fieldStart = 0,
                    fieldCount = 1,
                    token = 0x02000001,
                ),
                Il2CppTypeDefinitionSummary(
                    index = 1,
                    namespace = "Game.Internal",
                    name = "c",
                    fullName = "Game.Internal.c",
                    methodStart = 1,
                    methodCount = 2,
                    fieldStart = 1,
                    fieldCount = 2,
                    token = 0x02000002,
                ),
            ),
            methodDefinitions = listOf(
                Il2CppMethodDefinitionSummary(
                    index = 0,
                    declaringTypeIndex = 0,
                    declaringType = "Game.Payments.PaymentEntitlement",
                    name = "b",
                    parameterCount = 0,
                    token = 0x06000001,
                    flags = 0,
                ),
                Il2CppMethodDefinitionSummary(
                    index = 1,
                    declaringTypeIndex = 1,
                    declaringType = "Game.Internal.c",
                    name = "f",
                    parameterCount = 0,
                    token = 0x06000002,
                    flags = 0,
                ),
                Il2CppMethodDefinitionSummary(
                    index = 2,
                    declaringTypeIndex = 1,
                    declaringType = "Game.Internal.c",
                    name = "g",
                    parameterCount = 1,
                    token = 0x06000003,
                    flags = 0,
                ),
            ),
            fieldDefinitions = listOf(
                Il2CppFieldDefinitionSummary(
                    index = 0,
                    declaringTypeIndex = 0,
                    declaringType = "Game.Payments.PaymentEntitlement",
                    name = "a",
                    typeIndex = 2,
                    token = 0x04000001,
                ),
                Il2CppFieldDefinitionSummary(
                    index = 1,
                    declaringTypeIndex = 1,
                    declaringType = "Game.Internal.c",
                    name = "d",
                    typeIndex = 2,
                    token = 0x04000002,
                ),
                Il2CppFieldDefinitionSummary(
                    index = 2,
                    declaringTypeIndex = 1,
                    declaringType = "Game.Internal.c",
                    name = "e",
                    typeIndex = 2,
                    token = 0x04000003,
                ),
            ),
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
                displayName = "pair",
                sizeBytes = 1,
                sha256 = "11",
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
