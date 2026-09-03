package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.CrossRuntimeCorrelationSummary
import org.unirevlab.security.model.Il2CppMetadataSummary
import org.unirevlab.security.model.Il2CppMethodDefinitionSummary
import org.unirevlab.security.model.Il2CppMethodNativeCorrelation
import org.unirevlab.security.model.Il2CppSummary
import org.unirevlab.security.model.Il2CppTypeDefinitionSummary
import org.unirevlab.security.model.StaticAnalysisReport

class Il2CppEvidenceExplorerModelTest {
    @Test
    fun joinsSemanticCandidateToVerifiedNativeEvidence() {
        val result = Il2CppEvidenceExplorerModel.build(
            report(
                listOf(
                    correlation(
                        evidence = "CODEGEN_MODULE_METHOD_TOKEN_SLOT",
                        confidence = "HIGH",
                        functionName = "Game_PremiumService_IsPremium",
                    ),
                ),
            ),
        )

        val row = result.rows.first { it.methodIndex == 0 && it.semanticCategory == "PREMIUM" }
        assertEquals(Il2CppEvidenceExplorerModel.LinkStatus.VERIFIED, row.linkStatus)
        assertEquals("Game.PremiumService.IsPremium", row.managedIdentity)
        assertEquals("Game_PremiumService_IsPremium", row.nativeFunctionName)
        assertEquals("CODEGEN_MODULE_METHOD_TOKEN_SLOT", row.nativeProvenance)
        assertEquals(0x06000001, row.metadataToken)
        assertTrue(row.evidence.any { it.contains("canonical global-metadata.dat", ignoreCase = true) })
        assertEquals(1, result.verified)
    }

    @Test
    fun conflictingCorrelationIsVisibleButNotPromotedToNativeIdentity() {
        val result = Il2CppEvidenceExplorerModel.build(
            report(
                listOf(
                    correlation(
                        token = 0x06000002,
                        evidence = "UNIQUE_METADATA_TOKEN_LITERAL",
                        confidence = "HIGH",
                    ),
                ),
            ),
        )

        val row = result.rows.first { it.methodIndex == 0 && it.semanticCategory == "PREMIUM" }
        assertEquals(Il2CppEvidenceExplorerModel.LinkStatus.CONFLICTING, row.linkStatus)
        assertNull(row.nativeFunctionName)
        assertTrue(row.evidence.any { it.contains("do not form one internally consistent", ignoreCase = true) })
    }

    @Test
    fun filterMatchesAliasNativeFunctionAndStatus() {
        val result = Il2CppEvidenceExplorerModel.build(
            report(
                listOf(
                    correlation(
                        evidence = "UNIQUE_TYPE_METHOD_IDENTITY",
                        confidence = "MEDIUM",
                        functionName = "PremiumService_IsPremium",
                    ),
                ),
            ),
        )

        assertTrue(Il2CppEvidenceExplorerModel.filter(result, "premium_method_0").any { it.methodIndex == 0 })
        assertTrue(Il2CppEvidenceExplorerModel.filter(result, "PremiumService_IsPremium").any { it.methodIndex == 0 })
        val supported = Il2CppEvidenceExplorerModel.filter(
            result,
            query = "",
            status = Il2CppEvidenceExplorerModel.LinkStatus.SUPPORTED,
        )
        assertEquals(1, supported.count { it.methodIndex == 0 })
    }

    private fun correlation(
        token: Long = 0x06000001,
        libraryEntry: String = "lib/arm64-v8a/libil2cpp.so",
        functionRva: Long = 0x1000,
        evidence: String,
        confidence: String,
        functionName: String = "PremiumService_IsPremium",
    ) = Il2CppMethodNativeCorrelation(
        metadataEntry = "global-metadata.dat",
        methodIndex = 0,
        declaringType = "Game.PremiumService",
        methodName = "IsPremium",
        token = token,
        libraryEntry = libraryEntry,
        functionRva = functionRva,
        functionName = functionName,
        evidence = evidence,
        confidence = confidence,
    )

    private fun report(correlations: List<Il2CppMethodNativeCorrelation>): StaticAnalysisReport {
        val metadata = Il2CppMetadataSummary(
            entryName = "assets/bin/Data/Managed/Metadata/global-metadata.dat",
            sizeBytes = 4096,
            magicValid = true,
            metadataVersion = 29,
            headerPairsScanned = 20,
            assemblyNameCandidates = listOf("Assembly-CSharp"),
            managedNameCandidates = listOf("PremiumService", "IsPremium"),
            unityVersionCandidates = listOf("2022.3.20f1"),
            layoutProfile = "IL2CPP_METADATA_V27_V30",
            typeDefinitions = listOf(
                Il2CppTypeDefinitionSummary(
                    index = 0,
                    namespace = "Game",
                    name = "PremiumService",
                    fullName = "Game.PremiumService",
                    methodStart = 0,
                    methodCount = 1,
                    fieldStart = 0,
                    fieldCount = 0,
                    token = 0x02000001,
                ),
            ),
            methodDefinitions = listOf(
                Il2CppMethodDefinitionSummary(
                    index = 0,
                    declaringTypeIndex = 0,
                    declaringType = "Game.PremiumService",
                    name = "IsPremium",
                    parameterCount = 0,
                    token = 0x06000001,
                    flags = 0,
                ),
            ),
            fieldDefinitions = emptyList(),
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
                displayName = "sample.apk",
                sizeBytes = 1,
                sha256 = "11",
                archiveEntries = 1,
                dexFiles = 0,
                nativeLibraries = 1,
                hasAndroidManifest = true,
                suspiciousArchivePaths = 0,
                truncatedArchiveScan = false,
                sourceKind = "APK",
            ),
            manifest = null,
            il2cpp = Il2CppSummary(
                detected = true,
                confidence = "HIGH",
                metadata = metadata,
                libil2cppLibraries = listOf("lib/arm64-v8a/libil2cpp.so"),
                il2cppApiSymbols = emptyList(),
                registrationIndicators = emptyList(),
                parseErrors = 0,
                truncated = false,
            ),
            correlations = CrossRuntimeCorrelationSummary(
                il2cppMethods = correlations,
                il2cppMethodsConsidered = 1,
                il2cppMethodsResolved = if (correlations.isEmpty()) 0 else 1,
                truncated = false,
            ),
            findings = emptyList(),
        )
    }
}
