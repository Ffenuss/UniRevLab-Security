package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
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

class Il2CppNativeEvidenceEngineTest {
    @Test
    fun verifiesStrongTokenSlotCorrelationWhenMetadataIdentityMatches() {
        val result = Il2CppNativeEvidenceEngine.analyze(
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

        assertEquals(1, result.verified)
        assertEquals(0, result.conflicting)
        val method = result.forMethod(0)
        assertEquals(Il2CppNativeEvidenceEngine.Verdict.VERIFIED, method?.verdict)
        assertEquals("Game_PremiumService_IsPremium", method?.nativeFunctionName)
        assertTrue(method?.evidence.orEmpty().any { it.contains("static identity link", ignoreCase = true) })
    }

    @Test
    fun rejectsCorrelationWhenTokenDoesNotMatchCanonicalMetadata() {
        val result = Il2CppNativeEvidenceEngine.analyze(
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

        assertEquals(1, result.conflicting)
        assertEquals(Il2CppNativeEvidenceEngine.Verdict.CONFLICTING, result.forMethod(0)?.verdict)
        assertEquals(null, result.forMethod(0)?.nativeFunctionName)
    }

    @Test
    fun keepsUniqueIdentityMatchAsSupportedInsteadOfVerified() {
        val result = Il2CppNativeEvidenceEngine.analyze(
            report(
                listOf(
                    correlation(
                        evidence = "UNIQUE_TYPE_METHOD_IDENTITY",
                        confidence = "MEDIUM",
                    ),
                ),
            ),
        )

        assertEquals(0, result.verified)
        assertEquals(1, result.supported)
        assertEquals(Il2CppNativeEvidenceEngine.Verdict.SUPPORTED, result.forMethod(0)?.verdict)
    }

    @Test
    fun acceptsConsistentMultiAbiEvidenceWithoutTreatingDifferentLibrariesAsConflict() {
        val result = Il2CppNativeEvidenceEngine.analyze(
            report(
                listOf(
                    correlation(
                        libraryEntry = "lib/arm64-v8a/libil2cpp.so",
                        functionRva = 0x1000,
                        evidence = "CODEGEN_MODULE_METHOD_TOKEN_SLOT",
                        confidence = "HIGH",
                    ),
                    correlation(
                        libraryEntry = "lib/x86_64/libil2cpp.so",
                        functionRva = 0x2000,
                        evidence = "CODEGEN_MODULE_METHOD_TOKEN_SLOT",
                        confidence = "HIGH",
                    ),
                ),
            ),
        )

        assertEquals(0, result.conflicting)
        assertEquals(1, result.verified)
        assertEquals(2, result.forMethod(0)?.matchingCorrelations)
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
                nativeLibraries = 2,
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
                libil2cppLibraries = listOf("lib/arm64-v8a/libil2cpp.so", "lib/x86_64/libil2cpp.so"),
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
