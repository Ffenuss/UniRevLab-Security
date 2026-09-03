package org.unirevlab.security.analysis

import java.io.File
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

class Il2CppManagedDumpExporterTest {
    @Test
    fun rendersCSharpLikeStructureAndParameterMetadataWithoutPatchOffsets() {
        val metadataFile = syntheticMetadata()
        try {
            val dump = Il2CppManagedDumpExporter.export(report(), metadataFile)

            assertTrue(dump.contains("namespace Game.Payments"))
            assertTrue(dump.contains("class PaymentEntitlement"))
            assertTrue(dump.contains("/*TypeRef#123*/ object b("))
            assertTrue(dump.contains("/*TypeRef#456*/ object value"))
            assertTrue(dump.contains("analyst-alias:"))
            assertTrue(dump.contains("Runtime RVA/VA/patch offsets are not emitted"))
            assertTrue(!dump.contains("RVA: 0x"))
            assertTrue(!dump.contains("Offset: 0x"))
        } finally {
            metadataFile.delete()
        }
    }

    private fun syntheticMetadata(): File {
        val bytes = ByteArray(512)
        putIntLe(bytes, 0, 0xFAB11BAF.toInt())
        putIntLe(bytes, 4, 29)
        // strings table (header pair #2)
        putIntLe(bytes, 8 + 2 * 8, 200)
        putIntLe(bytes, 8 + 2 * 8 + 4, 32)
        // methods table (header pair #5)
        putIntLe(bytes, 8 + 5 * 8, 300)
        putIntLe(bytes, 8 + 5 * 8 + 4, 32)
        // parameters table (header pair #10)
        putIntLe(bytes, 8 + 10 * 8, 400)
        putIntLe(bytes, 8 + 10 * 8 + 4, 12)

        "value\u0000".toByteArray(Charsets.UTF_8).copyInto(bytes, 200)
        // Il2CppMethodDefinition subset: returnType @ +8, parameterStart @ +12.
        putIntLe(bytes, 308, 123)
        putIntLe(bytes, 312, 0)
        // Il2CppParameterDefinition subset: nameIndex @ +0, typeIndex @ +8.
        putIntLe(bytes, 400, 0)
        putIntLe(bytes, 404, 0x08000001)
        putIntLe(bytes, 408, 456)

        return File.createTempFile("unirevlab-il2cpp-dump-test-", ".dat").apply { writeBytes(bytes) }
    }

    private fun putIntLe(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = value.toByte()
        bytes[offset + 1] = (value ushr 8).toByte()
        bytes[offset + 2] = (value ushr 16).toByte()
        bytes[offset + 3] = (value ushr 24).toByte()
    }

    private fun report(): StaticAnalysisReport {
        val typeName = "Game.Payments.PaymentEntitlement"
        val metadata = Il2CppMetadataSummary(
            entryName = "global-metadata.dat",
            sizeBytes = 512,
            magicValid = true,
            metadataVersion = 29,
            headerPairsScanned = 20,
            assemblyNameCandidates = listOf("Assembly-CSharp"),
            managedNameCandidates = listOf("PaymentEntitlement"),
            unityVersionCandidates = emptyList(),
            layoutProfile = "IL2CPP_METADATA_V27_V30",
            typeDefinitions = listOf(
                Il2CppTypeDefinitionSummary(
                    index = 0,
                    namespace = "Game.Payments",
                    name = "PaymentEntitlement",
                    fullName = typeName,
                    methodStart = 0,
                    methodCount = 1,
                    fieldStart = 0,
                    fieldCount = 1,
                    token = 0x02000001,
                ),
            ),
            methodDefinitions = listOf(
                Il2CppMethodDefinitionSummary(
                    index = 0,
                    declaringTypeIndex = 0,
                    declaringType = typeName,
                    name = "b",
                    parameterCount = 1,
                    token = 0x06000001,
                    flags = 0x0016,
                ),
            ),
            fieldDefinitions = listOf(
                Il2CppFieldDefinitionSummary(
                    index = 0,
                    declaringTypeIndex = 0,
                    declaringType = typeName,
                    name = "a",
                    typeIndex = 77,
                    token = 0x04000001,
                ),
            ),
        )
        return StaticAnalysisReport(
            engineVersion = "test",
            assessment = AssessmentScope(
                projectName = "test",
                organization = "test",
                purpose = "authorized defensive review",
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
