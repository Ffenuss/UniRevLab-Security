package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.DexClassReference
import org.unirevlab.security.model.DexFieldXref
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.DexStringXref
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.StaticAnalysisReport

class AnalystMappingEngineTest {
    @Test
    fun generatesSemanticAndStructuralAliasesWithoutExternalMapping() {
        val dex = DexSummary(
            dexFilesDiscovered = 1,
            dexFilesScanned = 1,
            stringsDeclared = 2,
            stringsScanned = 2,
            classesDeclared = 2,
            classesIndexed = 2,
            methodsDeclared = 2,
            methodsIndexed = 2,
            classes = listOf(
                DexClassReference("classes.dex", 1, "La/b;", "Ljava/lang/Object;", 1),
                DexClassReference("classes.dex", 2, "Lc/d;", "Ljava/lang/Object;", 1),
            ),
            methods = listOf(
                DexMethodReference("classes.dex", 10, "La/b;", "a", "()Z"),
                DexMethodReference("classes.dex", 11, "Lc/d;", "b", "()V"),
            ),
            callXrefs = listOf(
                DexMethodCallXref(
                    dexEntry = "classes.dex",
                    callerMethodIndex = 10,
                    callerClass = "La/b;",
                    callerName = "a",
                    calleeMethodIndex = 99,
                    calleeClass = "Landroid/os/Debug;",
                    calleeName = "isDebuggerConnected",
                    calleePrototype = "()Z",
                    instructionOffsetCodeUnits = 2,
                ),
            ),
            stringXrefs = listOf(
                DexStringXref("classes.dex", 10, "La/b;", "a", 1, "debugger", 1),
                DexStringXref("classes.dex", 11, "Lc/d;", "b", 2, "plain text", 1),
            ),
            fieldXrefs = listOf(
                DexFieldXref(
                    dexEntry = "classes.dex",
                    callerMethodIndex = 11,
                    callerClass = "Lc/d;",
                    callerName = "b",
                    fieldIndex = 7,
                    declaringClass = "Lc/d;",
                    fieldName = "c",
                    fieldType = "I",
                    kind = "IGET",
                    instructionOffsetCodeUnits = 3,
                ),
            ),
            httpUrls = emptyList(),
            httpsUrls = emptyList(),
            secretCandidates = emptyList(),
            parseErrors = 0,
            truncated = false,
        )

        val result = AnalystMappingEngine.generate(report(dex))

        assertTrue(result.obfuscationScore > 0)
        assertTrue(result.mappedSymbols >= 5)
        assertTrue(result.semanticMappings >= 1)
        assertTrue(result.structuralMappings >= 1)
        assertTrue(result.entries.any { it.kind == "METHOD" && it.alias.startsWith("debugCheck") })
        assertTrue(result.entries.any { it.kind == "FIELD" && it.alias == "Field_f7" })
        assertTrue(result.mappingText.contains("analyst labels, not recovered developer-original identifiers"))
        assertTrue(result.mappingText.contains("SEMANTIC"))
        assertTrue(result.mappingText.contains("STRUCTURAL"))
        assertEquals(result.entries.size, result.mappedSymbols)
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
}
