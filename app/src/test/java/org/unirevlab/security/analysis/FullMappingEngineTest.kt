package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.DexClassReference
import org.unirevlab.security.model.DexFieldReference
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.StaticAnalysisReport

class FullMappingEngineTest {
    @Test
    fun emitsOriginalStyleMappingForEveryIndexedAppSymbol() {
        val dex = DexSummary(
            dexFilesDiscovered = 1,
            dexFilesScanned = 1,
            stringsDeclared = 0,
            stringsScanned = 0,
            classesDeclared = 2,
            classesIndexed = 2,
            methodsDeclared = 3,
            methodsIndexed = 3,
            fieldsDeclared = 1,
            fieldsIndexed = 1,
            fields = listOf(
                DexFieldReference("classes.dex", 7, "La/b;", "d", "I"),
            ),
            classes = listOf(
                DexClassReference("classes.dex", 1, "La/b;", "Ljava/lang/Object;", 1),
                DexClassReference("classes.dex", 2, "Lcom/acme/Readable;", "Ljava/lang/Object;", 1),
            ),
            methods = listOf(
                DexMethodReference("classes.dex", 10, "La/b;", "a", "(Ljava/lang/String;)Z"),
                DexMethodReference("classes.dex", 11, "La/b;", "c", "()V"),
                DexMethodReference("classes.dex", 12, "Lcom/acme/Readable;", "perform", "(I)V"),
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
                    instructionOffsetCodeUnits = 1,
                ),
            ),
            httpUrls = emptyList(),
            httpsUrls = emptyList(),
            secretCandidates = emptyList(),
            parseErrors = 0,
            truncated = false,
        )

        val result = FullMappingEngine.generate(report(dex))

        assertEquals(2, result.classesMapped)
        assertEquals(3, result.methodsMapped)
        assertEquals(1, result.fieldsMapped)
        assertTrue(result.dexCoverageComplete)
        assertTrue(result.fieldInventoryComplete)
        assertTrue(result.semanticSymbols >= 1)
        assertTrue(result.structuralSymbols >= 1)
        assertTrue(result.preservedSymbols >= 1)
        assertTrue(result.originalStyleMappingText.contains(" -> a.b:"))
        assertTrue(result.originalStyleMappingText.contains("boolean debugCheck"))
        assertTrue(result.originalStyleMappingText.contains("void perform(int) -> perform"))
        assertTrue(result.provenanceMappingText.contains("only EXACT entries claim developer-original names"))
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
