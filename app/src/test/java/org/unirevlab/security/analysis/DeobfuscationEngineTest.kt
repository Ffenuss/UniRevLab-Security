package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.DexClassReference
import org.unirevlab.security.model.DexMethodCallXref
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.DexStringXref
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.StaticAnalysisReport

class DeobfuscationEngineTest {
    @Test
    fun infersSemanticAliasForObfuscatedDeserializer() {
        val dex = DexSummary(
            dexFilesDiscovered = 1,
            dexFilesScanned = 1,
            stringsDeclared = 1,
            stringsScanned = 1,
            classesDeclared = 1,
            classesIndexed = 1,
            methodsDeclared = 1,
            methodsIndexed = 1,
            classes = listOf(
                DexClassReference("classes.dex", 0, "Lcom/example/a;", "Ljava/lang/Object;", 1),
            ),
            methods = listOf(
                DexMethodReference("classes.dex", 7, "Lcom/example/a;", "a", "()Ljava/lang/Object;"),
            ),
            callXrefs = listOf(
                DexMethodCallXref(
                    dexEntry = "classes.dex",
                    callerMethodIndex = 7,
                    callerClass = "Lcom/example/a;",
                    callerName = "a",
                    calleeMethodIndex = -1,
                    calleeClass = "Ljava/io/ObjectInputStream;",
                    calleeName = "readObject",
                    calleePrototype = "()Ljava/lang/Object;",
                    instructionOffsetCodeUnits = 4,
                ),
            ),
            stringXrefs = listOf(
                DexStringXref(
                    dexEntry = "classes.dex",
                    callerMethodIndex = 7,
                    callerClass = "Lcom/example/a;",
                    callerName = "a",
                    stringIndex = 0,
                    value = "payload",
                    instructionOffsetCodeUnits = 2,
                ),
            ),
            httpUrls = emptyList(),
            httpsUrls = emptyList(),
            secretCandidates = emptyList(),
            parseErrors = 0,
            truncated = false,
        )

        val summary = DeobfuscationEngine.analyze(report(dex))
        val alias = summary.aliases.first { it.kind == "METHOD" }
        assertEquals("Lcom/example/a;->a()Ljava/lang/Object;", alias.original)
        assertTrue(alias.suggestedAlias.startsWith("deserializeObject_"))
        assertEquals(DeobfuscationEngine.AliasConfidence.HIGH, alias.confidence)
        assertEquals(1, summary.obfuscatedClasses)
        assertEquals(1, summary.obfuscatedMethods)
    }

    @Test
    fun parsesStandardR8MappingWithoutExecutingTargetCode() {
        val mapping = """
            com.example.AccountRepository -> a.b:
                java.lang.String token -> a
                1:4:java.lang.Object readAccount(java.lang.String):10:13 -> b
            com.example.LoginActivity -> c.d:
                2:2:void onCreate(android.os.Bundle):20:20 -> a
        """.trimIndent()

        val parsed = DeobfuscationEngine.parseMapping(mapping)
        assertEquals(2, parsed.classes.size)
        assertEquals("com.example.AccountRepository", parsed.classes.first().originalName)
        assertEquals("a.b", parsed.classes.first().obfuscatedName)
        assertEquals(3, parsed.members.size)
        assertEquals("FIELD", parsed.members[0].kind)
        assertEquals("METHOD", parsed.members[1].kind)
        assertEquals("readAccount", parsed.members[1].originalName)
        assertEquals("b", parsed.members[1].obfuscatedName)
        assertEquals(0, parsed.parseErrors)
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
