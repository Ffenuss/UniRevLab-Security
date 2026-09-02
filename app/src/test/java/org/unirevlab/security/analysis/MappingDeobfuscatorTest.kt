package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.DexClassReference
import org.unirevlab.security.model.DexFieldXref
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.StaticAnalysisReport

class MappingDeobfuscatorTest {
    @Test
    fun resolvesExactClassMethodAndFieldNamesAgainstDexIndex() {
        val mapping = DeobfuscationEngine.parseMapping(
            """
            com.example.AccountRepository -> a.b:
                java.lang.String token -> a
                java.lang.Object readAccount(java.lang.String) -> b
            """.trimIndent(),
        )
        val dex = DexSummary(
            dexFilesDiscovered = 1,
            dexFilesScanned = 1,
            stringsDeclared = 0,
            stringsScanned = 0,
            classesDeclared = 1,
            classesIndexed = 1,
            methodsDeclared = 1,
            methodsIndexed = 1,
            classes = listOf(DexClassReference("classes.dex", 0, "La/b;", "Ljava/lang/Object;", 1)),
            methods = listOf(DexMethodReference("classes.dex", 5, "La/b;", "b", "(Ljava/lang/String;)Ljava/lang/Object;")),
            fieldXrefs = listOf(
                DexFieldXref(
                    dexEntry = "classes.dex",
                    callerMethodIndex = 5,
                    callerClass = "La/b;",
                    callerName = "b",
                    fieldIndex = 2,
                    declaringClass = "La/b;",
                    fieldName = "a",
                    fieldType = "Ljava/lang/String;",
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

        val aliases = MappingDeobfuscator.resolve(report(dex), mapping)
        assertTrue(aliases.any { it.kind == "CLASS" && it.originalSymbol == "com.example.AccountRepository" })
        assertTrue(aliases.any { it.kind == "METHOD" && it.originalSymbol.contains("readAccount") })
        assertTrue(aliases.any { it.kind == "FIELD" && it.originalSymbol.contains("token") })
        assertEquals(3, aliases.size)
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
