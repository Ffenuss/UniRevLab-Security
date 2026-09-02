package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.DexClassReference
import org.unirevlab.security.model.DexConstantReference
import org.unirevlab.security.model.DexMethodReference
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.ResourceResolutionSummary
import org.unirevlab.security.model.ResourceTableSummary
import org.unirevlab.security.model.StaticAnalysisReport

class SemanticRecoveryEngineTest {
    @Test
    fun sourceFileBeatsStructuralClassAlias() {
        val dex = baseDex(
            classes = listOf(
                DexClassReference(
                    dexEntry = "classes.dex",
                    classIndex = 3,
                    descriptor = "La;",
                    superDescriptor = "Ljava/lang/Object;",
                    accessFlags = 1,
                    sourceFile = "PaymentManager.kt",
                ),
            ),
            methods = listOf(DexMethodReference("classes.dex", 10, "La;", "a", "()V")),
        )

        val result = SemanticRecoveryEngine.generate(report(dex))
        val cls = result.entries.single { it.kind == "CLASS" }

        assertTrue(cls.alias.startsWith("PaymentManager_"))
        assertEquals(AnalystMappingEngine.Confidence.HIGH, cls.confidence)
        assertTrue(SemanticRecoveryEngine.EvidenceKind.SOURCE_METADATA in cls.evidenceKinds)
    }

    @Test
    fun inheritanceAndResourceEvidenceProduceStableSemanticAliases() {
        val method = DexMethodReference("classes.dex", 21, "Lb;", "a", "()V")
        val dex = baseDex(
            classes = listOf(
                DexClassReference(
                    dexEntry = "classes.dex",
                    classIndex = 4,
                    descriptor = "Lb;",
                    superDescriptor = "Ljava/lang/Object;",
                    accessFlags = 1,
                    interfaces = listOf("Landroidx/lifecycle/ViewModel;"),
                ),
            ),
            methods = listOf(method),
            constants = listOf(
                DexConstantReference(
                    dexEntry = "classes.dex",
                    methodIndex = 21,
                    register = 0,
                    kind = "INT",
                    value = "2131361793",
                    instructionOffsetCodeUnits = 2,
                ),
            ),
        )
        val resources = ResourceTableSummary(
            resolutions = listOf(
                ResourceResolutionSummary(
                    resourceId = 2131361793L,
                    packageId = 0x7f,
                    typeId = 0x0a,
                    entryId = 1,
                    packageName = "com.example",
                    typeName = "id",
                    entryName = "login_button",
                    dataType = 0,
                    dataValue = 0,
                ),
            ),
        )

        val result = SemanticRecoveryEngine.generate(report(dex, resources))
        val cls = result.entries.single { it.kind == "CLASS" }
        val recoveredMethod = result.entries.single { it.kind == "METHOD" }

        assertTrue(cls.alias.startsWith("ViewModel_"))
        assertTrue(SemanticRecoveryEngine.EvidenceKind.INHERITANCE in cls.evidenceKinds)
        assertTrue(recoveredMethod.alias.contains("idLoginButtonFlow"))
        assertTrue(SemanticRecoveryEngine.EvidenceKind.RESOURCE in recoveredMethod.evidenceKinds)
    }

    private fun baseDex(
        classes: List<DexClassReference>,
        methods: List<DexMethodReference>,
        constants: List<DexConstantReference> = emptyList(),
    ) = DexSummary(
        dexFilesDiscovered = 1,
        dexFilesScanned = 1,
        stringsDeclared = 0,
        stringsScanned = 0,
        classesDeclared = classes.size.toLong(),
        classesIndexed = classes.size.toLong(),
        methodsDeclared = methods.size.toLong(),
        methodsIndexed = methods.size.toLong(),
        classes = classes,
        methods = methods,
        constants = constants,
        httpUrls = emptyList(),
        httpsUrls = emptyList(),
        secretCandidates = emptyList(),
        parseErrors = 0,
        truncated = false,
    )

    private fun report(dex: DexSummary, resources: ResourceTableSummary? = null) = StaticAnalysisReport(
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
        resources = resources,
        dex = dex,
        findings = emptyList(),
    )
}
