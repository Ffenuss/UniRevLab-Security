package org.unirevlab.security.smoke

import java.io.File
import org.unirevlab.security.analysis.AssessmentDiffEngine
import org.unirevlab.security.analysis.GhidraResultIntegrator
import org.unirevlab.security.analysis.ReBrowserIndex
import org.unirevlab.security.analysis.ReportJsonExporter
import org.unirevlab.security.model.*

fun main(args: Array<String>) {
    val outDir = File(args.getOrElse(0) { error("output dir is required") })
    outDir.mkdirs()

    val dex = DexSummary(
        dexFilesDiscovered = 1,
        dexFilesScanned = 1,
        stringsDeclared = 0,
        stringsScanned = 0,
        classes = listOf(DexClassReference("classes.dex", 0, "Lcom/example/Native;", "Ljava/lang/Object;", 1)),
        methods = listOf(DexMethodReference("classes.dex", 7, "Lcom/example/Native;", "nativeCheck", "()Z")),
        nativeMethods = listOf(DexNativeMethodDeclaration("classes.dex", 7, "Lcom/example/Native;", "nativeCheck", "()Z", 0x101L)),
        httpUrls = emptyList(),
        httpsUrls = emptyList(),
        secretCandidates = emptyList(),
        parseErrors = 0,
        truncated = false,
    )
    val metadata = Il2CppMetadataSummary(
        entryName = "assets/bin/Data/Managed/Metadata/global-metadata.dat",
        sizeBytes = 4096,
        magicValid = true,
        metadataVersion = 29,
        headerPairsScanned = 16,
        assemblyNameCandidates = listOf("Assembly-CSharp"),
        managedNameCandidates = listOf("Game.Player"),
        unityVersionCandidates = emptyList(),
        methodDefinitions = listOf(
            Il2CppMethodDefinitionSummary(
                index = 11,
                declaringTypeIndex = 2,
                declaringType = "Game.Player",
                name = "UpdatePlayer",
                parameterCount = 0,
                token = 0x06000123,
                flags = 0,
            ),
        ),
    )
    val il2cpp = Il2CppSummary(
        detected = true,
        confidence = "HIGH",
        metadata = metadata,
        libil2cppLibraries = listOf("lib/arm64-v8a/libil2cpp.so"),
        il2cppApiSymbols = listOf("il2cpp_codegen_register"),
        registrationIndicators = listOf("CODEGEN_REGISTER"),
        registrationCandidates = listOf(
            Il2CppRegistrationCandidate(
                kind = "CODEGEN_REGISTER",
                libraryEntry = "lib/arm64-v8a/libil2cpp.so",
                symbolName = "il2cpp_codegen_register",
                virtualAddress = 0x3000,
                sizeBytes = 96,
                validatedDefinedSymbol = true,
            ),
        ),
        parseErrors = 0,
        truncated = false,
    )

    fun ghidra(updateSize: Long = 120): GhidraLibraryAnalysis = GhidraLibraryAnalysis(
        assessmentId = "v015-smoke",
        artifactSha256 = "a".repeat(64),
        libraryEntry = "lib/arm64-v8a/libil2cpp.so",
        status = "COMPLETE",
        engine = GhidraEngineSummary("Ghidra", "12.1.3", true, "DEEP"),
        coverage = GhidraCoverageSummary(3, 3, 4, 2, 2, false),
        functions = listOf(
            GhidraFunctionSummary(0x1000, "Java_com_example_Native_nativeCheck", "", "jboolean nativeCheck(JNIEnv*, jobject)", 64, false, "return 1;"),
            GhidraFunctionSummary(0x3000, "il2cpp_codegen_register", "", "void il2cpp_codegen_register(...) ", 96, false, null),
            GhidraFunctionSummary(0x5000, "Game_Player_UpdatePlayer_token_6000123", "Game.Player", "void UpdatePlayer()", updateSize, false, "player->tick++;"),
        ),
        cfg = listOf(
            GhidraFunctionCfg(0x1000, listOf(GhidraCfgBlock(0x1000, 0x1020, "RETURN")), emptyList()),
            GhidraFunctionCfg(0x5000, listOf(GhidraCfgBlock(0x5000, 0x5040, "RETURN")), emptyList()),
        ),
        xrefs = listOf(GhidraXref(0x1000, 0x5000, "CALL")),
        jniRegistrations = listOf(
            GhidraJniRegistration("STATIC_EXPORT", "com.example.Native", "nativeCheck", "", 0x1000, "MEDIUM"),
        ),
        il2cppRegistrations = listOf(
            GhidraIl2CppRegistration("CODEGEN_REGISTER", 0x3000, "il2cpp_codegen_register", "DEFINED_SYMBOL", "HIGH"),
        ),
        warnings = emptyList(),
    )

    val scope = AssessmentScope(
        assessmentId = "v015-smoke",
        createdAtEpochMs = 1,
        projectName = "v0.15 smoke",
        organization = "UniRevLab",
        purpose = "Authorized cross-runtime regression",
        confirmsAuthority = true,
        reverseEngineering = true,
    )
    val artifact = ArtifactSummary(
        displayName = "fixture.apk",
        sizeBytes = 1,
        sha256 = "a".repeat(64),
        archiveEntries = 3,
        dexFiles = 1,
        nativeLibraries = 1,
        hasAndroidManifest = true,
        suspiciousArchivePaths = 0,
        truncatedArchiveScan = false,
    )
    val base = StaticAnalysisReport(
        engineVersion = "0.15.0-dev-cross-runtime",
        assessment = scope,
        artifact = artifact,
        manifest = null,
        dex = dex,
        il2cpp = il2cpp,
        findings = emptyList(),
    )
    val first = GhidraResultIntegrator.attach(base, listOf(ghidra()))
    val correlations = checkNotNull(first.correlations)
    check(correlations.dexNativeMethodsResolved == 1)
    check(correlations.jniNative.single().functionRva == 0x1000L)
    check(correlations.jniNative.single().evidence == "UNIQUE_STATIC_EXPORT_CLASS_METHOD")
    check(correlations.il2cppRegistrations.single().evidence == "STATIC_AND_GHIDRA_RVA_MATCH")
    check(correlations.il2cppMethods.single().functionRva == 0x5000L)
    check(correlations.il2cppMethods.single().evidence == "UNIQUE_METADATA_TOKEN_LITERAL")

    val dexIndex = ReBrowserIndex.buildDex(dex, correlations)
    check(dexIndex.packages.single().classes.single().methods.single().nativeTargets.single().contains("0x1000"))
    val ghidraIndex = ReBrowserIndex.buildGhidra(first.ghidra, correlations)
    check(ReBrowserIndex.searchGhidra(ghidraIndex, "UpdatePlayer").any { it.crossRuntimeLinks.any { link -> link.contains("IL2CPP") } })
    check(ReBrowserIndex.searchGhidra(ghidraIndex, "nativeCheck").any { it.crossRuntimeLinks.any { link -> link.contains("DEX") } })

    val second = GhidraResultIntegrator.attach(base.copy(artifact = artifact.copy(displayName = "fixture-v2.apk")), listOf(ghidra(updateSize = 144)))
    val diff = AssessmentDiffEngine.diff(first, second)
    check(diff.items.any { it.category == "nativeFunctionShape" && it.change == "CHANGED" && it.key.contains("UpdatePlayer") })

    val json = ReportJsonExporter.export(first)
    check(json.contains("\"schemaVersion\": \"1.19\""))
    check(json.contains("\"correlations\": {"))
    check(json.contains("UNIQUE_METADATA_TOKEN_LITERAL"))
    File(outDir, "static-analysis-report.json").writeText(json)
    println("v0.15 cross-runtime correlation smoke PASS")
}
