package org.unirevlab.security.smoke

import java.io.File
import org.unirevlab.security.analysis.GhidraResultIntegrator
import org.unirevlab.security.analysis.ReBrowserIndex
import org.unirevlab.security.analysis.ReportJsonExporter
import org.unirevlab.security.analysis.ResourceTableResolver
import org.unirevlab.security.model.*

fun main(args: Array<String>) {
    val root = File(args.getOrElse(0) { error("repo root is required") })
    val outDir = File(args.getOrElse(1) { error("output dir is required") }).also { it.mkdirs() }

    val resources = ResourceTableResolver.parse(File(root, "test-corpus/fixtures/resources-minimal.arsc").readBytes())
    check(resources.parseErrors == 0)
    val resource = checkNotNull(ResourceTableResolver.resolveReference(resources, "@0x7f010000"))
    check(resource.packageName == "com.example")
    check(resource.typeName == "xml")
    check(resource.entryName == "network_security_config")
    check(resource.fileEntry == "res/xml/network_security_config.xml")

    val dex = DexSummary(
        dexFilesDiscovered = 1,
        dexFilesScanned = 1,
        stringsDeclared = 0,
        stringsScanned = 0,
        classes = listOf(DexClassReference("classes.dex", 0, "Lcom/example/Native;", "Ljava/lang/Object;", 1)),
        methods = listOf(DexMethodReference("classes.dex", 7, "Lcom/example/Native;", "nativeCheck", "()Z")),
        nativeMethods = listOf(DexNativeMethodDeclaration("classes.dex", 7, "Lcom/example/Native;", "nativeCheck", "()Z", 0x101L)),
        httpUrls = emptyList(), httpsUrls = emptyList(), secretCandidates = emptyList(), parseErrors = 0, truncated = false,
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
        methodDefinitions = listOf(Il2CppMethodDefinitionSummary(11, 2, "Game.Player", "UpdatePlayer", 0, 0x06000123, 0)),
    )
    val il2cpp = Il2CppSummary(
        detected = true,
        confidence = "HIGH",
        metadata = metadata,
        libil2cppLibraries = listOf("lib/arm64-v8a/libil2cpp.so"),
        il2cppApiSymbols = listOf("il2cpp_codegen_register"),
        registrationIndicators = listOf("CODEGEN_REGISTER"),
        registrationCandidates = listOf(
            Il2CppRegistrationCandidate("CODEGEN_REGISTER", "lib/arm64-v8a/libil2cpp.so", "il2cpp_codegen_register", 0x3000, 96, true),
        ),
        parseErrors = 0,
        truncated = false,
    )
    val ghidra = GhidraLibraryAnalysis(
        schemaVersion = "1.2",
        assessmentId = "v016-smoke",
        artifactSha256 = "a".repeat(64),
        libraryEntry = "lib/arm64-v8a/libil2cpp.so",
        status = "COMPLETE",
        engine = GhidraEngineSummary("Ghidra", "12.1.3", true, "DEEP"),
        architecture = GhidraArchitectureSummary("AARCH64", 8, "LITTLE"),
        coverage = GhidraCoverageSummary(3, 3, 4, 2, 2, false),
        functions = listOf(
            GhidraFunctionSummary(0x1000, "native_check_impl", "", "jboolean native_check_impl(JNIEnv*, jobject)", 64, false, "return 1;"),
            GhidraFunctionSummary(0x3000, "il2cpp_codegen_register", "", "void il2cpp_codegen_register(...) ", 96, false, null),
            GhidraFunctionSummary(0x5000, "Game_Player_UpdatePlayer_token_6000123", "Game.Player", "void UpdatePlayer()", 120, false, "player->tick++;"),
        ),
        cfg = listOf(GhidraFunctionCfg(0x1000, listOf(GhidraCfgBlock(0x1000, 0x1020, "RETURN")), emptyList())),
        xrefs = listOf(GhidraXref(0x1000, 0x5000, "CALL")),
        jniRegistrations = listOf(
            GhidraJniRegistration(
                source = "REGISTER_NATIVES_TABLE",
                className = "com/example/Native",
                methodName = "nativeCheck",
                signature = "()Z",
                functionRva = 0x1000,
                confidence = "HIGH",
                tableRva = 0x1800,
                registerNativesCallsiteRva = 0x900,
                findClassCallsiteRva = 0x880,
                classEvidence = "FUNCTION_FINDCLASS_STRING_AND_REGISTER_NATIVES",
            ),
        ),
        il2cppRegistrations = listOf(GhidraIl2CppRegistration("CODEGEN_REGISTER", 0x3000, "il2cpp_codegen_register", "DEFINED_SYMBOL", "HIGH")),
        il2cppCodegenCalls = listOf(
            GhidraIl2CppCodegenCall(0x3100, 0x4000, 0x4200, null, "DECOMPILER_PCODE_CALL_ARGUMENTS", "HIGH"),
        ),
        il2cppPointerTables = listOf(
            GhidraIl2CppPointerTable(0x4000, 16, 128, 0x4800, 16, 16, listOf(0x5000), "HIGH"),
        ),
        warnings = emptyList(),
    )

    val scope = AssessmentScope(
        assessmentId = "v016-smoke", createdAtEpochMs = 1, projectName = "v0.16 smoke", organization = "UniRevLab",
        purpose = "Authorized structural native/resource regression", confirmsAuthority = true, reverseEngineering = true,
    )
    val artifact = ArtifactSummary("fixture.apk", 1, "a".repeat(64), 4, 1, 1, true, 0, false)
    val base = StaticAnalysisReport(
        engineVersion = "0.16.0-dev-structural-native-resources",
        assessment = scope,
        artifact = artifact,
        manifest = null,
        resources = resources,
        dex = dex,
        il2cpp = il2cpp,
        findings = emptyList(),
    )
    val report = GhidraResultIntegrator.attach(base, listOf(ghidra))
    val correlations = checkNotNull(report.correlations)
    check(correlations.jniNative.single().evidence == "EXACT_CLASS_METHOD_SIGNATURE")
    check(correlations.jniNative.single().functionRva == 0x1000L)
    check(correlations.il2cppMethods.single().functionRva == 0x5000L)

    val index = ReBrowserIndex.buildGhidra(report.ghidra, correlations)
    check(index.il2cppCodegenCallCount == 1)
    check(index.il2cppPointerTableCount == 1)
    check(ReBrowserIndex.searchGhidra(index, "UpdatePlayer").single().crossRuntimeLinks.any { it.contains("IL2CPP_PTR_TABLE") })

    val json = ReportJsonExporter.export(report)
    check(json.contains("\"schemaVersion\": \"1.19\""))
    check(json.contains("res/xml/network_security_config.xml"))
    check(json.contains("DECOMPILER_PCODE_CALL_ARGUMENTS"))
    check(json.contains("\"il2cppPointerTables\": ["))
    File(outDir, "static-analysis-report.json").writeText(json)
    println("v0.16 structural native/resources smoke PASS")
}
