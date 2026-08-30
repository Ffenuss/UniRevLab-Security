package org.unirevlab.security.smoke

import java.io.File
import org.unirevlab.security.analysis.ReBrowserIndex
import org.unirevlab.security.analysis.ReportJsonExporter
import org.unirevlab.security.model.*

fun main(args: Array<String>) {
    val outDir = File(args.getOrElse(0) { error("output dir is required") })
    outDir.mkdirs()

    val analysis = GhidraLibraryAnalysis(
        assessmentId = "v014-smoke",
        artifactSha256 = "a".repeat(64),
        libraryEntry = "lib/arm64-v8a/libil2cpp.so",
        status = "COMPLETE",
        engine = GhidraEngineSummary("Ghidra", "12.1.3", true, "DEEP"),
        coverage = GhidraCoverageSummary(3, 2, 4, 2, 1, false),
        functions = listOf(
            GhidraFunctionSummary(
                rva = 0x1000,
                name = "JNI_OnLoad",
                namespace = "",
                signature = "jint JNI_OnLoad(JavaVM*, void*)",
                sizeBytes = 64,
                isThunk = false,
                decompilerPreview = "return JNI_VERSION_1_6;",
            ),
            GhidraFunctionSummary(
                rva = 0x2000,
                name = "il2cpp_codegen_register",
                namespace = "",
                signature = "void il2cpp_codegen_register(...)",
                sizeBytes = 96,
                isThunk = false,
            ),
        ),
        cfg = listOf(
            GhidraFunctionCfg(
                functionRva = 0x1000,
                blocks = listOf(GhidraCfgBlock(0x1000, 0x1020, "RETURN")),
                edges = emptyList(),
            ),
        ),
        xrefs = listOf(
            GhidraXref(0x1000, 0x2000, "CALL"),
            GhidraXref(0x3000, 0x1000, "CALL"),
        ),
        jniRegistrations = listOf(
            GhidraJniRegistration(
                source = "STATIC_EXPORT",
                className = "com.example.Native",
                methodName = "nativeCheck",
                signature = "()Z",
                functionRva = 0x1000,
                confidence = "HIGH",
            ),
        ),
        il2cppRegistrations = listOf(
            GhidraIl2CppRegistration(
                kind = "CODEGEN_REGISTER",
                rva = 0x2000,
                symbolName = "il2cpp_codegen_register",
                evidence = "DEFINED_SYMBOL",
                confidence = "HIGH",
            ),
        ),
        warnings = emptyList(),
    )

    val index = ReBrowserIndex.buildGhidra(listOf(analysis))
    check(index.libraries == listOf("lib/arm64-v8a/libil2cpp.so"))
    check(index.functions.size == 2)
    check(index.xrefCount == 2)
    check(index.jniRegistrationCount == 1)
    check(index.il2cppRegistrationCount == 1)
    check(ReBrowserIndex.searchGhidra(index, "nativeCheck").single().name == "JNI_OnLoad")
    check(ReBrowserIndex.searchGhidra(index, "il2cpp_codegen").single().rva == 0x2000L)

    val report = StaticAnalysisReport(
        engineVersion = "0.14.0-dev-ghidra-integration",
        assessment = AssessmentScope(
            assessmentId = "v014-smoke",
            createdAtEpochMs = 1,
            projectName = "v0.14 smoke",
            organization = "UniRevLab",
            purpose = "Authorized deep-native regression",
            confirmsAuthority = true,
            reverseEngineering = true,
        ),
        artifact = ArtifactSummary(
            displayName = "fixture.apk",
            sizeBytes = 1,
            sha256 = "a".repeat(64),
            archiveEntries = 1,
            dexFiles = 0,
            nativeLibraries = 1,
            hasAndroidManifest = true,
            suspiciousArchivePaths = 0,
            truncatedArchiveScan = false,
        ),
        manifest = null,
        ghidra = listOf(analysis),
        findings = emptyList(),
    )
    val json = ReportJsonExporter.export(report)
    check(json.contains("\"schemaVersion\": \"1.19\""))
    check(json.contains("\"ghidra\": ["))
    check(json.contains("\"JNI_OnLoad\""))
    check(json.contains("\"il2cpp_codegen_register\""))
    File(outDir, "static-analysis-report.json").writeText(json)
    println("v0.14 Ghidra integration smoke PASS")
}
