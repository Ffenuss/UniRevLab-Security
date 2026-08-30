package org.unirevlab.security.smoke

import java.io.File
import org.unirevlab.security.analysis.*
import org.unirevlab.security.model.*

private fun u16(b: ByteArray, o: Int) = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)
private fun u32(b: ByteArray, o: Int) = u16(b, o) or (u16(b, o + 2) shl 16)
private fun put16(b: ByteArray, o: Int, v: Int) { b[o] = v.toByte(); b[o + 1] = (v ushr 8).toByte() }
private fun findTypeChunk(b: ByteArray): Int {
    for (o in 0 until b.size - 20) {
        if (u16(b, o) != 0x0201) continue
        val hs = u16(b, o + 2)
        val size = u32(b, o + 4)
        if (hs >= 20 && size >= hs && o + size <= b.size) return o
    }
    error("type chunk not found")
}

private fun attr(name: String, value: String) = KotlinAxmlManifestParser.ParsedAttribute(name, null, value)
private fun element(depth: Int, name: String, vararg attrs: KotlinAxmlManifestParser.ParsedAttribute) =
    KotlinAxmlManifestParser.ParsedElement(depth, name, null, attrs.toList())

fun main(args: Array<String>) {
    val root = File(args.getOrElse(0) { error("repo root is required") })
    val outDir = File(args.getOrElse(1) { error("output dir is required") }).also { it.mkdirs() }

    val normalBytes = File(root, "test-corpus/fixtures/resources-minimal.arsc").readBytes()
    val normal = ResourceTableResolver.parse(normalBytes)
    val expected = checkNotNull(ResourceTableResolver.resolveReference(normal, "@0x7f010000"))
    check(expected.entryName == "network_security_config")

    val typeAt = findTypeChunk(normalBytes)
    val offset16Bytes = normalBytes.copyOf().also { it[typeAt + 9] = 0x02 }
    val offset16 = ResourceTableResolver.parse(offset16Bytes)
    check(ResourceTableResolver.resolveReference(offset16, "@0x7f010000")?.entryName == "network_security_config")
    check(!offset16.truncated)

    val sparseBytes = normalBytes.copyOf().also { it[typeAt + 9] = 0x01 }
    val sparse = ResourceTableResolver.parse(sparseBytes)
    check(ResourceTableResolver.resolveReference(sparse, "@0x7f010000")?.entryName == "network_security_config")
    check(!sparse.truncated)

    val complexBytes = normalBytes.copyOf()
    val hsize = u16(complexBytes, typeAt + 2)
    val entriesStart = u32(complexBytes, typeAt + 16)
    val rel = u32(complexBytes, typeAt + hsize)
    val entryAt = typeAt + entriesStart + rel
    put16(complexBytes, entryAt, 16)
    put16(complexBytes, entryAt + 2, 1)
    for (i in 8 until 16) complexBytes[entryAt + i] = 0
    val complex = ResourceTableResolver.parse(complexBytes)
    val complexEntry = checkNotNull(ResourceTableResolver.resolveReference(complex, "@0x7f010000"))
    check(complexEntry.complex)
    check(complexEntry.mapEntryCount == 0)

    val overlay = KotlinAxmlManifestParser.analyzeElements(listOf(
        element(0, "application"),
        element(1, "activity", attr("name", "com.example.MainActivity")),
        element(2, "intent-filter", attr("autoVerify", "true")),
        element(3, "action", attr("name", "android.intent.action.VIEW")),
        element(3, "category", attr("name", "android.intent.category.BROWSABLE")),
        element(3, "data", attr("scheme", "https"), attr("host", "example.com"), attr("port", "443"), attr("pathPrefix", "/api"), attr("pathPattern", "/v.*"), attr("mimeType", "application/json")),
        element(1, "provider", attr("name", "com.example.FilesProvider"), attr("authorities", "com.example.files;com.example.alt"), attr("exported", "true"), attr("grantUriPermissions", "true")),
        element(2, "path-permission", attr("pathPrefix", "/public"), attr("readPermission", "com.example.PUBLIC_READ")),
    ))
    val link = overlay.deepLinks.single()
    check(link.ports == listOf("443"))
    check(link.pathPrefixes == listOf("/api"))
    check(link.pathPatterns == listOf("/v.*"))
    check(link.mimeTypes == listOf("application/json"))
    val provider = overlay.providers.single()
    check(provider.authorities == listOf("com.example.alt", "com.example.files"))
    check(provider.grantUriPermissions)
    check(provider.pathPermissions.single().pathPrefix == "/public")
    check(provider.readPermission == null)

    val metadata = Il2CppMetadataSummary(
        entryName = "assets/bin/Data/Managed/Metadata/global-metadata.dat", sizeBytes = 4096, magicValid = true,
        metadataVersion = 29, headerPairsScanned = 16, assemblyNameCandidates = listOf("Assembly-CSharp"),
        managedNameCandidates = listOf("Game.Player"), unityVersionCandidates = emptyList(),
        methodDefinitions = listOf(Il2CppMethodDefinitionSummary(11, 2, "Game.Player", "UpdatePlayer", 0, 0x06000123, 0)),
    )
    val il2cpp = Il2CppSummary(
        detected = true, confidence = "HIGH", metadata = metadata,
        libil2cppLibraries = listOf("lib/arm64-v8a/libil2cpp.so"), il2cppApiSymbols = listOf("il2cpp_codegen_register"),
        registrationIndicators = listOf("CODEGEN_REGISTER"),
        registrationCandidates = listOf(Il2CppRegistrationCandidate("CODEGEN_REGISTER", "lib/arm64-v8a/libil2cpp.so", "il2cpp_codegen_register", 0x3000, 96, true)),
        parseErrors = 0, truncated = false,
    )
    val slot = (0x0123 - 1)
    val ghidra = GhidraLibraryAnalysis(
        schemaVersion = "1.3", assessmentId = "v017-smoke", artifactSha256 = "b".repeat(64),
        libraryEntry = "lib/arm64-v8a/libil2cpp.so", status = "COMPLETE",
        engine = GhidraEngineSummary("Ghidra", "12.1.3", true, "DEEP"), architecture = GhidraArchitectureSummary("AARCH64", 8, "LITTLE"),
        coverage = GhidraCoverageSummary(2, 2, 0, 0, 1, false),
        functions = listOf(
            GhidraFunctionSummary(0x3000, "il2cpp_codegen_register", "", "void il2cpp_codegen_register(...) ", 96, false, null),
            GhidraFunctionSummary(0x5000, "sub_5000", "", "void sub_5000()", 120, false, "return;"),
        ), cfg = emptyList(), xrefs = emptyList(), jniRegistrations = emptyList(),
        il2cppRegistrations = listOf(GhidraIl2CppRegistration("CODEGEN_REGISTER", 0x3000, "il2cpp_codegen_register", "DEFINED_SYMBOL", "HIGH")),
        il2cppCodegenCalls = listOf(GhidraIl2CppCodegenCall(0x3100, 0x4000, 0x4200, null, "DECOMPILER_PCODE_CALL_ARGUMENTS", "HIGH")),
        il2cppPointerTables = emptyList(),
        il2cppCodegenModules = listOf(GhidraIl2CppCodegenModule(
            ownerCodeRegistrationRva = 0x4000, moduleRva = 0x4500, moduleName = "Assembly-CSharp.dll",
            methodPointerCount = 512, methodPointersRva = 0x4800,
            sampledMethodPointers = listOf(GhidraIl2CppMethodPointerSlot(slot, 0x5000)),
            evidence = "CODE_REGISTRATION_MODULE_ARRAY_STRUCTURAL", confidence = "HIGH",
        )), warnings = emptyList(),
    )
    val correlations = CrossRuntimeCorrelator.correlate(null, il2cpp, listOf(ghidra))
    val methodLink = correlations.il2cppMethods.single()
    check(methodLink.functionRva == 0x5000L)
    check(methodLink.evidence == "CODEGEN_MODULE_METHOD_TOKEN_SLOT")
    val re = ReBrowserIndex.buildGhidra(listOf(ghidra), correlations)
    check(re.il2cppCodegenModuleCount == 1)
    check(ReBrowserIndex.searchGhidra(re, "Assembly-CSharp").single().crossRuntimeLinks.any { it.startsWith("IL2CPP_MODULE") })

    val report = StaticAnalysisReport(
        engineVersion = "0.17.0-dev-codegen-resources-intent",
        assessment = AssessmentScope("v017-smoke", 1L, "v017", "Example", "authorized regression", true, true, true, false, false),
        artifact = ArtifactSummary("fixture.apk", 1L, "b".repeat(64), 1, 1, 1, true, 0, false),
        manifest = ManifestSummary(
            packageName = "com.example", versionName = "1", versionCode = 1, minSdk = 24, targetSdk = 35,
            debuggable = false, allowBackup = false, fullBackupContentConfigured = false, dataExtractionRulesConfigured = false,
            usesCleartextTraffic = false, networkSecurityConfigConfigured = false, requestedPermissions = emptyList(), dangerousPermissions = emptyList(),
            components = listOf(ComponentExposure("provider", provider.name, true, listOfNotNull(provider.readPermission, provider.writePermission))),
            deepLinks = overlay.deepLinks, providers = overlay.providers, signingCertificateSha256 = emptyList(),
        ),
        resources = complex, il2cpp = il2cpp, ghidra = listOf(ghidra), correlations = correlations, findings = emptyList(),
    )
    val manifestFindings = ManifestRuleEngine.evaluate(checkNotNull(report.manifest))
    check(manifestFindings.any { it.id == "ANDROID-EXPORTED-PROVIDER-URI-GRANTS" })
    check(manifestFindings.any { it.id == "ANDROID-DEEP-LINK-PATH-PATTERN-REVIEW" })
    val json = ReportJsonExporter.export(report.copy(findings = manifestFindings))
    check(json.contains("\"schemaVersion\": \"1.19\""))
    check(json.contains("CODEGEN_MODULE_METHOD_TOKEN_SLOT"))
    check(json.contains("\"il2cppCodegenModules\": ["))
    check(json.contains("\"pathPrefixes\": [\"/api\"]"))
    check(json.contains("\"providers\": ["))
    check(json.contains("\"complex\": true"))
    File(outDir, "static-analysis-report.json").writeText(json)
    println("v0.17 codegen/resources/intent smoke PASS")
}
