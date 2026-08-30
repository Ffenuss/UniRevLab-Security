package org.unirevlab.security.smoke

import java.io.File
import org.unirevlab.security.analysis.ManifestDexReachabilityAnalyzer
import org.unirevlab.security.analysis.ReportJsonExporter
import org.unirevlab.security.analysis.ResourceTableResolver
import org.unirevlab.security.model.*

private fun u16(b: ByteArray, o: Int) = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)
private fun u32(b: ByteArray, o: Int) = u16(b, o) or (u16(b, o + 2) shl 16)
private fun put32(b: ByteArray, o: Int, v: Long) {
    for (i in 0 until 4) b[o + i] = (v ushr (i * 8)).toByte()
}
private fun findTypeChunk(b: ByteArray): Int {
    for (o in 0 until b.size - 20) {
        if (u16(b, o) != 0x0201) continue
        val hs = u16(b, o + 2); val size = u32(b, o + 4)
        if (hs >= 20 && size >= hs && o + size <= b.size) return o
    }
    error("type chunk not found")
}

fun main(args: Array<String>) {
    val root = File(args[0])
    val out = File(args[1]).also { it.mkdirs() }

    // Turn the one-entry benign resources fixture into a self-reference to verify cycle handling.
    val bytes = File(root, "test-corpus/fixtures/resources-minimal.arsc").readBytes().copyOf()
    val typeAt = findTypeChunk(bytes)
    val hsize = u16(bytes, typeAt + 2)
    val entriesStart = u32(bytes, typeAt + 16)
    val rel = u32(bytes, typeAt + hsize)
    val entryAt = typeAt + entriesStart + rel
    val entrySize = u16(bytes, entryAt)
    val valueAt = entryAt + entrySize
    bytes[valueAt + 3] = 0x01 // TYPE_REFERENCE
    put32(bytes, valueAt + 4, 0x7f010000L)
    val resources = ResourceTableResolver.parse(bytes)
    val chain = resources.referenceChains.single()
    check(chain.requestedResourceId == 0x7f010000L)
    check(chain.cycleDetected)
    check(chain.terminalResourceId == null)
    check(ResourceTableResolver.resolveReference(resources, "@0x7f010000") == null)

    val manifest = ManifestSummary(
        packageName = "com.example", versionName = "1", versionCode = 1, minSdk = 26, targetSdk = 36,
        debuggable = false, allowBackup = false, fullBackupContentConfigured = false, dataExtractionRulesConfigured = false,
        usesCleartextTraffic = false, networkSecurityConfigConfigured = false,
        requestedPermissions = emptyList(), dangerousPermissions = emptyList(),
        components = listOf(
            ComponentExposure("activity", ".MainActivity", true),
            ComponentExposure("provider", "FilesProvider", true),
        ),
        deepLinks = listOf(DeepLinkDeclaration(".MainActivity", listOf("https"), listOf("example.com"), true, true, true)),
        providers = listOf(ProviderDeclaration("FilesProvider", listOf("com.example.files"), true, true)),
        signingCertificateSha256 = emptyList(),
    )
    val methods = listOf(
        DexMethodReference("classes.dex", 1, "Lcom/example/MainActivity;", "onCreate", "()V"),
        DexMethodReference("classes.dex", 2, "Lcom/example/MainActivity;", "load", "()V"),
        DexMethodReference("classes.dex", 3, "Lcom/example/Repository;", "query", "()V"),
        DexMethodReference("classes.dex", 4, "Lcom/example/FilesProvider;", "query", "()V"),
        DexMethodReference("classes.dex", 5, "Lcom/example/FilesProvider;", "openFile", "()V"),
    )
    val calls = listOf(
        DexMethodCallXref("classes.dex", 1, "Lcom/example/MainActivity;", "onCreate", 2, "Lcom/example/MainActivity;", "load", "()V", 0),
        DexMethodCallXref("classes.dex", 2, "Lcom/example/MainActivity;", "load", 3, "Lcom/example/Repository;", "query", "()V", 2),
        DexMethodCallXref("classes.dex", 4, "Lcom/example/FilesProvider;", "query", 3, "Lcom/example/Repository;", "query", "()V", 0),
    )
    val dex = DexSummary(
        dexFilesDiscovered = 1, dexFilesScanned = 1, stringsDeclared = 0, stringsScanned = 0,
        methodsDeclared = methods.size.toLong(), methodsIndexed = methods.size.toLong(), methods = methods,
        callXrefs = calls, httpUrls = emptyList(), httpsUrls = emptyList(), secretCandidates = emptyList(),
        parseErrors = 0, truncated = false,
    )
    val reachability = checkNotNull(ManifestDexReachabilityAnalyzer.analyze(manifest, dex))
    val activity = reachability.components.single { it.componentKind == "activity" }
    check(activity.componentName == "com.example.MainActivity")
    check(activity.externallyAddressable)
    check(activity.entryMethodIndexes == listOf(1))
    check(activity.reachableMethodIndexes == listOf(1, 2, 3))
    val provider = reachability.components.single { it.componentKind == "provider" }
    check(provider.componentName == "com.example.FilesProvider")
    check(provider.entryMethodIndexes == listOf(4, 5))
    check(provider.reachableMethodIndexes == listOf(3, 4, 5))

    val report = StaticAnalysisReport(
        engineVersion = "0.18.0-dev-connected-reachability",
        assessment = AssessmentScope("v018-smoke", 1L, "v018", "Example", "authorized regression", true, true, true, false, false),
        artifact = ArtifactSummary("fixture.apk", 1L, "c".repeat(64), 1, 1, 0, true, 0, false),
        manifest = manifest, resources = resources, dex = dex, manifestDexReachability = reachability, findings = emptyList(),
    )
    val json = ReportJsonExporter.export(report)
    check(json.contains("\"schemaVersion\": \"1.19\""))
    check(json.contains("\"manifestDexReachability\""))
    check(json.contains("\"referenceChains\""))
    check(json.contains("\"cycleDetected\": true"))
    File(out, "static-analysis-report.json").writeText(json)
    println("v0.18 reachability/resource-chain smoke PASS")
}
