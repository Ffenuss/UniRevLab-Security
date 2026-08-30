import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.unirevlab.security.analysis.Il2CppScanner
import org.unirevlab.security.analysis.RuntimeArtifactScanner
import org.unirevlab.security.analysis.SbomExporter
import org.unirevlab.security.analysis.SupplyChainScanner
import org.unirevlab.security.model.*

private fun putU16(b: ByteBuffer, off: Int, value: Int) = b.putShort(off, value.toShort())

private class StringsHeapBuilder {
    private val bytes = mutableListOf<Byte>(0)
    private val indexes = linkedMapOf<String, Int>()
    fun add(value: String): Int = indexes.getOrPut(value) {
        val index = bytes.size
        value.toByteArray(Charsets.UTF_8).forEach(bytes::add)
        bytes.add(0)
        index
    }
    fun bytes(): ByteArray = bytes.toByteArray()
}

private fun managedAssembly(): ByteArray {
    val bytes = ByteArray(0x1000)
    val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    bytes[0] = 'M'.code.toByte(); bytes[1] = 'Z'.code.toByte(); b.putInt(0x3c, 0x80)
    bytes[0x80] = 'P'.code.toByte(); bytes[0x81] = 'E'.code.toByte()
    putU16(b, 0x84, 0x14c); putU16(b, 0x86, 1); putU16(b, 0x94, 0xE0)
    val opt = 0x98; putU16(b, opt, 0x10b); b.putInt(opt + 92, 16)
    val cliDir = opt + 96 + 14 * 8; b.putInt(cliDir, 0x2000); b.putInt(cliDir + 4, 0x48)
    val sec = opt + 0xE0
    b.putInt(sec + 8, 0x800); b.putInt(sec + 12, 0x2000); b.putInt(sec + 16, 0x800); b.putInt(sec + 20, 0x200)
    val cli = 0x200; b.putInt(cli, 0x48); b.putInt(cli + 8, 0x2080); b.putInt(cli + 12, 0x500)
    val md = 0x280
    b.putInt(md, 0x424A5342); putU16(b, md + 4, 1); putU16(b, md + 6, 1)
    val ver = "v4.0.30319\u0000".toByteArray(); b.putInt(md + 12, ver.size); ver.copyInto(bytes, md + 16)
    val dir = md + 28; putU16(b, dir, 0); putU16(b, dir + 2, 3)
    var dc = dir + 4
    fun stream(offset: Int, size: Int, name: String) {
        b.putInt(dc, offset); b.putInt(dc + 4, size); name.toByteArray().plus(0).copyInto(bytes, dc + 8)
        dc = (dc + 8 + name.length + 1 + 3) and -4
    }
    stream(0x80, 0x100, "#~")
    stream(0x200, 0x100, "#Strings")
    stream(0x300, 0x40, "#Blob")

    val strings = StringsHeapBuilder()
    val system = strings.add("System")
    val objectName = strings.add("Object")
    val game = strings.add("Game")
    val player = strings.add("Player")
    val run = strings.add("Run")
    val writeLine = strings.add("WriteLine")
    val assemblyName = strings.add("Assembly-CSharp")
    val mscorlib = strings.add("mscorlib")
    strings.bytes().copyInto(bytes, md + 0x200)
    bytes[md + 0x300] = 0
    bytes[md + 0x301] = 1; bytes[md + 0x302] = 0

    val t = md + 0x80
    b.putInt(t, 0); bytes[t + 4] = 2; bytes[t + 5] = 0; bytes[t + 6] = 0; bytes[t + 7] = 1
    val tables = listOf(1, 2, 6, 10, 32, 35)
    var valid = 0L; tables.forEach { valid = valid or (1L shl it) }
    b.putLong(t + 8, valid); b.putLong(t + 16, 0)
    var c = t + 24; tables.forEach { b.putInt(c, 1); c += 4 }
    // TypeRef: ResolutionScope=AssemblyRef#1 (tag 2), name, namespace
    putU16(b, c, (1 shl 2) or 2); putU16(b, c + 2, objectName); putU16(b, c + 4, system); c += 6
    // TypeDef
    b.putInt(c, 1); putU16(b, c + 4, player); putU16(b, c + 6, game); putU16(b, c + 8, (1 shl 2) or 1)
    putU16(b, c + 10, 1); putU16(b, c + 12, 1); c += 14
    // MethodDef
    b.putInt(c, 0x1234); putU16(b, c + 4, 0); putU16(b, c + 6, 0x16); putU16(b, c + 8, run); putU16(b, c + 10, 1); putU16(b, c + 12, 1); c += 14
    // MemberRef: parent TypeRef#1 (tag 1)
    putU16(b, c, (1 shl 3) or 1); putU16(b, c + 2, writeLine); putU16(b, c + 4, 1); c += 6
    // Assembly v1.2.3.4
    b.putInt(c, 0); putU16(b, c + 4, 1); putU16(b, c + 6, 2); putU16(b, c + 8, 3); putU16(b, c + 10, 4)
    b.putInt(c + 12, 0); putU16(b, c + 16, 0); putU16(b, c + 18, assemblyName); putU16(b, c + 20, 0); c += 22
    // AssemblyRef mscorlib 4.0.0.0
    putU16(b, c, 4); putU16(b, c + 2, 0); putU16(b, c + 4, 0); putU16(b, c + 6, 0); b.putInt(c + 8, 0)
    putU16(b, c + 12, 0); putU16(b, c + 14, mscorlib); putU16(b, c + 16, 0); putU16(b, c + 18, 0)
    return bytes
}

private fun hermesBytecode(): ByteArray {
    val size = 192
    val bytes = ByteArray(size)
    val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    b.putLong(0, 0x1F1903C103BC1FC6L); b.putInt(8, 96)
    for (i in 0 until 20) bytes[12 + i] = i.toByte()
    b.putInt(32, size); b.putInt(36, 0); b.putInt(40, 2); b.putInt(44, 1); b.putInt(48, 1); b.putInt(52, 2)
    b.putInt(56, 0); b.putInt(60, 8); b.putInt(64, 0); b.putInt(68, 0); b.putInt(72, 0); b.putInt(76, 0)
    b.putInt(80, 0); b.putInt(84, 0); b.putInt(88, 0); b.putInt(92, 0); b.putInt(96, 7); b.putInt(100, 1); b.putInt(104, 0); b.putInt(108, 180)
    bytes[112] = 1
    val f0 = 128
    b.putInt(f0, 176 or (2 shl 25) or (1 shl 30))
    b.putInt(f0 + 4, 8 or (1 shl 14) or (2 shl 22))
    bytes[f0 + 8] = 3; bytes[f0 + 11] = 0x04
    val f1 = 140
    b.putInt(f1, 0x1234)
    b.putInt(f1 + 4, 0x12 shl 14)
    bytes[f1 + 11] = 0x20
    return bytes
}

private fun nativeForRuntimes(): NativeSummary {
    fun lib(name: String) = NativeLibrarySummary("lib/arm64-v8a/$name", "arm64-v8a", "ELF64", "AARCH64", "DYN", 1, null, emptyList(), emptyList(), emptyList(), emptyList(), false, false, false, true, true, true, true, emptyList())
    val libs = listOf(lib("libmono.so"), lib("libunity.so"), lib("libhermes.so"))
    return NativeSummary(libs.size, libs.size, libs, parseErrors = 0, truncated = false)
}

private fun il2cppNative(): NativeSummary {
    val entry = "lib/arm64-v8a/libil2cpp.so"
    fun sym(name: String, addr: Long) = NativeSymbolReference(entry, name, "GLOBAL", "FUNC", true, addr, 16)
    val exports = listOf(
        sym("il2cpp_init", 0x4000), sym("il2cpp_class_from_name", 0x4010), sym("il2cpp_class_get_method_from_name", 0x4020),
        sym("g_CodeRegistration", 0x5000), sym("g_MetadataRegistration", 0x6000), sym("il2cpp_codegen_register", 0x7000),
    )
    val lib = NativeLibrarySummary(entry, "arm64-v8a", "ELF64", "AARCH64", "DYN", 100, null, emptyList(), emptyList(), exports, emptyList(), false, false, false, true, true, true, true, emptyList())
    return NativeSummary(1, 1, listOf(lib), parseErrors = 0, truncated = false)
}

fun main(args: Array<String>) {
    val outDir = File(args.firstOrNull() ?: System.getProperty("java.io.tmpdir")).apply { mkdirs() }
    val apk = File(outDir, "runtime.apk")
    ZipOutputStream(apk.outputStream()).use { z ->
        fun e(n: String, data: ByteArray) { z.putNextEntry(ZipEntry(n)); z.write(data); z.closeEntry() }
        e("assets/index.android.bundle.hbc", hermesBytecode())
        e("assets/bin/Data/Managed/Assembly-CSharp.dll", managedAssembly())
        e("META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties", "groupId=com.squareup.okhttp3\nartifactId=okhttp\nversion=4.12.0\n".toByteArray())
    }
    val runtime = requireNotNull(RuntimeArtifactScanner.scanApk(apk, nativeForRuntimes()))
    val hbc = requireNotNull(runtime.hermes).bytecodeFiles.single()
    check(hbc.functionCount == 2L && hbc.functionsScanned == 2 && hbc.functions.size == 2)
    check(hbc.functions[0].parameterCount == 2 && hbc.functions[0].strictMode == true)
    check(hbc.functions[1].overflowed && hbc.functions[1].largeHeaderOffset != null)
    check(hbc.structuredPrefixBytes == 176L)

    val asm = requireNotNull(runtime.unityMono).assemblies.single()
    check(asm.assemblyName == "Assembly-CSharp" && asm.assemblyVersion == "1.2.3.4")
    check(asm.typeReferences.single().fullName == "System.Object")
    check(asm.typeDefinitions.single().fullName == "Game.Player")
    check(asm.methodDefinitions.single().name == "Run")
    check(asm.memberReferences.single().name == "WriteLine")
    check(asm.assemblyReferences.single().name == "mscorlib")

    val dex = DexSummary(1, 1, 0, 0, classes = listOf(DexClassReference("classes.dex", 0, "Lokhttp3/OkHttpClient;", null, 1)), httpUrls = emptyList(), httpsUrls = emptyList(), secretCandidates = emptyList(), parseErrors = 0, truncated = false)
    val supply = SupplyChainScanner.scan(apk, dex, nativeForRuntimes(), null, runtime)
    val okhttp = supply.components.single { it.id == "maven:com.squareup.okhttp3:okhttp" }
    check(okhttp.version == "4.12.0" && okhttp.purl == "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0" && okhttp.confidence == "HIGH")

    val il2cppApk = File(outDir, "il2cpp.apk")
    ZipOutputStream(il2cppApk.outputStream()).use { }
    val il2cpp = requireNotNull(Il2CppScanner.scanApk(il2cppApk, il2cppNative()))
    check(il2cpp.registrationCandidates.count { it.validatedDefinedSymbol && it.virtualAddress != null } == 3)

    val scope = AssessmentScope(projectName = "M25", organization = "UniRevLab", purpose = "Regression", confirmsAuthority = true, staticAnalysis = true)
    val artifact = ArtifactSummary("runtime.apk", apk.length(), "a".repeat(64), 3, 1, 3, true, 0, false)
    val report = StaticAnalysisReport(engineVersion = "0.9.0-m2-deep-metadata-sbom-dev", assessment = scope, artifact = artifact, manifest = null, runtimeArtifacts = runtime, supplyChain = supply, findings = emptyList())
    val cdx = SbomExporter.exportCycloneDx16(report)
    val spdx = SbomExporter.exportSpdx301JsonLd(report)
    File(outDir, "bom.cdx.json").writeText(cdx)
    File(outDir, "bom.spdx.jsonld").writeText(spdx)
    check(cdx.contains("\"specVersion\": \"1.6\"") && cdx.contains("okhttp@4.12.0"))
    check(spdx.contains("spdx-context.jsonld") && spdx.contains("software_Package") && spdx.contains("dependsOn"))
    println("M2.5 deep Hermes + ECMA-335 + version evidence + SBOM smoke PASS")
}
