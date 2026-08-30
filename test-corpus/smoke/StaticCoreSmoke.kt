import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.unirevlab.security.analysis.DexRuleEngine
import org.unirevlab.security.analysis.DexCodeScanner
import org.unirevlab.security.analysis.Il2CppScanner
import org.unirevlab.security.analysis.Il2CppRuleEngine
import org.unirevlab.security.analysis.DexStringScanner
import org.unirevlab.security.analysis.ElfNativeScanner
import org.unirevlab.security.analysis.JniBridgeCorrelator
import org.unirevlab.security.analysis.NativeRuleEngine
import org.unirevlab.security.analysis.ReportJsonExporter
import org.unirevlab.security.analysis.RuntimeProfileScanner
import org.unirevlab.security.analysis.RuntimeArtifactScanner
import org.unirevlab.security.model.ArtifactSummary
import org.unirevlab.security.model.AssessmentScope
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.NativeSummary
import org.unirevlab.security.model.NativeLibrarySummary
import org.unirevlab.security.model.NativeSymbolReference
import org.unirevlab.security.model.StaticAnalysisReport

private fun indexedNativeDex(): File {
    val strings = listOf(
        "Lcom/example/NativeBridge;",
        "Ljava/lang/Object;",
        "V",
        "nativeCheck",
        "http://legacy.invalid/api?secret=not-exported",
    )
    val headerSize = 0x70
    val stringIdsOff = headerSize
    val typeIdsOff = stringIdsOff + strings.size * 4
    val protoIdsOff = typeIdsOff + 3 * 4
    val methodIdsOff = protoIdsOff + 12
    val classDefsOff = methodIdsOff + 8
    val classDataOff = classDefsOff + 32
    val classData = byteArrayOf(0, 0, 1, 0, 0, 0x81.toByte(), 0x02, 0)
    val stringDataOff = classDataOff + classData.size
    val stringData = mutableListOf<Byte>()
    val stringOffsets = mutableListOf<Int>()
    for (value in strings) {
        stringOffsets += stringDataOff + stringData.size
        require(value.length < 0x80)
        stringData += value.length.toByte()
        value.toByteArray(Charsets.UTF_8).forEach { stringData += it }
        stringData += 0
    }
    val total = stringDataOff + stringData.size
    val bytes = ByteArray(total)
    val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    b.put("dex\n035\u0000".toByteArray(Charsets.ISO_8859_1))
    b.position(0x20); b.putInt(total); b.putInt(0x70); b.putInt(0x12345678)
    b.position(0x38); b.putInt(strings.size); b.putInt(stringIdsOff)
    b.putInt(3); b.putInt(typeIdsOff)
    b.putInt(1); b.putInt(protoIdsOff)
    b.putInt(0); b.putInt(0)
    b.putInt(1); b.putInt(methodIdsOff)
    b.putInt(1); b.putInt(classDefsOff)
    stringOffsets.forEachIndexed { index, offset -> b.putInt(stringIdsOff + index * 4, offset) }
    b.putInt(typeIdsOff, 0); b.putInt(typeIdsOff + 4, 1); b.putInt(typeIdsOff + 8, 2)
    b.putInt(protoIdsOff, 2); b.putInt(protoIdsOff + 4, 2); b.putInt(protoIdsOff + 8, 0)
    b.putShort(methodIdsOff, 0); b.putShort(methodIdsOff + 2, 0); b.putInt(methodIdsOff + 4, 3)
    b.putInt(classDefsOff, 0); b.putInt(classDefsOff + 4, 1); b.putInt(classDefsOff + 8, 1)
    b.putInt(classDefsOff + 12, 0); b.putInt(classDefsOff + 16, -1); b.putInt(classDefsOff + 20, 0)
    b.putInt(classDefsOff + 24, classDataOff); b.putInt(classDefsOff + 28, 0)
    classData.forEachIndexed { index, value -> bytes[classDataOff + index] = value }
    stringData.forEachIndexed { index, value -> bytes[stringDataOff + index] = value }
    return File.createTempFile("unirevlab-indexed-native", ".dex").apply { writeBytes(bytes) }
}


private fun uleb(value: Int): ByteArray {
    var v = value
    val out = mutableListOf<Byte>()
    do {
        var b = v and 0x7f
        v = v ushr 7
        if (v != 0) b = b or 0x80
        out += b.toByte()
    } while (v != 0)
    return out.toByteArray()
}

private fun codeXrefDex(): File {
    val strings = listOf(
        "Lcom/example/CodeBridge;",
        "Ljava/lang/Object;",
        "V",
        "caller",
        "callee",
        "http://code.invalid/path?token=redacted",
    )
    val headerSize = 0x70
    val stringIdsOff = headerSize
    val typeIdsOff = stringIdsOff + strings.size * 4
    val protoIdsOff = typeIdsOff + 3 * 4
    val methodIdsOff = protoIdsOff + 12
    val classDefsOff = methodIdsOff + 16
    val classDataOff = classDefsOff + 32

    var classData = byteArrayOf()
    var codeOff = 0
    repeat(4) {
        val body = mutableListOf<Byte>()
        body += byteArrayOf(0, 0, 2, 0).toList() // fields=0, direct methods=2
        body += uleb(0).toList(); body += uleb(1).toList(); body += uleb(codeOff).toList()
        body += uleb(1).toList(); body += uleb(1).toList(); body += uleb(0).toList()
        classData = body.toByteArray()
        codeOff = (classDataOff + classData.size + 3) and -4
    }
    val stringDataOff = codeOff + 16 + 8 * 2
    val stringData = mutableListOf<Byte>()
    val stringOffsets = mutableListOf<Int>()
    for (value in strings) {
        stringOffsets += stringDataOff + stringData.size
        require(value.length < 0x80)
        stringData += value.length.toByte()
        value.toByteArray(Charsets.UTF_8).forEach { stringData += it }
        stringData += 0
    }
    val total = stringDataOff + stringData.size
    val bytes = ByteArray(total)
    val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    b.put("dex\n035\u0000".toByteArray(Charsets.ISO_8859_1))
    b.position(0x20); b.putInt(total); b.putInt(0x70); b.putInt(0x12345678)
    b.position(0x38); b.putInt(strings.size); b.putInt(stringIdsOff)
    b.putInt(3); b.putInt(typeIdsOff)
    b.putInt(1); b.putInt(protoIdsOff)
    b.putInt(0); b.putInt(0)
    b.putInt(2); b.putInt(methodIdsOff)
    b.putInt(1); b.putInt(classDefsOff)
    stringOffsets.forEachIndexed { index, offset -> b.putInt(stringIdsOff + index * 4, offset) }
    b.putInt(typeIdsOff, 0); b.putInt(typeIdsOff + 4, 1); b.putInt(typeIdsOff + 8, 2)
    b.putInt(protoIdsOff, 2); b.putInt(protoIdsOff + 4, 2); b.putInt(protoIdsOff + 8, 0)
    b.putShort(methodIdsOff, 0); b.putShort(methodIdsOff + 2, 0); b.putInt(methodIdsOff + 4, 3)
    b.putShort(methodIdsOff + 8, 0); b.putShort(methodIdsOff + 10, 0); b.putInt(methodIdsOff + 12, 4)
    b.putInt(classDefsOff, 0); b.putInt(classDefsOff + 4, 1); b.putInt(classDefsOff + 8, 1)
    b.putInt(classDefsOff + 12, 0); b.putInt(classDefsOff + 16, -1); b.putInt(classDefsOff + 20, 0)
    b.putInt(classDefsOff + 24, classDataOff); b.putInt(classDefsOff + 28, 0)
    classData.forEachIndexed { i, v -> bytes[classDataOff + i] = v }
    b.putShort(codeOff, 1); b.putShort(codeOff + 2, 0); b.putShort(codeOff + 4, 0); b.putShort(codeOff + 6, 0)
    b.putInt(codeOff + 8, 0); b.putInt(codeOff + 12, 8)
    val units = intArrayOf(0x001a, 5, 0x1071, 1, 0, 0x001c, 0, 0x000e)
    units.forEachIndexed { i, unit -> b.putShort(codeOff + 16 + i * 2, unit.toShort()) }
    stringData.forEachIndexed { i, v -> bytes[stringDataOff + i] = v }
    return File.createTempFile("unirevlab-code-xref", ".dex").apply { writeBytes(bytes) }
}

private fun cfgFieldDex(): File {
        val strings = listOf("Lcom/example/Cfg;", "Ljava/lang/Object;", "I", "V", "run", "enabled")
        val headerSize=0x70; val stringIdsOff=headerSize; val typeIdsOff=stringIdsOff+strings.size*4
        val protoIdsOff=typeIdsOff+4*4; val fieldIdsOff=protoIdsOff+12; val methodIdsOff=fieldIdsOff+8
        val classDefsOff=methodIdsOff+8; val classDataOff=classDefsOff+32
        var classData=byteArrayOf(); var codeOff=0
        repeat(4) {
            val body=mutableListOf<Byte>(); body += byteArrayOf(0,0,1,0).toList()
            body += uleb(0).toList(); body += uleb(1).toList(); body += uleb(codeOff).toList()
            classData=body.toByteArray(); codeOff=(classDataOff+classData.size+3) and -4
        }
        val units=intArrayOf(0x1012, 0x0060, 0, 0x0038, 2, 0x000e, 0x000e) // const/4 v0,#1; sget v0,field@0; if-eqz v0,+2; return; return
        val stringDataOff=codeOff+16+units.size*2
        val data=mutableListOf<Byte>(); val offsets=mutableListOf<Int>()
        for(v in strings){ offsets += stringDataOff+data.size; data += v.length.toByte(); v.toByteArray().forEach{data+=it}; data+=0 }
        val total=stringDataOff+data.size; val bytes=ByteArray(total); val b=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        b.put("dex\n035\u0000".toByteArray(Charsets.ISO_8859_1)); b.position(0x20); b.putInt(total); b.putInt(0x70); b.putInt(0x12345678)
        b.position(0x38); b.putInt(strings.size); b.putInt(stringIdsOff); b.putInt(4); b.putInt(typeIdsOff); b.putInt(1); b.putInt(protoIdsOff)
        b.putInt(1); b.putInt(fieldIdsOff); b.putInt(1); b.putInt(methodIdsOff); b.putInt(1); b.putInt(classDefsOff)
        offsets.forEachIndexed{i,o->b.putInt(stringIdsOff+i*4,o)}
        b.putInt(typeIdsOff,0); b.putInt(typeIdsOff+4,1); b.putInt(typeIdsOff+8,2); b.putInt(typeIdsOff+12,3)
        b.putInt(protoIdsOff,3); b.putInt(protoIdsOff+4,3); b.putInt(protoIdsOff+8,0)
        b.putShort(fieldIdsOff,0); b.putShort(fieldIdsOff+2,2); b.putInt(fieldIdsOff+4,5)
        b.putShort(methodIdsOff,0); b.putShort(methodIdsOff+2,0); b.putInt(methodIdsOff+4,4)
        b.putInt(classDefsOff,0); b.putInt(classDefsOff+4,1); b.putInt(classDefsOff+8,1); b.putInt(classDefsOff+12,0); b.putInt(classDefsOff+16,-1); b.putInt(classDefsOff+20,0); b.putInt(classDefsOff+24,classDataOff); b.putInt(classDefsOff+28,0)
        classData.forEachIndexed{i,v->bytes[classDataOff+i]=v}
        b.putShort(codeOff,1); b.putShort(codeOff+2,0); b.putShort(codeOff+4,0); b.putShort(codeOff+6,0); b.putInt(codeOff+8,0); b.putInt(codeOff+12,units.size)
        units.forEachIndexed{i,u->b.putShort(codeOff+16+i*2,u.toShort())}; data.forEachIndexed{i,v->bytes[stringDataOff+i]=v}
        return File.createTempFile("dex-cfg-field", ".dex").apply{writeBytes(bytes)}
    }



private fun runtimeCliAssembly(): ByteArray {
    val bytes = ByteArray(0x700)
    val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    bytes[0] = 'M'.code.toByte(); bytes[1] = 'Z'.code.toByte(); b.putInt(0x3c, 0x80)
    bytes[0x80] = 'P'.code.toByte(); bytes[0x81] = 'E'.code.toByte(); b.putShort(0x84, 0x14c.toShort()); b.putShort(0x86, 1); b.putShort(0x94, 0xE0.toShort())
    val optional = 0x98; b.putShort(optional, 0x10b.toShort()); b.putInt(optional + 92, 16)
    val cliDir = optional + 96 + 14 * 8; b.putInt(cliDir, 0x2000); b.putInt(cliDir + 4, 0x48)
    val section = optional + 0xE0; ".text".toByteArray().copyInto(bytes, section); b.putInt(section + 8, 0x500); b.putInt(section + 12, 0x2000); b.putInt(section + 16, 0x500); b.putInt(section + 20, 0x200)
    val cli = 0x200; b.putInt(cli, 0x48); b.putInt(cli + 8, 0x2080); b.putInt(cli + 12, 0x180)
    val metadata = 0x280; b.putInt(metadata, 0x424A5342); b.putShort(metadata + 4, 1); b.putShort(metadata + 6, 1)
    val version = "v4.0.30319\u0000".toByteArray(); b.putInt(metadata + 12, version.size); version.copyInto(bytes, metadata + 16)
    val dir = metadata + 28; b.putShort(dir, 0); b.putShort(dir + 2, 1); b.putInt(dir + 4, 0x40); b.putInt(dir + 8, 0x60); "#~\u0000".toByteArray().copyInto(bytes, dir + 12)
    val tables = metadata + 0x40; bytes[tables + 4] = 2; bytes[tables + 7] = 1
    val valid = (1L shl 2) or (1L shl 6) or (1L shl 10) or (1L shl 32) or (1L shl 35)
    b.putLong(tables + 8, valid); b.putLong(tables + 16, 0)
    var cursor = tables + 24; listOf(2, 4, 3, 1, 2).forEach { b.putInt(cursor, it); cursor += 4 }
    "Assembly-CSharp.dll\u0000Game.PlayerController\u0000".toByteArray().copyInto(bytes, metadata + 0xB0)
    return bytes
}

private fun runtimeMarkerFixture(): File = File.createTempFile("unirevlab-runtime-markers", ".apk").apply {
    ZipOutputStream(outputStream()).use { zip ->
        fun entry(name: String, data: ByteArray = byteArrayOf(0)) {
            zip.putNextEntry(ZipEntry(name)); zip.write(data); zip.closeEntry()
        }
        entry("assets/flutter_assets/AssetManifest.bin")
        val hermes = ByteArray(128)
        ByteBuffer.wrap(hermes).order(ByteOrder.LITTLE_ENDIAN).apply {
            putLong(0, 0x1F1903C103BC1FC6L); putInt(8, 96); putInt(32, hermes.size); putInt(36, 0)
            putInt(40, 1); putInt(48, 2); putInt(52, 3)
        }
        entry("assets/index.android.bundle.hbc", hermes)
        entry("assets/www/cordova.js")
        entry("assets/bin/Data/Managed/Game.dll", runtimeCliAssembly())
        entry("assets/Game/Paks/chunk0.pak")
        entry("assets/Game/Paks/global.utoc")
        entry("assets/Game/Paks/global.ucas")
        entry("assemblies/App.dll", byteArrayOf('M'.code.toByte(), 'Z'.code.toByte()))
    }
}


private fun runtimeNativeSummary(): NativeSummary {
    fun lib(name: String, buildId: String? = null) = NativeLibrarySummary(
        entryName = "lib/arm64-v8a/$name", abi = "arm64-v8a", elfClass = "ELF64", machine = "AARCH64", fileType = "DYN",
        sizeBytes = 1, buildId = buildId, neededLibraries = emptyList(), importedSymbols = emptyList(), exportedSymbols = emptyList(),
        jniSymbols = emptyList(), hasJniOnLoad = false, registerNativesIndicator = false, executableStack = false,
        hasGnuRelro = true, bindNow = true, hasStackCanaryImport = true, stripped = true, httpUrls = emptyList(),
    )
    val libs = listOf(lib("libflutter.so", "flutter-build-id"), lib("libapp.so"), lib("libhermes.so"), lib("libmono.so"), lib("libunity.so"), lib("libUnreal.so"))
    return NativeSummary(libs.size, libs.size, libs, parseErrors = 0, truncated = false)
}

private fun il2cppFixture(): Pair<File, NativeSummary> {
    val apk = File.createTempFile("unirevlab-il2cpp", ".apk")
    ZipOutputStream(apk.outputStream()).use { zip ->
        zip.putNextEntry(ZipEntry("assets/bin/Data/Managed/Metadata/global-metadata.dat"))
        val meta = ByteArray(768)
        val b = ByteBuffer.wrap(meta).order(ByteOrder.LITTLE_ENDIAN)
        b.putInt(0, 0xFAB11BAF.toInt()); b.putInt(4, 29)
        val stringsOff = 256
        val managedStrings = "Game\u0000PlayerController\u0000TakeDamage\u0000Assembly-CSharp.dll\u0000UnityEngine.CoreModule.dll\u0000".toByteArray()
        fun pair(index: Int, off: Int, size: Int) { b.putInt(8 + index * 8, off); b.putInt(12 + index * 8, size) }
        pair(2, stringsOff, managedStrings.size)
        pair(5, 512, 32)
        pair(19, 544, 88)
        managedStrings.copyInto(meta, stringsOff)
        val playerOff = "Game\u0000".toByteArray().size
        val takeDamageOff = playerOff + "PlayerController\u0000".toByteArray().size
        // Il2CppMethodDefinition v29
        b.putInt(512, takeDamageOff); b.putInt(516, 0); b.putInt(532, 0x06000001); b.putShort(536, 0x0006); b.putShort(542, 0)
        // Il2CppTypeDefinition v29
        b.putInt(544, playerOff); b.putInt(548, 0); b.putInt(576, 0); b.putInt(580, 0)
        b.putShort(608, 1); b.putShort(612, 0); b.putInt(628, 0x02000001)
        zip.write(meta); zip.closeEntry()
        zip.putNextEntry(ZipEntry("assets/bin/Data/globalgamemanagers"))
        zip.write("2022.3.45f1\u0000".toByteArray()); zip.closeEntry()
        zip.putNextEntry(ZipEntry("lib/arm64-v8a/libil2cpp.so"))
        zip.write(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())); zip.closeEntry()
    }
    val lib = NativeLibrarySummary(
        entryName = "lib/arm64-v8a/libil2cpp.so", abi = "arm64-v8a", elfClass = "ELF64", machine = "AARCH64", fileType = "DYN",
        sizeBytes = 4, buildId = null, neededLibraries = emptyList(), importedSymbols = emptyList(),
        exportedSymbols = listOf(
            NativeSymbolReference("lib/arm64-v8a/libil2cpp.so", "il2cpp_init", "GLOBAL", "FUNC", true),
            NativeSymbolReference("lib/arm64-v8a/libil2cpp.so", "il2cpp_class_from_name", "GLOBAL", "FUNC", true),
            NativeSymbolReference("lib/arm64-v8a/libil2cpp.so", "il2cpp_class_get_method_from_name", "GLOBAL", "FUNC", true),
            NativeSymbolReference("lib/arm64-v8a/libil2cpp.so", "il2cpp_codegen_register", "GLOBAL", "FUNC", true),
        ),
        jniSymbols = emptyList(), hasJniOnLoad = false, registerNativesIndicator = false, executableStack = false,
        hasGnuRelro = true, bindNow = true, hasStackCanaryImport = true, stripped = false, httpUrls = emptyList(),
    )
    return apk to NativeSummary(1, 1, listOf(lib), parseErrors = 0, truncated = false)
}

fun main(args: Array<String>) {
    val root = File(args.getOrElse(0) { "." }).canonicalFile
    val output = File(args.getOrElse(1) { File(root, "build/static-core-smoke-report.json").path })
    val dexFile = indexedNativeDex()
    val d = try {
        DexStringScanner.scan("classes.dex", dexFile)
    } finally {
        dexFile.delete()
    }
    check(d.classes.single().descriptor == "Lcom/example/NativeBridge;")
    check(d.methods.single().name == "nativeCheck")
    check(d.methods.single().prototype == "()V")
    check(d.nativeMethods.single().name == "nativeCheck")
    check(d.httpUrls.single().value == "http://legacy.invalid/api")

    val codeDex = codeXrefDex()
    val code = try { DexCodeScanner.scan("classes.dex", codeDex) } finally { codeDex.delete() }
    check(code.codeMethods.single().name == "caller")
    check(code.callXrefs.single().calleeName == "callee")
    check(code.stringXrefs.single().value == "http://code.invalid/path")
    check(code.typeXrefs.single().kind == "CONST_CLASS")
    check(code.constants.any { it.kind == "STRING" && it.value == "http://code.invalid/path" })
    check(code.invokeObservations.single().arguments.single().value == "http://code.invalid/path")
    check(code.basicBlocks.isNotEmpty())

    val cfgDex = cfgFieldDex()
    val cfg = try { DexCodeScanner.scan("classes.dex", cfgDex) } finally { cfgDex.delete() }
    check(cfg.fieldXrefs.single().fieldName == "enabled")
    check(cfg.fieldXrefs.single().kind == "STATIC_GET")
    check(cfg.constants.any { it.value == "1" })
    check(cfg.basicBlocks.size >= 2)
    check(cfg.basicBlocks.any { it.terminalKind == "CONDITIONAL" && it.successorCodeUnits.isNotEmpty() })

    val (il2cppApk, il2cppNative) = il2cppFixture()
    val il2cpp = try { requireNotNull(Il2CppScanner.scanApk(il2cppApk, il2cppNative)) } finally { il2cppApk.delete() }
    check(il2cpp.detected && il2cpp.confidence == "HIGH")
    check(il2cpp.metadata?.metadataVersion == 29)
    check(il2cpp.metadata?.assemblyNameCandidates?.contains("Assembly-CSharp.dll") == true)
    check(il2cpp.metadata?.unityVersionCandidates?.contains("2022.3.45f1") == true)
    check(il2cpp.metadata?.layoutProfile == "IL2CPP_METADATA_V27_V30")
    check(il2cpp.metadata?.typeDefinitions?.single()?.fullName == "Game.PlayerController")
    check(il2cpp.metadata?.methodDefinitions?.single()?.name == "TakeDamage")
    check(il2cpp.registrationCandidates.any { it.kind == "CODEGEN_REGISTER_SYMBOL" })

    val hardened = File(root, "app/src/test/resources/fixtures/libjni_hardened.so")
    val weak = File(root, "app/src/test/resources/fixtures/libjni_weak.so")
    val hardenedScan = ElfNativeScanner.scan("lib/x86_64/libjni_hardened.so", hardened)
    val weakScan = ElfNativeScanner.scan("lib/x86_64/libjni_weak.so", weak)
    check(hardenedScan.hasJniOnLoad)
    check(hardenedScan.jniSymbols.contains("Java_com_example_NativeBridge_nativeCheck"))
    check(hardenedScan.secretCandidates.any { it.kind == "JWT_LIKE_TOKEN" })
    check(hardenedScan.secretCandidates.all { it.redactedPreview.startsWith("<redacted:length=") })
    check(hardenedScan.executableStack == false && hardenedScan.hasGnuRelro && hardenedScan.bindNow)
    check(weakScan.executableStack == true && !weakScan.hasGnuRelro)
    val weakFindings = NativeRuleEngine.evaluate(
        NativeSummary(1, 1, listOf(weakScan), parseErrors = 0, truncated = false),
    )
    check(weakFindings.any { it.id == "NATIVE-EXECUTABLE-STACK" })
    check(weakFindings.any { it.id == "NATIVE-RELRO-MISSING" })

    val dex = DexSummary(
        dexFilesDiscovered = 1,
        dexFilesScanned = 1,
        stringsDeclared = d.stringsDeclared.toLong(),
        stringsScanned = d.stringsScanned.toLong(),
        typesDeclared = d.typesDeclared.toLong(),
        typesIndexed = d.typesIndexed.toLong(),
        classesDeclared = d.classesDeclared.toLong(),
        classesIndexed = d.classesIndexed.toLong(),
        methodsDeclared = d.methodsDeclared.toLong(),
        methodsIndexed = d.methodsIndexed.toLong(),
        classes = d.classes,
        methods = d.methods,
        nativeMethods = d.nativeMethods,
        codeMethods = code.codeMethods,
        callXrefs = code.callXrefs,
        stringXrefs = code.stringXrefs,
        typeXrefs = code.typeXrefs,
        fieldXrefs = code.fieldXrefs,
        basicBlocks = code.basicBlocks,
        constants = code.constants,
        invokeObservations = code.invokeObservations,
        httpUrls = d.httpUrls,
        httpsUrls = d.httpsUrls,
        secretCandidates = d.secretCandidates,
        parseErrors = 0,
        truncated = d.truncated,
    )
    val native = JniBridgeCorrelator.correlate(
        dex,
        NativeSummary(1, 1, listOf(hardenedScan), parseErrors = 0, truncated = false),
    )
    check(native.jniBridges.single().resolution == "STATIC_SYMBOL_MATCH")

    val findings = (DexRuleEngine.evaluate(dex) + NativeRuleEngine.evaluate(native) + Il2CppRuleEngine.evaluate(il2cpp))
        .sortedBy { it.id }
    val runtimeApk = il2cppFixture().first
    val runtimes = try { RuntimeProfileScanner.scanApk(runtimeApk, dex, il2cppNative, il2cpp) } finally { runtimeApk.delete() }
    check(runtimes?.profiles?.any { it.kind == "UNITY_IL2CPP" } == true)

    val runtimeFixture = runtimeMarkerFixture()
    val genericRuntimes = try { RuntimeProfileScanner.scanApk(runtimeFixture, null, null, null) } finally { runtimeFixture.delete() }
    val kinds = genericRuntimes?.profiles.orEmpty().map { it.kind }.toSet()
    check(setOf("UNITY_MONO", "UNREAL_ENGINE", "FLUTTER", "REACT_NATIVE", "HERMES", "XAMARIN_DOTNET", "CORDOVA_WEBVIEW").all { it in kinds })
    val runtimeArtifactApk = runtimeMarkerFixture()
    val runtimeArtifacts = try { RuntimeArtifactScanner.scanApk(runtimeArtifactApk, runtimeNativeSummary()) } finally { runtimeArtifactApk.delete() }
    check(runtimeArtifacts?.flutter?.detected == true)
    check(runtimeArtifacts?.flutter?.aotLikely == true)
    check(runtimeArtifacts?.hermes?.detected == true)
    check(runtimeArtifacts?.hermes?.bytecodeFiles?.single()?.magicValid == true)
    check(runtimeArtifacts?.hermes?.bytecodeFiles?.single()?.functionCount == 1L)
    check(runtimeArtifacts?.unreal?.detected == true)
    check(runtimeArtifacts?.unreal?.containers?.map { it.kind }?.toSet() == setOf("PAK", "IOSTORE_TOC", "IOSTORE_CAS"))
    check(runtimeArtifacts?.unityMono?.assemblies?.isNotEmpty() == true)
    check(runtimeArtifacts?.unityMono?.assemblies?.single { it.entryName.contains("Managed/Game.dll") }?.cliMetadataPresent == true)
    val report = StaticAnalysisReport(
        engineVersion = "0.9.0-m2-deep-metadata-sbom-dev",
        assessment = AssessmentScope(
            assessmentId = "static-core-smoke",
            createdAtEpochMs = 1,
            projectName = "Static Core Smoke",
            organization = "UniRevLab",
            purpose = "Authorized parser regression test",
            confirmsAuthority = true,
        ),
        artifact = ArtifactSummary(
            displayName = "fixture.apk",
            sizeBytes = 1,
            sha256 = "0".repeat(64),
            archiveEntries = 3,
            dexFiles = 1,
            nativeLibraries = 1,
            hasAndroidManifest = true,
            suspiciousArchivePaths = 0,
            truncatedArchiveScan = false,
        ),
        manifest = null,
        dex = dex,
        native = native,
        il2cpp = il2cpp,
        runtimes = runtimes,
        runtimeArtifacts = runtimeArtifacts,
        findings = findings,
    )
    output.parentFile?.mkdirs()
    val json = ReportJsonExporter.export(report)
    check(!json.contains("eyJabcdefghijk.abcdefghijkl.mnopqrstuvwxyz"))
    check(!json.contains("token=redacted"))
    check(!json.contains("secret=not-exported"))
    output.writeText(json)
    println(
        "static-core smoke: PASS; classes=${d.classes.size}; methods=${d.methods.size}; " +
            "nativeMethods=${d.nativeMethods.size}; calls=${code.callXrefs.size}; il2cpp=${il2cpp.confidence}; " +
            "runtimes=${kinds.size}; jni=${native.jniBridges.single().resolution}; findings=${findings.size}",
    )
}
