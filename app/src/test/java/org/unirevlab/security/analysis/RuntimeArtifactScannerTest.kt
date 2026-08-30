package org.unirevlab.security.analysis

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.NativeLibrarySummary
import org.unirevlab.security.model.NativeSummary

class RuntimeArtifactScannerTest {
    @Test
    fun inventoriesFlutterHermesUnityMonoAndUnrealWithoutExecution() {
        val apk = fixtureApk()
        try {
            val result = requireNotNull(RuntimeArtifactScanner.scanApk(apk, nativeSummary()))

            assertTrue(result.flutter?.detected == true)
            assertTrue(result.flutter?.aotLikely == true)
            assertEquals(2, result.flutter?.assetCount)

            val hbc = requireNotNull(result.hermes?.bytecodeFiles?.single())
            assertTrue(hbc.magicValid)
            assertEquals(96, hbc.bytecodeVersion)
            assertEquals(7L, hbc.functionCount)
            assertEquals(11L, hbc.stringCount)

            val assembly = requireNotNull(result.unityMono?.assemblies?.single())
            assertTrue(assembly.peValid)
            assertTrue(assembly.cliMetadataPresent)
            assertEquals("v4.0.30319", assembly.metadataVersion)
            assertTrue(assembly.metadataStreams.any { it.name == "#~" })
            assertEquals(3L, assembly.metadataTables.first { it.name == "TypeDef" }.rowCount)
            assertEquals(9L, assembly.metadataTables.first { it.name == "MethodDef" }.rowCount)
            assertEquals(64, result.flutter?.artifactFingerprints?.single()?.sha256?.length)

            assertTrue(result.unreal?.detected == true)
            assertTrue(result.unreal?.containers?.any { it.kind == "PAK" } == true)
            assertTrue(result.unreal?.containers?.any { it.kind == "IOSTORE_TOC" } == true)
            assertTrue(result.unreal?.containers?.any { it.kind == "IOSTORE_CAS" } == true)
        } finally {
            apk.delete()
        }
    }

    private fun fixtureApk(): File = File.createTempFile("runtime-artifact-fixture", ".apk").apply {
        ZipOutputStream(outputStream()).use { zip ->
            fun entry(name: String, bytes: ByteArray = byteArrayOf(0)) {
                zip.putNextEntry(ZipEntry(name)); zip.write(bytes); zip.closeEntry()
            }
            entry("assets/flutter_assets/AssetManifest.bin", byteArrayOf(1, 2, 3))
            entry("assets/flutter_assets/assets/logo.png", byteArrayOf(4, 5))
            entry("assets/flutter_assets/vm_snapshot_data", "snapshot-data".toByteArray())
            entry("assets/index.android.bundle.hbc", hermesHeader())
            entry("assets/bin/Data/Managed/Assembly-CSharp.dll", cliAssembly())
            entry("assets/Game/Content/Paks/pakchunk0-Android.pak", byteArrayOf(1))
            entry("assets/Game/Content/Paks/global.utoc", byteArrayOf(2))
            entry("assets/Game/Content/Paks/global.ucas", byteArrayOf(3))
        }
    }

    private fun hermesHeader(): ByteArray = ByteArray(128).also { bytes ->
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).apply {
            putLong(0, 0x1F1903C103BC1FC6L)
            putInt(8, 96)
            repeat(20) { bytes[12 + it] = it.toByte() }
            putInt(32, bytes.size)
            putInt(36, 2)
            putInt(40, 7)
            putInt(44, 1)
            putInt(48, 5)
            putInt(52, 11)
            putInt(56, 0)
            putInt(60, 128)
        }
    }

    private fun cliAssembly(): ByteArray {
        val bytes = ByteArray(0x700)
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        bytes[0] = 'M'.code.toByte(); bytes[1] = 'Z'.code.toByte(); b.putInt(0x3c, 0x80)
        bytes[0x80] = 'P'.code.toByte(); bytes[0x81] = 'E'.code.toByte()
        b.putShort(0x84, 0x14c.toShort()); b.putShort(0x86, 1); b.putShort(0x94, 0xE0.toShort())
        val optional = 0x98; b.putShort(optional, 0x10b.toShort()); b.putInt(optional + 92, 16)
        val cliDir = optional + 96 + 14 * 8; b.putInt(cliDir, 0x2000); b.putInt(cliDir + 4, 0x48)
        val section = optional + 0xE0; ".text".toByteArray().copyInto(bytes, section); b.putInt(section + 8, 0x500); b.putInt(section + 12, 0x2000); b.putInt(section + 16, 0x500); b.putInt(section + 20, 0x200)
        val cli = 0x200; b.putInt(cli, 0x48); b.putShort(cli + 4, 2); b.putShort(cli + 6, 5); b.putInt(cli + 8, 0x2080); b.putInt(cli + 12, 0x180)
        val metadata = 0x280; b.putInt(metadata, 0x424A5342); b.putShort(metadata + 4, 1); b.putShort(metadata + 6, 1)
        val version = "v4.0.30319\u0000".toByteArray(); b.putInt(metadata + 12, version.size); version.copyInto(bytes, metadata + 16)
        val dir = metadata + 28; b.putShort(dir, 0); b.putShort(dir + 2, 1); b.putInt(dir + 4, 0x40); b.putInt(dir + 8, 0x60); "#~\u0000".toByteArray().copyInto(bytes, dir + 12)
        val tables = metadata + 0x40; bytes[tables + 4] = 2; bytes[tables + 7] = 1
        val valid = (1L shl 2) or (1L shl 6) or (1L shl 10) or (1L shl 32) or (1L shl 35)
        b.putLong(tables + 8, valid); b.putLong(tables + 16, 0)
        var cursor = tables + 24; listOf(3, 9, 5, 1, 4).forEach { b.putInt(cursor, it); cursor += 4 }
        "Assembly-CSharp.dll\u0000Game.PlayerController\u0000".toByteArray().copyInto(bytes, metadata + 0xB0)
        return bytes
    }

    private fun nativeSummary(): NativeSummary {
        fun lib(name: String, buildId: String? = null) = NativeLibrarySummary(
            entryName = "lib/arm64-v8a/$name",
            abi = "arm64-v8a",
            elfClass = "ELF64",
            machine = "AARCH64",
            fileType = "DYN",
            sizeBytes = 1,
            buildId = buildId,
            neededLibraries = emptyList(),
            importedSymbols = emptyList(),
            exportedSymbols = emptyList(),
            jniSymbols = emptyList(),
            hasJniOnLoad = false,
            registerNativesIndicator = false,
            executableStack = false,
            hasGnuRelro = true,
            bindNow = true,
            hasStackCanaryImport = true,
            stripped = true,
            httpUrls = emptyList(),
        )
        val libs = listOf(
            lib("libflutter.so", "aabb"),
            lib("libapp.so"),
            lib("libhermes.so"),
            lib("libmono.so"),
            lib("libunity.so"),
            lib("libUnreal.so"),
        )
        return NativeSummary(libs.size, libs.size, libs, parseErrors = 0, truncated = false)
    }
}
