package org.unirevlab.security.analysis

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.NativeLibrarySummary
import org.unirevlab.security.model.NativeSummary
import org.unirevlab.security.model.NativeSymbolReference

class Il2CppScannerTest {
    @Test
    fun detectsPairFromArchiveIndexWhenDetailedElfListOmittedLibrary() {
        val apk = fixtureApk()
        try {
            val result = requireNotNull(
                Il2CppScanner.scanApk(
                    apk = apk,
                    native = null,
                    archiveEntryNames = listOf(
                        "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                        "lib/arm64-v8a/libil2cpp.so",
                    ),
                )
            )
            assertTrue(result.detected)
            assertEquals("HIGH", result.confidence)
            assertEquals(listOf("lib/arm64-v8a/libil2cpp.so"), result.libil2cppLibraries)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun detectsStandardMetadataAndNativePairWithoutExecution() {
        val apk = fixtureApk()
        try {
            val result = requireNotNull(Il2CppScanner.scanApk(apk, nativeSummary()))
            assertTrue(result.detected)
            assertEquals("HIGH", result.confidence)
            assertEquals(29, result.metadata?.metadataVersion)
            assertTrue(result.metadata?.assemblyNameCandidates?.contains("Assembly-CSharp.dll") == true)
            assertTrue(result.metadata?.unityVersionCandidates?.contains("2022.3.45f1") == true)
            assertTrue(result.il2cppApiSymbols.contains("il2cpp_init"))
            assertTrue(result.registrationCandidates.any { it.kind == "CODEGEN_REGISTER_SYMBOL" })
            assertEquals("IL2CPP_METADATA_V27_V30", result.metadata?.layoutProfile)
            assertEquals("Game.PlayerController", result.metadata?.typeDefinitions?.single()?.fullName)
            assertEquals("TakeDamage", result.metadata?.methodDefinitions?.single()?.name)
        } finally {
            apk.delete()
        }
    }

    private fun fixtureApk(): File = File.createTempFile("il2cpp-fixture", ".apk").apply {
        ZipOutputStream(outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("assets/bin/Data/Managed/Metadata/global-metadata.dat"))
            val header = ByteArray(768)
            val bb = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
            bb.putInt(0, 0xFAB11BAF.toInt()); bb.putInt(4, 29)
            val stringsOff = 256
            val managedStrings = "Game\u0000PlayerController\u0000TakeDamage\u0000Assembly-CSharp.dll\u0000".toByteArray()
            fun pair(index: Int, off: Int, size: Int) { bb.putInt(8 + index * 8, off); bb.putInt(12 + index * 8, size) }
            pair(2, stringsOff, managedStrings.size); pair(5, 512, 32); pair(19, 544, 88)
            managedStrings.copyInto(header, stringsOff)
            val playerOff = "Game\u0000".toByteArray().size
            val methodOff = playerOff + "PlayerController\u0000".toByteArray().size
            bb.putInt(512, methodOff); bb.putInt(516, 0); bb.putInt(532, 0x06000001); bb.putShort(536, 0x0006); bb.putShort(542, 0)
            bb.putInt(544, playerOff); bb.putInt(548, 0); bb.putInt(576, 0); bb.putInt(580, 0); bb.putShort(608, 1); bb.putShort(612, 0); bb.putInt(628, 0x02000001)
            zip.write(header)
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("assets/bin/Data/globalgamemanagers"))
            zip.write("2022.3.45f1\u0000".toByteArray()); zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/arm64-v8a/libil2cpp.so"))
            zip.write(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())); zip.closeEntry()
        }
    }

    private fun nativeSummary(): NativeSummary {
        val entry = "lib/arm64-v8a/libil2cpp.so"
        val lib = NativeLibrarySummary(
            entryName = entry, abi = "arm64-v8a", elfClass = "ELF64", machine = "AARCH64", fileType = "DYN",
            sizeBytes = 4, buildId = null, neededLibraries = emptyList(), importedSymbols = emptyList(),
            exportedSymbols = listOf(
                NativeSymbolReference(entry, "il2cpp_init", "GLOBAL", "FUNC", true),
                NativeSymbolReference(entry, "il2cpp_class_from_name", "GLOBAL", "FUNC", true),
                NativeSymbolReference(entry, "il2cpp_class_get_method_from_name", "GLOBAL", "FUNC", true),
                NativeSymbolReference(entry, "il2cpp_codegen_register", "GLOBAL", "FUNC", true),
            ), jniSymbols = emptyList(), hasJniOnLoad = false, registerNativesIndicator = false,
            executableStack = false, hasGnuRelro = true, bindNow = true, hasStackCanaryImport = true,
            stripped = false, httpUrls = emptyList(),
        )
        return NativeSummary(1, 1, listOf(lib), parseErrors = 0, truncated = false)
    }
}
