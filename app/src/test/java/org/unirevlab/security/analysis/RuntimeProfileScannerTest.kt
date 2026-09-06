package org.unirevlab.security.analysis

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Test
import org.unirevlab.security.model.NativeLibrarySummary
import org.unirevlab.security.model.NativeSummary

class RuntimeProfileScannerTest {
    @Test
    fun libunityAloneDoesNotIdentifyMono() {
        val apk = File.createTempFile("runtime-profiles-unity-only", ".apk")
        try {
            ZipOutputStream(apk.outputStream()).use { }
            val lib = NativeLibrarySummary(
                entryName = "lib/arm64-v8a/libunity.so",
                abi = "arm64-v8a",
                elfClass = "ELF64",
                machine = "AARCH64",
                fileType = "DYN",
                sizeBytes = 1,
                buildId = null,
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
            val result = RuntimeProfileScanner.scanApk(
                apk,
                null,
                NativeSummary(1, 1, listOf(lib), parseErrors = 0, truncated = false),
                null,
            )

            assertFalse(result?.profiles.orEmpty().any { it.kind == "UNITY_MONO" })
        } finally {
            apk.delete()
        }
    }

    @Test
    fun detectsPassiveFrameworkMarkersWithoutExecutingArtifact() {
        val apk = File.createTempFile("runtime-profiles", ".apk")
        try {
            ZipOutputStream(apk.outputStream()).use { zip ->
                listOf(
                    "assets/flutter_assets/AssetManifest.bin",
                    "assets/index.android.bundle.hbc",
                    "assets/www/cordova.js",
                    "assets/bin/Data/Managed/Game.dll",
                    "assets/Game/Paks/chunk0.pak",
                    "assemblies/App.dll",
                ).forEach { name ->
                    zip.putNextEntry(ZipEntry(name))
                    zip.write(byteArrayOf(0))
                    zip.closeEntry()
                }
            }
            val result = requireNotNull(RuntimeProfileScanner.scanApk(apk, null, null, null))
            val kinds = result.profiles.map { it.kind }.toSet()
            assertTrue("UNITY_MONO" in kinds)
            assertTrue("UNREAL_ENGINE" in kinds)
            assertTrue("FLUTTER" in kinds)
            assertTrue("REACT_NATIVE_HERMES" in kinds)
            assertTrue("XAMARIN_DOTNET" in kinds)
            assertTrue("CORDOVA_WEBVIEW" in kinds)
        } finally {
            apk.delete()
        }
    }
}
