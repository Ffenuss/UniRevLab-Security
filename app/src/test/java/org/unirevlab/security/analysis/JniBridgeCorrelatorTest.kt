package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Test
import org.unirevlab.security.model.DexNativeMethodDeclaration
import org.unirevlab.security.model.DexSummary
import org.unirevlab.security.model.NativeLibrarySummary
import org.unirevlab.security.model.NativeSummary

class JniBridgeCorrelatorTest {
    @Test
    fun matchesStaticJniExportToDexNativeDeclaration() {
        val dex = DexSummary(
            dexFilesDiscovered = 1,
            dexFilesScanned = 1,
            stringsDeclared = 0,
            stringsScanned = 0,
            nativeMethods = listOf(
                DexNativeMethodDeclaration("classes.dex", 0, "Lcom/example/NativeBridge;", "nativeCheck", "()V", 0x101)
            ),
            httpUrls = emptyList(),
            httpsUrls = emptyList(),
            secretCandidates = emptyList(),
            parseErrors = 0,
            truncated = false,
        )
        val library = NativeLibrarySummary(
            entryName = "lib/arm64-v8a/libnative.so",
            abi = "arm64-v8a",
            elfClass = "ELF64",
            machine = "AArch64",
            fileType = "DYN",
            sizeBytes = 1,
            buildId = null,
            neededLibraries = emptyList(),
            importedSymbols = emptyList(),
            exportedSymbols = emptyList(),
            jniSymbols = listOf("Java_com_example_NativeBridge_nativeCheck"),
            hasJniOnLoad = true,
            registerNativesIndicator = false,
            executableStack = false,
            hasGnuRelro = true,
            bindNow = true,
            hasStackCanaryImport = true,
            stripped = true,
            httpUrls = emptyList(),
        )
        val result = JniBridgeCorrelator.correlate(
            dex,
            NativeSummary(1, 1, listOf(library), parseErrors = 0, truncated = false),
        )
        assertEquals("STATIC_SYMBOL_MATCH", result.jniBridges.single().resolution)
        assertEquals("lib/arm64-v8a/libnative.so", result.jniBridges.single().libraryEntry)
    }

    @Test
    fun encodesUnderscoresPerJniNamingRules() {
        assertEquals(
            "Java_com_example_Native_1Bridge_native_1check",
            JniBridgeCorrelator.staticJniBase("Lcom/example/Native_Bridge;", "native_check"),
        )
    }
}
