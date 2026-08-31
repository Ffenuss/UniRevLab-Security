package org.unirevlab.security.analysis

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ElfNativeScannerTest {
    @Test
    fun inventoriesHardenedJniLibraryWithoutLoadingIt() {
        val file = fixture("libjni_hardened.so")
        val scan = ElfNativeScanner.scan("lib/x86_64/libjni_hardened.so", file)

        assertEquals("ELF64", scan.elfClass)
        assertTrue(scan.hasJniOnLoad)
        assertTrue(scan.jniSymbols.any { it == "Java_com_example_NativeBridge_nativeCheck" })
        assertTrue(scan.registerNativesIndicator)
        assertTrue(scan.hasGnuRelro)
        assertTrue(scan.bindNow)
        assertTrue(scan.hasStackCanaryImport)
        assertEquals(false, scan.executableStack)
        assertEquals(listOf("http://example.invalid/api"), scan.httpUrls)
        assertNotNull(scan.buildId)
    }

    @Test
    fun flagsWeakExecutableStackAndMissingRelro() {
        val file = fixture("libjni_weak.so")
        val scan = ElfNativeScanner.scan("lib/x86_64/libjni_weak.so", file)
        assertEquals(true, scan.executableStack)
        assertFalse(scan.hasGnuRelro)
        assertFalse(scan.bindNow)
    }

    @Test
    fun reportsProgressAndHonorsThreadInterruption() {
        val file = fixture("libjni_hardened.so")
        val progress = mutableListOf<Int>()
        ElfNativeScanner.scan("lib/x86_64/libjni_hardened.so", file) { percent, _, _, _ -> progress += percent }
        assertTrue(progress.isNotEmpty())
        assertEquals(100, progress.last())
        assertTrue(progress.zipWithNext().all { (a, b) -> b >= a })

        Thread.currentThread().interrupt()
        try {
            ElfNativeScanner.scan("lib/x86_64/libjni_hardened.so", file)
            throw AssertionError("Expected InterruptedIOException")
        } catch (_: java.io.InterruptedIOException) {
            // expected
        } finally {
            Thread.interrupted()
        }
    }

    @Test(expected = ElfNativeScanner.ElfFormatException::class)
    fun rejectsNonElfInput() {
        val file = File.createTempFile("not-elf", ".so")
        file.writeText("not an elf")
        try {
            ElfNativeScanner.scan("lib/x86_64/not.so", file)
        } finally {
            file.delete()
        }
    }

    private fun fixture(name: String): File {
        javaClass.classLoader?.getResource("fixtures/$name")?.let { return File(it.toURI()) }
        val candidates = listOf(
            File("src/test/resources/fixtures/$name"),
            File("app/src/test/resources/fixtures/$name"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: error("Missing native test fixture: ${candidates.joinToString { it.absolutePath }}")
    }
}
