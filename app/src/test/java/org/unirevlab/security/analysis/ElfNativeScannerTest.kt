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
        val url = checkNotNull(javaClass.classLoader?.getResource("fixtures/$name"))
        return File(url.toURI())
    }
}
