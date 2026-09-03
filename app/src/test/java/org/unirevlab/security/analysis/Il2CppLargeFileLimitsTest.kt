package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class Il2CppLargeFileLimitsTest {
    @Test
    fun standaloneIl2CppPairAcceptsLargeLibil2cppFiles() {
        val limits = ElfNativeScanner.Limits()
        assertEquals(2L * 1024L * 1024L * 1024L, limits.maxElfBytes)
        assertEquals(64L * 1024L * 1024L, limits.maxAsciiScanBytes)
    }

    @Test
    fun metadataLimitIsRaisedWithoutUnboundingReconstruction() {
        val limits = Il2CppScanner.Limits()
        assertEquals(128L * 1024L * 1024L, limits.maxMetadataBytes)
        assertTrue(limits.maxTypeDefinitions <= 20_000)
        assertTrue(limits.maxMethodDefinitions <= 50_000)
        assertTrue(limits.maxFieldDefinitions <= 50_000)
    }
}
