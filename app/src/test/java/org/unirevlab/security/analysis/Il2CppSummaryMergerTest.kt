package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.unirevlab.security.model.Il2CppMetadataSummary
import org.unirevlab.security.model.Il2CppSummary

class Il2CppSummaryMergerTest {
    @Test
    fun combinesMetadataAndLibraryFromDifferentSplits() {
        val metadata = Il2CppMetadataSummary(
            entryName = "assets/bin/Data/Managed/Metadata/global-metadata.dat",
            sizeBytes = 20_000_000,
            magicValid = true,
            metadataVersion = 29,
            headerPairsScanned = 32,
            assemblyNameCandidates = emptyList(),
            managedNameCandidates = emptyList(),
            unityVersionCandidates = emptyList(),
        )
        val merged = Il2CppSummaryMerger.merge(
            listOf(
                Il2CppSummary(
                    detected = false,
                    confidence = "LOW",
                    metadata = metadata,
                    libil2cppLibraries = emptyList(),
                    il2cppApiSymbols = emptyList(),
                    registrationIndicators = listOf("GLOBAL_METADATA_PRESENT"),
                    parseErrors = 0,
                    truncated = false,
                ),
                Il2CppSummary(
                    detected = false,
                    confidence = "LOW",
                    metadata = null,
                    libil2cppLibraries = listOf("split.apk!lib/arm64/libil2cpp.so"),
                    il2cppApiSymbols = emptyList(),
                    registrationIndicators = listOf("LIBIL2CPP_PRESENT"),
                    parseErrors = 0,
                    truncated = false,
                ),
            )
        )

        assertNotNull(merged)
        assertTrue(requireNotNull(merged).detected)
        assertEquals(metadata, merged.metadata)
        assertEquals("HIGH", merged.confidence)
        assertTrue("SPLIT_EVIDENCE_MERGED" in merged.registrationIndicators)
        assertTrue(merged.libil2cppLibraries.single().endsWith("libil2cpp.so"))
    }
}
