package org.unirevlab.security.analysis

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FlagSweepEngineTest {
    @Test
    fun findsDefaultCustomBinaryAndUtf16FlagsWithoutProSubstringNoise() {
        val dir = createTempDirectory("flag-sweep-test-").toFile()
        try {
            val apk = File(dir, "sample.apk")
            ZipOutputStream(apk.outputStream()).use { zip ->
                fun entry(name: String, bytes: ByteArray) {
                    zip.putNextEntry(ZipEntry(name))
                    zip.write(bytes)
                    zip.closeEntry()
                }
                entry("assets/config.json", "{\"premium\":true,\"hp\":250,\"privateTier\":\"gold\"}".toByteArray())
                entry("assets/profile.txt", "profile profile profiling".toByteArray())
                entry("res/raw/flags.bin", byteArrayOf(1, 2, 3, 4) + "vip".toByteArray() + byteArrayOf(0, 7))
                entry("res/raw/wide.bin", "no_ads".toByteArray(Charsets.UTF_16LE))
            }
            val workspace = PatchLabEngine.Workspace(
                root = dir,
                originalApk = apk,
                artifactSha256 = "test",
                apiLevel = 35,
                minSdk = 26,
                dexEntries = emptyList(),
                nativeEntries = emptyList(),
                archiveEntries = listOf("assets/config.json", "assets/profile.txt", "res/raw/flags.bin", "res/raw/wide.bin"),
            )

            val result = FlagSweepEngine.scan(workspace, listOf("privateTier"))
            assertTrue(result.matches.any { it.category == "ENTITLEMENT" && it.term.equals("premium", true) })
            assertTrue(result.matches.any { it.category == "LOCAL_STATE" && it.term.equals("hp", true) })
            assertTrue(result.matches.any { it.category == "ENTITLEMENT" && it.term.equals("vip", true) })
            assertTrue(result.matches.any { it.category == "ADS" && it.term.equals("no_ads", true) })
            assertTrue(result.matches.any { it.category == "CUSTOM" && it.term.equals("privatetier", true) })
            assertFalse(result.matches.any { it.entryName == "assets/profile.txt" && it.term.equals("pro", true) })
            assertTrue(result.entriesVisited == 4)
            assertTrue(result.entriesContentScanned == 4)
        } finally {
            dir.deleteRecursively()
        }
    }
}
