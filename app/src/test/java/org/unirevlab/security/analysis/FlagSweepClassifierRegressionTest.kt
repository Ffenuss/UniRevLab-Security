package org.unirevlab.security.analysis

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FlagSweepClassifierRegressionTest {
    @Test
    fun rejectsWordSubstringsButKeepsIdentifierTokens() {
        val dir = createTempDirectory("flag-classifier-regression-").toFile()
        try {
            val apk = File(dir, "sample.apk")
            ZipOutputStream(apk.outputStream()).use { zip ->
                fun entry(name: String, text: String) {
                    zip.putNextEntry(ZipEntry(name))
                    zip.write(text.toByteArray())
                    zip.closeEntry()
                }
                entry(
                    "assets/noise.txt",
                    "scoreboard process professional profile protobuf prepaid lifestyle ranking balanced configuration enabledness",
                )
                entry(
                    "assets/positive.txt",
                    "highScore isPremiumEnabled remoteConfigEnabled user_balance rootCheckPassed proMode",
                )
            }
            val workspace = PatchLabEngine.Workspace(
                root = dir,
                originalApk = apk,
                artifactSha256 = "test",
                apiLevel = 35,
                minSdk = 26,
                dexEntries = emptyList(),
                nativeEntries = emptyList(),
                archiveEntries = listOf("assets/noise.txt", "assets/positive.txt"),
            )

            val result = FlagSweepEngine.scan(workspace)
            val noisy = result.matches.filter { it.entryName == "assets/noise.txt" }
            listOf("score", "pro", "paid", "life", "rank", "balance", "config", "enabled").forEach { term ->
                assertFalse("$term must not match inside ordinary words", noisy.any { it.term.equals(term, true) })
            }

            val positive = result.matches.filter { it.entryName == "assets/positive.txt" }
            assertTrue(positive.any { it.term.equals("score", true) })
            assertTrue(positive.any { it.term.equals("pro", true) })
            assertTrue(positive.any { it.term.equals("premium", true) || it.term.equals("isPremium", true) })
            assertTrue(positive.any { it.term.equals("remoteConfig", true) || it.term.equals("config", true) })
            assertTrue(positive.any { it.term.equals("balance", true) })
            assertTrue(positive.any { it.term.equals("rootCheck", true) })
        } finally {
            dir.deleteRecursively()
        }
    }
}
