package org.unirevlab.security.analysis

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkMutationDiffEngineTest {
    @Test
    fun contentDiffIgnoresUnchangedEntriesAndMarksExpectedChange() {
        val dir = createTempDirectory("apk-diff-").toFile()
        val before = File(dir, "before.apk")
        val after = File(dir, "after.apk")
        zip(before, mapOf("classes.dex" to "old", "assets/a.txt" to "same", "META-INF/X.SF" to "old-sig"))
        zip(after, mapOf("classes.dex" to "new", "assets/a.txt" to "same", "META-INF/X.SF" to "new-sig"))
        val diff = ApkMutationDiffEngine.compare(before, after, listOf("classes.dex"))
        assertEquals(1, diff.contentChanges)
        assertEquals(1, diff.signatureMetadataChanges)
        assertTrue(diff.unexpectedContentChanges.isEmpty())
        val code = ApkMutationDiffEngine.diffText("SMALI", "Lx;", "a\nb\nc", "a\nB\nc")
        assertEquals(1, code.removedLines)
        assertEquals(1, code.addedLines)
        assertTrue(code.preview.contains("- b"))
        assertTrue(code.preview.contains("+ B"))
        dir.deleteRecursively()
    }

    private fun zip(file: File, entries: Map<String, String>) {
        ZipOutputStream(file.outputStream()).use { out ->
            entries.forEach { (name, value) ->
                out.putNextEntry(ZipEntry(name))
                out.write(value.toByteArray())
                out.closeEntry()
            }
        }
    }
}
