package org.unirevlab.security.analysis

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class NestedApkSetTest {
    @Test fun extractsBaseAndSplitFromOuterContainer() {
        val root = java.nio.file.Files.createTempDirectory("apkset-test-").toFile()
        try {
            val base = File(root, "base.apk")
            fakeApk(base, withDex = true)
            val split = File(root, "config.arm64_v8a.apk")
            fakeApk(split, withDex = false)
            val outer = File(root, "sample.apk+")
            ZipOutputStream(outer.outputStream()).use { out ->
                addFile(out, "base.apk", base)
                addFile(out, "splits/config.arm64_v8a.apk", split)
                out.putNextEntry(ZipEntry("meta.json")); out.write("{}".toByteArray()); out.closeEntry()
            }
            val extracted = NestedApkSet.extract(outer, File(root, "out"))
            assertNotNull(extracted)
            extracted!!
            assertEquals("base.apk", extracted.base.prefix)
            assertEquals(1, extracted.splits.size)
            assertEquals("split:config.arm64_v8a.apk", extracted.splits.single().prefix)
            assertEquals(extracted.splits.single(), extracted.selectForReportEntry("split:config.arm64_v8a.apk!/lib/arm64-v8a/libx.so"))
        } finally { root.deleteRecursively() }
    }

    @Test fun doesNotTreatPlainApkAsContainer() {
        val root = java.nio.file.Files.createTempDirectory("apkset-plain-").toFile()
        try {
            val apk = File(root, "plain.apk")
            fakeApk(apk, withDex = true)
            assertNull(NestedApkSet.extract(apk, File(root, "out")))
        } finally { root.deleteRecursively() }
    }

    private fun fakeApk(file: File, withDex: Boolean) {
        ZipOutputStream(file.outputStream()).use { out ->
            out.putNextEntry(ZipEntry("AndroidManifest.xml")); out.write(byteArrayOf(1, 2, 3)); out.closeEntry()
            if (withDex) { out.putNextEntry(ZipEntry("classes.dex")); out.write("dex\n035\u0000".toByteArray()); out.closeEntry() }
        }
    }

    private fun addFile(out: ZipOutputStream, name: String, file: File) {
        out.putNextEntry(ZipEntry(name)); file.inputStream().use { it.copyTo(out) }; out.closeEntry()
    }
}
