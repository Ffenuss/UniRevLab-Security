package org.unirevlab.security.analysis

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PatchLabEngineTest {
    @Test
    fun entryLogHookAddsTwoLocalsAndLogCall() {
        val source = """
            .class public Lx/Test;
            .super Ljava/lang/Object;

            .method public check(I)Z
                .locals 1
                const/4 v0, 0x1
                return v0
            .end method
        """.trimIndent()

        val patched = PatchLabEngine.addEntryLogHook(source, "check", "(I)Z", "TEST-001")

        assertTrue(patched.contains(".locals 3"))
        assertTrue(patched.contains("Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"))
        assertTrue(patched.contains("TEST-001: check(I)Z"))
    }

    @Test
    fun forceBooleanAddsImmediateReturn() {
        val source = """
            .class public Lx/Test;
            .super Ljava/lang/Object;

            .method public enabled()Z
                .locals 0
                const/4 v0, 0x1
                return v0
            .end method
        """.trimIndent()

        val patched = PatchLabEngine.forceBooleanReturn(source, "enabled", "()Z", false)

        assertTrue(patched.contains(".locals 1"))
        assertTrue(patched.contains("const/16 v0, 0x0"))
        assertTrue(patched.contains("return v0"))
    }

    @Test
    fun resourcesArscUsesFourByteStoredAlignment() {
        val alignment = PatchLabEngine.requiredStoredAlignment("resources.arsc", java.util.zip.ZipEntry.STORED)
        assertTrue(alignment == PatchLabEngine.APK_ALIGNMENT)

        val offset = 1_001L
        val name = "resources.arsc"
        val extra = PatchLabEngine.alignedExtra(offset, name, null, requireNotNull(alignment))
        val dataOffset = offset + 30L + name.toByteArray(Charsets.UTF_8).size + (extra?.size ?: 0)
        assertTrue(dataOffset % PatchLabEngine.APK_ALIGNMENT == 0L)
    }

    @Test
    fun compressedEntriesDoNotReceiveStoredAlignment() {
        val alignment = PatchLabEngine.requiredStoredAlignment("classes.dex", java.util.zip.ZipEntry.DEFLATED)
        assertTrue(alignment == null)
    }

    @Test
    fun nativeAlignmentPadsStoredSoTo16KiB() {
        val offset = 1_237L
        val name = "lib/arm64-v8a/libsample.so"
        val extra = PatchLabEngine.alignedExtra(offset, name, null)
        val dataOffset = offset + 30L + name.toByteArray(Charsets.UTF_8).size + (extra?.size ?: 0)
        assertTrue(dataOffset % PatchLabEngine.NATIVE_ALIGNMENT == 0L)
    }
    @Test
    fun onlySafeNewModEntryPathsAreAccepted() {
        assertTrue(PatchLabEngine.canAddArchiveEntry("classes5.dex"))
        assertTrue(PatchLabEngine.canAddArchiveEntry("lib/arm64-v8a/libunirevlab_mod.so"))
        assertTrue(PatchLabEngine.canAddArchiveEntry("assets/unirevlab/mod-plan.json"))
        assertFalse(PatchLabEngine.canAddArchiveEntry("../AndroidManifest.xml"))
        assertFalse(PatchLabEngine.canAddArchiveEntry("lib/armeabi-v7a/libmod.so"))
        assertFalse(PatchLabEngine.canAddArchiveEntry("classes.dex"))
    }
    @Test
    fun validatesDexAndArm64HeadersBeforeAddingModules() {
        val dex = java.io.File.createTempFile("unirevlab-", ".dex")
        val arm64 = java.io.File.createTempFile("unirevlab-", ".so")
        val wrongElf = java.io.File.createTempFile("unirevlab-", ".so")
        try {
            dex.writeBytes(ByteArray(24).apply {
                byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00).copyInto(this)
            })
            arm64.writeBytes(ByteArray(24).apply {
                this[0] = 0x7f
                this[1] = 0x45
                this[2] = 0x4c
                this[3] = 0x46
                this[4] = 2
                this[5] = 1
                this[18] = 183.toByte()
                this[19] = 0
            })
            wrongElf.writeBytes(ByteArray(24).apply {
                this[0] = 0x7f
                this[1] = 0x45
                this[2] = 0x4c
                this[3] = 0x46
                this[4] = 2
                this[5] = 1
                this[18] = 40
            })

            PatchLabEngine.validateNewArchiveEntry("classes2.dex", dex)
            PatchLabEngine.validateNewArchiveEntry("lib/arm64-v8a/libmodule.so", arm64)
            assertTrue(
                runCatching {
                    PatchLabEngine.validateNewArchiveEntry("lib/arm64-v8a/libwrong.so", wrongElf)
                }.isFailure,
            )
        } finally {
            dex.delete()
            arm64.delete()
            wrongElf.delete()
        }
    }

}
