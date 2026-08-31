package org.unirevlab.security.analysis

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
    fun nativeAlignmentPadsStoredSoTo16KiB() {
        val offset = 1_237L
        val name = "lib/arm64-v8a/libsample.so"
        val extra = PatchLabEngine.alignedExtra(offset, name, null)
        val dataOffset = offset + 30L + name.toByteArray(Charsets.UTF_8).size + (extra?.size ?: 0)
        assertTrue(dataOffset % PatchLabEngine.NATIVE_ALIGNMENT == 0L)
    }
}
