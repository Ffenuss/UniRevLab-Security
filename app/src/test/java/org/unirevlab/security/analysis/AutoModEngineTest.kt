package org.unirevlab.security.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AutoModEngineTest {
    @Test
    fun choosesSemanticallySafeBooleanDirections() {
        assertEquals(
            AutoModEngine.Mode.RETURN_TRUE,
            AutoModEngine.suggestForTesting("ENTITLEMENT_TRUST", "isPremium", "()Z")?.mode,
        )
        assertEquals(
            AutoModEngine.Mode.RETURN_FALSE,
            AutoModEngine.suggestForTesting("ENTITLEMENT_TRUST", "isTrialExpired", "()Z")?.mode,
        )
        assertEquals(
            AutoModEngine.Mode.RETURN_FALSE,
            AutoModEngine.suggestForTesting("INTEGRITY", "isTampered", "()Z")?.mode,
        )
        assertEquals(
            AutoModEngine.Mode.RETURN_TRUE,
            AutoModEngine.suggestForTesting("INTEGRITY", "verifySignature", "()Z")?.mode,
        )
        assertNull(AutoModEngine.suggestForTesting("ENTITLEMENT_TRUST", "professional", "()Z"))
        assertNull(AutoModEngine.suggestForTesting("LOCAL_STATE", "scoreboard", "()I"))
    }

    @Test
    fun evidenceBackedObfuscatedMethodsCanStillBecomeDemoTargets() {
        assertEquals(
            AutoModEngine.Mode.RETURN_TRUE,
            AutoModEngine.suggestForTesting("ENTITLEMENT_TRUST", "a", "()Z", 68, "premium entitlement access")?.mode,
        )
        val money = AutoModEngine.suggestForTesting("LOCAL_STATE", "b", "()I", 58, "player money balance")
        assertEquals(AutoModEngine.Mode.RETURN_INT, money?.mode)
        assertEquals(9999, money?.intValue)
    }

    @Test
    fun choosesBoundedLocalStateIntegerDemo() {
        val suggestion = AutoModEngine.suggestForTesting("LOCAL_STATE", "getHighScore", "()I")
        assertEquals(AutoModEngine.Mode.RETURN_INT, suggestion?.mode)
        assertEquals(9999, suggestion?.intValue)
    }

    @Test
    fun intReturnPatchAddsOneLocalAndImmediateReturn() {
        val input = """
            .class public Ldemo/Test;
            .super Ljava/lang/Object;

            .method public getScore()I
                .locals 1
                const/4 v0, 0x1
                return v0
            .end method
        """.trimIndent()

        val patched = AutoModEngine.forceIntReturnForTesting(input, "getScore", "()I", 9999)
        assertTrue(patched.contains(".locals 2"))
        assertTrue(patched.contains("# UniRevLab AutoMod Demo"))
        assertTrue(patched.contains("const/16 v1, 0x270f"))
        assertTrue(patched.contains("return v1"))
    }
}
