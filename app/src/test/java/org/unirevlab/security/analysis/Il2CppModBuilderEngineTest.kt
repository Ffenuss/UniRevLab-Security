package org.unirevlab.security.analysis

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Il2CppModBuilderEngineTest {
    @Test fun wholeTokenSearchDoesNotMatchSmoothPath() {
        val action = Il2CppModBuilderEngine.Action(
            "1", "SmoothPath get MinPos", "SmoothPath::get_MinPos()", "libil2cpp.so",
            4, Il2CppModBuilderEngine.ActionKind.CALL_VOID, null,
            Il2CppModBuilderEngine.Availability.BUILDABLE, "VERIFIED", "ok",
        )
        assertTrue(Il2CppModBuilderEngine.filter(listOf(action), "hp").isEmpty())
    }

    @Test fun hpMatchesDedicatedHpToken() {
        val action = Il2CppModBuilderEngine.Action(
            "1", "Player HP", "Player::get_HP()", "libil2cpp.so",
            4, Il2CppModBuilderEngine.ActionKind.CALL_VOID, null,
            Il2CppModBuilderEngine.Availability.BUILDABLE, "VERIFIED", "ok",
        )
        assertEquals(listOf(action), Il2CppModBuilderEngine.filter(listOf(action), "hp"))
    }
}
