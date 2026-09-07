package org.unirevlab.security.analysis

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfirmedIl2CppSurfaceExporterTest {
    @Test
    fun exportsOnlyConfirmedAddressesAndSeparatesDomains() {
        val dir = Files.createTempDirectory("confirmed-il2cpp").toFile()
        val dump = dir.resolve("dump.cs")
        dump.writeText(
            """
            // Namespace: Game.Core
            public class PlayerStats
            {
                // RVA: 0x1234 Offset: 0x1234 VA: 0x1234
                public void ApplyDamage(int value) { }
                public int Health; // 0x18
            }
            public class Account
            {
                // RVA: 0x7777 Offset: 0x7777 VA: 0x7777
                public bool IsPremium() { }
                // RVA: 0x9999 Offset: 0x9999 VA: 0x9999
                public void HarmlessTelemetry() { }
            }
            // Dll : Drova.dll
            // Namespace: Drova
            public class StoreService
            {
                private bool _hasBoughtGame; // 0x38
                // RVA: -1 Offset: -1
                public void PurchaseGame(bool isOffer = false) { }
                // RVA: -1 Offset: -1
                internal bool HasBoughtGame() { }
                /* GenericInstMethod :
                |
                |-RVA: 0x4567 Offset: 0x4167 VA: 0x4567
                |-GenericEvent<StoreService.PurchaseGameState>.AddEventListener
                */
            }
            """.trimIndent(),
        )
        dir.resolve("script.json").writeText(
            """
            {
              "ScriptMethod": [],
              "ScriptString": [
                {
                  "Address": 131514352,
                  "Value": "Invalid receipt, not unlocking content.",
                  "Name": "StringLiteral_Invalid_receipt"
                }
              ],
              "ScriptMetadata": []
            }
            """.trimIndent(),
        )
        val summary = ConfirmedIl2CppSurfaceExporter.export(dump, dir)
        val json = summary.outputJson.readText()
        assertEquals(2, summary.gameplayCount)
        assertEquals(1, summary.applicationCount)
        assertTrue(json.contains("0x1234"))
        assertTrue(json.contains("0x18"))
        assertTrue(json.contains("0x7777"))
        assertFalse(json.contains("0x9999"))
        val gameplay = org.json.JSONObject(json).getJSONArray("gameplayOffsets")
        val health = (0 until gameplay.length())
            .map { gameplay.getJSONObject(it) }
            .first { it.getString("memberName") == "Health" }
        assertEquals("Game.Core", health.getString("namespace"))
        assertEquals("PlayerStats", health.getString("className"))
        assertEquals("int", health.getString("declaredType"))
        assertEquals("0x18", health.getString("fieldOffset"))
        assertEquals("objectAddress(Game.Core.PlayerStats) + 0x18", health.getString("addressFormula"))
        assertFalse(health.has("runtimeAbsoluteAddress"))
        assertEquals("LIVE_OBJECT_INSTANCE_REQUIRED", health.getJSONObject("runtimeAddressResolution").getString("reason"))

        val damage = (0 until gameplay.length())
            .map { gameplay.getJSONObject(it) }
            .first { it.getString("memberName") == "ApplyDamage" }
        assertEquals("void", damage.getString("declaredType"))
        assertEquals("0x1234", damage.getString("methodRva"))
        assertEquals("0x1234", damage.getString("methodFileOffset"))
        assertEquals("moduleBase(lib/<abi>/libil2cpp.so) + 0x1234", damage.getString("addressFormula"))
        assertTrue(summary.methodCount >= 2)
        assertEquals(2, summary.unresolvedRelevantMethodCount)
        assertEquals(1, summary.relevantStringCount)
        val root = org.json.JSONObject(json)
        assertTrue(root.getJSONArray("unresolvedRelevantMethods").toString().contains("HasBoughtGame"))
        assertTrue(root.getJSONArray("relevantStringLiterals").toString().contains("Invalid receipt"))
    }
}
