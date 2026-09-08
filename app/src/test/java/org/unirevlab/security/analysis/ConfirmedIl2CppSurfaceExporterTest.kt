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
              "ScriptMethod": [
                {
                  "Address": 4660,
                  "Name": "PlayerStats_ApplyDamage",
                  "Signature": "void Game_Core_PlayerStats__ApplyDamage (void);",
                  "DotNetSignature": "Game.Core.PlayerStats::ApplyDamage()",
                  "Group": "Game/Game/Core/PlayerStats"
                },
                {
                  "Address": 17767,
                  "Name": "HttpWebRequest_MoveNext",
                  "Signature": "void System_Net_HttpWebRequest_State__MoveNext (void);",
                  "DotNetSignature": "System.Net.HttpWebRequest.<AuthorizationState>d__1::MoveNext()",
                  "Group": "System/System/Net/HttpWebRequest/<AuthorizationState>d__1"
                },
                {
                  "Address": 22136,
                  "Name": "StoreService_HasBoughtGame",
                  "Signature": "bool Drova_StoreService__HasBoughtGame (void);",
                  "DotNetSignature": "Drova.StoreService::HasBoughtGame()",
                  "Group": "Drova/Drova/StoreService"
                },
                {
                  "Address": 0,
                  "Name": "ZeroAddress",
                  "Signature": "void StoreService__PurchaseGame (void);",
                  "DotNetSignature": "Drova.StoreService::PurchaseGame()",
                  "Group": "Drova/Drova/StoreService"
                }
              ],
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
        assertEquals(3, summary.applicationCount)
        assertTrue(json.contains("0x1234"))
        assertTrue(json.contains("0x18"))
        assertTrue(json.contains("0x7777"))
        assertTrue(json.contains("_hasBoughtGame"))
        assertTrue(json.contains("0x4567"))
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
        assertFalse(damage.has("declaredType"))
        assertEquals("0x1234", damage.getString("methodRva"))
        assertFalse(damage.has("methodFileOffset"))
        assertEquals("moduleBase(lib/<abi>/libil2cpp.so) + 0x1234", damage.getString("addressFormula"))
        assertEquals(2, summary.methodCount)
        val resolved = rootArrays(json, "gameplayOffsets", "applicationAndMonetizationOffsets")
        assertTrue(resolved.any { it.getString("managedIdentity") == "Game.Core.PlayerStats::ApplyDamage()" })
        assertFalse(resolved.any { it.optString("address") == "0x0" })
        assertFalse(resolved.any { it.optString("managedIdentity").contains("PurchaseGame") })
        assertEquals(1, summary.unresolvedRelevantMethodCount)
        assertEquals(1, summary.relevantStringCount)
        val root = org.json.JSONObject(json)
        assertFalse(root.getJSONArray("unresolvedRelevantMethods").toString().contains("HasBoughtGame"))
        assertTrue(resolved.first { it.getString("managedIdentity").contains("HasBoughtGame") }
            .getString("resolutionSource") == "GLOBAL_METADATA_PLUS_CODE_REGISTRATION")
        assertTrue(root.getJSONArray("relevantStringLiterals").toString().contains("Invalid receipt"))
    }
    private fun rootArrays(json: String, vararg names: String): List<org.json.JSONObject> {
        val root = org.json.JSONObject(json)
        return names.flatMap { name ->
            val array = root.getJSONArray(name)
            (0 until array.length()).map { array.getJSONObject(it) }
        }
    }

}
